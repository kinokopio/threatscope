"""
DiecAnalyzer - File type identification using diec HTTP service.

Provides file format detection, architecture identification, and packer/compiler detection.
Falls back to python-magic if diec service is unavailable.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

# Optional fallback
try:
    import magic

    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


@dataclass
class FileTypeInfo:
    """File type identification result."""

    format: str = ""  # PE32, PE32+, ELF64, Script, Unknown
    arch: str = ""  # x86, x64, ARM, N/A
    category: str = ""  # pe, elf, script:python, script:shell, unknown
    platform: str = ""  # windows, linux, cross
    packers: list[dict[str, str]] = field(default_factory=list)
    compilers: list[dict[str, str]] = field(default_factory=list)
    protectors: list[dict[str, str]] = field(default_factory=list)
    libraries: list[dict[str, str]] = field(default_factory=list)
    script_language: str | None = None  # python, shell, powershell...
    is_fallback: bool = False  # True if using python-magic fallback

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "format": self.format,
            "arch": self.arch,
            "category": self.category,
            "platform": self.platform,
            "packers": self.packers,
            "compilers": self.compilers,
            "protectors": self.protectors,
            "libraries": self.libraries,
            "script_language": self.script_language,
            "is_fallback": self.is_fallback,
        }


# Script language detection mappings
SHEBANG_MAP = {
    "python": "python",
    "python3": "python",
    "python2": "python",
    "bash": "shell",
    "sh": "shell",
    "zsh": "shell",
    "dash": "shell",
    "ksh": "shell",
    "perl": "perl",
    "ruby": "ruby",
    "node": "javascript",
    "nodejs": "javascript",
    "php": "php",
}

EXTENSION_MAP = {
    ".py": "python",
    ".pyw": "python",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".psm1": "powershell",
    ".psd1": "powershell",
    ".bat": "batch",
    ".cmd": "batch",
    ".vbs": "vbscript",
    ".vbe": "vbscript",
    ".js": "javascript",
    ".jse": "javascript",
    ".wsf": "wsf",
    ".pl": "perl",
    ".rb": "ruby",
    ".php": "php",
}


class DiecAnalyzer(AnalysisTool):
    """
    File type identification analyzer using diec HTTP service.

    Identifies file format, architecture, packers, compilers, and protectors.
    Falls back to python-magic if diec service is unavailable.
    """

    def __init__(
        self,
        diec_url: str | None = None,
        timeout: int = 30,
    ):
        """
        Initialize DiecAnalyzer.

        Args:
            diec_url: URL of diec HTTP service. Defaults to DIEC_URL env var or http://localhost:8082
            timeout: Request timeout in seconds
        """
        self.diec_url = diec_url or os.environ.get("DIEC_URL", "http://localhost:8082")
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def name(self) -> str:
        return "diec_analyzer"

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
        return self._client

    async def analyze(self, file_path: Path) -> ToolResult:
        """
        Analyze file type using diec service.

        Args:
            file_path: Path to file to analyze

        Returns:
            ToolResult with FileTypeInfo data
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return ToolResult(success=False, error=f"File not found: {file_path}")

        try:
            # Try diec service first
            result = await self._analyze_with_diec(file_path)
            return ToolResult(success=True, data=result.to_dict())

        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            # diec service unavailable, try fallback
            if MAGIC_AVAILABLE:
                result = self._fallback_magic(file_path)
                return ToolResult(success=True, data=result.to_dict())
            else:
                return ToolResult(
                    success=False,
                    error=f"diec service unavailable and python-magic not installed: {e}",
                )

        except Exception as e:
            return ToolResult(success=False, error=str(e))

    async def _analyze_with_diec(self, file_path: Path) -> FileTypeInfo:
        """
        Call diec HTTP service to analyze file.

        Args:
            file_path: Path to file

        Returns:
            FileTypeInfo with detection results
        """
        client = await self._get_client()

        # Use path-based endpoint if file is accessible to diec container
        # Otherwise upload the file
        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            response = await client.post(f"{self.diec_url}/analyze", files=files)

        response.raise_for_status()
        data = response.json()

        return self._parse_diec_response(data, file_path)

    def _parse_diec_response(self, data: dict[str, Any], file_path: Path) -> FileTypeInfo:
        """
        Parse diec response into FileTypeInfo.

        Args:
            data: diec JSON response
            file_path: Original file path (for script detection)

        Returns:
            FileTypeInfo object
        """
        result = FileTypeInfo(
            format=data.get("format", ""),
            arch=data.get("arch", ""),
            is_fallback=False,
        )

        # Parse detections
        for detect in data.get("detects", []):
            detect_type = detect.get("type", "")
            entry = {"name": detect.get("name", ""), "version": detect.get("version", "")}

            if detect_type == "compiler":
                result.compilers.append(entry)
            elif detect_type == "packer":
                result.packers.append(entry)
            elif detect_type == "protector":
                result.protectors.append(entry)
            elif detect_type == "library":
                result.libraries.append(entry)

        # Determine category and platform
        result.category, result.platform = self._determine_category_platform(
            result.format, file_path
        )

        # Check for script if category is unknown or text
        if result.category in ("unknown", "text"):
            script_lang = self._detect_script_language(file_path)
            if script_lang:
                result.script_language = script_lang
                result.category = f"script:{script_lang}"
                result.platform = "cross"

        return result

    def _determine_category_platform(self, format_str: str, file_path: Path) -> tuple[str, str]:
        """
        Determine file category and platform from format string.

        Args:
            format_str: Format string from diec (e.g., "PE32", "ELF64")
            file_path: File path for extension-based detection

        Returns:
            Tuple of (category, platform)
        """
        fmt_upper = format_str.upper()

        # PE formats
        if "PE32" in fmt_upper or "PE64" in fmt_upper or fmt_upper.startswith("PE"):
            return "pe", "windows"

        # ELF formats
        if "ELF" in fmt_upper:
            return "elf", "linux"

        # Mach-O (not supported but detect)
        if "MACH" in fmt_upper:
            return "macho", "macos"

        # Text/Script detection by extension
        ext = file_path.suffix.lower()
        if ext in EXTENSION_MAP:
            lang = EXTENSION_MAP[ext]
            return f"script:{lang}", "cross"

        # Check if it's a text file
        if "TEXT" in fmt_upper or "ASCII" in fmt_upper or "UTF" in fmt_upper:
            return "text", "unknown"

        return "unknown", "unknown"

    def _detect_script_language(self, file_path: Path) -> str | None:
        """
        Detect script language from shebang and extension.

        Args:
            file_path: Path to file

        Returns:
            Script language name or None
        """
        # Try shebang first
        try:
            with open(file_path, "rb") as f:
                first_line = f.readline(256)

            if first_line.startswith(b"#!"):
                shebang = first_line.decode("utf-8", errors="ignore").strip()
                # Parse shebang: #!/usr/bin/env python3 or #!/bin/bash
                parts = shebang[2:].split()
                if parts:
                    # Handle "env python3" case
                    interpreter = parts[-1] if "env" in parts[0] else parts[0]
                    interpreter = Path(interpreter).name

                    for key, lang in SHEBANG_MAP.items():
                        if key in interpreter.lower():
                            return lang

        except Exception:
            pass

        # Fall back to extension
        ext = file_path.suffix.lower()
        return EXTENSION_MAP.get(ext)

    def _fallback_magic(self, file_path: Path) -> FileTypeInfo:
        """
        Fallback to python-magic for basic file type detection.

        Args:
            file_path: Path to file

        Returns:
            FileTypeInfo with basic detection
        """
        result = FileTypeInfo(is_fallback=True)

        try:
            mime = magic.from_file(str(file_path), mime=True)
            description = magic.from_file(str(file_path))

            # Parse MIME type
            if "x-executable" in mime or "x-sharedlib" in mime:
                if "ELF" in description:
                    result.format = "ELF"
                    result.category = "elf"
                    result.platform = "linux"
                    # Try to get arch from description
                    if "64-bit" in description:
                        result.arch = "AMD64"
                    elif "32-bit" in description:
                        result.arch = "I386"

            elif "x-dosexec" in mime or "x-msdos-program" in mime:
                result.format = "PE"
                result.category = "pe"
                result.platform = "windows"
                if "PE32+" in description:
                    result.format = "PE32+"
                    result.arch = "AMD64"
                elif "PE32" in description:
                    result.format = "PE32"
                    result.arch = "I386"

            elif "text/" in mime or mime == "application/x-sh":
                # Text file - check for script
                script_lang = self._detect_script_language(file_path)
                if script_lang:
                    result.script_language = script_lang
                    result.category = f"script:{script_lang}"
                    result.platform = "cross"
                else:
                    result.category = "text"
                    result.format = "Text"

            else:
                result.category = "unknown"
                result.format = description[:50] if description else "Unknown"

        except Exception:
            result.category = "unknown"
            result.format = "Unknown"

        return result

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
