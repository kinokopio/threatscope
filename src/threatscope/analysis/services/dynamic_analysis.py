"""Dynamic analysis service - routes to appropriate analyzer based on file type.

Supports:
- ELF binaries → Tracee (Linux eBPF)
- PE binaries → Skipped (CAPE integration planned)
- Other files → Skipped (not supported)
"""

import logging
from pathlib import Path
from typing import Any

from src.threatscope.analysis.tools.dynamic.tracee_analyzer import (
    TraceeAnalyzer,
    TraceeConfig,
)

logger = logging.getLogger(__name__)


# Supported architectures for Tracee
TRACEE_SUPPORTED_ARCHS = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "i386": "i386",
    "i686": "i386",
    "x86": "i386",
}


class DynamicAnalysisService:
    """
    Dynamic analysis service with file type routing.

    Routes analysis based on file type:
    - ELF → Tracee (if architecture supported)
    - PE → Skip (CAPE planned)
    - Other → Skip (not supported)
    """

    def __init__(self, timeout: int = 30):
        """
        Initialize DynamicAnalysisService.

        Args:
            timeout: Timeout for dynamic analysis in seconds.
        """
        self.timeout = timeout
        self._tracee_analyzer: TraceeAnalyzer | None = None

    @property
    def tracee_analyzer(self) -> TraceeAnalyzer:
        """Lazy initialization of Tracee analyzer."""
        if self._tracee_analyzer is None:
            config = TraceeConfig(timeout=self.timeout)
            self._tracee_analyzer = TraceeAnalyzer(config)
        return self._tracee_analyzer

    async def analyze(
        self,
        file_path: str | Path,
        file_type: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Run dynamic analysis based on file type.

        Args:
            file_path: Path to file to analyze.
            file_type: File type info from diec (contains category, arch, etc.)

        Returns:
            Dictionary with analysis results or skip info.
        """
        file_path = Path(file_path)
        category = file_type.get("category", "unknown")
        arch = file_type.get("arch", "").lower()

        logger.info(f"Dynamic analysis routing: category={category}, arch={arch}")

        # Route based on category
        if category == "elf":
            return await self._analyze_elf(file_path, arch)
        elif category == "pe":
            return self._skip_pe(file_type)
        else:
            return self._skip_unsupported(category, file_type)

    async def _analyze_elf(
        self,
        file_path: Path,
        arch: str,
    ) -> dict[str, Any]:
        """
        Analyze ELF binary with Tracee.

        Args:
            file_path: Path to ELF binary.
            arch: Architecture string from diec.

        Returns:
            Tracee analysis results or skip info if arch not supported.
        """
        # Check architecture support
        target_arch = self._get_tracee_arch(arch)

        if not target_arch:
            logger.warning(f"Unsupported architecture for Tracee: {arch}")
            return {
                "success": False,
                "skipped": True,
                "method": "tracee",
                "reason": f"Tracee requires x86_64/i386 architecture, got: {arch}",
                "file_type": "elf",
            }

        # Run Tracee analysis
        try:
            result = self.tracee_analyzer.analyze(str(file_path), target_arch)
            return {
                "success": result.success,
                "skipped": False,
                "method": "tracee",
                "process_tree": result.process_tree,
                "network_summary": result.network_summary,
                "security_events": result.security_events,
                "syscall_summary": result.syscall_summary,
                "file_activity": result.file_activity,
                "duration_seconds": result.duration_seconds,
                "raw_events_count": result.raw_events_count,
                "error": result.error,
                "event_types": result.event_types,
            }
        except Exception as e:
            logger.exception(f"Tracee analysis failed: {e}")
            return {
                "success": False,
                "skipped": False,
                "method": "tracee",
                "error": str(e),
            }

    def _skip_pe(self, file_type: dict[str, Any]) -> dict[str, Any]:
        """
        Return skip result for PE files.

        PE dynamic analysis requires CAPE sandbox (not yet integrated).
        """
        logger.info("Skipping dynamic analysis for PE file (CAPE not yet integrated)")
        return {
            "success": False,
            "skipped": True,
            "method": "none",
            "reason": "Windows PE dynamic analysis requires CAPE sandbox (not yet integrated)",
            "file_type": "pe",
            "planned_method": "cape",
        }

    def _skip_unsupported(
        self,
        category: str,
        file_type: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Return skip result for unsupported file types.
        """
        logger.info(f"Skipping dynamic analysis for unsupported file type: {category}")
        return {
            "success": False,
            "skipped": True,
            "method": "none",
            "reason": f"Dynamic analysis not supported for file type: {category}",
            "file_type": category,
        }

    def _get_tracee_arch(self, arch: str) -> str | None:
        """
        Map architecture string to Tracee-compatible architecture.

        Args:
            arch: Architecture string from diec (e.g., "AMD64", "I386").

        Returns:
            Tracee architecture string or None if not supported.
        """
        arch_lower = arch.lower()
        for key, value in TRACEE_SUPPORTED_ARCHS.items():
            if key in arch_lower:
                return value
        return None
