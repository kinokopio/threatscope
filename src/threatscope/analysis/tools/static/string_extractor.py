"""String extractor - extracts and categorizes strings from binaries."""

import asyncio
import re
from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

URL_PATTERN = re.compile(
    r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|de|uk|info|biz|xyz|top|cc|tk|ml|ga|cf|gq)\b",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

SUSPICIOUS_PATTERNS = [
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"LD_PRELOAD"),
    re.compile(r"/proc/self"),
    re.compile(r"/dev/null"),
    re.compile(r"base64"),
    re.compile(r"chmod\s+[0-7]{3,4}"),
    re.compile(r"curl\s+"),
    re.compile(r"wget\s+"),
]


class StringExtractor(AnalysisTool):
    def __init__(self, min_length: int = 4):
        self.min_length = min_length

    @property
    def name(self) -> str:
        return "string_extractor"

    async def analyze(self, file_path: Path) -> ToolResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                "strings",
                "-n",
                str(self.min_length),
                str(file_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult(success=False, error="String extraction timed out")

            all_strings = stdout.decode("utf-8", errors="replace").splitlines()

            urls: set[str] = set()
            ips: set[str] = set()
            domains: set[str] = set()
            emails: set[str] = set()
            suspicious: set[str] = set()

            for s in all_strings:
                for match in URL_PATTERN.findall(s):
                    urls.add(match)

                for match in IP_PATTERN.findall(s):
                    if not match.startswith(("0.", "127.", "255.")):
                        ips.add(match)

                for match in DOMAIN_PATTERN.findall(s):
                    domains.add(match.lower())

                for match in EMAIL_PATTERN.findall(s):
                    emails.add(match.lower())

                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(s):
                        suspicious.add(s[:200])

            return ToolResult(
                success=True,
                data={
                    "total_strings": len(all_strings),
                    "urls": sorted(urls),
                    "ips": sorted(ips),
                    "domains": sorted(domains),
                    "emails": sorted(emails),
                    "suspicious": sorted(suspicious)[:50],
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))
