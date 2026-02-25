"""String extractor tool."""

import re
import subprocess
from pathlib import Path

from tools.base import AnalysisResult, BaseTool

# Patterns for extracting interesting strings
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

# Suspicious patterns
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


class StringExtractor(BaseTool):
    """Extract and categorize strings from binary files."""

    def __init__(self, min_length: int = 4):
        self.min_length = min_length

    @property
    def name(self) -> str:
        return "string_extractor"

    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Extract strings and categorize them.

        Args:
            file_path: Path to the binary file.

        Returns:
            AnalysisResult with categorized strings.
        """
        try:
            # Use strings command
            result = subprocess.run(
                ["strings", "-n", str(self.min_length), str(file_path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
            all_strings = result.stdout.splitlines()

            # Categorize strings
            urls = set()
            ips = set()
            domains = set()
            emails = set()
            suspicious = set()

            for s in all_strings:
                # URLs
                for match in URL_PATTERN.findall(s):
                    urls.add(match)

                # IPs (exclude common ones)
                for match in IP_PATTERN.findall(s):
                    if not match.startswith(("0.", "127.", "255.")):
                        ips.add(match)

                # Domains
                for match in DOMAIN_PATTERN.findall(s):
                    domains.add(match.lower())

                # Emails
                for match in EMAIL_PATTERN.findall(s):
                    emails.add(match.lower())

                # Suspicious patterns
                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.search(s):
                        suspicious.add(s[:200])  # Limit length

            return AnalysisResult(
                success=True,
                data={
                    "total_strings": len(all_strings),
                    "urls": sorted(urls),
                    "ips": sorted(ips),
                    "domains": sorted(domains),
                    "emails": sorted(emails),
                    "suspicious": sorted(suspicious)[:50],  # Limit count
                },
            )
        except subprocess.TimeoutExpired:
            return AnalysisResult(success=False, error="String extraction timed out")
        except Exception as e:
            return AnalysisResult(success=False, error=str(e))
