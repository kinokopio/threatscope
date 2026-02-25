"""Hash calculator tool."""

import hashlib
from pathlib import Path

from tools.base import AnalysisResult, BaseTool


class HashCalculator(BaseTool):
    """Calculate file hashes (MD5, SHA1, SHA256)."""

    @property
    def name(self) -> str:
        return "hash_calculator"

    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Calculate MD5, SHA1, and SHA256 hashes.

        Args:
            file_path: Path to the file.

        Returns:
            AnalysisResult with hash values.
        """
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()

            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)

            return AnalysisResult(
                success=True,
                data={
                    "md5": md5.hexdigest(),
                    "sha1": sha1.hexdigest(),
                    "sha256": sha256.hexdigest(),
                },
            )
        except Exception as e:
            return AnalysisResult(success=False, error=str(e))
