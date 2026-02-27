"""Hash calculator tool."""

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from tools.base import AnalysisResult, BaseTool

# Shared thread pool for I/O operations
_executor = ThreadPoolExecutor(max_workers=4)


def _calculate_hashes(file_path: Path) -> dict[str, str]:
    """Calculate hashes synchronously (runs in thread pool)."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    # Use larger buffer for better performance
    buffer_size = 1024 * 1024  # 1MB chunks

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(buffer_size), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


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
            loop = asyncio.get_event_loop()
            # Run in thread pool to avoid blocking
            hashes = await loop.run_in_executor(_executor, _calculate_hashes, file_path)

            return AnalysisResult(success=True, data=hashes)
        except Exception as e:
            return AnalysisResult(success=False, error=str(e))
