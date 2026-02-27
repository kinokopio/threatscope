"""Hash calculator - computes MD5, SHA1, SHA256 for files."""

import asyncio
import hashlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

_executor = ThreadPoolExecutor(max_workers=4)


def _calculate_hashes_sync(file_path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    buffer_size = 1024 * 1024

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


class HashCalculator(AnalysisTool):
    @property
    def name(self) -> str:
        return "hash_calculator"

    async def analyze(self, file_path: Path) -> ToolResult:
        try:
            loop = asyncio.get_event_loop()
            hashes = await loop.run_in_executor(_executor, _calculate_hashes_sync, file_path)
            return ToolResult(success=True, data=hashes)
        except Exception as e:
            return ToolResult(success=False, error=str(e))
