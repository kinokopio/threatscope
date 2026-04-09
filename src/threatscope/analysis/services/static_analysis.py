"""Static analysis service - orchestrates all static analysis tools.

Refactored to support intelligent routing based on file type:
- PE/ELF binaries → capa analysis
- Scripts → (placeholder for future)
- All files → hash, strings, YARA

Two-phase parallel execution (coordinated by AnalysisCoordinator):
- Phase 1: Hash + diec (parallel) - determines file type
- Phase 2: capa + strings + yara + threat_intel + dynamic (all parallel)
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Awaitable, Callable

from src.threatscope.analysis.tools.static import (
    CapaAnalyzer,
    DiecAnalyzer,
    HashCalculator,
    StringExtractor,
    YaraScanner,
)

logger = logging.getLogger(__name__)

ProgressCallback = Callable[
    [str, str, str, dict[str, Any] | None, dict[str, Any] | None], Awaitable[None]
]


class StaticAnalysisService:
    """
    Static analysis service with intelligent file type routing.

    Provides methods for:
    - File identification (hash + diec)
    - Individual analysis tools (capa, strings, yara)

    The AnalysisCoordinator orchestrates the parallel execution.
    """

    def __init__(
        self,
        yara_rules_path: str | Path | None = None,
        diec_url: str | None = None,
        capa_rules_path: str | Path | None = None,
        capa_timeout: int = 300,
    ):
        """
        Initialize StaticAnalysisService.

        Args:
            yara_rules_path: Path to YARA rules directory
            diec_url: URL of diec HTTP service
            capa_rules_path: Path to capa rules directory
            capa_timeout: Timeout for capa analysis in seconds
        """
        self.hash_calculator = HashCalculator()
        self.string_extractor = StringExtractor()
        self.yara_scanner = YaraScanner(yara_rules_path)
        self.diec_analyzer = DiecAnalyzer(diec_url=diec_url)
        self.capa_analyzer = CapaAnalyzer(rules_path=capa_rules_path, timeout=capa_timeout)

    async def identify_file(
        self,
        file_path: str | Path,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """
        Identify file type and calculate hashes (Phase 1).

        Runs hash calculation and diec analysis in parallel.

        Args:
            file_path: Path to file to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary with hashes and file_type
        """
        file_path = Path(file_path)

        output: dict[str, Any] = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size if file_path.exists() else 0,
        }

        async def notify(step_id: str, step_name: str, status: str, preview: dict | None = None):
            if progress_callback:
                await progress_callback(step_id, step_name, status, preview, output)

        # Run hash + diec in parallel
        await notify("hashing", "Hash Calculation", "running")
        await notify("file_identification", "File Type Identification", "running")

        hash_task = self._calculate_hashes(file_path)
        diec_task = self._identify_file_type(file_path)

        hash_result, diec_result = await asyncio.gather(hash_task, diec_task)

        # Process hash result
        if hash_result["success"]:
            output["hashes"] = hash_result["data"]
            await notify(
                "hashing",
                "Hash Calculation",
                "completed",
                {
                    "md5": hash_result["data"].get("md5", "")[:16] + "...",
                    "sha256": hash_result["data"].get("sha256", "")[:16] + "...",
                },
            )
        else:
            output["hashes"] = {"error": hash_result["error"]}
            await notify("hashing", "Hash Calculation", "failed")

        # Process diec result
        if diec_result["success"]:
            output["file_type"] = diec_result["data"]
            category = diec_result["data"].get("category", "unknown")
            logger.info(
                f"File type identified: category={category}, format={diec_result['data'].get('format')}"
            )
            await notify(
                "file_identification",
                "File Type Identification",
                "completed",
                {
                    "format": diec_result["data"].get("format", ""),
                    "category": category,
                    "platform": diec_result["data"].get("platform", ""),
                },
            )
        else:
            output["file_type"] = {"error": diec_result["error"]}
            await notify("file_identification", "File Type Identification", "failed")
            logger.warning(f"File type identification failed: {diec_result['error']}")

        return output

    async def analyze_capabilities(
        self,
        file_path: str | Path,
        category: str,
    ) -> dict[str, Any]:
        """
        Run capa capability analysis.

        Args:
            file_path: Path to file to analyze
            category: File category from diec (pe, elf, etc.)

        Returns:
            Dictionary with capa results or skip info
        """
        file_path = Path(file_path)

        if category in ("pe", "elf"):
            result = await self.capa_analyzer.analyze(file_path)
            return {
                "success": result.success,
                "skipped": False,
                "data": result.data if result.success else None,
                "error": result.error,
                "reason": None,
            }
        elif category.startswith("script:"):
            return {
                "success": False,
                "skipped": True,
                "data": None,
                "error": None,
                "reason": "Script analysis not yet implemented",
            }
        else:
            return {
                "success": False,
                "skipped": True,
                "data": None,
                "error": None,
                "reason": f"Unsupported file type: {category}",
            }

    async def extract_strings(self, file_path: str | Path) -> dict[str, Any]:
        """
        Extract strings from file.

        Args:
            file_path: Path to file to analyze

        Returns:
            Dictionary with extracted strings
        """
        file_path = Path(file_path)
        result = await self.string_extractor.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def scan_yara(self, file_path: str | Path) -> dict[str, Any]:
        """
        Scan file with YARA rules.

        Args:
            file_path: Path to file to analyze

        Returns:
            Dictionary with YARA matches
        """
        file_path = Path(file_path)
        result = await self.yara_scanner.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def _calculate_hashes(self, file_path: Path) -> dict[str, Any]:
        """Run hash calculation."""
        result = await self.hash_calculator.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def _identify_file_type(self, file_path: Path) -> dict[str, Any]:
        """Run diec file type identification."""
        logger.info(
            f"Starting diec analysis for {file_path}, diec_url={self.diec_analyzer.diec_url}"
        )
        result = await self.diec_analyzer.analyze(file_path)
        logger.info(
            f"diec result: success={result.success}, error={result.error}, data={result.data}"
        )
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def close(self) -> None:
        """Clean up resources."""
        await self.diec_analyzer.close()
