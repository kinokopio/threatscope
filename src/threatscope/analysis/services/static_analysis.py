"""Static analysis service - orchestrates all static analysis tools.

Refactored to support intelligent routing based on file type:
- PE/ELF binaries → capa analysis
- Scripts → (placeholder for future)
- All files → hash, strings, YARA

Two-phase parallel execution:
- Phase 1: Hash + diec (parallel)
- Phase 2: capa + strings + yara (parallel, after phase 1)
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

# Analysis steps for progress tracking
ANALYSIS_STEPS = [
    ("hashing", "Hash Calculation"),
    ("file_identification", "File Type Identification"),
    ("capability_analysis", "Capability Analysis"),  # Only for PE/ELF
    ("string_extraction", "String Extraction"),
    ("yara_scanning", "YARA Scanning"),
]


class StaticAnalysisService:
    """
    Static analysis service with intelligent file type routing.

    Two-phase parallel execution:
    - Phase 1: Hash + diec (parallel) - determines file type
    - Phase 2: capa + strings + yara (parallel) - capa depends on category
    """

    def __init__(
        self,
        yara_rules_path: str | Path | None = None,
        diec_url: str | None = None,
        capa_rules_path: str | Path | None = None,
        capa_timeout: int = 60,
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

    async def analyze(
        self,
        file_path: str | Path,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """
        Analyze a file using all available static analysis tools.

        Args:
            file_path: Path to file to analyze
            progress_callback: Optional callback for progress updates

        Returns:
            Dictionary with analysis results
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

        # ========================================
        # Phase 1: Hash + diec (parallel)
        # ========================================
        await notify("hashing", "Hash Calculation", "running")
        await notify("file_identification", "File Type Identification", "running")

        hash_task = self._run_hash(file_path)
        diec_task = self._run_diec(file_path)

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
            category = "unknown"
            await notify("file_identification", "File Type Identification", "failed")
            logger.warning(f"File type identification failed: {diec_result['error']}")

        # ========================================
        # Phase 2: capa + strings + yara (parallel)
        # ========================================
        await notify("capability_analysis", "Capability Analysis", "running")
        await notify("string_extraction", "String Extraction", "running")
        await notify("yara_scanning", "YARA Scanning", "running")

        capa_task = self._run_capa(file_path, category)
        strings_task = self._run_strings(file_path)
        yara_task = self._run_yara(file_path)

        capa_result, strings_result, yara_result = await asyncio.gather(
            capa_task, strings_task, yara_task
        )

        # Process capa result
        if capa_result["skipped"]:
            output["capa"] = {"skipped": True, "reason": capa_result["reason"]}
            await notify("capability_analysis", "Capability Analysis", "skipped")
            logger.info(f"Skipping capability analysis: {capa_result['reason']}")
        elif capa_result["success"]:
            output["capa"] = capa_result["data"]
            capabilities = capa_result["data"].get("capabilities", [])
            attack = capa_result["data"].get("attack", {})
            await notify(
                "capability_analysis",
                "Capability Analysis",
                "completed",
                {
                    "capabilities": len(capabilities),
                    "attack_techniques": len(attack.get("techniques", [])),
                    "analysis_time": capa_result["data"].get("analysis_time", 0),
                },
            )
        else:
            output["capa"] = {"error": capa_result["error"]}
            await notify("capability_analysis", "Capability Analysis", "failed")
            logger.warning(f"capa analysis failed: {capa_result['error']}")

        # Process strings result
        if strings_result["success"]:
            output["strings"] = strings_result["data"]
            await notify(
                "string_extraction",
                "String Extraction",
                "completed",
                {
                    "urls": len(strings_result["data"].get("urls", [])),
                    "ips": len(strings_result["data"].get("ips", [])),
                    "domains": len(strings_result["data"].get("domains", [])),
                },
            )
        else:
            output["strings"] = {"error": strings_result["error"]}
            await notify("string_extraction", "String Extraction", "failed")
            logger.warning(f"String extraction failed: {strings_result['error']}")

        # Process yara result
        if yara_result["success"]:
            output["yara"] = yara_result["data"]
            matches = yara_result["data"].get("matches", [])
            await notify(
                "yara_scanning",
                "YARA Scanning",
                "completed",
                {
                    "matches": len(matches),
                    "rules": [m.get("rule") for m in matches[:3]] if matches else [],
                },
            )
        else:
            output["yara"] = {"error": yara_result["error"]}
            await notify("yara_scanning", "YARA Scanning", "failed")
            logger.warning(f"YARA scanning failed: {yara_result['error']}")

        return output

    async def _run_hash(self, file_path: Path) -> dict[str, Any]:
        """Run hash calculation."""
        result = await self.hash_calculator.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def _run_diec(self, file_path: Path) -> dict[str, Any]:
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

    async def _run_capa(self, file_path: Path, category: str) -> dict[str, Any]:
        """Run capa analysis based on file category."""
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

    async def _run_strings(self, file_path: Path) -> dict[str, Any]:
        """Run string extraction."""
        result = await self.string_extractor.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def _run_yara(self, file_path: Path) -> dict[str, Any]:
        """Run YARA scanning."""
        result = await self.yara_scanner.analyze(file_path)
        return {
            "success": result.success,
            "data": result.data if result.success else None,
            "error": result.error,
        }

    async def close(self) -> None:
        """Clean up resources."""
        await self.diec_analyzer.close()
