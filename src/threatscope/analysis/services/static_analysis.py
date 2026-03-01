"""Static analysis service - orchestrates all static analysis tools.

Refactored to support intelligent routing based on file type:
- PE/ELF binaries → capa analysis
- Scripts → (placeholder for future)
- All files → hash, strings, YARA
"""

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

    Analysis flow:
    1. Hash calculation (all files)
    2. File type identification via diec
    3. Route based on file type:
       - PE/ELF → capa capability analysis
       - Script → (placeholder)
       - Unknown → skip capability analysis
    4. String extraction (all files)
    5. YARA scanning (all files)
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

        # Step 1: Hash calculation
        await notify("hashing", "Hash Calculation", "running")
        hash_result = await self.hash_calculator.analyze(file_path)
        if hash_result.success:
            output["hashes"] = hash_result.data
            await notify(
                "hashing",
                "Hash Calculation",
                "completed",
                {
                    "md5": hash_result.data.get("md5", "")[:16] + "...",
                    "sha256": hash_result.data.get("sha256", "")[:16] + "...",
                },
            )
        else:
            output["hashes"] = {"error": hash_result.error}
            await notify("hashing", "Hash Calculation", "failed")

        # Step 2: File type identification
        await notify("file_identification", "File Type Identification", "running")
        logger.info(f"Starting diec analysis for {file_path}, diec_url={self.diec_analyzer.diec_url}")
        diec_result = await self.diec_analyzer.analyze(file_path)
        logger.info(f"diec result: success={diec_result.success}, error={diec_result.error}, data={diec_result.data}")
        if diec_result.success:
            output["file_type"] = diec_result.data
            category = diec_result.data.get("category", "unknown")
            logger.info(f"File type identified: category={category}, format={diec_result.data.get('format')}")
            await notify(
                "file_identification",
                "File Type Identification",
                "completed",
                {
                    "format": diec_result.data.get("format", ""),
                    "category": category,
                    "platform": diec_result.data.get("platform", ""),
                },
            )
        else:
            output["file_type"] = {"error": diec_result.error}
            category = "unknown"
            await notify("file_identification", "File Type Identification", "failed")
            logger.warning(f"File type identification failed: {diec_result.error}")

        # Step 3: Route based on file type
        if category in ("pe", "elf"):
            # Binary file - run capa analysis
            await notify("capability_analysis", "Capability Analysis", "running")
            capa_result = await self.capa_analyzer.analyze(file_path)
            if capa_result.success:
                output["capa"] = capa_result.data
                capabilities = capa_result.data.get("capabilities", [])
                attack = capa_result.data.get("attack", {})
                await notify(
                    "capability_analysis",
                    "Capability Analysis",
                    "completed",
                    {
                        "capabilities": len(capabilities),
                        "attack_techniques": len(attack.get("techniques", [])),
                        "analysis_time": capa_result.data.get("analysis_time", 0),
                    },
                )
            else:
                output["capa"] = {"error": capa_result.error}
                await notify("capability_analysis", "Capability Analysis", "failed")
                logger.warning(f"capa analysis failed: {capa_result.error}")

        elif category.startswith("script:"):
            # Script file - placeholder for future script analysis
            await notify("capability_analysis", "Capability Analysis", "skipped")
            output["capa"] = {"skipped": True, "reason": "Script analysis not yet implemented"}
            logger.info(f"Skipping capability analysis for script: {category}")

        else:
            # Unknown file type - skip capability analysis
            await notify("capability_analysis", "Capability Analysis", "skipped")
            output["capa"] = {"skipped": True, "reason": f"Unsupported file type: {category}"}
            logger.info(f"Skipping capability analysis for: {category}")

        # Step 4: String extraction (all files)
        await notify("string_extraction", "String Extraction", "running")
        string_result = await self.string_extractor.analyze(file_path)
        if string_result.success:
            output["strings"] = string_result.data
            await notify(
                "string_extraction",
                "String Extraction",
                "completed",
                {
                    "urls": len(string_result.data.get("urls", [])),
                    "ips": len(string_result.data.get("ips", [])),
                    "domains": len(string_result.data.get("domains", [])),
                },
            )
        else:
            output["strings"] = {"error": string_result.error}
            await notify("string_extraction", "String Extraction", "failed")
            logger.warning(f"String extraction failed: {string_result.error}")

        # Step 5: YARA scanning (all files)
        await notify("yara_scanning", "YARA Scanning", "running")
        yara_result = await self.yara_scanner.analyze(file_path)
        if yara_result.success:
            output["yara"] = yara_result.data
            matches = yara_result.data.get("matches", [])
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
            output["yara"] = {"error": yara_result.error}
            await notify("yara_scanning", "YARA Scanning", "failed")
            logger.warning(f"YARA scanning failed: {yara_result.error}")

        return output

    async def close(self) -> None:
        """Clean up resources."""
        await self.diec_analyzer.close()
