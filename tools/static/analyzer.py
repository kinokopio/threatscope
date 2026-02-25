"""Static analyzer - aggregates all static analysis tools."""

import asyncio
from pathlib import Path
from typing import Any, Callable, Awaitable

from tools.base import AnalysisResult
from tools.static.elf_parser import ELFParser
from tools.static.function_classifier import FunctionClassifier
from tools.static.hash_calculator import HashCalculator
from tools.static.mitre_mapper import MitreMapper
from tools.static.string_extractor import StringExtractor
from tools.static.yara_scanner import YaraScanner

# Type for progress callback: (step_id, step_name, status, result_preview)
ProgressCallback = Callable[[str, str, str, dict[str, Any] | None], Awaitable[None]]


class StaticAnalyzer:
    """Aggregates all static analysis tools for comprehensive analysis."""

    def __init__(
        self,
        yara_rules_path: str | Path | None = None,
        categories_path: str | Path | None = None,
        mitre_path: str | Path | None = None,
    ):
        """Initialize static analyzer with all tools.

        Args:
            yara_rules_path: Path to YARA rules.
            categories_path: Path to function categories JSON.
            mitre_path: Path to MITRE mappings JSON.
        """
        self.hash_calculator = HashCalculator()
        self.string_extractor = StringExtractor()
        self.elf_parser = ELFParser()
        self.yara_scanner = YaraScanner(yara_rules_path)
        self.function_classifier = FunctionClassifier(categories_path)
        self.mitre_mapper = MitreMapper(mitre_path)

    async def analyze(
        self, 
        file_path: str | Path,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """Run all static analysis tools on a file.

        Args:
            file_path: Path to the file to analyze.
            progress_callback: Optional callback for progress updates.

        Returns:
            Dict with results from all tools.
        """
        file_path = Path(file_path)

        # Initialize output
        output: dict[str, Any] = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size if file_path.exists() else 0,
        }

        # Helper to notify progress
        async def notify(step_id: str, step_name: str, status: str, preview: dict | None = None):
            if progress_callback:
                await progress_callback(step_id, step_name, status, preview)

        # Step 1: Hash calculation
        await notify("hash", "Hash Calculation", "running")
        hash_result = await self.hash_calculator.analyze(file_path)
        if isinstance(hash_result, AnalysisResult) and hash_result.success:
            output["hashes"] = hash_result.data
            await notify("hash", "Hash Calculation", "completed", {
                "md5": hash_result.data.get("md5", "")[:16] + "...",
                "sha256": hash_result.data.get("sha256", "")[:16] + "...",
            })
        else:
            output["hashes"] = {"error": str(hash_result)}
            await notify("hash", "Hash Calculation", "failed")

        # Step 2: String extraction
        await notify("strings", "String Extraction", "running")
        string_result = await self.string_extractor.analyze(file_path)
        if isinstance(string_result, AnalysisResult) and string_result.success:
            output["strings"] = string_result.data
            await notify("strings", "String Extraction", "completed", {
                "urls": len(string_result.data.get("urls", [])),
                "ips": len(string_result.data.get("ips", [])),
                "domains": len(string_result.data.get("domains", [])),
            })
        else:
            output["strings"] = {"error": str(string_result)}
            await notify("strings", "String Extraction", "failed")

        # Step 3: ELF parsing
        await notify("elf", "ELF Parsing", "running")
        elf_result = await self.elf_parser.analyze(file_path)
        if isinstance(elf_result, AnalysisResult) and elf_result.success:
            output["elf"] = elf_result.data
            await notify("elf", "ELF Parsing", "completed", {
                "format": elf_result.data.get("format", ""),
                "arch": elf_result.data.get("arch", ""),
                "imports": len(elf_result.data.get("imports", [])),
            })

            # Step 4: Function classification (depends on ELF)
            imports = elf_result.data.get("imports", [])
            if imports:
                await notify("func_class", "Function Classification", "running")
                output["function_categories"] = self.function_classifier.get_category_summary(imports)
                categories_found = [k for k, v in output["function_categories"].items() if v]
                await notify("func_class", "Function Classification", "completed", {
                    "categories": len(categories_found),
                })

                # Step 5: MITRE ATT&CK mapping (depends on ELF)
                await notify("mitre", "MITRE ATT&CK Mapping", "running")
                output["mitre_mapping"] = self.mitre_mapper.get_mapping_summary(imports)
                techniques = output["mitre_mapping"].get("techniques", [])
                await notify("mitre", "MITRE ATT&CK Mapping", "completed", {
                    "techniques": len(techniques) if isinstance(techniques, list) else 0,
                })
        else:
            output["elf"] = {"error": str(elf_result)}
            await notify("elf", "ELF Parsing", "failed")

        # Step 6: YARA scanning
        await notify("yara", "YARA Scanning", "running")
        yara_result = await self.yara_scanner.analyze(file_path)
        if isinstance(yara_result, AnalysisResult) and yara_result.success:
            output["yara"] = yara_result.data
            matches = yara_result.data.get("matches", [])
            await notify("yara", "YARA Scanning", "completed", {
                "matches": len(matches),
                "rules": matches[:3] if matches else [],
            })
        else:
            output["yara"] = {"error": str(yara_result)}
            await notify("yara", "YARA Scanning", "failed")

        return output
