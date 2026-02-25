"""Static analyzer - aggregates all static analysis tools."""

import asyncio
from pathlib import Path
from typing import Any

from tools.base import AnalysisResult
from tools.static.elf_parser import ELFParser
from tools.static.function_classifier import FunctionClassifier
from tools.static.hash_calculator import HashCalculator
from tools.static.mitre_mapper import MitreMapper
from tools.static.string_extractor import StringExtractor
from tools.static.yara_scanner import YaraScanner


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

    async def analyze(self, file_path: str | Path) -> dict[str, Any]:
        """Run all static analysis tools on a file.

        Args:
            file_path: Path to the file to analyze.

        Returns:
            Dict with results from all tools.
        """
        file_path = Path(file_path)

        # Run independent analyses in parallel
        hash_task = self.hash_calculator.analyze(file_path)
        string_task = self.string_extractor.analyze(file_path)
        elf_task = self.elf_parser.analyze(file_path)
        yara_task = self.yara_scanner.analyze(file_path)

        results = await asyncio.gather(
            hash_task, string_task, elf_task, yara_task,
            return_exceptions=True
        )

        # Process results
        output: dict[str, Any] = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size if file_path.exists() else 0,
        }

        # Hash results
        if isinstance(results[0], AnalysisResult) and results[0].success:
            output["hashes"] = results[0].data
        else:
            output["hashes"] = {"error": str(results[0])}

        # String results
        if isinstance(results[1], AnalysisResult) and results[1].success:
            output["strings"] = results[1].data
        else:
            output["strings"] = {"error": str(results[1])}

        # ELF results
        if isinstance(results[2], AnalysisResult) and results[2].success:
            output["elf"] = results[2].data

            # Run function classification and MITRE mapping on imports
            imports = results[2].data.get("imports", [])
            if imports:
                output["function_categories"] = self.function_classifier.get_category_summary(imports)
                output["mitre_mapping"] = self.mitre_mapper.get_mapping_summary(imports)
        else:
            output["elf"] = {"error": str(results[2])}

        # YARA results
        if isinstance(results[3], AnalysisResult) and results[3].success:
            output["yara"] = results[3].data
        else:
            output["yara"] = {"error": str(results[3])}

        return output
