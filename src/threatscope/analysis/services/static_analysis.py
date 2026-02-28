"""Static analysis service - orchestrates all static analysis tools.

This replaces the old "Stage 1-4" naming with clear functional names:
- Hash calculation
- String extraction
- Binary parsing (ELF)
- Function classification
- MITRE ATT&CK mapping
- YARA scanning
"""

from pathlib import Path
from typing import Any, Awaitable, Callable

from src.threatscope.analysis.tools.static import (
    ELFParser,
    FunctionClassifier,
    HashCalculator,
    MitreMapper,
    StringExtractor,
    YaraScanner,
)

ProgressCallback = Callable[[str, str, str, dict[str, Any] | None, dict[str, Any] | None], Awaitable[None]]


class StaticAnalysisService:
    def __init__(
        self,
        yara_rules_path: str | Path | None = None,
        categories_path: str | Path | None = None,
        mitre_path: str | Path | None = None,
    ):
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
        file_path = Path(file_path)

        output: dict[str, Any] = {
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size": file_path.stat().st_size if file_path.exists() else 0,
        }

        async def notify(step_id: str, step_name: str, status: str, preview: dict | None = None):
            if progress_callback:
                await progress_callback(step_id, step_name, status, preview, output)

        # Hash calculation
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

        # String extraction
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

        # Binary parsing (ELF)
        await notify("binary_parsing", "Binary Parsing", "running")
        elf_result = await self.elf_parser.analyze(file_path)
        if elf_result.success:
            output["elf"] = elf_result.data
            await notify(
                "binary_parsing",
                "Binary Parsing",
                "completed",
                {
                    "format": elf_result.data.get("format", ""),
                    "arch": elf_result.data.get("arch", ""),
                    "imports": len(elf_result.data.get("imports", [])),
                },
            )

            imports = elf_result.data.get("imports", [])
            if imports:
                # Function classification
                await notify("function_classification", "Function Classification", "running")
                output["function_categories"] = self.function_classifier.get_category_summary(
                    imports
                )
                categories_found = [
                    k
                    for k, v in output["function_categories"].get("classifications", {}).items()
                    if v
                ]
                await notify(
                    "function_classification",
                    "Function Classification",
                    "completed",
                    {
                        "categories": len(categories_found),
                    },
                )

                # MITRE ATT&CK mapping
                await notify("mitre_mapping", "MITRE ATT&CK Mapping", "running")
                output["mitre_mapping"] = self.mitre_mapper.get_mapping_summary(imports)
                techniques = output["mitre_mapping"].get("techniques", [])
                await notify(
                    "mitre_mapping",
                    "MITRE ATT&CK Mapping",
                    "completed",
                    {
                        "techniques": len(techniques) if isinstance(techniques, list) else 0,
                    },
                )
        else:
            output["elf"] = {"error": elf_result.error}
            await notify("binary_parsing", "Binary Parsing", "failed")

        # YARA scanning
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

        return output
