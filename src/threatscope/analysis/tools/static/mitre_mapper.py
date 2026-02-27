"""MITRE ATT&CK mapper - maps functions to ATT&CK techniques."""

import json
from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

DEFAULT_MITRE_PATH = (
    Path(__file__).parent.parent.parent.parent.parent.parent / "data" / "mitre_for_linux.json"
)


class MitreMapper(AnalysisTool):
    def __init__(self, mitre_path: str | Path | None = None):
        self.mitre_path = Path(mitre_path) if mitre_path else DEFAULT_MITRE_PATH
        self._mappings: dict = {}
        self._load_mappings()

    def _load_mappings(self) -> None:
        if self.mitre_path.exists():
            with open(self.mitre_path) as f:
                self._mappings = json.load(f)

    @property
    def name(self) -> str:
        return "mitre_mapper"

    async def analyze(self, file_path: Path) -> ToolResult:
        tactics = list(self._mappings.keys())
        techniques = []
        for tactic_data in self._mappings.values():
            techniques.extend(tactic_data.keys())

        return ToolResult(
            success=True,
            data={
                "tactics": tactics,
                "technique_count": len(techniques),
            },
        )

    def map_functions(self, functions: list[str]) -> list[dict]:
        if not self._mappings:
            return []

        func_set = set(functions)
        results = []

        for tactic, techniques in self._mappings.items():
            for technique_name, technique_data in techniques.items():
                api_list = set(technique_data.get("api_list", []))
                matched = func_set & api_list

                if matched:
                    results.append(
                        {
                            "tactic": tactic,
                            "technique": technique_name,
                            "matched_apis": sorted(matched),
                            "match_count": len(matched),
                            "total_apis": len(api_list),
                            "confidence": round(len(matched) / len(api_list), 2) if api_list else 0,
                        }
                    )

        results.sort(key=lambda x: x["match_count"], reverse=True)
        return results

    def get_mapping_summary(self, functions: list[str]) -> dict:
        mappings = self.map_functions(functions)

        tactics = set()
        techniques = set()
        total_matches = 0

        for m in mappings:
            tactics.add(m["tactic"])
            techniques.add(m["technique"])
            total_matches += m["match_count"]

        high_risk_tactics = {
            "Defense Evasion",
            "Credential Access",
            "Exfiltration",
            "Impact",
            "Command and Control",
        }
        risk_level = "low"
        if tactics & high_risk_tactics:
            risk_level = "high"
        elif len(tactics) >= 3:
            risk_level = "medium"

        return {
            "mappings": mappings,
            "tactics": sorted(tactics),
            "techniques": sorted(techniques),
            "tactic_count": len(tactics),
            "technique_count": len(techniques),
            "total_api_matches": total_matches,
            "risk_level": risk_level,
        }
