"""MITRE ATT&CK mapper tool."""

import json
from pathlib import Path

from tools.base import AnalysisResult, BaseTool

# Default path to MITRE mappings
DEFAULT_MITRE_PATH = Path(__file__).parent.parent.parent / "data" / "mitre_for_linux.json"


class MitreMapper(BaseTool):
    """Map functions/APIs to MITRE ATT&CK techniques."""

    def __init__(self, mitre_path: str | Path | None = None):
        """Initialize MITRE mapper.

        Args:
            mitre_path: Path to MITRE mappings JSON file.
        """
        self.mitre_path = Path(mitre_path) if mitre_path else DEFAULT_MITRE_PATH
        self._mappings: dict = {}
        self._load_mappings()

    def _load_mappings(self) -> None:
        """Load MITRE mappings from JSON file."""
        if self.mitre_path.exists():
            with open(self.mitre_path) as f:
                self._mappings = json.load(f)

    @property
    def name(self) -> str:
        return "mitre_mapper"

    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Return available MITRE tactics and techniques.

        Args:
            file_path: Path to the file (not used directly).

        Returns:
            AnalysisResult with available mappings.
        """
        tactics = list(self._mappings.keys())
        techniques = []
        for tactic_data in self._mappings.values():
            techniques.extend(tactic_data.keys())

        return AnalysisResult(
            success=True,
            data={
                "tactics": tactics,
                "technique_count": len(techniques),
            },
        )

    def map_functions(self, functions: list[str]) -> list[dict]:
        """Map functions to MITRE ATT&CK techniques.

        Args:
            functions: List of function names or API calls.

        Returns:
            List of matched techniques with evidence.
        """
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

        # Sort by match count descending
        results.sort(key=lambda x: x["match_count"], reverse=True)
        return results

    def get_mapping_summary(self, functions: list[str]) -> dict:
        """Get a summary of MITRE mappings.

        Args:
            functions: List of function names.

        Returns:
            Summary with tactics, techniques, and risk level.
        """
        mappings = self.map_functions(functions)

        tactics = set()
        techniques = set()
        total_matches = 0

        for m in mappings:
            tactics.add(m["tactic"])
            techniques.add(m["technique"])
            total_matches += m["match_count"]

        # Risk assessment based on tactics
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
