"""Function classifier - categorizes imported functions by behavior."""

import json
from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

DEFAULT_CATEGORIES_PATH = (
    Path(__file__).parent.parent.parent.parent.parent.parent / "data" / "linux_func_categories.json"
)


class FunctionClassifier(AnalysisTool):
    def __init__(self, categories_path: str | Path | None = None):
        self.categories_path = Path(categories_path) if categories_path else DEFAULT_CATEGORIES_PATH
        self._categories: dict = {}
        self._load_categories()

    def _load_categories(self) -> None:
        if self.categories_path.exists():
            with open(self.categories_path) as f:
                self._categories = json.load(f)

    @property
    def name(self) -> str:
        return "function_classifier"

    async def analyze(self, file_path: Path) -> ToolResult:
        return ToolResult(
            success=True,
            data={
                "categories": list(self._categories.keys()),
                "total_indicators": sum(
                    len(cat.get("funcs", [])) for cat in self._categories.values()
                ),
            },
        )

    def classify_functions(self, functions: list[str]) -> dict[str, list[str]]:
        if not self._categories:
            return {}

        results: dict[str, list[str]] = {}
        func_set = set(functions)

        for category, data in self._categories.items():
            indicators = set(data.get("funcs", []))
            matched = func_set & indicators
            if matched:
                results[category] = sorted(matched)

        return results

    def get_category_summary(self, functions: list[str]) -> dict:
        classified = self.classify_functions(functions)

        high_risk = {"Networking", "Cryptography", "Evasion", "Keylogger", "Injection"}
        medium_risk = {"Process", "File", "Information Gathering"}

        risk_score = 0
        for category in classified:
            if category in high_risk:
                risk_score += len(classified[category]) * 3
            elif category in medium_risk:
                risk_score += len(classified[category]) * 1

        return {
            "classifications": classified,
            "category_counts": {k: len(v) for k, v in classified.items()},
            "total_classified": sum(len(v) for v in classified.values()),
            "risk_score": risk_score,
        }
