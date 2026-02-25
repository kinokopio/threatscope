"""Function classifier tool."""

import json
from pathlib import Path

from tools.base import AnalysisResult, BaseTool

# Default path to function categories
DEFAULT_CATEGORIES_PATH = Path(__file__).parent.parent.parent / "data" / "linux_func_categories.json"


class FunctionClassifier(BaseTool):
    """Classify functions into behavioral categories."""

    def __init__(self, categories_path: str | Path | None = None):
        """Initialize function classifier.

        Args:
            categories_path: Path to function categories JSON file.
        """
        self.categories_path = Path(categories_path) if categories_path else DEFAULT_CATEGORIES_PATH
        self._categories: dict = {}
        self._load_categories()

    def _load_categories(self) -> None:
        """Load function categories from JSON file."""
        if self.categories_path.exists():
            with open(self.categories_path) as f:
                self._categories = json.load(f)

    @property
    def name(self) -> str:
        return "function_classifier"

    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Classify functions found in the binary.

        This tool expects imports/exports to be passed via analyze_functions().
        For standalone use, it returns the available categories.

        Args:
            file_path: Path to the file (not used directly).

        Returns:
            AnalysisResult with category information.
        """
        return AnalysisResult(
            success=True,
            data={
                "categories": list(self._categories.keys()),
                "total_indicators": sum(
                    len(cat.get("funcs", [])) for cat in self._categories.values()
                ),
            },
        )

    def classify_functions(self, functions: list[str]) -> dict[str, list[str]]:
        """Classify a list of functions into categories.

        Args:
            functions: List of function names to classify.

        Returns:
            Dict mapping category names to matched functions.
        """
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
        """Get a summary of function classifications.

        Args:
            functions: List of function names.

        Returns:
            Summary with counts and risk assessment.
        """
        classified = self.classify_functions(functions)

        # Risk categories
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
