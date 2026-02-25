"""YARA scanner tool."""

from pathlib import Path

from tools.base import AnalysisResult, BaseTool

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner(BaseTool):
    """Scan files with YARA rules."""

    def __init__(self, rules_path: str | Path | None = None):
        """Initialize YARA scanner.

        Args:
            rules_path: Path to YARA rules directory or file.
        """
        self.rules_path = Path(rules_path) if rules_path else None
        self._compiled_rules: list = []

    @property
    def name(self) -> str:
        return "yara_scanner"

    def load_rules(self, rules_path: str | Path) -> bool:
        """Load and compile YARA rules.

        Args:
            rules_path: Path to rules directory or file.

        Returns:
            True if rules loaded successfully.
        """
        if not YARA_AVAILABLE:
            return False

        rules_path = Path(rules_path)
        self._compiled_rules = []

        try:
            if rules_path.is_file():
                self._compiled_rules.append(yara.compile(filepath=str(rules_path)))
            elif rules_path.is_dir():
                for rule_file in rules_path.rglob("*.yar"):
                    try:
                        self._compiled_rules.append(yara.compile(filepath=str(rule_file)))
                    except yara.SyntaxError:
                        continue  # Skip invalid rules
                for rule_file in rules_path.rglob("*.yara"):
                    try:
                        self._compiled_rules.append(yara.compile(filepath=str(rule_file)))
                    except yara.SyntaxError:
                        continue
            return len(self._compiled_rules) > 0
        except Exception:
            return False

    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Scan file with loaded YARA rules.

        Args:
            file_path: Path to the file to scan.

        Returns:
            AnalysisResult with matched rules.
        """
        if not YARA_AVAILABLE:
            return AnalysisResult(success=False, error="yara-python not installed")

        # Load rules if path provided but not loaded
        if self.rules_path and not self._compiled_rules:
            if not self.load_rules(self.rules_path):
                return AnalysisResult(success=False, error="Failed to load YARA rules")

        if not self._compiled_rules:
            return AnalysisResult(success=True, data={"matches": [], "rule_count": 0})

        try:
            matches = []
            for rules in self._compiled_rules:
                for match in rules.match(str(file_path)):
                    matches.append(
                        {
                            "rule": match.rule,
                            "namespace": match.namespace,
                            "tags": list(match.tags),
                            "meta": dict(match.meta) if match.meta else {},
                        }
                    )

            return AnalysisResult(
                success=True,
                data={
                    "matches": matches,
                    "rule_count": len(self._compiled_rules),
                    "match_count": len(matches),
                },
            )
        except Exception as e:
            return AnalysisResult(success=False, error=str(e))
