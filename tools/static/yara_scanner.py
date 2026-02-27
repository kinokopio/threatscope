"""YARA scanner tool with precompiled rules support."""

import logging
from pathlib import Path

from tools.base import AnalysisResult, BaseTool

logger = logging.getLogger(__name__)

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner(BaseTool):
    """Scan files with YARA rules.

    Supports both precompiled (.yarc) and source (.yar) rules.
    Precompiled rules load ~100x faster.
    """

    def __init__(self, rules_path: str | Path | None = None):
        """Initialize YARA scanner.

        Args:
            rules_path: Path to YARA rules directory or compiled file (.yarc).
        """
        self.rules_path = Path(rules_path) if rules_path else None
        self._rules = None  # Single compiled rules object
        self._rule_count = 0

    @property
    def name(self) -> str:
        return "yara_scanner"

    def load_rules(self, rules_path: str | Path) -> bool:
        """Load YARA rules (precompiled or source).

        Args:
            rules_path: Path to rules directory or compiled file.

        Returns:
            True if rules loaded successfully.
        """
        if not YARA_AVAILABLE:
            return False

        rules_path = Path(rules_path)

        try:
            # Check for precompiled rules first (much faster)
            compiled_file = None
            if rules_path.is_dir():
                # Look for compiled_rules.yarc in the directory
                compiled_file = rules_path / "compiled_rules.yarc"
                if not compiled_file.exists():
                    compiled_file = None
            elif rules_path.suffix == ".yarc":
                compiled_file = rules_path

            if compiled_file and compiled_file.exists():
                logger.info(f"Loading precompiled YARA rules from {compiled_file}")
                self._rules = yara.load(str(compiled_file))
                self._rule_count = -1  # Unknown count for compiled rules
                logger.info("Precompiled YARA rules loaded successfully")
                return True

            # Fall back to compiling from source
            logger.info(f"Compiling YARA rules from {rules_path}")

            if rules_path.is_file() and rules_path.suffix in (".yar", ".yara"):
                self._rules = yara.compile(filepath=str(rules_path))
                self._rule_count = 1
                return True

            if rules_path.is_dir():
                # Collect all rule files
                filepaths = {}
                for rule_file in rules_path.rglob("*.yar"):
                    try:
                        # Test compile first
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError:
                        continue

                for rule_file in rules_path.rglob("*.yara"):
                    try:
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError:
                        continue

                if filepaths:
                    self._rules = yara.compile(filepaths=filepaths)
                    self._rule_count = len(filepaths)
                    logger.info(f"Compiled {self._rule_count} YARA rule files")
                    return True

            return False
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
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
        if self.rules_path and not self._rules:
            if not self.load_rules(self.rules_path):
                return AnalysisResult(success=False, error="Failed to load YARA rules")

        if not self._rules:
            return AnalysisResult(success=True, data={"matches": [], "rule_count": 0})

        try:
            import warnings
            matches = []
            # Suppress YARA "too many matches" warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", RuntimeWarning)
                for match in self._rules.match(str(file_path)):
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
                    "rule_count": self._rule_count,
                    "match_count": len(matches),
                },
            )
        except Exception as e:
            return AnalysisResult(success=False, error=str(e))

    @staticmethod
    def compile_rules(source_dir: str | Path, output_file: str | Path) -> bool:
        """Compile all rules in a directory to a single file.

        Args:
            source_dir: Directory containing .yar files.
            output_file: Output .yarc file path.

        Returns:
            True if compilation successful.
        """
        if not YARA_AVAILABLE:
            return False

        source_dir = Path(source_dir)
        output_file = Path(output_file)

        try:
            filepaths = {}
            for rule_file in source_dir.rglob("*.yar"):
                try:
                    yara.compile(filepath=str(rule_file))
                    namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                    filepaths[namespace] = str(rule_file)
                except:
                    continue

            if filepaths:
                compiled = yara.compile(filepaths=filepaths)
                compiled.save(str(output_file))
                logger.info(f"Compiled {len(filepaths)} rules to {output_file}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to compile rules: {e}")
            return False
