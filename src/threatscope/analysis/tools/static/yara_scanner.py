"""YARA scanner with precompiled rules support."""

import logging
from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

logger = logging.getLogger(__name__)

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraScanner(AnalysisTool):
    def __init__(self, rules_path: str | Path | None = None):
        self.rules_path = Path(rules_path) if rules_path else None
        self._rules = None
        self._rule_count = 0

    @property
    def name(self) -> str:
        return "yara_scanner"

    def load_rules(self, rules_path: str | Path) -> bool:
        if not YARA_AVAILABLE:
            return False

        rules_path = Path(rules_path)

        try:
            compiled_file = None
            if rules_path.is_dir():
                compiled_file = rules_path / "compiled_rules.yarc"
                if not compiled_file.exists():
                    compiled_file = None
            elif rules_path.suffix == ".yarc":
                compiled_file = rules_path

            if compiled_file and compiled_file.exists():
                logger.info(f"Loading precompiled YARA rules from {compiled_file}")
                self._rules = yara.load(str(compiled_file))
                self._rule_count = -1
                return True

            logger.info(f"Compiling YARA rules from {rules_path}")

            if rules_path.is_file() and rules_path.suffix in (".yar", ".yara"):
                self._rules = yara.compile(filepath=str(rules_path))
                self._rule_count = 1
                return True

            if rules_path.is_dir():
                filepaths = {}
                for rule_file in rules_path.rglob("*.yar"):
                    try:
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

    async def analyze(self, file_path: Path) -> ToolResult:
        if not YARA_AVAILABLE:
            return ToolResult(success=False, error="yara-python not installed")

        if self.rules_path and not self._rules:
            if not self.load_rules(self.rules_path):
                return ToolResult(success=False, error="Failed to load YARA rules")

        if not self._rules:
            return ToolResult(success=True, data={"matches": [], "rule_count": 0})

        try:
            import warnings

            matches = []
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

            return ToolResult(
                success=True,
                data={
                    "matches": matches,
                    "rule_count": self._rule_count,
                    "match_count": len(matches),
                },
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    @staticmethod
    def compile_rules(source_dir: str | Path, output_file: str | Path) -> bool:
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
                except Exception:
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
