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
        """Load YARA rules from path.

        Supports:
        - Directory with .yar/.yara files (compiled on-the-fly)
        - Single .yar/.yara file
        - Precompiled .yarc file (platform-specific, use with caution)

        Note: .yarc files are platform-specific and cannot be shared between
        different OS/architectures. Prefer source .yar files for portability.
        """
        if not YARA_AVAILABLE:
            return False

        rules_path = Path(rules_path)

        try:
            # Priority 1: Compile from source files (portable)
            if rules_path.is_dir():
                filepaths = {}
                for rule_file in rules_path.rglob("*.yar"):
                    try:
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError as e:
                        logger.warning(f"Skipping invalid rule {rule_file}: {e}")
                        continue

                for rule_file in rules_path.rglob("*.yara"):
                    try:
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError as e:
                        logger.warning(f"Skipping invalid rule {rule_file}: {e}")
                        continue

                if filepaths:
                    self._rules = yara.compile(filepaths=filepaths)
                    self._rule_count = len(filepaths)
                    logger.info(f"Compiled {self._rule_count} YARA rule files from {rules_path}")
                    return True

                # Fallback: Try precompiled .yarc if no source files found
                compiled_file = rules_path / "compiled_rules.yarc"
                if compiled_file.exists():
                    logger.info(f"No source rules found, trying precompiled: {compiled_file}")
                    try:
                        self._rules = yara.load(str(compiled_file))
                        self._rule_count = -1
                        logger.info("Loaded precompiled YARA rules (platform-specific)")
                        return True
                    except Exception as e:
                        logger.warning(f"Failed to load precompiled rules (platform mismatch?): {e}")
                        return False

                logger.warning(f"No YARA rules found in {rules_path}")
                return False

            # Single .yar/.yara file
            if rules_path.is_file() and rules_path.suffix in (".yar", ".yara"):
                self._rules = yara.compile(filepath=str(rules_path))
                self._rule_count = 1
                logger.info(f"Compiled YARA rule from {rules_path}")
                return True

            # Precompiled .yarc file (platform-specific)
            if rules_path.is_file() and rules_path.suffix == ".yarc":
                logger.warning("Loading .yarc file - this is platform-specific!")
                self._rules = yara.load(str(rules_path))
                self._rule_count = -1
                return True

            logger.error(f"Invalid rules path: {rules_path}")
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
