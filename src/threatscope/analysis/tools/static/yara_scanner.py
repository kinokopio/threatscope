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
            logger.error("yara-python is not installed!")
            return False

        rules_path = Path(rules_path)
        logger.info(f"Loading YARA rules from: {rules_path} (exists={rules_path.exists()})")

        if not rules_path.exists():
            logger.error(f"YARA rules path does not exist: {rules_path.absolute()}")
            return False

        try:
            # Check for cached compiled rules first (in rules/yara/)
            if rules_path.is_dir():
                cache_file = rules_path.parent / "yara" / "compiled_rules.yarc"
                if cache_file.exists():
                    try:
                        logger.info(f"Loading cached compiled rules from {cache_file}")
                        self._rules = yara.load(str(cache_file))
                        self._rule_count = -1  # Unknown count from cache
                        logger.info("Successfully loaded YARA rules from cache")
                        return True
                    except Exception as e:
                        logger.warning(f"Cache load failed (will recompile): {e}")

                # No cache or cache failed - compile from source
                filepaths = {}
                yar_files = list(rules_path.rglob("*.yar"))
                yara_files = list(rules_path.rglob("*.yara"))
                logger.info(f"Found {len(yar_files)} .yar files and {len(yara_files)} .yara files")

                for rule_file in yar_files:
                    try:
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError as e:
                        logger.debug(f"Skipping invalid rule {rule_file.name}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Error compiling {rule_file.name}: {e}")
                        continue

                for rule_file in yara_files:
                    try:
                        yara.compile(filepath=str(rule_file))
                        namespace = rule_file.stem.replace("-", "_").replace(".", "_")
                        filepaths[namespace] = str(rule_file)
                    except yara.SyntaxError as e:
                        logger.debug(f"Skipping invalid rule {rule_file.name}: {e}")
                        continue
                    except Exception as e:
                        logger.debug(f"Error compiling {rule_file.name}: {e}")
                        continue

                if filepaths:
                    logger.info(f"Compiling {len(filepaths)} valid YARA rules...")
                    self._rules = yara.compile(filepaths=filepaths)
                    self._rule_count = len(filepaths)
                    logger.info(f"Successfully compiled {self._rule_count} YARA rules")

                    # Auto-save compiled rules to rules/yara directory for faster loading
                    try:
                        # Find project root and save to rules/yara/
                        cache_dir = rules_path.parent / "yara"
                        cache_dir.mkdir(parents=True, exist_ok=True)
                        cache_file = cache_dir / "compiled_rules.yarc"
                        self._rules.save(str(cache_file))
                        logger.info(f"Saved compiled rules cache to {cache_file}")
                    except Exception as e:
                        logger.warning(f"Failed to save compiled rules cache: {e}")

                    return True

                # Fallback: Try precompiled .yarc if no source files found
                compiled_file = rules_path / "compiled_rules.yarc"
                if compiled_file.exists():
                    logger.info(f"No source rules compiled, trying precompiled: {compiled_file}")
                    try:
                        self._rules = yara.load(str(compiled_file))
                        self._rule_count = -1
                        logger.info("Loaded precompiled YARA rules (platform-specific)")
                        return True
                    except Exception as e:
                        logger.error(f"Failed to load precompiled rules (platform mismatch?): {e}")
                        return False

                logger.error(f"No valid YARA rules found in {rules_path}")
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

            logger.error(f"Invalid rules path (not a file or directory): {rules_path}")
            return False

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}", exc_info=True)
            return False

    async def analyze(self, file_path: Path) -> ToolResult:
        if not YARA_AVAILABLE:
            return ToolResult(success=False, error="yara-python not installed")

        if self.rules_path and not self._rules:
            if not self.load_rules(self.rules_path):
                return ToolResult(success=False, error="Failed to load YARA rules")

        if not self._rules:
            logger.warning("No YARA rules loaded, returning empty matches")
            return ToolResult(
                success=True,
                data={"matches": [], "rule_count": 0, "message": "No rules loaded"},
            )

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
