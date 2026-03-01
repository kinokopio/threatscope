"""
CapaAnalyzer - Capability detection using capa Python API.

Analyzes PE/ELF binaries to detect capabilities, ATT&CK techniques, and MBC behaviors.
"""

import asyncio
import os
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

# capa imports - optional to allow graceful degradation
try:
    import capa.main
    import capa.rules
    import capa.loader
    import capa.capabilities.common
    import capa.render.result_document as rd
    import capa.render.utils as rutils
    import capa.features.freeze.features as frzf
    from capa.features.common import OS_AUTO, FORMAT_AUTO

    CAPA_AVAILABLE = True
except ImportError:
    CAPA_AVAILABLE = False


@dataclass
class AttackMapping:
    """ATT&CK mapping result."""

    tactics: list[str] = field(default_factory=list)
    techniques: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"tactics": self.tactics, "techniques": self.techniques}


@dataclass
class MbcMapping:
    """MBC (Malware Behavior Catalog) mapping result."""

    objectives: list[str] = field(default_factory=list)
    behaviors: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"objectives": self.objectives, "behaviors": self.behaviors}


@dataclass
class CapaResult:
    """capa analysis result."""

    format: str = ""  # pe, elf, dotnet
    arch: str = ""  # i386, amd64
    os: str = ""  # windows, linux
    capabilities: list[dict[str, Any]] = field(default_factory=list)
    attack: AttackMapping = field(default_factory=AttackMapping)
    mbc: MbcMapping = field(default_factory=MbcMapping)
    analysis_time: float = 0.0
    rule_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "arch": self.arch,
            "os": self.os,
            "capabilities": self.capabilities,
            "attack": self.attack.to_dict(),
            "mbc": self.mbc.to_dict(),
            "analysis_time": self.analysis_time,
            "rule_count": self.rule_count,
        }


# Thread pool for running capa (CPU-bound)
_executor = ThreadPoolExecutor(max_workers=2)


class CapaAnalyzer(AnalysisTool):
    """
    Capability detection analyzer using capa Python API.

    Analyzes PE/ELF binaries to detect:
    - Capabilities (900+ rules)
    - ATT&CK techniques
    - MBC behaviors
    """

    def __init__(
        self,
        rules_path: str | Path | None = None,
        signatures_path: str | Path | None = None,
        timeout: int = 60,
    ):
        """
        Initialize CapaAnalyzer.

        Args:
            rules_path: Path to capa rules directory. Defaults to CAPA_RULES_PATH env var
            signatures_path: Path to signatures for library identification (optional)
            timeout: Analysis timeout in seconds (default 60)
        """
        self.rules_path = Path(rules_path or os.environ.get("CAPA_RULES_PATH", "/app/rules/capa"))
        self.signatures_path = Path(signatures_path) if signatures_path else None
        self.timeout = timeout
        self._rules: Any = None  # capa.rules.RuleSet

    @property
    def name(self) -> str:
        return "capa_analyzer"

    def _load_rules(self) -> Any:
        """Load capa rules (cached)."""
        if self._rules is None:
            if not CAPA_AVAILABLE:
                raise RuntimeError("capa is not installed")
            if not self.rules_path.exists():
                raise RuntimeError(f"capa rules not found at {self.rules_path}")
            self._rules = capa.rules.get_rules([self.rules_path])
        return self._rules

    async def analyze(self, file_path: Path) -> ToolResult:
        """
        Analyze file capabilities using capa.

        Args:
            file_path: Path to PE/ELF file to analyze

        Returns:
            ToolResult with CapaResult data
        """
        if not CAPA_AVAILABLE:
            return ToolResult(success=False, error="capa is not installed (pip install flare-capa)")

        file_path = Path(file_path)
        if not file_path.exists():
            return ToolResult(success=False, error=f"File not found: {file_path}")

        try:
            # Load rules (cached)
            rules = self._load_rules()

            # Run capa in thread pool with timeout
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(_executor, self._run_capa, file_path, rules),
                timeout=self.timeout,
            )

            return ToolResult(success=True, data=result.to_dict())

        except asyncio.TimeoutError:
            return ToolResult(success=False, error=f"capa analysis timed out after {self.timeout}s")
        except Exception as e:
            return ToolResult(success=False, error=str(e))

    def _run_capa(self, file_path: Path, rules: Any) -> CapaResult:
        """
        Run capa analysis synchronously.

        Args:
            file_path: Path to file
            rules: Loaded capa rules

        Returns:
            CapaResult with analysis results
        """
        start_time = time.time()

        # Get extractor
        sig_paths = [self.signatures_path] if self.signatures_path else []
        extractor = capa.loader.get_extractor(
            file_path,
            FORMAT_AUTO,
            OS_AUTO,
            capa.main.BACKEND_VIV,
            sig_paths,
            should_save_workspace=False,
            disable_progress=True,
        )

        # Find capabilities
        capabilities = capa.capabilities.common.find_capabilities(
            rules, extractor, disable_progress=True
        )

        # Collect metadata
        meta = capa.loader.collect_metadata(
            [], file_path, FORMAT_AUTO, OS_AUTO, [self.rules_path], extractor, capabilities
        )
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

        # Create result document
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)

        # Parse results
        result = self._parse_result_document(doc)
        result.analysis_time = round(time.time() - start_time, 2)
        result.rule_count = len(rules)

        return result

    def _parse_result_document(self, doc: Any) -> CapaResult:
        """
        Parse capa ResultDocument into CapaResult.

        Args:
            doc: capa ResultDocument

        Returns:
            CapaResult with parsed data
        """
        result = CapaResult()

        # Extract metadata
        if hasattr(doc.meta, "analysis"):
            analysis = doc.meta.analysis
            result.format = str(analysis.format) if hasattr(analysis, "format") else ""
            result.arch = str(analysis.arch) if hasattr(analysis, "arch") else ""
            result.os = str(analysis.os) if hasattr(analysis, "os") else ""

        # Extract capabilities
        subrule_matches = self._find_subrule_matches(doc)
        for rule in rutils.capability_rules(doc):
            if rule.meta.name in subrule_matches:
                # Skip rules matched as subrules
                continue

            capability = {
                "name": rule.meta.name,
                "namespace": rule.meta.namespace or "",
                "matches": len(rule.matches),
            }
            result.capabilities.append(capability)

        # Extract ATT&CK mapping
        result.attack = self._extract_attack_mapping(doc)

        # Extract MBC mapping
        result.mbc = self._extract_mbc_mapping(doc)

        return result

    def _find_subrule_matches(self, doc: Any) -> set[str]:
        """Find rules that are matched as subrules."""
        matches = set()

        def rec(node):
            if not node.success:
                return
            if isinstance(node.node, rd.StatementNode):
                for child in node.children:
                    rec(child)
            elif isinstance(node.node, rd.FeatureNode):
                if isinstance(node.node.feature, frzf.MatchFeature):
                    matches.add(node.node.feature.match)

        for rule in rutils.capability_rules(doc):
            for _, node in rule.matches:
                rec(node)

        return matches

    def _extract_attack_mapping(self, doc: Any) -> AttackMapping:
        """Extract ATT&CK mapping from result document."""
        result = AttackMapping()
        tactics_set: set[str] = set()
        techniques_dict: dict[str, dict[str, str]] = {}

        for rule in rutils.capability_rules(doc):
            if not rule.meta.attack:
                continue
            for attack in rule.meta.attack:
                tactics_set.add(attack.tactic.upper())

                # Build technique entry
                tech_id = attack.id
                if tech_id not in techniques_dict:
                    if attack.subtechnique:
                        name = f"{attack.technique}::{attack.subtechnique}"
                    else:
                        name = attack.technique
                    techniques_dict[tech_id] = {"id": tech_id, "name": name}

        result.tactics = sorted(tactics_set)
        result.techniques = list(techniques_dict.values())

        return result

    def _extract_mbc_mapping(self, doc: Any) -> MbcMapping:
        """Extract MBC mapping from result document."""
        result = MbcMapping()
        objectives_set: set[str] = set()
        behaviors_dict: dict[str, dict[str, str]] = {}

        for rule in rutils.capability_rules(doc):
            if not rule.meta.mbc:
                continue
            for mbc in rule.meta.mbc:
                objectives_set.add(mbc.objective.upper())

                # Build behavior entry
                behavior_id = mbc.id
                if behavior_id not in behaviors_dict:
                    if mbc.method:
                        name = f"{mbc.behavior}::{mbc.method}"
                    else:
                        name = mbc.behavior
                    behaviors_dict[behavior_id] = {"id": behavior_id, "name": name}

        result.objectives = sorted(objectives_set)
        result.behaviors = list(behaviors_dict.values())

        return result
