"""AnalysisCoordinator - Pipeline orchestration for malware analysis."""

import asyncio
import logging
from pathlib import Path
from typing import Any

from ai import AgentConfig, GhidraAgent, MalwareAnalysisAgent
from clients import ThreatIntelClient
from core.config import Config, load_config
from core.task import AnalysisTask, TaskStatus
from tools import StaticAnalyzer
from tools.dynamic import DynamicAnalyzer

logger = logging.getLogger(__name__)


class AnalysisCoordinator:
    """Orchestrates the complete malware analysis pipeline.

    Pipeline stages:
    - Stage 1-2: Static analysis, feature extraction
    - Stage 3: Threat intelligence queries
    - Stage 4: Dynamic analysis (emulation)
    - Stage 5: Ghidra deep analysis (AI-driven)
    - Stage 6: Final report generation (AI-driven)
    """

    def __init__(
        self,
        config: Config | None = None,
        project_dir: str | Path = ".",
    ):
        """Initialize the coordinator.

        Args:
            config: Configuration object. Loads from config.yaml if not provided.
            project_dir: Project directory for memory storage.
        """
        self.config = config or load_config()
        self.project_dir = Path(project_dir)

        # Initialize analyzers
        self.static_analyzer = StaticAnalyzer(
            yara_rules_path=self.config.analysis.yara_rules_path,
        )

        # Initialize dynamic analyzer
        self.dynamic_analyzer = DynamicAnalyzer(
            emulation_timeout=self.config.analysis.default_timeout,
        )

        # Initialize threat intel client
        self.threat_intel = ThreatIntelClient(
            malwarebazaar_url=self.config.threat_intel.malwarebazaar.base_url,
            threatfox_url=self.config.threat_intel.threatfox.base_url,
            urlhaus_url=self.config.threat_intel.urlhaus.base_url,
        )

        # Initialize agents
        ghidra_config = AgentConfig(
            system_prompt_path=self.config.agents.ghidra_agent.system_prompt_path,
            max_iterations=self.config.agents.ghidra_agent.max_iterations,
        )
        self.ghidra_agent = GhidraAgent(
            ghidra_config,
            self.project_dir,
            ghidra_url=self.config.ghidra.base_url,
        )

        malware_config = AgentConfig(
            system_prompt_path=self.config.agents.malware_analysis.system_prompt_path,
        )
        self.malware_agent = MalwareAnalysisAgent(malware_config)

    async def analyze(
        self,
        file_path: str | Path,
        enable_ghidra: bool | None = None,
        enable_dynamic: bool | None = None,
        enable_threat_intel: bool = True,
    ) -> dict[str, Any]:
        """Run complete analysis pipeline on a file.

        Args:
            file_path: Path to the file to analyze.
            enable_ghidra: Enable Ghidra analysis. Defaults to config setting.
            enable_dynamic: Enable dynamic analysis. Defaults to config setting.
            enable_threat_intel: Enable threat intelligence queries.

        Returns:
            Complete analysis results dictionary.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}

        # Create task
        task = AnalysisTask(file_path=str(file_path))

        # Use config defaults if not specified
        if enable_ghidra is None:
            enable_ghidra = self.config.analysis.enable_ghidra_analysis
        if enable_dynamic is None:
            enable_dynamic = self.config.analysis.enable_dynamic_analysis

        try:
            # Stage 1-4: Static + Threat Intel + Dynamic (parallel where possible)
            task.update_status(TaskStatus.STAGE_1_4)
            stage_1_4_results = await self._run_stage_1_4(
                file_path, enable_dynamic, enable_threat_intel
            )
            task.stage_1_4_results = stage_1_4_results

            # Stage 5: Ghidra analysis (if enabled)
            ghidra_results = {}
            if enable_ghidra:
                task.update_status(TaskStatus.STAGE_5)
                ghidra_results = await self._run_stage_5(stage_1_4_results, file_path)
                task.ghidra_results = ghidra_results

            # Stage 6: Report generation
            task.update_status(TaskStatus.STAGE_6)
            report = await self._run_stage_6(stage_1_4_results, ghidra_results)
            task.report = report

            task.update_status(TaskStatus.COMPLETED)

            # Aggregate final output
            return {
                "task_id": task.id,
                "status": task.status.value,
                "metadata": {
                    "file_path": str(file_path),
                    "file_name": file_path.name,
                    "file_size": file_path.stat().st_size,
                },
                "static_analysis": stage_1_4_results,
                "dynamic_analysis": stage_1_4_results.get("dynamic_analysis"),
                "ghidra_analysis": ghidra_results if enable_ghidra else None,
                "report": report.get("report", {}),
            }

        except Exception as e:
            logger.exception(f"Analysis failed for {file_path}")
            task.set_error(str(e))
            return {
                "task_id": task.id,
                "status": task.status.value,
                "error": str(e),
            }

    async def _run_stage_1_4(
        self,
        file_path: Path,
        enable_dynamic: bool,
        enable_threat_intel: bool,
    ) -> dict[str, Any]:
        """Run Stage 1-4: Static analysis, threat intel, and dynamic analysis.

        Args:
            file_path: Path to the file.
            enable_dynamic: Whether to run dynamic analysis.
            enable_threat_intel: Whether to query threat intel.

        Returns:
            Combined results from all Stage 1-4 analyses.
        """
        # Stage 1-2: Static analysis
        static_results = await self.static_analyzer.analyze(file_path)
        if not isinstance(static_results, dict):
            static_results = {}

        # Stage 3: Threat intel (parallel with dynamic)
        threat_intel_task = None
        if enable_threat_intel:
            threat_intel_task = asyncio.create_task(self._query_threat_intel(static_results))

        # Stage 4: Dynamic analysis
        dynamic_results = {}
        if enable_dynamic:
            dynamic_results = await self._run_dynamic_analysis(file_path, static_results)

        # Wait for threat intel
        if threat_intel_task:
            threat_intel_results = await threat_intel_task
            static_results["threat_intel"] = threat_intel_results

        # Add dynamic results
        static_results["dynamic_analysis"] = dynamic_results

        return static_results

    async def _run_dynamic_analysis(
        self,
        file_path: Path,
        static_results: dict,
    ) -> dict[str, Any]:
        """Run dynamic analysis (binary emulation).

        Args:
            file_path: Path to the binary.
            static_results: Static analysis results (for architecture info).

        Returns:
            Dynamic analysis results.
        """
        # Get architecture from static analysis
        elf_info = static_results.get("elf_info", {})
        arch = elf_info.get("machine", "").lower()

        # Map common architecture names
        arch_mapping = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "i386": "i386",
            "i686": "i386",
            "arm": "arm",
            "aarch64": "aarch64",
            "mips": "mips",
            "mipsel": "mipsel",
        }

        # Try to determine architecture
        target_arch = None
        for key, value in arch_mapping.items():
            if key in arch:
                target_arch = value
                break

        if not target_arch:
            logger.warning(f"Unknown architecture: {arch}, skipping dynamic analysis")
            return {
                "success": False,
                "error": f"Unsupported architecture: {arch}",
                "skipped": True,
            }

        # Run emulation
        try:
            result = self.dynamic_analyzer.emulate(str(file_path), target_arch)
            return result
        except Exception as e:
            logger.warning(f"Dynamic analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    async def _query_threat_intel(self, static_results: dict) -> dict[str, Any]:
        """Query threat intelligence services.

        Args:
            static_results: Static analysis results containing hashes and IoCs.

        Returns:
            Threat intelligence results.
        """
        results = {}

        # Query by hash
        hashes = static_results.get("hashes", {})
        sha256 = hashes.get("sha256")
        if sha256:
            hash_results = await self.threat_intel.query_hash(sha256)
            results["hash_lookup"] = {
                source: {
                    "found": r.found,
                    "data": r.data,
                    "error": r.error,
                }
                for source, r in hash_results.items()
            }

        # Query IoCs
        strings = static_results.get("strings", {})
        domains = strings.get("domains", [])
        ips = strings.get("ips", [])
        urls = strings.get("urls", [])

        if domains or ips or urls:
            ioc_results = await self.threat_intel.query_iocs(
                domains=domains[:5],
                ips=ips[:5],
                urls=urls[:5],
            )
            results["ioc_lookup"] = {
                ioc_type: [{"found": r.found, "data": r.data, "error": r.error} for r in ioc_list]
                for ioc_type, ioc_list in ioc_results.items()
            }

        return results

    async def _run_stage_5(
        self,
        static_results: dict[str, Any],
        file_path: Path,
    ) -> dict[str, Any]:
        """Run Stage 5: Ghidra deep analysis.

        Args:
            static_results: Results from Stage 1-4.
            file_path: Path to the file.

        Returns:
            Ghidra analysis results.
        """
        sample_hash = static_results.get("hashes", {}).get("sha256", "")

        result = await self.ghidra_agent.analyze(
            {
                "static_results": static_results,
                "file_path": str(file_path),
                "sample_hash": sample_hash,
            }
        )

        return result.data if result.success else {"error": result.error}

    async def _run_stage_6(
        self,
        static_results: dict[str, Any],
        ghidra_results: dict[str, Any],
    ) -> dict[str, Any]:
        """Run Stage 6: Final report generation.

        Args:
            static_results: Results from Stage 1-4.
            ghidra_results: Results from Stage 5.

        Returns:
            Final analysis report.
        """
        # Extract results for report
        threat_intel = static_results.get("threat_intel", {})
        dynamic_results = static_results.get("dynamic_analysis", {})

        result = await self.malware_agent.analyze(
            {
                "static_results": static_results,
                "ghidra_analysis": ghidra_results,
                "threat_intel": threat_intel,
                "dynamic_results": dynamic_results,
            }
        )

        return result.data if result.success else {"error": result.error}

    async def analyze_batch(
        self,
        file_paths: list[str | Path],
        max_parallel: int | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze multiple files with controlled parallelism.

        Args:
            file_paths: List of file paths to analyze.
            max_parallel: Maximum parallel analyses. Defaults to config.

        Returns:
            List of analysis results.
        """
        if max_parallel is None:
            max_parallel = self.config.workers.stage_1_4

        semaphore = asyncio.Semaphore(max_parallel)

        async def analyze_with_semaphore(path: str | Path) -> dict[str, Any]:
            async with semaphore:
                return await self.analyze(path)

        tasks = [analyze_with_semaphore(p) for p in file_paths]
        return await asyncio.gather(*tasks, return_exceptions=False)
