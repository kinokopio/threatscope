"""AnalysisCoordinator - Pipeline orchestration for malware analysis.

This coordinator orchestrates the complete malware analysis pipeline using
functional status names instead of generic "Stage X" naming.

Pipeline phases:
- Static Analysis: hashing, string_extraction, binary_parsing, yara_scanning
- Threat Intelligence: threat_intel
- Dynamic Analysis: dynamic_analysis
- Deep Analysis: ghidra_analysis
- Report Generation: report_generation
"""

import asyncio
import logging
from pathlib import Path
from typing import Any, Callable

from src.threatscope.analysis.agents import (
    AgentConfig,
    GhidraAgent,
    MalwareAnalysisAgent,
)
from src.threatscope.analysis.services.threat_intel import ThreatIntelService
from src.threatscope.analysis.task import AnalysisStatus, AnalysisTask
from src.threatscope.analysis.tools.dynamic import TraceeAnalyzer, TraceeConfig
from src.threatscope.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


# Type alias for progress callback
# Signature: (step_id, step_name, status, preview_data, current_results) -> Any
ProgressCallback = Callable[[str, str, str, dict | None, dict | None], Any] | None


class AnalysisCoordinator:
    """Orchestrates the complete malware analysis pipeline.

    Pipeline phases (using functional names):
    - Static Analysis: hashing, string_extraction, binary_parsing, yara_scanning
    - Threat Intelligence: threat_intel
    - Dynamic Analysis: dynamic_analysis (Tracee eBPF sandbox)
    - Deep Analysis: ghidra_analysis (AI-driven reverse engineering)
    - Report Generation: report_generation (AI-driven report synthesis)
    """

    def __init__(
        self,
        settings: Settings | None = None,
        project_dir: str | Path = ".",
        ghidra_pool: Any | None = None,  # GhidraInstancePool
    ):
        """Initialize the coordinator.

        Args:
            settings: Application settings. Uses get_settings() if not provided.
            project_dir: Project directory for memory storage.
            ghidra_pool: Optional GhidraInstancePool for Docker mode.
        """
        self.settings = settings or get_settings()
        self.project_dir = Path(project_dir)
        self.ghidra_pool = ghidra_pool

        # Initialize dynamic analyzer
        tracee_config = TraceeConfig(
            timeout=self.settings.analysis.dynamic_analysis_timeout,
        )
        self.dynamic_analyzer = TraceeAnalyzer(tracee_config)

        # Initialize threat intel service
        self.threat_intel = ThreatIntelService()

        # Initialize agents (lazy - created when needed)
        self._ghidra_agent: GhidraAgent | None = None
        self._malware_agent: MalwareAnalysisAgent | None = None

    @property
    def ghidra_agent(self) -> GhidraAgent:
        """Lazy-initialize Ghidra agent."""
        if self._ghidra_agent is None:
            config = AgentConfig(
                system_prompt_path=str(self.project_dir / "prompts" / "ghidra_agent.md"),
                max_iterations=20,
            )
            self._ghidra_agent = GhidraAgent(
                config,
                self.project_dir,
                ghidra_url=self.settings.ghidra.base_url,
            )
        return self._ghidra_agent

    @property
    def malware_agent(self) -> MalwareAnalysisAgent:
        """Lazy-initialize malware analysis agent."""
        if self._malware_agent is None:
            config = AgentConfig(
                system_prompt_path=str(self.project_dir / "prompts" / "malware_agent.md"),
            )
            self._malware_agent = MalwareAnalysisAgent(config)
        return self._malware_agent

    async def analyze(
        self,
        file_path: str | Path,
        enable_ghidra: bool = True,
        enable_dynamic: bool = True,
        enable_threat_intel: bool = True,
        progress_callback: ProgressCallback = None,
    ) -> dict[str, Any]:
        """Run complete analysis pipeline on a file.

        Args:
            file_path: Path to the file to analyze.
            enable_ghidra: Enable Ghidra deep analysis.
            enable_dynamic: Enable dynamic analysis.
            enable_threat_intel: Enable threat intelligence queries.
            progress_callback: Optional callback for progress updates.
                Signature: (step_id, step_name, status, preview_data) -> None

        Returns:
            Complete analysis results dictionary.
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": f"File not found: {file_path}"}

        # Create task
        task = AnalysisTask(file_path=str(file_path))

        logger.info(
            f"Starting analysis: ghidra={enable_ghidra}, "
            f"dynamic={enable_dynamic}, threat_intel={enable_threat_intel}"
        )

        try:
            # Phase 1: Static Analysis
            static_results = await self._run_static_analysis(file_path, task, progress_callback)

            # Phase 2: Threat Intelligence
            if enable_threat_intel:
                task.update_status(AnalysisStatus.THREAT_INTEL)
                if progress_callback:
                    await progress_callback(
                        "threat_intel", "Threat Intelligence Query", "running", None, static_results
                    )
                threat_intel_results = await self._query_threat_intel(static_results)
                static_results["threat_intel"] = threat_intel_results
                if progress_callback:
                    found_count = sum(
                        1
                        for source in threat_intel_results.get("hash_lookup", {}).values()
                        if isinstance(source, dict) and source.get("found")
                    )
                    await progress_callback(
                        "threat_intel",
                        "Threat Intelligence Query",
                        "completed",
                        {"sources_found": found_count},
                        static_results,
                    )

            # Phase 3: Dynamic Analysis
            dynamic_results = {}
            if enable_dynamic:
                task.update_status(AnalysisStatus.DYNAMIC_ANALYSIS)
                if progress_callback:
                    await progress_callback(
                        "dynamic_analysis", "Dynamic Analysis (Tracee)", "running", None, static_results
                    )
                dynamic_results = await self._run_dynamic_analysis(file_path, static_results)
                static_results["dynamic_analysis"] = dynamic_results
                if progress_callback:
                    await progress_callback(
                        "dynamic_analysis",
                        "Dynamic Analysis (Tracee)",
                        "completed",
                        {
                            "success": dynamic_results.get("success", False),
                            "events_count": dynamic_results.get("raw_events_count", 0),
                        },
                        static_results,
                    )

            task.static_results = static_results

            # Phase 4: Ghidra Deep Analysis
            ghidra_results = {}
            if enable_ghidra:
                task.update_status(AnalysisStatus.GHIDRA_ANALYSIS)
                if progress_callback:
                    await progress_callback(
                        "ghidra_analysis", "Ghidra Deep Analysis", "running", None, static_results
                    )
                ghidra_results = await self._run_ghidra_analysis(
                    static_results, file_path, progress_callback
                )
                task.ghidra_results = ghidra_results
                if progress_callback:
                    await progress_callback(
                        "ghidra_analysis",
                        "Ghidra Deep Analysis",
                        "completed",
                        {"status": ghidra_results.get("status", "unknown")},
                        static_results,
                    )

            # Phase 5: Report Generation
            task.update_status(AnalysisStatus.REPORT_GENERATION)
            if progress_callback:
                await progress_callback("report_generation", "Report Generation", "running", None, static_results)
            report = await self._run_report_generation(static_results, ghidra_results, progress_callback)
            task.report = report
            if progress_callback:
                await progress_callback(
                    "report_generation",
                    "Report Generation",
                    "completed",
                    {"verdict": report.get("report", {}).get("verdict", "unknown")},
                    static_results,
                )

            task.update_status(AnalysisStatus.COMPLETED)

            # Aggregate final output
            return {
                "task_id": task.id,
                "status": task.status.value,
                "metadata": {
                    "file_path": str(file_path),
                    "file_name": file_path.name,
                    "file_size": file_path.stat().st_size,
                },
                "static_analysis": static_results,
                "dynamic_analysis": dynamic_results if enable_dynamic else None,
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

    async def _run_static_analysis(
        self,
        file_path: Path,
        task: AnalysisTask,
        progress_callback: ProgressCallback,
    ) -> dict[str, Any]:
        """Run static analysis phases.

        Phases: hashing, string_extraction, binary_parsing, yara_scanning
        """
        # Import static analysis service
        from src.threatscope.analysis.services.static_analysis import (
            StaticAnalysisService,
        )

        service = StaticAnalysisService()

        # Run static analysis with status updates
        task.update_status(AnalysisStatus.HASHING)
        if progress_callback:
            await progress_callback("hashing", "Hash Calculation", "running", None, {})

        results = await service.analyze(file_path, progress_callback)

        return results

    async def _run_dynamic_analysis(
        self,
        file_path: Path,
        static_results: dict,
    ) -> dict[str, Any]:
        """Run dynamic analysis using Tracee."""
        elf_info = static_results.get("elf", {})
        arch = elf_info.get("arch", "").lower()

        arch_mapping = {
            "x86_64": "x86_64",
            "amd64": "x86_64",
            "i386": "i386",
            "i686": "i386",
        }

        target_arch = None
        for key, value in arch_mapping.items():
            if key in arch:
                target_arch = value
                break

        if not target_arch:
            logger.warning(f"Unsupported architecture for Tracee: {arch}")
            return {
                "success": False,
                "error": f"Tracee only supports x86_64, got: {arch}",
                "skipped": True,
                "method": "tracee",
            }

        try:
            result = self.dynamic_analyzer.analyze(str(file_path), target_arch)
            return {
                "success": result.success,
                "method": result.method,
                "process_tree": result.process_tree,
                "network_summary": result.network_summary,
                "security_events": result.security_events,
                "syscall_summary": result.syscall_summary,
                "file_activity": result.file_activity,
                "duration_seconds": result.duration_seconds,
                "raw_events_count": result.raw_events_count,
                "error": result.error,
                "event_types": result.event_types,
            }
        except Exception as e:
            logger.warning(f"Dynamic analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "method": "tracee",
            }

    async def _query_threat_intel(self, static_results: dict) -> dict[str, Any]:
        """Query threat intelligence services."""
        results: dict[str, Any] = {}

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

    async def _run_ghidra_analysis(
        self,
        static_results: dict[str, Any],
        file_path: Path,
        progress_callback: ProgressCallback,
    ) -> dict[str, Any]:
        """Run Ghidra deep analysis.

        If ghidra_pool is available (Docker mode), acquires an instance from the pool.
        Otherwise, uses the default ghidra_url from settings.
        """
        sample_hash = static_results.get("hashes", {}).get("sha256", "")

        # Try to acquire instance from pool (Docker mode)
        instance = None
        ghidra_url = self.settings.ghidra.base_url

        if self.ghidra_pool is not None:
            instance = await self.ghidra_pool.acquire(timeout=60.0)
            if instance:
                ghidra_url = instance.http_url
                instance.current_sample = sample_hash
                logger.info(f"Acquired Ghidra instance {instance.id} at {ghidra_url}")
            else:
                logger.warning("No Ghidra instance available from pool, using default URL")

        try:
            # Create agent with the appropriate URL
            config = AgentConfig(
                system_prompt_path=str(self.project_dir / "prompts" / "ghidra_agent.md"),
                max_iterations=20,
            )
            agent = GhidraAgent(
                config,
                self.project_dir,
                ghidra_url=ghidra_url,
            )

            result = await agent.analyze(
                {
                    "static_results": static_results,
                    "file_path": str(file_path),
                    "sample_hash": sample_hash,
                },
                progress_callback=progress_callback,
            )

            return result.data if result.success else {"error": result.error}

        finally:
            # Release instance back to pool
            if instance is not None and self.ghidra_pool is not None:
                await self.ghidra_pool.release(instance)
                logger.info(f"Released Ghidra instance {instance.id}")

    async def _run_report_generation(
        self,
        static_results: dict[str, Any],
        ghidra_results: dict[str, Any],
        progress_callback: ProgressCallback = None,
    ) -> dict[str, Any]:
        """Run final report generation."""
        threat_intel = static_results.get("threat_intel", {})
        dynamic_results = static_results.get("dynamic_analysis", {})

        result = await self.malware_agent.analyze(
            {
                "static_results": static_results,
                "ghidra_analysis": ghidra_results,
                "threat_intel": threat_intel,
                "dynamic_results": dynamic_results,
            },
            progress_callback=progress_callback,
        )

        return result.data if result.success else {"error": result.error}

    async def analyze_batch(
        self,
        file_paths: list[str | Path],
        max_parallel: int = 4,
        **kwargs,
    ) -> list[dict[str, Any]]:
        """Analyze multiple files with controlled parallelism.

        Args:
            file_paths: List of file paths to analyze.
            max_parallel: Maximum parallel analyses.
            **kwargs: Additional arguments passed to analyze().

        Returns:
            List of analysis results.
        """
        semaphore = asyncio.Semaphore(max_parallel)

        async def analyze_with_semaphore(path: str | Path) -> dict[str, Any]:
            async with semaphore:
                return await self.analyze(path, **kwargs)

        tasks = [analyze_with_semaphore(p) for p in file_paths]
        return await asyncio.gather(*tasks, return_exceptions=False)
