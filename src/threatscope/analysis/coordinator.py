"""AnalysisCoordinator - Pipeline orchestration for malware analysis.

This coordinator orchestrates the complete malware analysis pipeline using
functional status names instead of generic "Stage X" naming.

Pipeline phases:
- Phase 1: Hash + diec (parallel) - determines file type
- Phase 2: capa + strings + yara + threat_intel + dynamic (parallel)
- Phase 3: Ghidra deep analysis
- Phase 4: Report generation

File type routing:
- PE/ELF → Full analysis pipeline
- Other → Return unsupported after Phase 1
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
from src.threatscope.analysis.services.dynamic_analysis import DynamicAnalysisService
from src.threatscope.analysis.services.threat_intel import ThreatIntelService
from src.threatscope.analysis.task import AnalysisStatus, AnalysisTask
from src.threatscope.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


# Type alias for progress callback
# Signature: (step_id, step_name, status, preview_data, current_results) -> Any
ProgressCallback = Callable[[str, str, str, dict | None, dict | None], Any] | None


class AnalysisCoordinator:
    """Orchestrates the complete malware analysis pipeline.

    Pipeline phases:
    - Phase 1: Static analysis (hash + diec + capa + strings + yara)
    - Phase 2: Threat intel + Dynamic analysis (parallel)
    - Phase 3: Ghidra deep analysis
    - Phase 4: Report generation

    File type routing:
    - PE/ELF → Full pipeline
    - Other → Return unsupported after basic identification
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

        # Initialize services
        self.dynamic_analysis_service = DynamicAnalysisService(
            timeout=self.settings.analysis.dynamic_analysis_timeout,
        )
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
            # ========================================
            # Phase 1: Static Analysis
            # ========================================
            static_results = await self._run_static_analysis(file_path, task, progress_callback)

            # Check file type - only PE/ELF continue full analysis
            file_type = static_results.get("file_type", {})
            category = file_type.get("category", "unknown")

            if category not in ("pe", "elf"):
                # Unsupported file type - return early
                logger.info(f"Unsupported file type: {category}, returning early")
                task.update_status(AnalysisStatus.COMPLETED)
                return {
                    "task_id": task.id,
                    "status": "unsupported",
                    "reason": f"不支持的文件类型: {category}",
                    "metadata": {
                        "file_path": str(file_path),
                        "file_name": file_path.name,
                        "file_size": file_path.stat().st_size,
                    },
                    "file_type": file_type,
                    "hashes": static_results.get("hashes", {}),
                }

            # ========================================
            # Phase 2: Threat Intel + Dynamic Analysis (parallel)
            # ========================================
            threat_intel_results = {}
            dynamic_results = {}

            phase2_tasks = []

            if enable_threat_intel:
                task.update_status(AnalysisStatus.THREAT_INTEL)
                if progress_callback:
                    await progress_callback(
                        "threat_intel", "Threat Intelligence Query", "running", None, static_results
                    )
                phase2_tasks.append(("threat_intel", self._query_threat_intel(static_results)))

            if enable_dynamic:
                task.update_status(AnalysisStatus.DYNAMIC_ANALYSIS)
                if progress_callback:
                    await progress_callback(
                        "dynamic_analysis", "Dynamic Analysis", "running", None, static_results
                    )
                phase2_tasks.append(("dynamic", self._run_dynamic_analysis(file_path, file_type)))

            # Execute phase 2 tasks in parallel
            if phase2_tasks:
                results = await asyncio.gather(*[t[1] for t in phase2_tasks])
                for i, (task_name, _) in enumerate(phase2_tasks):
                    if task_name == "threat_intel":
                        threat_intel_results = results[i]
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
                    elif task_name == "dynamic":
                        dynamic_results = results[i]
                        static_results["dynamic_analysis"] = dynamic_results
                        if progress_callback:
                            status = (
                                "completed" if not dynamic_results.get("skipped") else "skipped"
                            )
                            await progress_callback(
                                "dynamic_analysis",
                                "Dynamic Analysis",
                                status,
                                {
                                    "success": dynamic_results.get("success", False),
                                    "skipped": dynamic_results.get("skipped", False),
                                    "method": dynamic_results.get("method", "none"),
                                    "events_count": dynamic_results.get("raw_events_count", 0),
                                },
                                static_results,
                            )

            task.static_results = static_results

            # ========================================
            # Phase 3: Ghidra Deep Analysis
            # ========================================
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

            # ========================================
            # Phase 4: Report Generation
            # ========================================
            task.update_status(AnalysisStatus.REPORT_GENERATION)
            if progress_callback:
                await progress_callback(
                    "report_generation", "Report Generation", "running", None, static_results
                )
            report = await self._run_report_generation(
                static_results, ghidra_results, progress_callback
            )
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

        Phases: hashing, file_identification, capability_analysis, string_extraction, yara_scanning
        """
        # Import static analysis service
        from src.threatscope.analysis.services.static_analysis import (
            StaticAnalysisService,
        )

        # Resolve YARA rules path relative to project directory
        yara_rules_path = self.settings.analysis.yara_rules_path
        if yara_rules_path and not Path(yara_rules_path).is_absolute():
            yara_rules_path = str(self.project_dir / yara_rules_path)

        # Resolve capa rules path
        capa_rules_path = self.settings.capa.rules_path
        if capa_rules_path and not Path(capa_rules_path).is_absolute():
            capa_rules_path = str(self.project_dir / capa_rules_path)

        logger.info(f"YARA rules path resolved to: {yara_rules_path}")
        logger.info(f"capa rules path resolved to: {capa_rules_path}")
        logger.info(f"diec URL: {self.settings.diec.url}")

        service = StaticAnalysisService(
            yara_rules_path=yara_rules_path,
            diec_url=self.settings.diec.url,
            capa_rules_path=capa_rules_path,
            capa_timeout=self.settings.capa.timeout,
        )

        # Run static analysis with status updates
        task.update_status(AnalysisStatus.HASHING)
        if progress_callback:
            await progress_callback("hashing", "Hash Calculation", "running", None, {})

        results = await service.analyze(file_path, progress_callback)

        return results

    async def _run_dynamic_analysis(
        self,
        file_path: Path,
        file_type: dict[str, Any],
    ) -> dict[str, Any]:
        """Run dynamic analysis using DynamicAnalysisService.

        Routes based on file type:
        - ELF → Tracee (if architecture supported)
        - PE → Skip (CAPE planned)
        - Other → Skip
        """
        return await self.dynamic_analysis_service.analyze(file_path, file_type)

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
        Otherwise, starts Ghidra service on-demand using GhidraServiceManager.
        """
        from src.threatscope.ghidra.manager import GhidraServiceManager

        sample_hash = static_results.get("hashes", {}).get("sha256", "")

        # Try to acquire instance from pool (Docker mode)
        instance = None
        ghidra_url = self.settings.ghidra.base_url
        ghidra_manager: GhidraServiceManager | None = None

        if self.ghidra_pool is not None:
            instance = await self.ghidra_pool.acquire(timeout=60.0)
            if instance:
                ghidra_url = instance.http_url
                instance.current_sample = sample_hash
                logger.info(f"Acquired Ghidra instance {instance.id} at {ghidra_url}")
            else:
                logger.warning("No Ghidra instance available from pool, using default URL")
        else:
            # No pool - start Ghidra service on-demand
            ghidra_manager = GhidraServiceManager(
                mode="docker",
                docker_image=self.settings.ghidra.docker_image,
                host=self.settings.ghidra.service_host,
                port=self.settings.ghidra.base_http_port,
                startup_timeout=self.settings.ghidra.startup_timeout,
            )

            if progress_callback:
                try:
                    await progress_callback(
                        "ghidra_startup",
                        "Starting Ghidra service (this may take 1-2 minutes)",
                        "running",
                        {"mode": "docker", "image": self.settings.ghidra.docker_image},
                    )
                except Exception:
                    pass

            if not ghidra_manager.start():
                logger.error("Failed to start Ghidra service on-demand")
                return {
                    "error": "Failed to start Ghidra service",
                    "status": "ghidra_unavailable",
                }

            ghidra_url = ghidra_manager.base_url
            logger.info(f"Started Ghidra service on-demand at {ghidra_url}")

            if progress_callback:
                try:
                    await progress_callback(
                        "ghidra_startup",
                        "Ghidra service started",
                        "completed",
                        {"url": ghidra_url},
                    )
                except Exception:
                    pass

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

            # Stop on-demand Ghidra service
            if ghidra_manager is not None:
                logger.info("Stopping on-demand Ghidra service")
                ghidra_manager.stop()

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
