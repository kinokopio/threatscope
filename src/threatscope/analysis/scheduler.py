"""TaskScheduler - Hybrid parallel task scheduler for malware analysis."""

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.threatscope.analysis.task import AnalysisTask
from src.threatscope.api.schemas import TaskStatus

logger = logging.getLogger(__name__)


@dataclass
class SchedulerConfig:
    """Configuration for TaskScheduler."""

    pre_ghidra_workers: int = 4
    report_workers: int = 4
    ghidra_pool_size: int = 1
    max_queue_size: int = 100
    retry_count: int = 3


@dataclass
class TaskProgress:
    """Progress information for a task."""

    task_id: str
    status: TaskStatus
    stage: str
    progress_percent: int
    message: str
    updated_at: datetime = field(default_factory=datetime.now)


class TaskScheduler:
    """Hybrid parallel task scheduler.

    Architecture:
    - Pre-Ghidra: Static + Dynamic + Threat Intel (fully parallel)
    - Ghidra: Deep analysis (limited by instance pool)
    - Report: AI report generation (fully parallel)

    Task flow:
    pending_queue → Pre-Ghidra → ghidra_queue → Ghidra → report_queue → Report → completed
    """

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        on_progress: Callable[[TaskProgress], None] | None = None,
    ):
        """Initialize scheduler.

        Args:
            config: Scheduler configuration.
            on_progress: Callback for progress updates.
        """
        self.config = config or SchedulerConfig()
        self.on_progress = on_progress

        # Task storage
        self._tasks: dict[str, AnalysisTask] = {}

        # Queues
        self._pending_queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self.config.max_queue_size)
        self._ghidra_queue: asyncio.Queue[str] = asyncio.Queue()
        self._report_queue: asyncio.Queue[str] = asyncio.Queue()

        # Semaphores for parallel control
        self._pre_ghidra_semaphore = asyncio.Semaphore(self.config.pre_ghidra_workers)
        self._report_semaphore = asyncio.Semaphore(self.config.report_workers)
        self._ghidra_semaphore = asyncio.Semaphore(self.config.ghidra_pool_size)

        # Control flags
        self._running = False
        self._processor_tasks: list[asyncio.Task] = []

        # Callbacks for actual analysis (set by coordinator)
        self._run_pre_ghidra: Callable | None = None
        self._run_ghidra: Callable | None = None
        self._run_report: Callable | None = None

    def set_stage_handlers(
        self,
        pre_ghidra: Callable[[AnalysisTask], Any],
        ghidra: Callable[[AnalysisTask], Any],
        report: Callable[[AnalysisTask], Any],
    ) -> None:
        """Set handlers for each stage.

        Args:
            pre_ghidra: Handler for pre-Ghidra analysis (static + dynamic + threat intel).
            ghidra: Handler for Ghidra deep analysis.
            report: Handler for report generation.
        """
        self._run_pre_ghidra = pre_ghidra
        self._run_ghidra = ghidra
        self._run_report = report

    async def start(self) -> None:
        """Start the scheduler processors."""
        if self._running:
            return

        self._running = True

        # Start processor tasks
        self._processor_tasks = [
            asyncio.create_task(self._pre_ghidra_processor()),
            asyncio.create_task(self._ghidra_processor()),
            asyncio.create_task(self._report_processor()),
        ]

        logger.info("TaskScheduler started")

    async def stop(self) -> None:
        """Stop the scheduler."""
        self._running = False

        # Cancel processor tasks
        for task in self._processor_tasks:
            task.cancel()

        # Wait for cancellation
        await asyncio.gather(*self._processor_tasks, return_exceptions=True)
        self._processor_tasks = []

        logger.info("TaskScheduler stopped")

    async def submit(self, file_path: str) -> str:
        """Submit a file for analysis.

        Args:
            file_path: Path to the file.

        Returns:
            Task ID.
        """
        task = AnalysisTask(file_path=file_path)
        self._tasks[task.id] = task

        await self._pending_queue.put(task.id)
        self._notify_progress(task, "queued", 0, "Task queued for analysis")

        logger.info(f"Task {task.id} submitted: {file_path}")
        return task.id

    async def submit_batch(self, file_paths: list[str]) -> list[str]:
        """Submit multiple files for analysis.

        Args:
            file_paths: List of file paths.

        Returns:
            List of task IDs.
        """
        task_ids = []
        for path in file_paths:
            task_id = await self.submit(path)
            task_ids.append(task_id)
        return task_ids

    def get_task(self, task_id: str) -> AnalysisTask | None:
        """Get task by ID."""
        return self._tasks.get(task_id)

    def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get task status as dictionary."""
        task = self._tasks.get(task_id)
        if task:
            return task.to_dict()
        return None

    def get_all_tasks(self) -> list[dict[str, Any]]:
        """Get all tasks as dictionaries."""
        return [task.to_dict() for task in self._tasks.values()]

    def get_queue_stats(self) -> dict[str, int]:
        """Get queue statistics."""
        return {
            "pending": self._pending_queue.qsize(),
            "ghidra_waiting": self._ghidra_queue.qsize(),
            "report_waiting": self._report_queue.qsize(),
            "total_tasks": len(self._tasks),
            "completed": sum(1 for t in self._tasks.values() if t.status == TaskStatus.COMPLETED),
            "failed": sum(1 for t in self._tasks.values() if t.status == TaskStatus.FAILED),
        }

    # --- Processors ---

    async def _pre_ghidra_processor(self) -> None:
        """Process pre-Ghidra tasks (parallel)."""
        while self._running:
            try:
                task_id = await asyncio.wait_for(self._pending_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Acquire semaphore and process
            asyncio.create_task(self._run_pre_ghidra_task(task_id))

    async def _run_pre_ghidra_task(self, task_id: str) -> None:
        """Run pre-Ghidra analysis for a task."""
        async with self._pre_ghidra_semaphore:
            task = self._tasks.get(task_id)
            if not task:
                return

            try:
                task.update_status(TaskStatus.STATIC_ANALYSIS)
                self._notify_progress(task, "pre_ghidra", 10, "Running static analysis")

                if self._run_pre_ghidra:
                    result = await self._run_pre_ghidra(task)
                    task.pre_ghidra_results = result

                    # Check if file type is unsupported
                    if result.get("status") == "unsupported":
                        logger.info(f"Task {task_id} has unsupported file type, completing early")
                        task.update_status(TaskStatus.COMPLETED)
                        self._notify_progress(
                            task, "completed", 100,
                            f"Unsupported file type: {result.get('reason', 'unknown')}"
                        )
                        return

                self._notify_progress(task, "pre_ghidra", 40, "Pre-Ghidra analysis complete")

                # Move to Ghidra queue
                task.update_status(TaskStatus.QUEUED)
                await self._ghidra_queue.put(task_id)

            except Exception as e:
                logger.exception(f"Pre-Ghidra analysis failed for task {task_id}")
                self._handle_task_failure(task, str(e))

    async def _ghidra_processor(self) -> None:
        """Process Ghidra tasks (limited by pool)."""
        while self._running:
            try:
                task_id = await asyncio.wait_for(self._ghidra_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Acquire Ghidra semaphore and process
            asyncio.create_task(self._run_ghidra_task(task_id))

    async def _run_ghidra_task(self, task_id: str) -> None:
        """Run Ghidra analysis for a task."""
        async with self._ghidra_semaphore:
            task = self._tasks.get(task_id)
            if not task:
                return

            try:
                task.update_status(TaskStatus.GHIDRA_ANALYSIS)
                self._notify_progress(task, "ghidra", 50, "Running Ghidra analysis")

                if self._run_ghidra:
                    task.ghidra_results = await self._run_ghidra(task)

                self._notify_progress(task, "ghidra", 70, "Ghidra analysis complete")

                # Move to report queue
                await self._report_queue.put(task_id)

            except Exception as e:
                logger.exception(f"Ghidra analysis failed for task {task_id}")
                self._handle_task_failure(task, str(e))

    async def _report_processor(self) -> None:
        """Process report generation tasks (parallel)."""
        while self._running:
            try:
                task_id = await asyncio.wait_for(self._report_queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            # Acquire semaphore and process
            asyncio.create_task(self._run_report_task(task_id))

    async def _run_report_task(self, task_id: str) -> None:
        """Run report generation for a task."""
        async with self._report_semaphore:
            task = self._tasks.get(task_id)
            if not task:
                return

            try:
                task.update_status(TaskStatus.REPORT_GENERATION)
                self._notify_progress(task, "report", 80, "Generating report")

                if self._run_report:
                    task.report = await self._run_report(task)

                task.update_status(TaskStatus.COMPLETED)
                self._notify_progress(task, "completed", 100, "Analysis complete")

                logger.info(f"Task {task_id} completed")

            except Exception as e:
                logger.exception(f"Report generation failed for task {task_id}")
                self._handle_task_failure(task, str(e))

    # --- Helpers ---

    def _handle_task_failure(self, task: AnalysisTask, error: str) -> None:
        """Handle task failure with retry logic."""
        task.retry_count += 1

        if task.retry_count < self.config.retry_count:
            # Retry by putting back in pending queue
            logger.warning(f"Task {task.id} failed (attempt {task.retry_count}), retrying: {error}")
            task.update_status(TaskStatus.PENDING)
            asyncio.create_task(self._pending_queue.put(task.id))
        else:
            # Max retries exceeded
            logger.error(f"Task {task.id} failed after {task.retry_count} attempts: {error}")
            task.set_error(error)
            self._notify_progress(task, "failed", 0, f"Failed: {error}")

    def _notify_progress(
        self,
        task: AnalysisTask,
        stage: str,
        percent: int,
        message: str,
    ) -> None:
        """Send progress notification."""
        if self.on_progress:
            progress = TaskProgress(
                task_id=task.id,
                status=task.status,
                stage=stage,
                progress_percent=percent,
                message=message,
            )
            try:
                self.on_progress(progress)
            except Exception as e:
                logger.warning(f"Progress callback failed: {e}")


class ScheduledCoordinator:
    """Coordinator that uses TaskScheduler for batch processing."""

    def __init__(
        self,
        coordinator: Any,  # AnalysisCoordinator
        scheduler_config: SchedulerConfig | None = None,
    ):
        """Initialize scheduled coordinator.

        Args:
            coordinator: The AnalysisCoordinator instance.
            scheduler_config: Scheduler configuration.
        """
        self.coordinator = coordinator
        self.scheduler = TaskScheduler(config=scheduler_config)

        # Set up stage handlers
        self.scheduler.set_stage_handlers(
            pre_ghidra=self._handle_pre_ghidra,
            ghidra=self._handle_ghidra,
            report=self._handle_report,
        )

    async def start(self) -> None:
        """Start the scheduler."""
        await self.scheduler.start()

    async def stop(self) -> None:
        """Stop the scheduler."""
        await self.scheduler.stop()

    async def submit(self, file_path: str) -> str:
        """Submit a file for analysis."""
        return await self.scheduler.submit(file_path)

    async def submit_batch(self, file_paths: list[str]) -> list[str]:
        """Submit multiple files for analysis."""
        return await self.scheduler.submit_batch(file_paths)

    def get_task_status(self, task_id: str) -> dict[str, Any] | None:
        """Get task status."""
        return self.scheduler.get_task_status(task_id)

    def get_queue_stats(self) -> dict[str, int]:
        """Get queue statistics."""
        return self.scheduler.get_queue_stats()

    async def _handle_pre_ghidra(self, task: AnalysisTask) -> dict[str, Any]:
        """Handle pre-Ghidra analysis."""
        from pathlib import Path

        return await self.coordinator._run_pre_ghidra(
            Path(task.file_path),
            enable_dynamic=True,
            enable_threat_intel=True,
        )

    async def _handle_ghidra(self, task: AnalysisTask) -> dict[str, Any]:
        """Handle Ghidra analysis."""
        from pathlib import Path

        return await self.coordinator._run_ghidra(
            task.pre_ghidra_results or {},
            Path(task.file_path),
        )

    async def _handle_report(self, task: AnalysisTask) -> dict[str, Any]:
        """Handle report generation."""
        return await self.coordinator._run_report(
            task.pre_ghidra_results or {},
            task.ghidra_results or {},
        )
