"""Analysis API router.

This module provides REST endpoints for malware analysis operations.
"""

import logging
import tempfile
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, File, Query, UploadFile

from src.threatscope.api.schemas import (
    AnalysisResult,
    BatchSubmitRequest,
    BatchSubmitResponse,
    QueueStats,
    TaskListResponse,
    TaskResponse,
    TaskStatus,
)
from src.threatscope.core.dependencies import (
    CoordinatorDep,
    DatabaseDep,
    ScheduledCoordinatorDep,
    SettingsDep,
)
from src.threatscope.shared.exceptions import TaskNotFoundError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analysis"])


# =============================================================================
# Analysis Endpoints
# =============================================================================


@router.post(
    "/analyze",
    response_model=TaskResponse,
    status_code=202,
    summary="Submit file for analysis",
    description="Upload a file and start asynchronous malware analysis",
    responses={
        202: {"description": "Analysis task created"},
        413: {"description": "File too large"},
        503: {"description": "Queue full"},
    },
)
async def analyze_file(
    background_tasks: BackgroundTasks,
    settings: SettingsDep,
    db: DatabaseDep,
    coordinator: CoordinatorDep,
    file: UploadFile = File(..., description="File to analyze"),
    enable_ghidra: bool = Query(default=True, description="Enable Ghidra analysis"),
    enable_dynamic: bool = Query(default=True, description="Enable dynamic analysis"),
    enable_threat_intel: bool = Query(default=True, description="Enable threat intel"),
) -> TaskResponse:
    """Submit a file for asynchronous analysis.

    The file is uploaded, saved temporarily, and analysis is started
    in the background. Returns immediately with a task ID for tracking.
    """
    task_id = str(uuid.uuid4())[:8]
    logger.info(f"Creating analysis task {task_id} for {file.filename}")

    # Save uploaded file
    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    # Create task in database
    db.create_task(
        task_id=task_id,
        file_path=str(file_path),
        file_name=file.filename,
        options={
            "enable_ghidra": enable_ghidra,
            "enable_dynamic": enable_dynamic,
            "enable_threat_intel": enable_threat_intel,
        },
    )

    # Start background analysis
    background_tasks.add_task(
        _run_analysis_background,
        task_id=task_id,
        file_path=file_path,
        coordinator=coordinator,
        db=db,
        enable_ghidra=enable_ghidra,
        enable_dynamic=enable_dynamic,
        enable_threat_intel=enable_threat_intel,
    )

    return TaskResponse(
        task_id=task_id,
        status=TaskStatus.PENDING,
        message="Analysis started",
    )


@router.post(
    "/analyze/sync",
    response_model=AnalysisResult,
    summary="Synchronous analysis",
    description="Upload and analyze a file synchronously (waits for completion)",
    responses={
        200: {"description": "Analysis completed"},
        500: {"description": "Analysis failed"},
    },
)
async def analyze_file_sync(
    coordinator: CoordinatorDep,
    file: UploadFile = File(...),
    enable_ghidra: bool = Query(default=True),
    enable_dynamic: bool = Query(default=True),
    enable_threat_intel: bool = Query(default=True),
) -> AnalysisResult:
    """Analyze a file synchronously.

    This endpoint waits for the analysis to complete before returning.
    Use for smaller files or when immediate results are needed.
    """
    task_id = str(uuid.uuid4())[:8]

    # Save uploaded file
    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    try:
        content = await file.read()
        file_path.write_bytes(content)

        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
        )

        return AnalysisResult(
            task_id=task_id,
            status=TaskStatus.COMPLETED,
            **result,
        )

    except Exception as e:
        logger.exception(f"Sync analysis failed: {e}")
        return AnalysisResult(
            task_id=task_id,
            status=TaskStatus.FAILED,
            error=str(e),
        )

    finally:
        # Cleanup temp file
        try:
            file_path.unlink()
        except Exception:
            pass


# =============================================================================
# Task Management Endpoints
# =============================================================================


@router.get(
    "/tasks/{task_id}",
    response_model=AnalysisResult,
    summary="Get task status",
    description="Get the current status and results of an analysis task",
    responses={
        200: {"description": "Task found"},
        404: {"description": "Task not found"},
    },
)
async def get_task(
    task_id: str,
    db: DatabaseDep,
    scheduled: ScheduledCoordinatorDep,
) -> AnalysisResult:
    """Get task status and results by ID."""
    task = db.get_task(task_id)

    if not task:
        # Try scheduled coordinator
        task_status = scheduled.get_task_status(task_id)
        if task_status:
            return AnalysisResult(
                task_id=task_id,
                status=TaskStatus(task_status["status"]),
                error=task_status.get("error"),
            )
        raise TaskNotFoundError(task_id)

    return AnalysisResult(
        task_id=task_id,
        status=TaskStatus(task["status"]),
        file_name=task.get("file_name"),
        metadata=task.get("metadata", {}),
        error=task.get("error"),
        **_extract_results(task),
    )


@router.get(
    "/tasks",
    response_model=TaskListResponse,
    summary="List all tasks",
    description="Get a list of all analysis tasks with queue statistics",
)
async def list_tasks(
    db: DatabaseDep,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    status: TaskStatus | None = Query(default=None),
) -> TaskListResponse:
    """List all tasks with optional filtering."""
    tasks = db.get_all_tasks(limit=limit, offset=offset, status=status.value if status else None)
    stats = db.get_stats()

    return TaskListResponse(
        tasks=[
            {
                "id": t["id"],
                "status": t["status"],
                "file_name": t.get("file_name"),
                "result_summary": _extract_result_summary(t.get("result")),
            }
            for t in tasks
        ],
        queue_stats=QueueStats(
            pending=stats.get("pending", 0),
            ghidra_waiting=stats.get("queued", 0),
            report_waiting=stats.get("stage_6", 0),
            total_tasks=stats.get("total", 0),
            completed=stats.get("completed", 0),
            failed=stats.get("failed", 0),
        ),
    )


@router.delete(
    "/tasks/{task_id}",
    status_code=204,
    summary="Delete task",
    description="Delete an analysis task and its results",
    responses={
        204: {"description": "Task deleted"},
        404: {"description": "Task not found"},
    },
)
async def delete_task(task_id: str, db: DatabaseDep) -> None:
    """Delete a task by ID."""
    if not db.delete_task(task_id):
        raise TaskNotFoundError(task_id)


# =============================================================================
# Batch Endpoints
# =============================================================================


@router.post(
    "/batch/submit",
    response_model=BatchSubmitResponse,
    summary="Submit batch analysis",
    description="Submit multiple files for analysis",
)
async def submit_batch(
    request: BatchSubmitRequest,
    scheduled: ScheduledCoordinatorDep,
) -> BatchSubmitResponse:
    """Submit multiple files for batch analysis."""
    task_ids = await scheduled.submit_batch(request.file_paths)

    return BatchSubmitResponse(
        task_ids=task_ids,
        message=f"Submitted {len(task_ids)} tasks for analysis",
    )


@router.get(
    "/batch/stats",
    response_model=QueueStats,
    summary="Get queue statistics",
    description="Get current queue statistics",
)
async def get_queue_stats(scheduled: ScheduledCoordinatorDep) -> QueueStats:
    """Get queue statistics."""
    stats = scheduled.get_queue_stats()
    return QueueStats(**stats)


# =============================================================================
# Helper Functions
# =============================================================================


def _run_analysis_background(
    task_id: str,
    file_path: Path,
    coordinator,
    db,
    enable_ghidra: bool,
    enable_dynamic: bool,
    enable_threat_intel: bool,
) -> None:
    """Run analysis in background.

    This function runs in a background task.
    """
    import asyncio

    async def _do_analysis():
        try:
            # Update status
            db.update_task_status(task_id, TaskStatus.STAGE_1_4.value)

            # Run analysis
            result = await coordinator.analyze(
                file_path=file_path,
                enable_ghidra=enable_ghidra,
                enable_dynamic=enable_dynamic,
                enable_threat_intel=enable_threat_intel,
            )

            # Save results
            if "error" in result:
                db.update_task_status(task_id, TaskStatus.FAILED.value, error=result["error"])
            else:
                db.update_task_result(task_id, "stage_1_4_results", result.get("static_analysis", {}))
                if result.get("ghidra_analysis"):
                    db.update_task_result(task_id, "ghidra_results", result["ghidra_analysis"])
                if result.get("report"):
                    db.update_task_result(task_id, "report", result["report"])
                db.update_task_status(task_id, TaskStatus.COMPLETED.value)

        except Exception as e:
            logger.exception(f"Background analysis failed for {task_id}")
            db.update_task_status(task_id, TaskStatus.FAILED.value, error=str(e))

        finally:
            # Cleanup temp file
            try:
                file_path.unlink()
            except Exception:
                pass

    # Run in event loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, create task
            asyncio.create_task(_do_analysis())
        else:
            loop.run_until_complete(_do_analysis())
    except RuntimeError:
        # No event loop, create new one
        asyncio.run(_do_analysis())


def _extract_results(task: dict) -> dict:
    """Extract analysis results from task data."""
    results = {}

    if task.get("stage_1_4_results"):
        stage_results = task["stage_1_4_results"]
        results["hashes"] = stage_results.get("hashes")
        results["strings"] = stage_results.get("strings")
        results["elf"] = stage_results.get("elf")
        results["yara"] = stage_results.get("yara")
        results["threat_intel"] = stage_results.get("threat_intel")
        results["dynamic_analysis"] = stage_results.get("dynamic_analysis")

    if task.get("ghidra_results"):
        results["ghidra_analysis"] = task["ghidra_results"]

    if task.get("report"):
        results["malware_report"] = task["report"]

    return results


def _extract_result_summary(result: dict | None) -> dict | None:
    """Extract summary from result for list view."""
    if not result:
        return None

    summary = {}

    if "malware_report" in result:
        report = result["malware_report"]
        if isinstance(report, dict):
            summary["verdict"] = report.get("verdict")
            summary["confidence"] = report.get("confidence")
            summary["family"] = report.get("family")

    return summary if summary else None
