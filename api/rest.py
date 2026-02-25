"""REST API for ThreatScope."""

import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from api.websocket import (
    router as websocket_router,
    notify_step_started,
    notify_step_completed,
    notify_task_started,
    notify_task_completed,
)
from core import (
    AnalysisCoordinator,
    ScheduledCoordinator,
    SchedulerConfig,
    TaskStatus,
    TaskProgress,
)
from core.database import get_database, TaskDatabase

_coordinator: AnalysisCoordinator | None = None
_scheduled_coordinator: ScheduledCoordinator | None = None


def get_db() -> TaskDatabase:
    """Get database instance."""
    return get_database()

def get_coordinator() -> AnalysisCoordinator:
    global _coordinator
    if _coordinator is None:
        _coordinator = AnalysisCoordinator()
    return _coordinator


def get_scheduled_coordinator() -> ScheduledCoordinator:
    global _scheduled_coordinator, _coordinator
    if _scheduled_coordinator is None:
        coordinator = get_coordinator()
        config = SchedulerConfig(
            stage_1_4_workers=4,
            stage_6_workers=4,
            ghidra_pool_size=1,
        )
        _scheduled_coordinator = ScheduledCoordinator(coordinator, config)
    return _scheduled_coordinator


class AnalysisOptions(BaseModel):
    enable_ghidra: bool = True
    enable_dynamic: bool = True
    enable_threat_intel: bool = True


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str | None = None


class AnalysisResponse(BaseModel):
    task_id: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None


class BatchSubmitRequest(BaseModel):
    file_paths: list[str]
    options: AnalysisOptions | None = None


class BatchSubmitResponse(BaseModel):
    task_ids: list[str]
    message: str


class QueueStatsResponse(BaseModel):
    pending: int
    ghidra_waiting: int
    report_waiting: int
    total_tasks: int
    completed: int
    failed: int


app = FastAPI(
    title="ThreatScope API",
    description="AI-driven malware analysis framework",
    version="0.2.0",
)

# CORS middleware - allow frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register WebSocket router
app.include_router(websocket_router)

@app.on_event("startup")
async def startup_event():
    scheduler = get_scheduled_coordinator()
    await scheduler.start()


@app.on_event("shutdown")
async def shutdown_event():
    if _scheduled_coordinator:
        await _scheduled_coordinator.stop()


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/analyze", response_model=TaskResponse)
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_dynamic: bool = True,
    enable_threat_intel: bool = True,
):
    task_id = str(uuid.uuid4())[:8]

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    # Save to database
    db = get_db()
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

    background_tasks.add_task(
        run_analysis_task,
        task_id,
        file_path,
        enable_ghidra,
        enable_dynamic,
        enable_threat_intel,
    )

    return TaskResponse(
        task_id=task_id,
        status=TaskStatus.PENDING.value,
        message="Analysis started",
    )


async def run_analysis_task(
    task_id: str,
    file_path: Path,
    enable_ghidra: bool,
    enable_dynamic: bool,
    enable_threat_intel: bool,
):
    db = get_db()
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        # Notify task started
        await notify_task_started(task_id, str(file_path))
        logger.info(f"Task {task_id}: Starting analysis for {file_path}")
        
        # Stage 1: Static analysis
        db.update_task_status(task_id, TaskStatus.STAGE_1_4.value)
        await notify_step_started(task_id, "static", "Static Analysis (hashes, strings, ELF parsing)")
        
        coordinator = get_coordinator()
        
        # Run the full analysis pipeline
        await notify_step_started(task_id, "stage_1_4", "Running analysis pipeline...")
        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
        )
        logger.info(f"Task {task_id}: Analysis completed, result keys: {result.keys()}")
        
        # Check for errors in result
        if result.get("error"):
            raise Exception(result["error"])
        
        # Save static analysis results
        if result.get("static_analysis"):
            db.update_task_result(task_id, "stage_1_4_results", result["static_analysis"])
            await notify_step_completed(task_id, "static", "completed")
        
        # Save Ghidra results
        if result.get("ghidra_analysis"):
            db.update_task_result(task_id, "ghidra_results", result["ghidra_analysis"])
            await notify_step_completed(task_id, "ghidra", "completed")
        
        # Save report (note: coordinator returns 'report' not 'malware_report')
        if result.get("report"):
            db.update_task_result(task_id, "report", result["report"])
            await notify_step_completed(task_id, "report", "completed")
        
        await notify_step_completed(task_id, "stage_1_4", "completed")
        
        # Mark completed
        db.update_task_status(task_id, TaskStatus.COMPLETED.value)
        
        verdict = "unknown"
        if result.get("report"):
            verdict = result["report"].get("verdict", "unknown")
        
        await notify_task_completed(task_id, "completed", {"verdict": verdict})
        logger.info(f"Task {task_id}: Completed with verdict: {verdict}")

    except Exception as e:
        import traceback
        logger.error(f"Task {task_id}: Failed with error: {e}")
        logger.error(traceback.format_exc())
        db.update_task_status(task_id, TaskStatus.FAILED.value, error=str(e))
        await notify_task_completed(task_id, "failed", {"error": str(e)})

    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


@app.get("/tasks/{task_id}", response_model=AnalysisResponse)
async def get_task_status(task_id: str):
    db = get_db()
    task = db.get_task(task_id)
    
    if not task:
        # Try scheduled coordinator
        scheduled = get_scheduled_coordinator()
        task_status = scheduled.get_task_status(task_id)
        if task_status:
            return AnalysisResponse(
                task_id=task_id,
                status=task_status["status"],
                result=None,
                error=task_status.get("error"),
            )
        raise HTTPException(status_code=404, detail="Task not found")

    return AnalysisResponse(
        task_id=task_id,
        status=task["status"],
        result=task.get("result"),
        error=task.get("error"),
    )


@app.get("/tasks")
async def list_tasks():
    db = get_db()
    tasks = db.get_all_tasks(limit=100)
    stats = db.get_stats()
    
    # Map stats to expected format
    queue_stats = {
        "pending": stats.get("pending", 0),
        "ghidra_waiting": stats.get("queued", 0),
        "report_waiting": stats.get("stage_6", 0),
        "total_tasks": stats.get("total", 0),
        "completed": stats.get("completed", 0),
        "failed": stats.get("failed", 0),
    }

    return {
        "tasks": [
            {
                "id": t["id"],
                "status": t["status"],
                "file_name": t.get("file_name"),
            }
            for t in tasks
        ],
        "queue_stats": queue_stats,
    }


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    db = get_db()
    if not db.delete_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted"}


@app.post("/batch/submit", response_model=BatchSubmitResponse)
async def submit_batch(request: BatchSubmitRequest):
    scheduled = get_scheduled_coordinator()
    task_ids = await scheduled.submit_batch(request.file_paths)

    return BatchSubmitResponse(
        task_ids=task_ids,
        message=f"Submitted {len(task_ids)} tasks for analysis",
    )


@app.get("/batch/stats", response_model=QueueStatsResponse)
async def get_queue_stats():
    scheduled = get_scheduled_coordinator()
    stats = scheduled.get_queue_stats()

    return QueueStatsResponse(**stats)


@app.post("/analyze/sync", response_model=AnalysisResponse)
async def analyze_file_sync(
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_dynamic: bool = True,
    enable_threat_intel: bool = True,
):
    task_id = str(uuid.uuid4())[:8]

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    try:
        content = await file.read()
        file_path.write_bytes(content)

        coordinator = get_coordinator()
        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
        )

        return AnalysisResponse(
            task_id=task_id,
            status=TaskStatus.COMPLETED.value,
            result=result,
        )

    except Exception as e:
        return AnalysisResponse(
            task_id=task_id,
            status=TaskStatus.FAILED.value,
            error=str(e),
        )

    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


def create_app() -> FastAPI:
    return app
