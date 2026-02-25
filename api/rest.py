"""REST API for ThreatScope."""

import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core import (
    AnalysisCoordinator,
    ScheduledCoordinator,
    SchedulerConfig,
    TaskStatus,
)

_tasks: dict[str, dict[str, Any]] = {}
_coordinator: AnalysisCoordinator | None = None
_scheduled_coordinator: ScheduledCoordinator | None = None


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

    _tasks[task_id] = {
        "id": task_id,
        "status": TaskStatus.PENDING.value,
        "file_path": str(file_path),
        "file_name": file.filename,
        "options": {
            "enable_ghidra": enable_ghidra,
            "enable_dynamic": enable_dynamic,
            "enable_threat_intel": enable_threat_intel,
        },
        "result": None,
        "error": None,
    }

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
    try:
        _tasks[task_id]["status"] = TaskStatus.STAGE_1_4.value

        coordinator = get_coordinator()
        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
        )

        _tasks[task_id]["status"] = TaskStatus.COMPLETED.value
        _tasks[task_id]["result"] = result

    except Exception as e:
        _tasks[task_id]["status"] = TaskStatus.FAILED.value
        _tasks[task_id]["error"] = str(e)

    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


@app.get("/tasks/{task_id}", response_model=AnalysisResponse)
async def get_task_status(task_id: str):
    if task_id not in _tasks:
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

    task = _tasks[task_id]
    return AnalysisResponse(
        task_id=task_id,
        status=task["status"],
        result=task.get("result"),
        error=task.get("error"),
    )


@app.get("/tasks")
async def list_tasks():
    scheduled = get_scheduled_coordinator()
    queue_stats = scheduled.get_queue_stats()

    return {
        "tasks": [
            {
                "id": t["id"],
                "status": t["status"],
                "file_name": t.get("file_name"),
            }
            for t in _tasks.values()
        ],
        "queue_stats": queue_stats,
    }


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    if task_id not in _tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    del _tasks[task_id]
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
