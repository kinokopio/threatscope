"""REST API for ThreatScope."""

import asyncio
from pathlib import Path
from typing import Any
import tempfile
import uuid

from fastapi import FastAPI, File, HTTPException, UploadFile, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from core import AnalysisCoordinator, AnalysisTask, TaskStatus


# Task storage (in-memory for now)
_tasks: dict[str, dict[str, Any]] = {}
_coordinator: AnalysisCoordinator | None = None


def get_coordinator() -> AnalysisCoordinator:
    """Get or create the coordinator instance."""
    global _coordinator
    if _coordinator is None:
        _coordinator = AnalysisCoordinator()
    return _coordinator


# Pydantic models
class AnalysisOptions(BaseModel):
    """Options for analysis."""
    enable_ghidra: bool = True
    enable_threat_intel: bool = True


class TaskResponse(BaseModel):
    """Response for task operations."""
    task_id: str
    status: str
    message: str | None = None


class AnalysisResponse(BaseModel):
    """Response for analysis results."""
    task_id: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None


# Create FastAPI app
app = FastAPI(
    title="ThreatScope API",
    description="AI-driven malware analysis framework",
    version="0.1.0",
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/analyze", response_model=TaskResponse)
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_threat_intel: bool = True,
):
    """Submit a file for analysis.

    Returns a task ID that can be used to check status and retrieve results.
    """
    # Generate task ID
    task_id = str(uuid.uuid4())[:8]

    # Save uploaded file
    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    # Initialize task
    _tasks[task_id] = {
        "id": task_id,
        "status": TaskStatus.PENDING.value,
        "file_path": str(file_path),
        "file_name": file.filename,
        "options": {
            "enable_ghidra": enable_ghidra,
            "enable_threat_intel": enable_threat_intel,
        },
        "result": None,
        "error": None,
    }

    # Run analysis in background
    background_tasks.add_task(
        run_analysis_task,
        task_id,
        file_path,
        enable_ghidra,
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
    enable_threat_intel: bool,
):
    """Run analysis task in background."""
    try:
        _tasks[task_id]["status"] = TaskStatus.STAGE_1_4.value

        coordinator = get_coordinator()
        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_threat_intel=enable_threat_intel,
        )

        _tasks[task_id]["status"] = TaskStatus.COMPLETED.value
        _tasks[task_id]["result"] = result

    except Exception as e:
        _tasks[task_id]["status"] = TaskStatus.FAILED.value
        _tasks[task_id]["error"] = str(e)

    finally:
        # Cleanup temp file
        try:
            file_path.unlink()
        except Exception:
            pass


@app.get("/tasks/{task_id}", response_model=AnalysisResponse)
async def get_task_status(task_id: str):
    """Get the status and results of an analysis task."""
    if task_id not in _tasks:
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
    """List all tasks."""
    return {
        "tasks": [
            {
                "id": t["id"],
                "status": t["status"],
                "file_name": t.get("file_name"),
            }
            for t in _tasks.values()
        ]
    }


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    """Delete a task and its results."""
    if task_id not in _tasks:
        raise HTTPException(status_code=404, detail="Task not found")

    del _tasks[task_id]
    return {"message": "Task deleted"}


@app.post("/analyze/sync", response_model=AnalysisResponse)
async def analyze_file_sync(
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_threat_intel: bool = True,
):
    """Submit a file for synchronous analysis.

    Waits for analysis to complete and returns results directly.
    Use for smaller files or when immediate results are needed.
    """
    # Generate task ID
    task_id = str(uuid.uuid4())[:8]

    # Save uploaded file
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
        # Cleanup temp file
        try:
            file_path.unlink()
        except Exception:
            pass


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    return app
