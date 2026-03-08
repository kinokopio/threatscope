import tempfile
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile

from src.threatscope.api.schemas import TaskStatus
from src.threatscope.api.shared.schemas import PaginatedResponse
from src.threatscope.api.v1.tasks.dependencies import valid_task_for_delete, valid_task_id
from src.threatscope.api.v1.tasks.schemas import (
    BatchCreateRequest,
    BatchCreateResponse,
    QueueStats,
    StepProgress,
    TaskDetailResponse,
    TaskListItem,
    TaskResponse,
)
from src.threatscope.api.v1.tasks.service import TaskService
from src.threatscope.core.dependencies import (
    CoordinatorDep,
    DatabaseDep,
    ScheduledCoordinatorDep,
)

router = APIRouter(prefix="/tasks", tags=["tasks"])


def get_task_service(
    coordinator: CoordinatorDep,
    db: DatabaseDep,
) -> TaskService:
    return TaskService(coordinator, db)


@router.post(
    "",
    response_model=TaskResponse,
    status_code=202,
    summary="Create analysis task (async)",
    description="Upload a file and start asynchronous malware analysis",
)
async def create_task(
    file: UploadFile = File(..., description="File to analyze"),
    enable_ghidra: bool = Form(default=True, description="Enable Ghidra analysis"),
    enable_dynamic: bool = Form(default=True, description="Enable dynamic analysis"),
    enable_threat_intel: bool = Form(default=True, description="Enable threat intel"),
    enable_capa: bool = Form(default=True, description="Enable CAPA capability analysis"),
    enable_strings: bool = Form(default=True, description="Enable string extraction"),
    enable_yara: bool = Form(default=True, description="Enable YARA scanning"),
    service: TaskService = Depends(get_task_service),
) -> TaskResponse:
    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)

    task_id = await service.create_task_async(
        file_path=file_path,
        file_name=file.filename or "unknown",
        options={
            "enable_ghidra": enable_ghidra,
            "enable_dynamic": enable_dynamic,
            "enable_threat_intel": enable_threat_intel,
            "enable_capa": enable_capa,
            "enable_strings": enable_strings,
            "enable_yara": enable_yara,
        },
    )

    return TaskResponse(
        task_id=task_id,
        status=TaskStatus.PENDING,
        message="Analysis task created",
    )


@router.get(
    "/{task_id}",
    response_model=TaskDetailResponse,
    summary="Get task details",
    description="Get task status and analysis results",
)
async def get_task(
    task: Annotated[dict, Depends(valid_task_id)],
) -> TaskDetailResponse:
    steps_progress = None
    if task.get("steps_status"):
        steps_progress = {
            step_id: StepProgress(**step_data)
            for step_id, step_data in task["steps_status"].items()
        }

    return TaskDetailResponse(
        task_id=task["id"],
        status=TaskStatus(task["status"]),
        file_name=task.get("file_name"),
        current_step=task.get("current_step"),
        error=task.get("error"),
        steps_progress=steps_progress,
        hashes=task.get("hashes"),
        file_type=task.get("file_type"),
        capa=task.get("capa"),
        strings=task.get("strings"),
        yara=task.get("yara"),
        threat_intel=task.get("threat_intel"),
        dynamic_analysis=task.get("dynamic_analysis"),
        ghidra_analysis=task.get("ghidra_analysis"),
        unified_report=task.get("unified_report"),
    )


@router.get(
    "/{task_id}/export",
    summary="Export task results",
    description="Export task analysis results as JSON",
)
async def export_task(
    task: Annotated[dict, Depends(valid_task_id)],
):
    from fastapi.responses import JSONResponse

    export_data = {
        "task_id": task["id"],
        "status": task["status"],
        "file_name": task.get("file_name"),
        "created_at": task.get("created_at"),
        "hashes": task.get("hashes"),
        "file_type": task.get("file_type"),
        "capa": task.get("capa"),
        "strings": task.get("strings"),
        "yara": task.get("yara"),
        "threat_intel": task.get("threat_intel"),
        "dynamic_analysis": task.get("dynamic_analysis"),
        "ghidra_analysis": task.get("ghidra_analysis"),
        "unified_report": task.get("unified_report"),
    }

    filename = f"threatscope-{task['id'][:8]}.json"
    return JSONResponse(
        content=export_data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get(
    "",
    response_model=PaginatedResponse[TaskListItem],
    summary="List all tasks",
    description="Get paginated list of analysis tasks",
)
async def list_tasks(
    db: DatabaseDep,
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status: TaskStatus | None = Query(default=None, description="Filter by status"),
    verdict: str | None = Query(
        default=None, description="Filter by verdict (malicious/suspicious/benign)"
    ),
    file_type: str | None = Query(default=None, description="Filter by file type (pe/elf/macho)"),
    from_date: str | None = Query(default=None, description="Filter from date (YYYY-MM-DD)"),
    to_date: str | None = Query(default=None, description="Filter to date (YYYY-MM-DD)"),
    search: str | None = Query(default=None, description="Search in file name, hash, or family"),
) -> PaginatedResponse[TaskListItem]:
    offset = (page - 1) * page_size
    tasks = db.get_all_tasks(
        limit=page_size,
        offset=offset,
        status=status.value if status else None,
        verdict=verdict,
        file_type=file_type,
        from_date=from_date,
        to_date=to_date,
        search=search,
    )

    stats = db.get_stats()
    total = stats.get("total", 0)

    items = [
        TaskListItem(
            id=t["id"],
            status=TaskStatus(t["status"]),
            file_name=t.get("file_name"),
            created_at=t.get("created_at"),
            file_type=_extract_file_type(t),
            result_summary=_extract_result_summary(t),
        )
        for t in tasks
    ]

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.delete(
    "/{task_id}",
    status_code=204,
    summary="Delete task",
    description="Delete an analysis task and its results",
)
async def delete_task(
    task: Annotated[dict, Depends(valid_task_for_delete)],
    db: DatabaseDep,
) -> None:
    db.delete_task(task["id"])


@router.post(
    "/{task_id}/reanalyze",
    response_model=TaskResponse,
    status_code=202,
    summary="Reanalyze task",
    description="Create a new analysis task using the same file",
)
async def reanalyze_task(
    task: Annotated[dict, Depends(valid_task_id)],
    service: TaskService = Depends(get_task_service),
) -> TaskResponse:
    from fastapi import HTTPException

    file_path = Path(task.get("file_path", ""))
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Original file no longer exists")

    options = task.get("options", {})
    new_task_id = await service.create_task_async(
        file_path=file_path,
        file_name=task.get("file_name", "unknown"),
        options=options,
    )

    return TaskResponse(
        task_id=new_task_id,
        status=TaskStatus.PENDING,
        message="Reanalysis task created",
    )


@router.post(
    "/batch",
    response_model=BatchCreateResponse,
    summary="Batch create tasks",
    description="Submit multiple files for analysis",
)
async def create_batch(
    request: BatchCreateRequest,
    scheduled: ScheduledCoordinatorDep,
) -> BatchCreateResponse:
    task_ids = await scheduled.submit_batch(request.file_paths)

    return BatchCreateResponse(
        task_ids=task_ids,
        total=len(task_ids),
        message=f"Submitted {len(task_ids)} tasks for analysis",
    )


@router.get(
    "/stats/queue",
    response_model=QueueStats,
    summary="Get queue statistics",
    description="Get current queue statistics",
)
async def get_queue_stats(scheduled: ScheduledCoordinatorDep) -> QueueStats:
    stats = scheduled.get_queue_stats()
    return QueueStats(**stats)


def _extract_file_type(task: dict) -> str | None:
    file_type = task.get("file_type")
    if not file_type or not isinstance(file_type, dict):
        return None
    return file_type.get("format") or file_type.get("category")


def _extract_result_summary(task: dict) -> dict[str, str | float | None] | None:
    unified_report = task.get("unified_report")
    if not unified_report or not isinstance(unified_report, dict):
        return None

    return {
        "verdict": unified_report.get("verdict"),
        "confidence": unified_report.get("confidence"),
        "severity": unified_report.get("severity"),
        "family": unified_report.get("family"),
    }
