import tempfile
from pathlib import Path
from typing import Annotated

import aiofiles
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
    UrlCreateRequest,
)
from src.threatscope.api.v1.tasks.service import TaskService
from src.threatscope.core.dependencies import (
    CoordinatorDep,
    DatabaseDep,
    ScheduledCoordinatorDep,
)

router = APIRouter(prefix="/tasks", tags=["tasks"])

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB


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
    from fastapi import HTTPException

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{file.filename}"

    downloaded = 0
    async with aiofiles.open(file_path, "wb") as out_file:
        while chunk := await file.read(1024 * 1024):
            downloaded += len(chunk)
            if downloaded > MAX_FILE_SIZE:
                await out_file.close()
                file_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=400,
                    detail=f"File too large: exceeded {MAX_FILE_SIZE // (1024 * 1024)}MB limit",
                )
            await out_file.write(chunk)

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


@router.post(
    "/url",
    response_model=TaskResponse,
    status_code=202,
    summary="Create analysis task from URL",
    description="Download a file from URL and start asynchronous malware analysis",
)
async def create_task_from_url(
    request: UrlCreateRequest,
    service: TaskService = Depends(get_task_service),
) -> TaskResponse:
    import logging
    import uuid
    from urllib.parse import urlparse

    import httpx
    from fastapi import HTTPException

    logger = logging.getLogger(__name__)

    parsed = urlparse(request.url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are supported")

    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=120.0) as client:
            async with client.stream("GET", request.url) as response:
                response.raise_for_status()

                content_type = response.headers.get("content-type", "").split(";")[0].strip()
                non_binary_types = (
                    "text/html",
                    "text/plain",
                    "text/css",
                    "text/javascript",
                    "application/json",
                    "application/xml",
                )
                if content_type in non_binary_types:
                    raise HTTPException(
                        status_code=400,
                        detail=f"URL returned non-binary content ({content_type}), expected a downloadable file",
                    )

                content_length = response.headers.get("content-length")
                if content_length and int(content_length) > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File too large: {int(content_length)} bytes (max {MAX_FILE_SIZE})",
                    )

                file_name = _extract_filename(response, parsed.path)
                short_id = uuid.uuid4().hex[:8]
                file_path = temp_dir / f"{short_id}_{file_name}"

                downloaded = 0
                async with aiofiles.open(file_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        downloaded += len(chunk)
                        if downloaded > MAX_FILE_SIZE:
                            await f.close()
                            file_path.unlink(missing_ok=True)
                            raise HTTPException(
                                status_code=400,
                                detail=f"File too large: exceeded {MAX_FILE_SIZE} bytes",
                            )
                        await f.write(chunk)

        if not file_path.exists() or file_path.stat().st_size == 0:
            file_path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Downloaded file is empty")

        logger.info(f"Downloaded {request.url} -> {file_path} ({file_path.stat().st_size} bytes)")

    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=502, detail=f"Download failed: HTTP {e.response.status_code}"
        )
    except httpx.RequestError as e:
        raise HTTPException(status_code=502, detail=f"Download failed: {e}")

    options = request.options.model_dump()
    task_id = await service.create_task_async(
        file_path=file_path,
        file_name=file_name,
        options=options,
    )

    return TaskResponse(
        task_id=task_id,
        status=TaskStatus.PENDING,
        message=f"Downloaded and queued for analysis: {file_name}",
    )


def _extract_filename(response, url_path: str) -> str:
    cd = response.headers.get("content-disposition", "")
    if "filename=" in cd:
        for part in cd.split(";"):
            part = part.strip()
            if part.startswith("filename="):
                name = part[len("filename=") :].strip().strip('"').strip("'")
                if name:
                    return name

    name = Path(url_path).name
    if name and "." in name:
        return name

    return "downloaded_file"


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
        steps_progress = {}
        for step_id, step_data in task["steps_status"].items():
            if step_id == "ai_logs":
                steps_progress["ai_logs"] = step_data
            elif isinstance(step_data, dict):
                steps_progress[step_id] = StepProgress(**step_data)

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
    "/{task_id}/cancel",
    status_code=200,
    summary="Cancel running task",
    description="Cancel a running analysis task",
)
async def cancel_task(
    task: Annotated[dict, Depends(valid_task_id)],
    db: DatabaseDep,
    service: TaskService = Depends(get_task_service),
) -> dict:
    from fastapi import HTTPException

    running_statuses = {
        TaskStatus.PENDING.value,
        TaskStatus.QUEUED.value,
        TaskStatus.STATIC_ANALYSIS.value,
        TaskStatus.DYNAMIC_ANALYSIS.value,
        TaskStatus.GHIDRA_ANALYSIS.value,
        TaskStatus.REPORT_GENERATION.value,
    }

    if task["status"] not in running_statuses:
        raise HTTPException(
            status_code=409,
            detail=f"Task is not running (status: {task['status']})",
        )

    cancelled = service.cancel_task(task["id"])
    if not cancelled:
        # asyncio.Task 已结束但 DB 状态还是 running，直接更新 DB
        db.update_task_status(task["id"], TaskStatus.FAILED.value, error="用户取消分析")

    return {"task_id": task["id"], "status": "cancelled"}


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
