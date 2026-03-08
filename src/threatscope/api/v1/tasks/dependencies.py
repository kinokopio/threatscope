from typing import Annotated

from fastapi import Depends, HTTPException, Path

from src.threatscope.api.schemas import TaskStatus
from src.threatscope.core.dependencies import DatabaseDep
from src.threatscope.shared.exceptions import TaskNotFoundError


async def valid_task_id(
    task_id: Annotated[str, Path(description="Task ID")],
    db: DatabaseDep,
) -> dict:
    task = db.get_task(task_id)
    if not task:
        raise TaskNotFoundError(task_id)
    return task


async def valid_task_for_delete(
    task: Annotated[dict, Depends(valid_task_id)],
) -> dict:
    if task["status"] in (
        TaskStatus.STATIC_ANALYSIS.value,
        TaskStatus.GHIDRA_ANALYSIS.value,
        TaskStatus.REPORT_GENERATION.value,
    ):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot delete running task: {task['id']}",
        )
    return task
