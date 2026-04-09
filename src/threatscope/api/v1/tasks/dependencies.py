from typing import Annotated

from fastapi import Depends, Path

from src.threatscope.api.v1.tasks.service import TaskService
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
    running_statuses = {
        "pending",
        "queued",
        "static_analysis",
        "dynamic_analysis",
        "ghidra_analysis",
        "report_generation",
    }

    if task["status"] in running_statuses:
        TaskService.cancel_task_by_id(task["id"])

    return task
