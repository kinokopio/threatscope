from fastapi import APIRouter

from src.threatscope.api.v1.skills.router import router as skills_router
from src.threatscope.api.v1.system.router import router as system_router
from src.threatscope.api.v1.tasks.router import router as tasks_router

router = APIRouter()

router.include_router(tasks_router)
router.include_router(system_router)
router.include_router(skills_router)
