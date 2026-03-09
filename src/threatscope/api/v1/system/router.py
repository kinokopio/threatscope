import httpx
from fastapi import APIRouter

from src.threatscope.api.v1.system.schemas import (
    HealthResponse,
    SystemStatsResponse,
    VerdictStats,
)
from src.threatscope.core.config import get_settings
from src.threatscope.core.dependencies import DatabaseDep, ScheduledCoordinatorDep

router = APIRouter(prefix="/system", tags=["system"])


import logging

logger = logging.getLogger(__name__)


async def _check_service(url: str, path: str = "/health") -> bool:
    full_url = f"{url}{path}"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(full_url)
            return response.status_code in (200, 405)
    except Exception as e:
        logger.debug(f"Health check failed for {full_url}: {e}")
        return False


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check API health status",
)
async def health_check() -> HealthResponse:
    settings = get_settings()

    ghidra_url = settings.ghidra.base_url
    diec_url = settings.diec.url

    ghidra_status = await _check_service(ghidra_url, "/health")
    diec_status = await _check_service(diec_url, "/health")

    gdb_status = False
    gdb_enabled = settings.gdb.enabled
    if gdb_enabled and settings.gdb.service_mode in ("http", "sse"):
        gdb_url = settings.gdb.mcp_url.rstrip("/sse").rstrip("/mcp")
        gdb_status = await _check_service(gdb_url, "/health")

    return HealthResponse(
        status="healthy",
        version="0.2.0",
        services={
            "api": True,
            "database": True,
            "ghidra_mcp": ghidra_status,
            "diec": diec_status,
            "gdb": gdb_status if gdb_enabled else False,
        },
    )


@router.get(
    "/stats",
    response_model=SystemStatsResponse,
    summary="System statistics",
    description="Get system-wide statistics",
)
async def get_system_stats(
    db: DatabaseDep,
    scheduled: ScheduledCoordinatorDep,
) -> SystemStatsResponse:
    db_stats = db.get_stats()
    verdict_data = db_stats.pop("verdict_stats", {})
    return SystemStatsResponse(
        queue_stats=scheduled.get_queue_stats(),
        database_stats=db_stats,
        verdict_stats=VerdictStats(**verdict_data),
    )
