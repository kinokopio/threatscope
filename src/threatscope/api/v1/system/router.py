import httpx
from fastapi import APIRouter

from src.threatscope.api.v1.system.schemas import (
    HealthResponse,
    SystemStatsResponse,
    VerdictStats,
)
from src.threatscope.core.dependencies import DatabaseDep, ScheduledCoordinatorDep

router = APIRouter(prefix="/system", tags=["system"])

GHIDRA_MCP_URL = "http://localhost:9000"


async def _check_ghidra_mcp() -> bool:
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            response = await client.get(f"{GHIDRA_MCP_URL}/sse")
            return response.status_code in (200, 405)
    except Exception:
        return False


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check API health status",
)
async def health_check() -> HealthResponse:
    ghidra_status = await _check_ghidra_mcp()
    return HealthResponse(
        status="healthy",
        version="0.2.0",
        services={
            "api": True,
            "database": True,
            "ghidra_mcp": ghidra_status,
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
