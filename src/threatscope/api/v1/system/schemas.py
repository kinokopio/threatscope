from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.2.0"
    services: dict[str, bool] = Field(default_factory=dict)


class VerdictStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    benign: int = 0


class SystemStatsResponse(BaseModel):
    queue_stats: dict[str, int] = Field(default_factory=dict)
    database_stats: dict[str, Any] = Field(default_factory=dict)
    verdict_stats: VerdictStats = Field(default_factory=VerdictStats)
