"""ThreatScope API module."""

from src.threatscope.api.app import app, create_app
from src.threatscope.api.mcp_server import ThreatScopeMCPServer, get_mcp_server
from src.threatscope.api.router import router
from src.threatscope.api.schemas import (
    AnalysisOptions,
    AnalysisResult,
    BatchSubmitRequest,
    BatchSubmitResponse,
    ErrorResponse,
    HealthResponse,
    QueueStats,
    TaskListResponse,
    TaskResponse,
    TaskStatus,
)

__all__ = [
    # App
    "app",
    "create_app",
    "router",
    # MCP
    "ThreatScopeMCPServer",
    "get_mcp_server",
    # Schemas
    "AnalysisOptions",
    "AnalysisResult",
    "BatchSubmitRequest",
    "BatchSubmitResponse",
    "ErrorResponse",
    "HealthResponse",
    "QueueStats",
    "TaskListResponse",
    "TaskResponse",
    "TaskStatus",
]
