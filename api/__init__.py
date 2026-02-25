"""API module - REST API, WebSocket, and MCP Server."""

from api.rest import app, create_app
from api.mcp_server import ThreatScopeMCPServer, get_mcp_server
from api.websocket import (
    ConnectionManager,
    ProgressMessage,
    get_connection_manager,
    notify_error,
    notify_step_completed,
    notify_step_started,
    notify_task_completed,
    notify_task_started,
    router as websocket_router,
)

__all__ = [
    "app",
    "create_app",
    "ThreatScopeMCPServer",
    "get_mcp_server",
    "websocket_router",
    "ConnectionManager",
    "ProgressMessage",
    "get_connection_manager",
    "notify_task_started",
    "notify_step_started",
    "notify_step_completed",
    "notify_task_completed",
    "notify_error",
]
