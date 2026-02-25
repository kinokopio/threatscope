"""API module - REST API and MCP Server."""

from api.rest import app, create_app
from api.mcp_server import ThreatScopeMCPServer, get_mcp_server

__all__ = [
    "app",
    "create_app",
    "ThreatScopeMCPServer",
    "get_mcp_server",
]
