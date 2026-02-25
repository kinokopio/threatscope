"""API module - REST API and WebSocket."""

from api.rest import app, create_app

__all__ = [
    "app",
    "create_app",
]
