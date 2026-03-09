"""Base schemas for API responses.

This module provides common response structures used across all API endpoints.
"""

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Error detail structure."""

    code: str = Field(description="Error code")
    message: str = Field(description="Human-readable error message")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional error details")


class APIResponse(BaseModel, Generic[T]):
    """Generic API response wrapper.

    Provides consistent response structure across all endpoints.
    """

    success: bool = Field(default=True, description="Whether the request succeeded")
    data: T | None = Field(default=None, description="Response data")
    error: ErrorDetail | None = Field(default=None, description="Error details if failed")
    timestamp: datetime = Field(default_factory=datetime.now, description="Response timestamp")

    model_config = {
        "json_schema_extra": {
            "example": {"success": True, "data": {}, "timestamp": "2024-03-05T10:00:00"}
        }
    }
