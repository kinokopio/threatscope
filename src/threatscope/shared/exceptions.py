"""Shared exceptions for ThreatScope.

This module provides a consistent exception hierarchy for the application.
All exceptions inherit from ThreatScopeError and include error codes for
API responses.
"""

from typing import Any


class ThreatScopeError(Exception):
    """Base exception for all ThreatScope errors.

    Attributes:
        message: Human-readable error message.
        error_code: Machine-readable error code for API responses.
        status_code: HTTP status code for API responses.
        details: Additional error details.
    """

    def __init__(
        self,
        message: str,
        error_code: str = "INTERNAL_ERROR",
        status_code: int = 500,
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        """Convert exception to API response format."""
        return {
            "error": self.error_code,
            "message": self.message,
            "details": self.details,
        }


# =============================================================================
# Task Errors (400-499)
# =============================================================================


class TaskNotFoundError(ThreatScopeError):
    """Task with given ID was not found."""

    def __init__(self, task_id: str):
        super().__init__(
            message=f"Task not found: {task_id}",
            error_code="TASK_NOT_FOUND",
            status_code=404,
            details={"task_id": task_id},
        )


class TaskAlreadyExistsError(ThreatScopeError):
    """Task with given ID already exists."""

    def __init__(self, task_id: str):
        super().__init__(
            message=f"Task already exists: {task_id}",
            error_code="TASK_ALREADY_EXISTS",
            status_code=409,
            details={"task_id": task_id},
        )


class TaskQueueFullError(ThreatScopeError):
    """Task queue is at capacity."""

    def __init__(self, max_size: int):
        super().__init__(
            message=f"Task queue is full (max: {max_size})",
            error_code="QUEUE_FULL",
            status_code=503,
            details={"max_queue_size": max_size},
        )


# =============================================================================
# File Errors (400-499)
# =============================================================================


class FileNotFoundError(ThreatScopeError):
    """File was not found at the specified path."""

    def __init__(self, file_path: str):
        super().__init__(
            message=f"File not found: {file_path}",
            error_code="FILE_NOT_FOUND",
            status_code=404,
            details={"file_path": file_path},
        )


class InvalidFileError(ThreatScopeError):
    """File is invalid or unsupported."""

    def __init__(self, file_path: str, reason: str):
        super().__init__(
            message=f"Invalid file: {reason}",
            error_code="INVALID_FILE",
            status_code=400,
            details={"file_path": file_path, "reason": reason},
        )


class FileTooLargeError(ThreatScopeError):
    """File exceeds maximum allowed size."""

    def __init__(self, file_size: int, max_size: int):
        super().__init__(
            message=f"File too large: {file_size} bytes (max: {max_size})",
            error_code="FILE_TOO_LARGE",
            status_code=413,
            details={"file_size": file_size, "max_size": max_size},
        )


# =============================================================================
# Analysis Errors (500-599)
# =============================================================================


class AnalysisError(ThreatScopeError):
    """Base class for analysis-related errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "ANALYSIS_ERROR",
        stage: str | None = None,
        details: dict[str, Any] | None = None,
    ):
        details = details or {}
        if stage:
            details["stage"] = stage
        super().__init__(
            message=message,
            error_code=error_code,
            status_code=500,
            details=details,
        )


class StaticAnalysisError(AnalysisError):
    """Error during static analysis."""

    def __init__(self, message: str, tool: str | None = None):
        super().__init__(
            message=message,
            error_code="STATIC_ANALYSIS_ERROR",
            stage="static",
            details={"tool": tool} if tool else None,
        )


class DynamicAnalysisError(AnalysisError):
    """Error during dynamic analysis."""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_code="DYNAMIC_ANALYSIS_ERROR",
            stage="dynamic",
        )


class GhidraAnalysisError(AnalysisError):
    """Error during Ghidra analysis."""

    def __init__(self, message: str):
        super().__init__(
            message=message,
            error_code="GHIDRA_ANALYSIS_ERROR",
            stage="ghidra",
        )


class AIAnalysisError(AnalysisError):
    """Error during AI-driven analysis."""

    def __init__(self, message: str, agent: str | None = None):
        super().__init__(
            message=message,
            error_code="AI_ANALYSIS_ERROR",
            stage="ai",
            details={"agent": agent} if agent else None,
        )


class AnalysisTimeoutError(AnalysisError):
    """Analysis exceeded timeout."""

    def __init__(self, stage: str, timeout: int):
        super().__init__(
            message=f"Analysis timed out after {timeout}s",
            error_code="ANALYSIS_TIMEOUT",
            stage=stage,
            details={"timeout_seconds": timeout},
        )


# =============================================================================
# Service Errors (500-599)
# =============================================================================


class ServiceUnavailableError(ThreatScopeError):
    """External service is unavailable."""

    def __init__(self, service: str, reason: str | None = None):
        message = f"Service unavailable: {service}"
        if reason:
            message += f" ({reason})"
        super().__init__(
            message=message,
            error_code="SERVICE_UNAVAILABLE",
            status_code=503,
            details={"service": service, "reason": reason},
        )


class GhidraServiceError(ServiceUnavailableError):
    """Ghidra service is unavailable."""

    def __init__(self, reason: str | None = None):
        super().__init__(service="ghidra", reason=reason)


class ThreatIntelServiceError(ServiceUnavailableError):
    """Threat intelligence service is unavailable."""

    def __init__(self, source: str, reason: str | None = None):
        super().__init__(service=f"threat_intel:{source}", reason=reason)


# =============================================================================
# Configuration Errors
# =============================================================================


class ConfigurationError(ThreatScopeError):
    """Configuration is invalid or missing."""

    def __init__(self, message: str, config_key: str | None = None):
        super().__init__(
            message=message,
            error_code="CONFIGURATION_ERROR",
            status_code=500,
            details={"config_key": config_key} if config_key else None,
        )


class MissingAPIKeyError(ConfigurationError):
    """Required API key is not configured."""

    def __init__(self, key_name: str):
        super().__init__(
            message=f"Missing required API key: {key_name}",
            config_key=key_name,
        )
