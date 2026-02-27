"""Shared module exports."""

from src.threatscope.shared.exceptions import (
    AIAnalysisError,
    AnalysisError,
    AnalysisTimeoutError,
    ConfigurationError,
    DynamicAnalysisError,
    FileNotFoundError,
    FileTooLargeError,
    GhidraAnalysisError,
    GhidraServiceError,
    InvalidFileError,
    MissingAPIKeyError,
    ServiceUnavailableError,
    StaticAnalysisError,
    TaskAlreadyExistsError,
    TaskNotFoundError,
    TaskQueueFullError,
    ThreatIntelServiceError,
    ThreatScopeError,
)

__all__ = [
    # Base
    "ThreatScopeError",
    # Task errors
    "TaskNotFoundError",
    "TaskAlreadyExistsError",
    "TaskQueueFullError",
    # File errors
    "FileNotFoundError",
    "InvalidFileError",
    "FileTooLargeError",
    # Analysis errors
    "AnalysisError",
    "StaticAnalysisError",
    "DynamicAnalysisError",
    "GhidraAnalysisError",
    "AIAnalysisError",
    "AnalysisTimeoutError",
    # Service errors
    "ServiceUnavailableError",
    "GhidraServiceError",
    "ThreatIntelServiceError",
    # Config errors
    "ConfigurationError",
    "MissingAPIKeyError",
]
