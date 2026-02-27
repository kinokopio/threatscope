"""ThreatScope core module."""

from src.threatscope.core.config import Settings, get_settings, load_from_yaml
from src.threatscope.core.dependencies import (
    CoordinatorDep,
    DatabaseDep,
    ScheduledCoordinatorDep,
    SettingsDep,
    get_coordinator,
    get_database,
    get_scheduled_coordinator,
    reset_dependencies,
    shutdown_dependencies,
)

__all__ = [
    # Config
    "Settings",
    "get_settings",
    "load_from_yaml",
    # Dependencies
    "SettingsDep",
    "DatabaseDep",
    "CoordinatorDep",
    "ScheduledCoordinatorDep",
    "get_coordinator",
    "get_database",
    "get_scheduled_coordinator",
    "reset_dependencies",
    "shutdown_dependencies",
]
