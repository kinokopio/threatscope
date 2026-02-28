"""Dependency injection container for ThreatScope.

This module provides a centralized dependency injection system using
FastAPI's Depends mechanism. It eliminates global singletons and makes
the application more testable.
"""

from typing import Annotated

from fastapi import Depends

from src.threatscope.core.config import Settings, get_settings

# =============================================================================
# Settings Dependencies
# =============================================================================


def get_app_settings() -> Settings:
    """Get application settings.

    This is the primary way to access settings throughout the application.
    The settings are cached after first load.

    Returns:
        Application settings instance.
    """
    return get_settings()


# Type alias for dependency injection
SettingsDep = Annotated[Settings, Depends(get_app_settings)]


# =============================================================================
# Database Dependencies
# =============================================================================


class TaskDatabase:
    """Task database - will be imported from actual implementation."""

    pass


_db_instance: TaskDatabase | None = None


def get_database(settings: SettingsDep) -> TaskDatabase:
    """Get database instance.

    Args:
        settings: Application settings (injected).

    Returns:
        TaskDatabase instance.
    """
    global _db_instance
    if _db_instance is None:
        # Import here to avoid circular imports
        from src.threatscope.analysis.repository import TaskRepository

        _db_instance = TaskRepository(settings.database.path)
    return _db_instance


DatabaseDep = Annotated[TaskDatabase, Depends(get_database)]


# =============================================================================
# Service Dependencies
# =============================================================================


class AnalysisCoordinator:
    """Analysis coordinator - will be imported from actual implementation."""

    pass


_coordinator_instance: AnalysisCoordinator | None = None
_ghidra_pool = None  # Set by app lifespan


def set_ghidra_pool(pool) -> None:
    """Set the Ghidra pool instance (called from app lifespan)."""
    global _ghidra_pool
    _ghidra_pool = pool


def get_coordinator(settings: SettingsDep) -> AnalysisCoordinator:
    """Get analysis coordinator instance.

    Args:
        settings: Application settings (injected).

    Returns:
        AnalysisCoordinator instance.
    """
    import logging
    from pathlib import Path

    logger = logging.getLogger(__name__)

    global _coordinator_instance
    if _coordinator_instance is None:
        # Import here to avoid circular imports
        from src.threatscope.analysis.coordinator import AnalysisCoordinator as Coordinator

        # Try to find project root by looking for pyproject.toml
        project_dir = Path.cwd()
        for parent in [Path(__file__).parent] + list(Path(__file__).parents):
            if (parent / "pyproject.toml").exists():
                project_dir = parent
                break

        logger.info(f"Initializing AnalysisCoordinator with project_dir={project_dir}")

        try:
            _coordinator_instance = Coordinator(
                settings,
                project_dir=project_dir,
                ghidra_pool=_ghidra_pool,
            )
            logger.info("AnalysisCoordinator initialized successfully")
        except Exception as e:
            logger.exception(f"Failed to initialize AnalysisCoordinator: {e}")
            raise

    return _coordinator_instance


CoordinatorDep = Annotated[AnalysisCoordinator, Depends(get_coordinator)]


class ScheduledCoordinator:
    """Scheduled coordinator - will be imported from actual implementation."""

    pass


_scheduled_coordinator_instance: ScheduledCoordinator | None = None


def get_scheduled_coordinator(
    settings: SettingsDep,
    coordinator: CoordinatorDep,
) -> ScheduledCoordinator:
    """Get scheduled coordinator instance.

    Args:
        settings: Application settings (injected).
        coordinator: Analysis coordinator (injected).

    Returns:
        ScheduledCoordinator instance.
    """
    global _scheduled_coordinator_instance
    if _scheduled_coordinator_instance is None:
        # Import here to avoid circular imports
        from src.threatscope.analysis.scheduler import (
            ScheduledCoordinator as Scheduler,
        )
        from src.threatscope.analysis.scheduler import (
            SchedulerConfig,
        )

        config = SchedulerConfig(
            stage_1_4_workers=settings.workers.stage_1_4,
            stage_6_workers=settings.workers.stage_6,
            ghidra_pool_size=settings.ghidra.pool_size,
        )
        _scheduled_coordinator_instance = Scheduler(coordinator, config)
    return _scheduled_coordinator_instance


ScheduledCoordinatorDep = Annotated[ScheduledCoordinator, Depends(get_scheduled_coordinator)]


# =============================================================================
# Cleanup Functions
# =============================================================================


def reset_dependencies() -> None:
    """Reset all cached dependencies.

    This is useful for testing to ensure a clean state between tests.
    """
    global _db_instance, _coordinator_instance, _scheduled_coordinator_instance

    _db_instance = None
    _coordinator_instance = None
    _scheduled_coordinator_instance = None

    # Clear settings cache
    get_settings.cache_clear()


async def shutdown_dependencies() -> None:
    """Shutdown all dependencies gracefully.

    This should be called during application shutdown.
    """
    global _scheduled_coordinator_instance

    if _scheduled_coordinator_instance is not None:
        # Stop scheduler if it has a stop method
        if hasattr(_scheduled_coordinator_instance, "stop"):
            await _scheduled_coordinator_instance.stop()

    reset_dependencies()
