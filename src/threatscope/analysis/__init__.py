"""ThreatScope analysis module."""

from src.threatscope.analysis.coordinator import AnalysisCoordinator
from src.threatscope.analysis.task import AnalysisStatus, AnalysisTask

# TaskRepository is intentionally NOT eagerly imported here to avoid a
# circular import:  repository → api.schemas → api.__init__ → api.app
# (module-level create_app()) → mcp_server → repository.
# Import TaskRepository directly where needed:
#   from src.threatscope.analysis.repository import TaskRepository
def __getattr__(name: str):  # noqa: N807  (module-level __getattr__)
    if name == "TaskRepository":
        from src.threatscope.analysis.repository import TaskRepository
        return TaskRepository
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AnalysisCoordinator",
    "AnalysisStatus",
    "AnalysisTask",
    "TaskRepository",
]
