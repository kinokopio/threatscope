"""Task model for analysis jobs."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class TaskStatus(Enum):
    """Task status states."""
    PENDING = "pending"
    STAGE_1_4 = "stage_1_4"  # Static + Threat Intel + Dynamic
    QUEUED = "queued"        # Waiting for Ghidra instance
    STAGE_5 = "stage_5"      # Ghidra analysis
    STAGE_6 = "stage_6"      # Report generation
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AnalysisTask:
    """Analysis task representing a single sample analysis job."""

    file_path: str
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Stage results
    stage_1_4_results: dict[str, Any] | None = None
    ghidra_results: dict[str, Any] | None = None
    report: dict[str, Any] | None = None

    # Error tracking
    error: str | None = None
    retry_count: int = 0

    def update_status(self, status: TaskStatus) -> None:
        """Update task status and timestamp."""
        self.status = status
        self.updated_at = datetime.now()

    def set_error(self, error: str) -> None:
        """Set error and mark as failed."""
        self.error = error
        self.status = TaskStatus.FAILED
        self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        """Convert task to dictionary."""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "error": self.error,
            "retry_count": self.retry_count,
            "has_results": {
                "stage_1_4": self.stage_1_4_results is not None,
                "ghidra": self.ghidra_results is not None,
                "report": self.report is not None,
            },
        }
