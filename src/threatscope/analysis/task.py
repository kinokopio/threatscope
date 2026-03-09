"""Analysis task model and status definitions."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import uuid


class AnalysisStatus(str, Enum):
    """Analysis task status - named by actual pipeline stage."""

    PENDING = "pending"
    QUEUED = "queued"

    # Static Analysis Pipeline
    HASHING = "hashing"
    FILE_IDENTIFICATION = "file_identification"
    STATIC_ANALYSIS = "static_analysis"  # capa + strings + yara + threat_intel + dynamic
    THREAT_INTEL = "threat_intel"
    DYNAMIC_ANALYSIS = "dynamic_analysis"

    # Deep Analysis
    GHIDRA_ANALYSIS = "ghidra_analysis"

    # Report Generation
    REPORT_GENERATION = "report_generation"

    # Terminal states
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AnalysisTask:
    """Represents a malware analysis task."""

    file_path: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: AnalysisStatus = AnalysisStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    error: str | None = None
    retry_count: int = 0

    # Results from each analysis phase
    pre_ghidra_results: dict[str, Any] | None = None
    ghidra_results: dict[str, Any] | None = None
    report: dict[str, Any] | None = None

    def update_status(self, status: AnalysisStatus) -> None:
        self.status = status
        self.updated_at = datetime.now()

    def set_error(self, error: str) -> None:
        self.status = AnalysisStatus.FAILED
        self.error = error
        self.updated_at = datetime.now()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "file_path": self.file_path,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "error": self.error,
            "retry_count": self.retry_count,
            "pre_ghidra_results": self.pre_ghidra_results,
            "ghidra_results": self.ghidra_results,
            "report": self.report,
        }
