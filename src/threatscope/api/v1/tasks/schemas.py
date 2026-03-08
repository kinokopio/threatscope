from enum import Enum

from pydantic import BaseModel, Field

from src.threatscope.api.schemas import TaskStatus
from src.threatscope.api.shared.schemas import (
    CapaResult,
    DynamicAnalysisResult,
    FileTypeResult,
    GhidraAnalysisResult,
    HashesResult,
    StringsResult,
    ThreatIntelResult,
    UnifiedReportSchema,
    YaraResult,
)


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class StepProgress(BaseModel):
    status: StepStatus
    updated_at: str | None = None
    preview: dict | None = None


class AILogEntry(BaseModel):
    step_id: str
    status: str
    updated_at: str
    preview: dict | None = None


class TaskCreateOptions(BaseModel):
    enable_ghidra: bool = Field(default=True, description="Enable Ghidra deep analysis")
    enable_dynamic: bool = Field(default=True, description="Enable dynamic analysis")
    enable_threat_intel: bool = Field(default=True, description="Enable threat intel queries")
    enable_capa: bool = Field(default=True, description="Enable CAPA capability analysis")
    enable_strings: bool = Field(default=True, description="Enable string extraction")
    enable_yara: bool = Field(default=True, description="Enable YARA scanning")


class TaskResponse(BaseModel):
    task_id: str
    status: TaskStatus
    message: str | None = None


class TaskListItem(BaseModel):
    id: str
    status: TaskStatus
    file_name: str | None
    created_at: str | None = None
    file_type: str | None = None
    result_summary: dict[str, str | float | None] | None = None


class TaskDetailResponse(BaseModel):
    task_id: str
    status: TaskStatus
    file_name: str | None
    current_step: str | None
    error: str | None
    steps_progress: dict[str, StepProgress | list[AILogEntry]] | None = None
    hashes: HashesResult | None = None
    file_type: FileTypeResult | None = None
    capa: CapaResult | None = None
    strings: StringsResult | None = None
    yara: YaraResult | None = None
    threat_intel: ThreatIntelResult | None = None
    dynamic_analysis: DynamicAnalysisResult | None = None
    ghidra_analysis: GhidraAnalysisResult | None = None
    unified_report: UnifiedReportSchema | None = None


class BatchCreateRequest(BaseModel):
    file_paths: list[str] = Field(min_length=1, max_length=100)
    options: TaskCreateOptions = Field(default_factory=TaskCreateOptions)


class BatchCreateResponse(BaseModel):
    task_ids: list[str]
    total: int
    message: str


class QueueStats(BaseModel):
    pending: int = 0
    ghidra_waiting: int = 0
    report_waiting: int = 0
    total_tasks: int = 0
    completed: int = 0
    failed: int = 0
