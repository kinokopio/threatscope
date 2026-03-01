"""API request/response schemas using Pydantic v2.

This module defines all API schemas with proper validation,
following the pattern of separating input and output schemas.
"""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# =============================================================================
# Enums
# =============================================================================


class TaskStatus(str, Enum):
    """Task status enumeration."""

    PENDING = "pending"
    QUEUED = "queued"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    GHIDRA_ANALYSIS = "ghidra_analysis"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"


# =============================================================================
# Analysis Options
# =============================================================================


class AnalysisOptions(BaseModel):
    """Options for analysis request."""

    enable_ghidra: bool = Field(default=True, description="Enable Ghidra deep analysis")
    enable_dynamic: bool = Field(default=True, description="Enable dynamic analysis")
    enable_threat_intel: bool = Field(default=True, description="Enable threat intel queries")


# =============================================================================
# Task Schemas
# =============================================================================


class TaskCreate(BaseModel):
    """Schema for creating a new task (internal use)."""

    file_path: str
    file_name: str | None = None
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)


class TaskResponse(BaseModel):
    """Response schema for task creation."""

    task_id: str = Field(description="Unique task identifier")
    status: TaskStatus = Field(description="Current task status")
    message: str | None = Field(default=None, description="Status message")

    model_config = ConfigDict(from_attributes=True)


class TaskDetail(BaseModel):
    """Detailed task information."""

    id: str = Field(alias="task_id")
    status: TaskStatus
    file_name: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    error: str | None = None
    result: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TaskListItem(BaseModel):
    """Task item for list responses."""

    id: str
    status: TaskStatus
    file_name: str | None = None
    result_summary: dict[str, Any] | None = None

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Analysis Result Schemas
# =============================================================================


class HashesResult(BaseModel):
    """Hash calculation results."""

    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    ssdeep: str | None = None


class StringsResult(BaseModel):
    """String extraction results."""

    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    suspicious: list[str] = Field(default_factory=list)


class FileTypeResult(BaseModel):
    """File type identification results from diec."""

    format: str = Field(default="", description="File format (PE32, ELF64, etc.)")
    arch: str = Field(default="", description="Architecture (x86, x64, ARM)")
    category: str = Field(default="unknown", description="Category (pe, elf, script:python, unknown)")
    platform: str = Field(default="unknown", description="Platform (windows, linux, cross)")
    packers: list[dict[str, str]] = Field(default_factory=list, description="Detected packers")
    compilers: list[dict[str, str]] = Field(default_factory=list, description="Detected compilers")
    protectors: list[dict[str, str]] = Field(default_factory=list, description="Detected protectors")
    libraries: list[dict[str, str]] = Field(default_factory=list, description="Detected libraries")
    script_language: str | None = Field(default=None, description="Script language if detected")
    is_fallback: bool = Field(default=False, description="True if using fallback detection")


class AttackMappingResult(BaseModel):
    """ATT&CK mapping from capa."""

    tactics: list[str] = Field(default_factory=list)
    techniques: list[dict[str, str]] = Field(default_factory=list)


class MbcMappingResult(BaseModel):
    """MBC mapping from capa."""

    objectives: list[str] = Field(default_factory=list)
    behaviors: list[dict[str, str]] = Field(default_factory=list)


class CapaResult(BaseModel):
    """Capability detection results from capa."""

    format: str = Field(default="", description="Binary format")
    arch: str = Field(default="", description="Architecture")
    os: str = Field(default="", description="Operating system")
    capabilities: list[dict[str, Any]] = Field(default_factory=list, description="Detected capabilities")
    attack: AttackMappingResult = Field(default_factory=AttackMappingResult)
    mbc: MbcMappingResult = Field(default_factory=MbcMappingResult)
    analysis_time: float = Field(default=0.0, description="Analysis time in seconds")
    rule_count: int = Field(default=0, description="Number of rules used")
    skipped: bool = Field(default=False, description="True if analysis was skipped")
    reason: str | None = Field(default=None, description="Reason if skipped")
    error: str | None = Field(default=None, description="Error message if failed")


class ELFResult(BaseModel):
    """ELF parsing results."""

    format: str | None = None
    arch: str | None = None
    entry_point: str | None = None
    imports: list[str] = Field(default_factory=list)
    exports: list[str] = Field(default_factory=list)
    sections: list[dict[str, Any]] = Field(default_factory=list)


class YaraResult(BaseModel):
    """YARA scanning results."""

    matches: list[Any] = Field(default_factory=list)
    rule_count: int = Field(default=0, description="Number of rules loaded")
    match_count: int = Field(default=0, description="Number of matches found")
    message: str | None = Field(default=None, description="Optional status message")
class ThreatIntelResult(BaseModel):
    """Threat intelligence results."""

    hash_lookup: dict[str, Any] = Field(default_factory=dict)
    ioc_lookup: dict[str, Any] = Field(default_factory=dict)


class DynamicAnalysisResult(BaseModel):
    """Dynamic analysis results."""

    success: bool = False
    method: str | None = None
    duration_seconds: float = 0.0
    # Process information
    process_tree: list[dict[str, Any]] = Field(default_factory=list)
    # Network information
    network_summary: dict[str, Any] = Field(default_factory=dict)
    network_activity: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    # Security events
    security_events: list[dict[str, Any]] = Field(default_factory=list)
    # Syscall information
    syscall_summary: dict[str, Any] = Field(default_factory=dict)
    syscalls: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    # File activity
    file_activity: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=dict)
    # Raw data
    raw_events_count: int = 0
    event_types: list[str] = Field(default_factory=list)
    # Error handling
    error: str | None = None
    skipped: bool = False
    help: str | None = None
class GhidraAIAnalysis(BaseModel):
    """AI analysis results from Ghidra agent."""

    analyzed_functions: list[dict[str, Any]] = Field(default_factory=list)
    key_findings: list[dict[str, Any]] = Field(default_factory=list)
    malware_classification: dict[str, Any] | None = None
    call_graph: dict[str, Any] | None = None
    analysis_path: list[str] | list[dict[str, Any]] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] | None = None

    @field_validator('key_findings', mode='before')
    @classmethod
    def normalize_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ensure evidence field is always a list."""
        if not v:
            return v
        for finding in v:
            if 'evidence' in finding and not isinstance(finding['evidence'], list):
                # Convert string evidence to list
                finding['evidence'] = [finding['evidence']] if finding['evidence'] else []
        return v

class GhidraAnalysisResult(BaseModel):
    """Ghidra analysis results."""

    status: str | None = None
    ghidra_available: bool = False
    ghidra_info: dict[str, Any] | None = None
    ai_analysis: GhidraAIAnalysis | None = None
    # Fallback fields for direct access (backward compatibility)
    analyzed_functions: list[dict[str, Any]] = Field(default_factory=list)
    key_findings: list[dict[str, Any]] = Field(default_factory=list)
    # Additional fields
    cached_functions: list[str] = Field(default_factory=list)
    findings_count: int = 0
    message: str | None = None
    error: str | None = None

class MalwareReport(BaseModel):
    """Final malware analysis report."""

    verdict: str = Field(description="Malware verdict: malicious, suspicious, benign")
    confidence: float = Field(ge=0, le=1, description="Confidence score 0-1")
    family: str | None = Field(default=None, description="Malware family if identified")
    summary: str | None = Field(default=None, description="Analysis summary")
    iocs: dict[str, Any] | list[str] = Field(default_factory=dict, description="Indicators of compromise")
    mitre_techniques: list[str] = Field(default_factory=list, description="MITRE ATT&CK techniques")
    mitre_mapping: list[dict[str, Any]] = Field(default_factory=list, description="MITRE ATT&CK mapping")
    recommendations: list[str] = Field(
        default_factory=list, description="Remediation recommendations"
    )
    capabilities: list[str] = Field(default_factory=list, description="Malware capabilities")
    technical_details: dict[str, Any] = Field(default_factory=dict, description="Technical details")


class AnalysisResult(BaseModel):
    """Complete analysis result."""

    task_id: str
    status: TaskStatus
    current_step: str | None = None
    file_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    hashes: HashesResult | None = None
    file_type: FileTypeResult | None = None
    capa: CapaResult | None = None
    strings: StringsResult | None = None
    yara: YaraResult | None = None
    threat_intel: ThreatIntelResult | None = None
    dynamic_analysis: DynamicAnalysisResult | None = None
    ghidra_analysis: GhidraAnalysisResult | None = None
    malware_report: MalwareReport | None = None
    error: str | None = None

    model_config = ConfigDict(from_attributes=True)


# =============================================================================
# Batch Schemas
# =============================================================================


class BatchSubmitRequest(BaseModel):
    """Request for batch analysis submission."""

    file_paths: list[str] = Field(min_length=1, max_length=100)
    options: AnalysisOptions | None = None


class BatchSubmitResponse(BaseModel):
    """Response for batch submission."""

    task_ids: list[str]
    message: str


# =============================================================================
# Queue Stats
# =============================================================================


class QueueStats(BaseModel):
    """Queue statistics."""

    pending: int = 0
    ghidra_waiting: int = 0
    report_waiting: int = 0
    total_tasks: int = 0
    completed: int = 0
    failed: int = 0


# =============================================================================
# Task List Response
# =============================================================================


class TaskListResponse(BaseModel):
    """Response for task list endpoint."""

    tasks: list[TaskListItem]
    queue_stats: QueueStats


# =============================================================================
# Health Check
# =============================================================================


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    version: str = "0.2.0"
    services: dict[str, bool] = Field(default_factory=dict)


# =============================================================================
# Error Response
# =============================================================================


class ErrorResponse(BaseModel):
    """Standard error response."""

    error: str = Field(description="Error code")
    message: str = Field(description="Human-readable error message")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional error details")
