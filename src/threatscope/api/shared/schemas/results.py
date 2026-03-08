from typing import Any

from pydantic import BaseModel, Field, field_validator


class HashesResult(BaseModel):
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    ssdeep: str | None = None


class StringsResult(BaseModel):
    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    suspicious: list[str] = Field(default_factory=list)


class FileTypeResult(BaseModel):
    format: str = Field(default="", description="File format (PE32, ELF64, etc.)")
    arch: str = Field(default="", description="Architecture (x86, x64, ARM)")
    category: str = Field(
        default="unknown", description="Category (pe, elf, script:python, unknown)"
    )
    platform: str = Field(default="unknown", description="Platform (windows, linux, cross)")
    packers: list[dict[str, str]] = Field(default_factory=list, description="Detected packers")
    compilers: list[dict[str, str]] = Field(default_factory=list, description="Detected compilers")
    protectors: list[dict[str, str]] = Field(
        default_factory=list, description="Detected protectors"
    )
    libraries: list[dict[str, str]] = Field(default_factory=list, description="Detected libraries")
    script_language: str | None = Field(default=None, description="Script language if detected")
    is_fallback: bool = Field(default=False, description="True if using fallback detection")


class AttackMappingResult(BaseModel):
    tactics: list[str] = Field(default_factory=list)
    techniques: list[dict[str, str]] = Field(default_factory=list)


class MbcMappingResult(BaseModel):
    objectives: list[str] = Field(default_factory=list)
    behaviors: list[dict[str, str]] = Field(default_factory=list)


class CapaResult(BaseModel):
    format: str = Field(default="", description="Binary format")
    arch: str = Field(default="", description="Architecture")
    os: str = Field(default="", description="Operating system")
    capabilities: list[dict[str, Any]] = Field(
        default_factory=list, description="Detected capabilities"
    )
    attack: AttackMappingResult = Field(default_factory=AttackMappingResult)
    mbc: MbcMappingResult = Field(default_factory=MbcMappingResult)
    analysis_time: float = Field(default=0.0, description="Analysis time in seconds")
    rule_count: int = Field(default=0, description="Number of rules used")
    skipped: bool = Field(default=False, description="True if analysis was skipped")
    reason: str | None = Field(default=None, description="Reason if skipped")
    error: str | None = Field(default=None, description="Error message if failed")


class YaraResult(BaseModel):
    matches: list[Any] = Field(default_factory=list)
    rule_count: int = Field(default=0, description="Number of rules loaded")
    match_count: int = Field(default=0, description="Number of matches found")
    message: str | None = Field(default=None, description="Optional status message")


class ThreatIntelResult(BaseModel):
    hash_lookup: dict[str, Any] = Field(default_factory=dict)
    ioc_lookup: dict[str, Any] = Field(default_factory=dict)


class DynamicAnalysisResult(BaseModel):
    success: bool = False
    method: str | None = None
    duration_seconds: float = 0.0
    process_tree: list[dict[str, Any]] = Field(default_factory=list)
    network_summary: dict[str, Any] = Field(default_factory=dict)
    network_activity: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    security_events: list[dict[str, Any]] = Field(default_factory=list)
    syscall_summary: dict[str, Any] = Field(default_factory=dict)
    syscalls: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)
    file_activity: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=dict)
    raw_events_count: int = 0
    event_types: list[str] = Field(default_factory=list)
    error: str | None = None
    skipped: bool = False
    help: str | None = None


class GhidraAIAnalysis(BaseModel):
    analyzed_functions: list[dict[str, Any]] = Field(default_factory=list)
    key_findings: list[dict[str, Any]] = Field(default_factory=list)
    malware_classification: dict[str, Any] | None = None
    call_graph: dict[str, Any] | None = None
    analysis_path: list[str] | list[dict[str, Any]] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] | None = None

    @field_validator("key_findings", mode="before")
    @classmethod
    def normalize_findings(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not v:
            return v
        for finding in v:
            if "evidence" in finding and not isinstance(finding["evidence"], list):
                finding["evidence"] = [finding["evidence"]] if finding["evidence"] else []
        return v


class GhidraAnalysisResult(BaseModel):
    status: str | None = None
    ghidra_available: bool = False
    ghidra_info: dict[str, Any] | None = None
    ai_analysis: GhidraAIAnalysis | None = None
    analyzed_functions: list[dict[str, Any]] = Field(default_factory=list)
    key_findings: list[dict[str, Any]] = Field(default_factory=list)
    cached_functions: list[str] = Field(default_factory=list)
    findings_count: int = 0
    message: str | None = None
    error: str | None = None


class UnifiedReportSchema(BaseModel):
    verdict: str = Field(description="Analysis verdict: malicious, suspicious, benign")
    confidence: float = Field(ge=0, le=1, description="Confidence score 0.0-1.0")
    severity: str = Field(description="Severity: critical, high, medium, low, info")
    summary: str = Field(description="Detailed summary in Chinese")
    executive_summary: str = Field(description="One-sentence summary")
    classification: dict[str, Any] = Field(
        default_factory=dict, description="Malware classification"
    )
    key_findings: list[dict[str, Any]] = Field(
        default_factory=list, description="Key findings from Ghidra"
    )
    analyzed_functions: list[dict[str, Any]] = Field(
        default_factory=list, description="Analyzed functions"
    )
    attack_chain: str | None = Field(default=None, description="Attack chain description")
    mitre_mapping: list[dict[str, Any]] = Field(
        default_factory=list, description="MITRE ATT&CK mappings"
    )
    iocs: dict[str, Any] = Field(default_factory=dict, description="Indicators of Compromise")
    technical_details: dict[str, Any] = Field(default_factory=dict, description="Technical details")
    recommendations: list[dict[str, Any]] = Field(
        default_factory=list, description="Security recommendations"
    )
    data_sources: dict[str, Any] = Field(default_factory=dict, description="Data sources used")
