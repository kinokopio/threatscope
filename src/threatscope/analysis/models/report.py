"""Unified Report Models for malware analysis.

This module defines the data structures for the unified malware analysis report.
The UnifiedReport aggregates data from all analysis phases (static, dynamic, Ghidra)
into a single, comprehensive report structure.
"""

from typing import Literal

from pydantic import BaseModel, Field


class MalwareClassification(BaseModel):
    """Malware classification information."""

    type: str = Field(description="Malware type: RAT, Backdoor, Miner, Ransomware, Trojan, etc.")
    family: str | None = Field(default=None, description="Malware family name if known")
    variant: str | None = Field(default=None, description="Malware variant if known")
    aliases: list[str] = Field(default_factory=list, description="Known aliases for this malware")


class KeyFinding(BaseModel):
    """Key finding from analysis - maps directly from Ghidra's key_findings."""

    id: str = Field(description="Unique finding identifier")
    title: str = Field(description="Finding title")
    category: str = Field(description="Category: 命令与控制, 执行, 防御规避, 持久化, etc.")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = Field(
        description="Severity level"
    )
    description: str = Field(description="Detailed description of the finding")
    evidence: list[str] = Field(
        default_factory=list, description="Evidence supporting this finding"
    )
    impact: str = Field(description="Impact of this finding")
    recommendation: str = Field(description="Recommended action")
    mitre_technique: str | None = Field(default=None, description="MITRE ATT&CK technique ID")


class AnalyzedFunction(BaseModel):
    """Analyzed function from Ghidra reverse engineering."""

    name: str = Field(description="Function name")
    address: str = Field(description="Function address in hex")
    purpose: str = Field(description="Purpose of the function")
    analysis: str = Field(description="Detailed analysis of the function")
    risk: Literal["critical", "high", "medium", "low"] = Field(description="Risk level")
    category: str | None = Field(default=None, description="Function category: C2, Execution, etc.")


class MitreMapping(BaseModel):
    """MITRE ATT&CK technique mapping."""

    tactic: str = Field(description="ATT&CK tactic name")
    technique_id: str = Field(description="Technique ID (e.g., T1071.001)")
    technique_name: str = Field(description="Technique name")
    sub_technique: str | None = Field(default=None, description="Sub-technique name if applicable")
    evidence: str = Field(description="Evidence for this mapping")
    confidence: Literal["high", "medium", "low"] = Field(
        default="medium", description="Confidence level"
    )
    source: str = Field(description="Source of mapping: ghidra_finding_001, capa, yara")


class IoCItem(BaseModel):
    """Individual Indicator of Compromise."""

    value: str = Field(description="IOC value")
    type: str = Field(description="IOC type: domain, ip, url, md5, sha256, path, etc.")
    context: str | None = Field(default=None, description="Context: C2 server, Dropped file, etc.")
    source: str = Field(description="Source: ghidra, strings, dynamic, threat_intel")
    confidence: Literal["high", "medium", "low"] = Field(
        default="medium", description="Confidence level"
    )


class IoCs(BaseModel):
    """Aggregated Indicators of Compromise."""

    domains: list[IoCItem] = Field(default_factory=list, description="Malicious domains")
    ips: list[IoCItem] = Field(default_factory=list, description="Malicious IP addresses")
    urls: list[IoCItem] = Field(default_factory=list, description="Malicious URLs")
    file_hashes: list[IoCItem] = Field(default_factory=list, description="File hashes")
    file_paths: list[IoCItem] = Field(default_factory=list, description="Suspicious file paths")
    registry_keys: list[IoCItem] = Field(default_factory=list, description="Registry keys")
    mutexes: list[IoCItem] = Field(default_factory=list, description="Mutex names")


class TechnicalDetails(BaseModel):
    """Technical details about the analyzed file."""

    # File information
    file_format: str = Field(description="File format: ELF, PE, Mach-O")
    architecture: str = Field(description="Architecture: x86_64, ARM64, etc.")
    platform: str = Field(description="Platform: Linux, Windows, macOS")
    file_size: int = Field(description="File size in bytes")

    # Compilation information
    compiler: str | None = Field(default=None, description="Compiler used")
    linker: str | None = Field(default=None, description="Linker used")
    build_timestamp: str | None = Field(default=None, description="Build timestamp if available")

    # Protection/obfuscation
    packers: list[str] = Field(default_factory=list, description="Detected packers")
    protectors: list[str] = Field(default_factory=list, description="Detected protectors")
    obfuscation: list[str] = Field(default_factory=list, description="Obfuscation techniques")

    # Communication
    c2_protocol: str | None = Field(default=None, description="C2 protocol: HTTP, DNS, TCP")
    encryption: str | None = Field(default=None, description="Encryption: RSA, AES, XOR")

    # Capabilities
    capabilities: list[str] = Field(
        default_factory=list, description="Detected capabilities from capa and ghidra"
    )


class Recommendation(BaseModel):
    """Security recommendation."""

    priority: Literal["immediate", "high", "medium", "low"] = Field(description="Priority level")
    category: str = Field(description="Category: containment, eradication, recovery, prevention")
    action: str = Field(description="Recommended action")
    details: str | None = Field(default=None, description="Additional details")


class DataSources(BaseModel):
    """Data sources used in the analysis."""

    static_analysis: bool = Field(default=False, description="Static analysis was performed")
    dynamic_analysis: bool = Field(default=False, description="Dynamic analysis was performed")
    ghidra_analysis: bool = Field(default=False, description="Ghidra analysis was performed")
    threat_intel: bool = Field(default=False, description="Threat intel lookup was performed")
    analysis_duration_seconds: float = Field(default=0.0, description="Total analysis duration")
    ghidra_functions_analyzed: int = Field(default=0, description="Number of functions analyzed")
    ghidra_findings_count: int = Field(default=0, description="Number of findings from Ghidra")


class UnifiedReport(BaseModel):
    """Unified malware analysis report.

    This is the single source of truth for the frontend display.
    It aggregates data from all analysis phases into one comprehensive structure.
    """

    # Core verdict
    verdict: Literal["malicious", "suspicious", "benign"] = Field(description="Analysis verdict")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score 0.0-1.0")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Overall severity"
    )

    # AI-generated summaries
    summary: str = Field(description="3-5 sentence detailed summary in Chinese")
    executive_summary: str = Field(description="1 sentence summary for executives")

    # Malware classification
    classification: MalwareClassification = Field(description="Malware classification")

    # Key findings (directly from Ghidra)
    key_findings: list[KeyFinding] = Field(
        default_factory=list, description="Key findings from analysis"
    )

    # Analyzed functions (directly from Ghidra)
    analyzed_functions: list[AnalyzedFunction] = Field(
        default_factory=list, description="Analyzed functions"
    )

    # Attack chain (directly from Ghidra)
    attack_chain: str | None = Field(default=None, description="Attack chain description")

    # MITRE ATT&CK mapping
    mitre_mapping: list[MitreMapping] = Field(
        default_factory=list, description="MITRE ATT&CK mappings"
    )

    # Aggregated IOCs
    iocs: IoCs = Field(default_factory=IoCs, description="Indicators of Compromise")

    # Technical details
    technical_details: TechnicalDetails = Field(description="Technical details")

    # Recommendations (AI-generated)
    recommendations: list[Recommendation] = Field(
        default_factory=list, description="Security recommendations"
    )

    # Data sources
    data_sources: DataSources = Field(default_factory=DataSources, description="Data sources used")
