"""Pydantic models for Ghidra AI analysis structured output."""

from typing import Literal

from pydantic import BaseModel, Field


class AnalyzedFunction(BaseModel):
    """A function analyzed by the Ghidra agent."""

    name: str = Field(description="Function name")
    address: str = Field(description="Hex address like 0x12345678 or 'unknown'")
    purpose: str = Field(description="Brief description of what this function does")
    analysis: str | None = Field(
        default=None, description="Detailed analysis of the function behavior"
    )
    risk: Literal["critical", "high", "medium", "low"] = Field(description="Risk level")


class KeyFinding(BaseModel):
    """A key finding from the analysis."""

    id: str = Field(description="Unique ID like finding_001")
    title: str = Field(description="Short title of the finding")
    category: str = Field(description="Category (e.g., Persistence, Network, Evasion)")
    description: str = Field(description="Detailed description of the finding")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Severity level")
    evidence: list[str] = Field(default_factory=list, description="Evidence items")
    impact: str | None = Field(default=None, description="Impact description")
    recommendation: str | None = Field(default=None, description="Remediation advice")


class MalwareClassification(BaseModel):
    """Malware classification result."""

    type: str = Field(
        description="Malware type: RAT, Backdoor, Miner, Ransomware, Trojan, Stealer, Botnet, Benign, or Unknown"
    )
    family: str | None = Field(default=None, description="Malware family if identified")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Overall severity")


class GhidraAnalysisOutput(BaseModel):
    """Structured output schema for Ghidra AI analysis."""

    analyzed_functions: list[AnalyzedFunction] = Field(
        default_factory=list, description="List of analyzed functions with their details"
    )
    key_findings: list[KeyFinding] = Field(
        default_factory=list, description="Key security findings from the analysis"
    )
    malware_classification: MalwareClassification | None = Field(
        default=None, description="Malware classification if malicious"
    )
    analysis_path: list[str] = Field(
        default_factory=list,
        description="Steps taken during analysis (e.g., 'Step 1: Analyzed entry point')",
    )
    attack_chain: str | None = Field(
        default=None,
        description="Attack flow chain: FuncA (purpose) -> FuncB (purpose) -> FuncC (purpose)",
    )
