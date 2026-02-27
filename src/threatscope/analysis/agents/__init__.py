"""AI agents for malware analysis."""

from src.threatscope.analysis.agents.base import AgentConfig, AgentResult, BaseAgent
from src.threatscope.analysis.agents.ghidra_agent import GhidraAgent
from src.threatscope.analysis.agents.malware_agent import MalwareAnalysisAgent

__all__ = [
    "AgentConfig",
    "AgentResult",
    "BaseAgent",
    "GhidraAgent",
    "MalwareAnalysisAgent",
]
