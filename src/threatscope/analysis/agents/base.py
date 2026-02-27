"""Base classes for AI agents."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentConfig:
    """Configuration for an AI agent."""

    system_prompt_path: str = ""
    max_iterations: int = 20
    model: str = "claude-sonnet-4-20250514"


@dataclass
class AgentResult:
    """Result from an AI agent."""

    success: bool = True
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    iterations: int = 0
    tokens_used: int = 0


class BaseAgent(ABC):
    """Base class for AI agents."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self._system_prompt: str = ""

    @property
    @abstractmethod
    def name(self) -> str:
        """Agent name for identification."""
        pass

    def load_system_prompt(self) -> str:
        """Load system prompt from file."""
        if self.config.system_prompt_path and not self._system_prompt:
            try:
                with open(self.config.system_prompt_path) as f:
                    self._system_prompt = f.read()
            except FileNotFoundError:
                pass
        return self._system_prompt

    @abstractmethod
    async def analyze(self, context: dict[str, Any]) -> AgentResult:
        """Run agent analysis.

        Args:
            context: Input context for the agent.

        Returns:
            AgentResult with analysis output.
        """
        pass
