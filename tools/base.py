"""Base classes and types for analysis tools."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class FileType(Enum):
    """Supported file types."""

    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    APK = "apk"
    UNKNOWN = "unknown"


@dataclass
class AnalysisResult:
    """Base result for all analysis tools."""

    success: bool = True
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """Base class for all analysis tools."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Tool name for identification."""
        pass

    @abstractmethod
    async def analyze(self, file_path: Path) -> AnalysisResult:
        """Run analysis on the given file.

        Args:
            file_path: Path to the file to analyze.

        Returns:
            AnalysisResult with success status and data.
        """
        pass
