"""Base classes for analysis tools."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class FileType(Enum):
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    APK = "apk"
    UNKNOWN = "unknown"


@dataclass
class ToolResult:
    success: bool = True
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


class AnalysisTool(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    async def analyze(self, file_path: Path) -> ToolResult:
        pass
