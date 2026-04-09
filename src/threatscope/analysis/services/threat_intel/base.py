# src/threatscope/analysis/services/threat_intel/base.py
"""Base classes for threat intelligence providers."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ThreatIntelResult:
    """Result from a single threat intelligence provider query."""

    source: str
    found: bool
    data: dict[str, Any]
    error: str | None = None


class BaseThreatIntelProvider(ABC):
    """Abstract base class for threat intelligence providers.

    Each provider wraps one external threat intel service.
    Subclasses must implement query_hash; query_ioc is optional.
    """

    name: str  # Identifier string, e.g. "virustotal", "tencent_tix"

    @abstractmethod
    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query provider for a file hash (SHA256, SHA1, or MD5).

        Args:
            hash_value: Hex-encoded hash string.

        Returns:
            ThreatIntelResult with found=True if the hash is known malicious.
        """
        ...

    async def query_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        """Query provider for an IOC (domain, IP, URL).

        Default implementation returns found=False. Override in providers
        that support IOC queries (e.g. URLhaus).

        Args:
            ioc: The IOC value (domain name, IP address, or URL).
            ioc_type: One of "domain", "ip:port", "url".

        Returns:
            ThreatIntelResult with found=True if the IOC is known malicious.
        """
        return ThreatIntelResult(source=self.name, found=False, data={})
