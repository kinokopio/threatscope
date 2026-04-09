"""VirusTotal threat intelligence provider."""

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)

_VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseThreatIntelProvider):
    """Queries VirusTotal v3 API for file hash lookups.

    Authentication: x-apikey header.
    API docs: https://developers.virustotal.com/reference/files
    """

    name = "virustotal"

    def __init__(self, api_key: str, timeout: int = 30):
        """Args:
        api_key: VirusTotal API key (free or premium).
        timeout: HTTP request timeout in seconds.
        """
        self._api_key = api_key
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query VirusTotal for a file hash.

        Returns found=True only when malicious engine count > 0.
        Returns found=False (no error) for HTTP 404 (hash unknown to VT).
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{_VT_BASE_URL}/files/{hash_value}",
                    headers={"x-apikey": self._api_key},
                )

                if response.status_code == 404:
                    return ThreatIntelResult(source=self.name, found=False, data={})

                response.raise_for_status()
                attrs = response.json()["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)

                return ThreatIntelResult(
                    source=self.name,
                    found=malicious_count > 0,
                    data={
                        "malicious": malicious_count,
                        "suspicious": stats.get("suspicious", 0),
                        "undetected": stats.get("undetected", 0),
                        "harmless": stats.get("harmless", 0),
                        "meaningful_name": attrs.get("meaningful_name"),
                        "threat_label": (attrs.get("popular_threat_classification", {}) or {}).get(
                            "suggested_threat_label"
                        ),
                    },
                )
        except Exception as e:
            return ThreatIntelResult(source=self.name, found=False, data={}, error=str(e))
