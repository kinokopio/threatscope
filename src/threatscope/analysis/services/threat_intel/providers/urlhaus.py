# src/threatscope/analysis/services/threat_intel/providers/urlhaus.py
"""URLhaus threat intelligence provider."""

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)


class URLhausProvider(BaseThreatIntelProvider):
    """Queries URLhaus for URL-based IOC lookups.

    URLhaus does not support hash queries; query_hash always returns found=False.
    No authentication required.
    API docs: https://urlhaus-api.abuse.ch/
    """

    name = "urlhaus"

    def __init__(self, base_url: str = "https://urlhaus-api.abuse.ch/v1/", timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """URLhaus does not support hash lookups."""
        return ThreatIntelResult(source=self.name, found=False, data={})

    async def query_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        """Query URLhaus for a URL IOC. Non-URL ioc_types return found=False."""
        if ioc_type != "url":
            return ThreatIntelResult(source=self.name, found=False, data={"ioc": ioc})

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(f"{self.base_url}url/", data={"url": ioc})
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
                        source=self.name,
                        found=True,
                        data={
                            "url": ioc,
                            "threat": data.get("threat"),
                            "tags": data.get("tags", []),
                            "urlhaus_reference": data.get("urlhaus_reference"),
                            "date_added": data.get("date_added"),
                        },
                    )
                return ThreatIntelResult(source=self.name, found=False, data={"url": ioc})
        except Exception as e:
            return ThreatIntelResult(source=self.name, found=False, data={"url": ioc}, error=str(e))
