"""ThreatFox threat intelligence provider."""

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)


class ThreatFoxProvider(BaseThreatIntelProvider):
    """Queries ThreatFox for hash and IOC lookups.

    No authentication required.
    API docs: https://threatfox.abuse.ch/api/
    """

    name = "threatfox"

    def __init__(self, base_url: str = "https://threatfox-api.abuse.ch/api/v1/", timeout: int = 30):
        self.base_url = base_url
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.base_url,
                    json={"query": "search_hash", "hash": hash_value},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
                        source=self.name,
                        found=True,
                        data={"iocs": data.get("data", [])},
                    )
                return ThreatIntelResult(source=self.name, found=False, data={})
        except Exception as e:
            return ThreatIntelResult(source=self.name, found=False, data={}, error=str(e))

    async def query_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.base_url,
                    json={"query": "search_ioc", "search_term": ioc},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
                        source=self.name,
                        found=True,
                        data={"ioc": ioc, "type": ioc_type, "matches": data.get("data", [])},
                    )
                return ThreatIntelResult(
                    source=self.name, found=False, data={"ioc": ioc, "type": ioc_type}
                )
        except Exception as e:
            return ThreatIntelResult(
                source=self.name, found=False, data={"ioc": ioc, "type": ioc_type}, error=str(e)
            )
