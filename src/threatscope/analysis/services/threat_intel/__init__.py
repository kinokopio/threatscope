# src/threatscope/analysis/services/threat_intel/__init__.py
"""Threat intelligence service package.

Backward-compatibility shim: re-exports ThreatIntelService from the legacy
implementation so that existing imports (e.g. analysis/services/__init__.py)
continue to work while the new provider architecture is built out in Tasks 2-8.
The legacy class will be removed and this module fully wired in Task 8.
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class _LegacyThreatIntelResult:
    """Legacy result dataclass kept for backward-compat."""

    source: str
    found: bool
    data: dict[str, Any]
    error: str | None = None


class ThreatIntelService:
    """Service for querying threat intelligence sources.

    Supports:
    - MalwareBazaar: Hash lookups
    - ThreatFox: IoC lookups
    - URLhaus: URL lookups
    """

    def __init__(
        self,
        malwarebazaar_url: str = "https://mb-api.abuse.ch/api/v1/",
        threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/",
        urlhaus_url: str = "https://urlhaus-api.abuse.ch/v1/",
        timeout: int = 30,
    ):
        self.malwarebazaar_url = malwarebazaar_url
        self.threatfox_url = threatfox_url
        self.urlhaus_url = urlhaus_url
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> dict[str, _LegacyThreatIntelResult]:
        tasks = [
            self._query_malwarebazaar_hash(hash_value),
            self._query_threatfox_hash(hash_value),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        output = {}
        for result in results:
            if isinstance(result, _LegacyThreatIntelResult):
                output[result.source] = result
            elif isinstance(result, Exception):
                output["error"] = _LegacyThreatIntelResult(
                    source="unknown", found=False, data={}, error=str(result)
                )
        return output

    async def query_iocs(
        self,
        domains: list[str] | None = None,
        ips: list[str] | None = None,
        urls: list[str] | None = None,
    ) -> dict[str, list[_LegacyThreatIntelResult]]:
        results: dict[str, list[_LegacyThreatIntelResult]] = {
            "domains": [],
            "ips": [],
            "urls": [],
        }
        if domains:
            for domain in domains[:10]:
                results["domains"].append(await self._query_threatfox_ioc(domain, "domain"))
        if ips:
            for ip in ips[:10]:
                results["ips"].append(await self._query_threatfox_ioc(ip, "ip:port"))
        if urls:
            for url in urls[:10]:
                results["urls"].append(await self._query_urlhaus(url))
        return results

    async def _query_malwarebazaar_hash(self, hash_value: str) -> _LegacyThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.malwarebazaar_url,
                    data={"query": "get_info", "hash": hash_value},
                )
                data = response.json()
                if data.get("query_status") == "ok":
                    sample_data = data.get("data", [{}])[0]
                    return _LegacyThreatIntelResult(
                        source="malwarebazaar",
                        found=True,
                        data={
                            "family": sample_data.get("signature"),
                            "tags": sample_data.get("tags", []),
                            "first_seen": sample_data.get("first_seen"),
                            "file_type": sample_data.get("file_type"),
                            "delivery_method": sample_data.get("delivery_method"),
                            "intelligence": sample_data.get("intelligence", {}),
                        },
                    )
                return _LegacyThreatIntelResult(source="malwarebazaar", found=False, data={})
        except Exception as e:
            return _LegacyThreatIntelResult(
                source="malwarebazaar", found=False, data={}, error=str(e)
            )

    async def _query_threatfox_hash(self, hash_value: str) -> _LegacyThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.threatfox_url,
                    json={"query": "search_hash", "hash": hash_value},
                )
                data = response.json()
                if data.get("query_status") == "ok":
                    return _LegacyThreatIntelResult(
                        source="threatfox", found=True, data={"iocs": data.get("data", [])}
                    )
                return _LegacyThreatIntelResult(source="threatfox", found=False, data={})
        except Exception as e:
            return _LegacyThreatIntelResult(
                source="threatfox", found=False, data={}, error=str(e)
            )

    async def _query_threatfox_ioc(self, ioc: str, ioc_type: str) -> _LegacyThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.threatfox_url,
                    json={"query": "search_ioc", "search_term": ioc},
                )
                data = response.json()
                if data.get("query_status") == "ok":
                    return _LegacyThreatIntelResult(
                        source="threatfox",
                        found=True,
                        data={"ioc": ioc, "type": ioc_type, "matches": data.get("data", [])},
                    )
                return _LegacyThreatIntelResult(
                    source="threatfox", found=False, data={"ioc": ioc, "type": ioc_type}
                )
        except Exception as e:
            return _LegacyThreatIntelResult(
                source="threatfox",
                found=False,
                data={"ioc": ioc, "type": ioc_type},
                error=str(e),
            )

    async def _query_urlhaus(self, url: str) -> _LegacyThreatIntelResult:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(f"{self.urlhaus_url}url/", data={"url": url})
                data = response.json()
                if data.get("query_status") == "ok":
                    return _LegacyThreatIntelResult(
                        source="urlhaus",
                        found=True,
                        data={
                            "url": url,
                            "threat": data.get("threat"),
                            "tags": data.get("tags", []),
                            "urlhaus_reference": data.get("urlhaus_reference"),
                            "date_added": data.get("date_added"),
                        },
                    )
                return _LegacyThreatIntelResult(source="urlhaus", found=False, data={"url": url})
        except Exception as e:
            return _LegacyThreatIntelResult(
                source="urlhaus", found=False, data={"url": url}, error=str(e)
            )


# Backward-compat alias
ThreatIntelClient = ThreatIntelService
