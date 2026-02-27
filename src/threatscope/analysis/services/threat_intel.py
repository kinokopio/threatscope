"""Threat intelligence service for abuse.ch services.

Provides integration with:
- MalwareBazaar: Hash lookups
- ThreatFox: IoC lookups
- URLhaus: URL lookups
"""

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass
class ThreatIntelResult:
    """Result from threat intelligence query."""

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
        """Initialize threat intel service.

        Args:
            malwarebazaar_url: MalwareBazaar API URL.
            threatfox_url: ThreatFox API URL.
            urlhaus_url: URLhaus API URL.
            timeout: Request timeout in seconds.
        """
        self.malwarebazaar_url = malwarebazaar_url
        self.threatfox_url = threatfox_url
        self.urlhaus_url = urlhaus_url
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> dict[str, ThreatIntelResult]:
        """Query all services for a file hash.

        Args:
            hash_value: MD5, SHA1, or SHA256 hash.

        Returns:
            Dict mapping service name to result.
        """
        tasks = [
            self._query_malwarebazaar_hash(hash_value),
            self._query_threatfox_hash(hash_value),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = {}
        for result in results:
            if isinstance(result, ThreatIntelResult):
                output[result.source] = result
            elif isinstance(result, Exception):
                output["error"] = ThreatIntelResult(
                    source="unknown",
                    found=False,
                    data={},
                    error=str(result),
                )

        return output

    async def query_iocs(
        self,
        domains: list[str] | None = None,
        ips: list[str] | None = None,
        urls: list[str] | None = None,
    ) -> dict[str, list[ThreatIntelResult]]:
        """Query services for IoCs.

        Args:
            domains: List of domains to check.
            ips: List of IPs to check.
            urls: List of URLs to check.

        Returns:
            Dict mapping IoC type to list of results.
        """
        results: dict[str, list[ThreatIntelResult]] = {
            "domains": [],
            "ips": [],
            "urls": [],
        }

        # Query ThreatFox for domains and IPs
        if domains:
            for domain in domains[:10]:  # Limit queries
                result = await self._query_threatfox_ioc(domain, "domain")
                results["domains"].append(result)

        if ips:
            for ip in ips[:10]:
                result = await self._query_threatfox_ioc(ip, "ip:port")
                results["ips"].append(result)

        # Query URLhaus for URLs
        if urls:
            for url in urls[:10]:
                result = await self._query_urlhaus(url)
                results["urls"].append(result)

        return results

    async def _query_malwarebazaar_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query MalwareBazaar for a hash.

        Args:
            hash_value: File hash.

        Returns:
            ThreatIntelResult with query results.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.malwarebazaar_url,
                    data={"query": "get_info", "hash": hash_value},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    sample_data = data.get("data", [{}])[0]
                    return ThreatIntelResult(
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
                else:
                    return ThreatIntelResult(
                        source="malwarebazaar",
                        found=False,
                        data={},
                    )
        except Exception as e:
            return ThreatIntelResult(
                source="malwarebazaar",
                found=False,
                data={},
                error=str(e),
            )

    async def _query_threatfox_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query ThreatFox for a hash.

        Args:
            hash_value: File hash.

        Returns:
            ThreatIntelResult with query results.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.threatfox_url,
                    json={"query": "search_hash", "hash": hash_value},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
                        source="threatfox",
                        found=True,
                        data={
                            "iocs": data.get("data", []),
                        },
                    )
                else:
                    return ThreatIntelResult(
                        source="threatfox",
                        found=False,
                        data={},
                    )
        except Exception as e:
            return ThreatIntelResult(
                source="threatfox",
                found=False,
                data={},
                error=str(e),
            )

    async def _query_threatfox_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        """Query ThreatFox for an IoC.

        Args:
            ioc: IoC value.
            ioc_type: Type of IoC (domain, ip:port, url).

        Returns:
            ThreatIntelResult with query results.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.threatfox_url,
                    json={"query": "search_ioc", "search_term": ioc},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
                        source="threatfox",
                        found=True,
                        data={
                            "ioc": ioc,
                            "type": ioc_type,
                            "matches": data.get("data", []),
                        },
                    )
                else:
                    return ThreatIntelResult(
                        source="threatfox",
                        found=False,
                        data={"ioc": ioc, "type": ioc_type},
                    )
        except Exception as e:
            return ThreatIntelResult(
                source="threatfox",
                found=False,
                data={"ioc": ioc, "type": ioc_type},
                error=str(e),
            )

    async def _query_urlhaus(self, url: str) -> ThreatIntelResult:
        """Query URLhaus for a URL.

        Args:
            url: URL to check.

        Returns:
            ThreatIntelResult with query results.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.urlhaus_url}url/",
                    data={"url": url},
                )
                data = response.json()

                if data.get("query_status") == "ok":
                    return ThreatIntelResult(
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
                else:
                    return ThreatIntelResult(
                        source="urlhaus",
                        found=False,
                        data={"url": url},
                    )
        except Exception as e:
            return ThreatIntelResult(
                source="urlhaus",
                found=False,
                data={"url": url},
                error=str(e),
            )


# Backwards compatibility alias
ThreatIntelClient = ThreatIntelService
