# src/threatscope/analysis/services/threat_intel/service.py
"""ThreatIntelService aggregator and build_service factory."""

import asyncio

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)
from src.threatscope.analysis.services.threat_intel.providers.malwarebazaar import (
    MalwareBazaarProvider,
)
from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import TencentTIXProvider
from src.threatscope.analysis.services.threat_intel.providers.threatfox import ThreatFoxProvider
from src.threatscope.analysis.services.threat_intel.providers.urlhaus import URLhausProvider
from src.threatscope.analysis.services.threat_intel.providers.virustotal import VirusTotalProvider
from src.threatscope.core.config import ThreatIntelSettings


class ThreatIntelService:
    """Aggregates multiple threat intelligence providers.

    Queries all enabled providers in parallel. A single provider failure
    does not affect results from other providers.
    """

    def __init__(self, providers: list[BaseThreatIntelProvider]):
        self.providers = providers

    async def query_hash(self, hash_value: str) -> dict[str, ThreatIntelResult]:
        """Query all providers for a file hash in parallel.

        Args:
            hash_value: MD5, SHA1, or SHA256 hex string.

        Returns:
            Dict mapping provider name to ThreatIntelResult.
            Failed providers appear under an "error_<provider_name>" key.
        """
        if not self.providers:
            return {}

        raw = await asyncio.gather(
            *[p.query_hash(hash_value) for p in self.providers],
            return_exceptions=True,
        )

        output: dict[str, ThreatIntelResult] = {}
        for provider, result in zip(self.providers, raw):
            if isinstance(result, ThreatIntelResult):
                output[result.source] = result
            elif isinstance(result, Exception):
                output[f"error_{provider.name}"] = ThreatIntelResult(
                    source=provider.name, found=False, data={}, error=str(result)
                )
        return output

    async def query_iocs(
        self,
        domains: list[str] | None = None,
        ips: list[str] | None = None,
        urls: list[str] | None = None,
    ) -> dict[str, list[ThreatIntelResult]]:
        """Query all providers for IOCs (domains, IPs, URLs).

        Limits each category to 10 items. Only providers that override
        query_ioc will return meaningful results.

        Args:
            domains: Domain names to check.
            ips: IP addresses to check.
            urls: URLs to check.

        Returns:
            Dict with keys "domains", "ips", "urls", each a list of results.
        """
        results: dict[str, list[ThreatIntelResult]] = {
            "domains": [],
            "ips": [],
            "urls": [],
        }

        for domain in (domains or [])[:10]:
            raw = await asyncio.gather(
                *[p.query_ioc(domain, "domain") for p in self.providers],
                return_exceptions=True,
            )
            for provider, r in zip(self.providers, raw):
                if isinstance(r, ThreatIntelResult):
                    results["domains"].append(r)
                elif isinstance(r, Exception):
                    results["domains"].append(
                        ThreatIntelResult(
                            source=provider.name, found=False, data={}, error=str(r)
                        )
                    )

        for ip in (ips or [])[:10]:
            raw = await asyncio.gather(
                *[p.query_ioc(ip, "ip:port") for p in self.providers],
                return_exceptions=True,
            )
            for provider, r in zip(self.providers, raw):
                if isinstance(r, ThreatIntelResult):
                    results["ips"].append(r)
                elif isinstance(r, Exception):
                    results["ips"].append(
                        ThreatIntelResult(
                            source=provider.name, found=False, data={}, error=str(r)
                        )
                    )

        for url in (urls or [])[:10]:
            raw = await asyncio.gather(
                *[p.query_ioc(url, "url") for p in self.providers],
                return_exceptions=True,
            )
            for provider, r in zip(self.providers, raw):
                if isinstance(r, ThreatIntelResult):
                    results["urls"].append(r)
                elif isinstance(r, Exception):
                    results["urls"].append(
                        ThreatIntelResult(
                            source=provider.name, found=False, data={}, error=str(r)
                        )
                    )

        return results


def build_service(settings: ThreatIntelSettings) -> ThreatIntelService:
    """Construct a ThreatIntelService from application settings.

    Only providers with enabled=True (and a non-empty API key where required)
    are included. Providers with missing keys are silently skipped.

    Args:
        settings: ThreatIntelSettings instance from core.config.

    Returns:
        Configured ThreatIntelService ready for use.
    """
    providers: list[BaseThreatIntelProvider] = []

    if settings.malwarebazaar_enabled:
        providers.append(MalwareBazaarProvider(base_url=settings.malwarebazaar_url))

    if settings.threatfox_enabled:
        providers.append(ThreatFoxProvider(base_url=settings.threatfox_url))

    if settings.urlhaus_enabled:
        providers.append(URLhausProvider(base_url=settings.urlhaus_url))

    if settings.virustotal_enabled and settings.virustotal_api_key.get_secret_value():
        providers.append(VirusTotalProvider(api_key=settings.virustotal_api_key.get_secret_value()))

    if settings.tix_enabled and settings.tix_app_key.get_secret_value():
        providers.append(TencentTIXProvider(app_key=settings.tix_app_key.get_secret_value()))

    return ThreatIntelService(providers=providers)
