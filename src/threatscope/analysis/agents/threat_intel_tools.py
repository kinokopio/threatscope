"""Threat Intelligence MCP tools for AI agents.

Provides threat intelligence query capabilities as in-process MCP tools
for use with claude-agent-sdk.
"""

import json
from dataclasses import asdict
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool

from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService


def _format_results(results: dict) -> str:
    serializable = {}
    for key, value in results.items():
        if hasattr(value, "__dataclass_fields__"):
            serializable[key] = asdict(value)
        elif isinstance(value, list):
            serializable[key] = [
                asdict(item) if hasattr(item, "__dataclass_fields__") else item for item in value
            ]
        else:
            serializable[key] = value
    return json.dumps(serializable, indent=2, ensure_ascii=False, default=str)


def create_threat_intel_tools(service: ThreatIntelService) -> list:
    @tool(
        "threat_intel_query_hash",
        "Query threat intelligence for a file hash (MD5/SHA1/SHA256). Returns results from multiple providers including VirusTotal, MalwareBazaar, ThreatFox, and Tencent TIX.",
        {"hash": str},
    )
    async def query_hash(args: dict[str, Any]) -> dict:
        hash_value = args["hash"].strip()
        results = await service.query_hash(hash_value)

        if not results:
            return {
                "content": [
                    {"type": "text", "text": "No threat intelligence providers configured."}
                ]
            }

        found_any = any(r.found for r in results.values() if hasattr(r, "found"))
        summary = f"Hash: {hash_value}\nFound in threat intel: {'Yes' if found_any else 'No'}\n\n"
        summary += _format_results(results)

        return {"content": [{"type": "text", "text": summary}]}

    @tool(
        "threat_intel_query_domain",
        "Query threat intelligence for a domain name. Checks if the domain is associated with malware, C2 servers, or other malicious activity.",
        {"domain": str},
    )
    async def query_domain(args: dict[str, Any]) -> dict:
        domain = args["domain"].strip().lower()
        results = await service.query_iocs(domains=[domain])

        domain_results = results.get("domains", [])
        if not domain_results:
            return {"content": [{"type": "text", "text": f"No results for domain: {domain}"}]}

        found_any = any(r.found for r in domain_results)
        summary = f"Domain: {domain}\nFound in threat intel: {'Yes' if found_any else 'No'}\n\n"

        for r in domain_results:
            if r.found:
                summary += f"[{r.source}] MALICIOUS\n"
                summary += json.dumps(r.data, indent=2, ensure_ascii=False, default=str) + "\n\n"
            elif r.error:
                summary += f"[{r.source}] Error: {r.error}\n"
            else:
                summary += f"[{r.source}] Not found\n"

        return {"content": [{"type": "text", "text": summary}]}

    @tool(
        "threat_intel_query_ip",
        "Query threat intelligence for an IP address. Checks if the IP is associated with malware, C2 servers, botnets, or other malicious activity.",
        {"ip": str},
    )
    async def query_ip(args: dict[str, Any]) -> dict:
        ip = args["ip"].strip()
        results = await service.query_iocs(ips=[ip])

        ip_results = results.get("ips", [])
        if not ip_results:
            return {"content": [{"type": "text", "text": f"No results for IP: {ip}"}]}

        found_any = any(r.found for r in ip_results)
        summary = f"IP: {ip}\nFound in threat intel: {'Yes' if found_any else 'No'}\n\n"

        for r in ip_results:
            if r.found:
                summary += f"[{r.source}] MALICIOUS\n"
                summary += json.dumps(r.data, indent=2, ensure_ascii=False, default=str) + "\n\n"
            elif r.error:
                summary += f"[{r.source}] Error: {r.error}\n"
            else:
                summary += f"[{r.source}] Not found\n"

        return {"content": [{"type": "text", "text": summary}]}

    @tool(
        "threat_intel_query_url",
        "Query threat intelligence for a URL. Checks if the URL is associated with malware distribution, phishing, or other malicious activity.",
        {"url": str},
    )
    async def query_url(args: dict[str, Any]) -> dict:
        url = args["url"].strip()
        results = await service.query_iocs(urls=[url])

        url_results = results.get("urls", [])
        if not url_results:
            return {"content": [{"type": "text", "text": f"No results for URL: {url}"}]}

        found_any = any(r.found for r in url_results)
        summary = f"URL: {url}\nFound in threat intel: {'Yes' if found_any else 'No'}\n\n"

        for r in url_results:
            if r.found:
                summary += f"[{r.source}] MALICIOUS\n"
                summary += json.dumps(r.data, indent=2, ensure_ascii=False, default=str) + "\n\n"
            elif r.error:
                summary += f"[{r.source}] Error: {r.error}\n"
            else:
                summary += f"[{r.source}] Not found\n"

        return {"content": [{"type": "text", "text": summary}]}

    @tool(
        "threat_intel_batch_query",
        "Query threat intelligence for multiple IOCs at once. Useful when you have discovered multiple domains, IPs, or URLs during analysis.",
        {"domains": list, "ips": list, "urls": list},
    )
    async def batch_query(args: dict[str, Any]) -> dict:
        domains = args.get("domains") or []
        ips = args.get("ips") or []
        urls = args.get("urls") or []

        if not domains and not ips and not urls:
            return {"content": [{"type": "text", "text": "No IOCs provided for query."}]}

        results = await service.query_iocs(domains=domains, ips=ips, urls=urls)

        summary_parts = []

        if domains:
            domain_results = results.get("domains", [])
            found_domains = [r for r in domain_results if r.found]
            summary_parts.append(f"Domains: {len(found_domains)}/{len(domains)} malicious")
            for r in found_domains:
                summary_parts.append(f"  - {r.data.get('ioc_value', 'unknown')} [{r.source}]")

        if ips:
            ip_results = results.get("ips", [])
            found_ips = [r for r in ip_results if r.found]
            summary_parts.append(f"IPs: {len(found_ips)}/{len(ips)} malicious")
            for r in found_ips:
                summary_parts.append(f"  - {r.data.get('ioc_value', 'unknown')} [{r.source}]")

        if urls:
            url_results = results.get("urls", [])
            found_urls = [r for r in url_results if r.found]
            summary_parts.append(f"URLs: {len(found_urls)}/{len(urls)} malicious")
            for r in found_urls:
                summary_parts.append(f"  - {r.data.get('ioc_value', 'unknown')} [{r.source}]")

        summary_parts.append("\nFull results:\n" + _format_results(results))

        return {"content": [{"type": "text", "text": "\n".join(summary_parts)}]}

    return [query_hash, query_domain, query_ip, query_url, batch_query]


def create_threat_intel_mcp_server(service: ThreatIntelService):
    return create_sdk_mcp_server(
        name="threat_intel",
        version="1.0.0",
        tools=create_threat_intel_tools(service),
    )
