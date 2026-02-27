"""MCP Server for ThreatScope - Exposes analysis capabilities via MCP protocol."""

from typing import Any

from src.threatscope.analysis import AnalysisCoordinator


class ThreatScopeMCPServer:
    """MCP Server exposing ThreatScope analysis capabilities.

    This server can be used by AI agents to perform malware analysis
    through the Model Context Protocol.
    """

    def __init__(self):
        """Initialize MCP server."""
        self.coordinator = AnalysisCoordinator()
        self._tools = self._define_tools()

    def _define_tools(self) -> list[dict[str, Any]]:
        """Define available MCP tools."""
        return [
            {
                "name": "analyze_file",
                "description": "Analyze a file for malware indicators",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        },
                        "enable_ghidra": {
                            "type": "boolean",
                            "description": "Enable Ghidra deep analysis",
                            "default": True,
                        },
                        "enable_threat_intel": {
                            "type": "boolean",
                            "description": "Enable threat intelligence queries",
                            "default": True,
                        },
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "get_static_analysis",
                "description": "Get static analysis results for a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {
                            "type": "string",
                            "description": "Path to the file to analyze",
                        },
                    },
                    "required": ["file_path"],
                },
            },
            {
                "name": "query_threat_intel",
                "description": "Query threat intelligence for a hash or IoC",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "hash": {
                            "type": "string",
                            "description": "File hash (MD5, SHA1, or SHA256)",
                        },
                        "domain": {
                            "type": "string",
                            "description": "Domain to check",
                        },
                        "ip": {
                            "type": "string",
                            "description": "IP address to check",
                        },
                        "url": {
                            "type": "string",
                            "description": "URL to check",
                        },
                    },
                },
            },
        ]

    def get_tools(self) -> list[dict[str, Any]]:
        """Get list of available tools.

        Returns:
            List of tool definitions.
        """
        return self._tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a tool by name.

        Args:
            name: Tool name.
            arguments: Tool arguments.

        Returns:
            Tool result.
        """
        if name == "analyze_file":
            return await self._analyze_file(arguments)
        elif name == "get_static_analysis":
            return await self._get_static_analysis(arguments)
        elif name == "query_threat_intel":
            return await self._query_threat_intel(arguments)
        else:
            return {"error": f"Unknown tool: {name}"}

    async def _analyze_file(self, args: dict[str, Any]) -> dict[str, Any]:
        """Run full analysis on a file."""
        file_path = args.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}

        result = await self.coordinator.analyze(
            file_path=file_path,
            enable_ghidra=args.get("enable_ghidra", True),
            enable_threat_intel=args.get("enable_threat_intel", True),
        )
        return result

    async def _get_static_analysis(self, args: dict[str, Any]) -> dict[str, Any]:
        """Get static analysis only."""
        file_path = args.get("file_path")
        if not file_path:
            return {"error": "file_path is required"}

        result = await self.coordinator.analyze(
            file_path=file_path,
            enable_ghidra=False,
            enable_threat_intel=False,
        )
        return result.get("static_analysis", {})

    async def _query_threat_intel(self, args: dict[str, Any]) -> dict[str, Any]:
        """Query threat intelligence."""
        results = {}

        if "hash" in args:
            hash_results = await self.coordinator.threat_intel.query_hash(args["hash"])
            results["hash_lookup"] = {
                source: {"found": r.found, "data": r.data} for source, r in hash_results.items()
            }

        if any(k in args for k in ["domain", "ip", "url"]):
            ioc_results = await self.coordinator.threat_intel.query_iocs(
                domains=[args["domain"]] if "domain" in args else None,
                ips=[args["ip"]] if "ip" in args else None,
                urls=[args["url"]] if "url" in args else None,
            )
            results["ioc_lookup"] = {
                ioc_type: [{"found": r.found, "data": r.data} for r in ioc_list]
                for ioc_type, ioc_list in ioc_results.items()
                if ioc_list
            }

        return results


# Singleton instance
_mcp_server: ThreatScopeMCPServer | None = None


def get_mcp_server() -> ThreatScopeMCPServer:
    """Get or create the MCP server instance."""
    global _mcp_server
    if _mcp_server is None:
        _mcp_server = ThreatScopeMCPServer()
    return _mcp_server
