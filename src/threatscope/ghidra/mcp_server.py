"""
Ghidra MCP Server - Model Context Protocol server for AI agents.

Provides MCP tools for binary analysis operations via Ghidra.
"""

import logging
import os
from typing import Any

import httpx
import uvicorn
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Configuration
GHIDRA_HTTP_URL = os.getenv("GHIDRA_HTTP_URL", "http://localhost:8000").rstrip("/")
MCP_HOST = os.getenv("GHIDRA_MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("GHIDRA_MCP_PORT", "9000"))
REQUEST_TIMEOUT = float(os.getenv("GHIDRA_MCP_TIMEOUT", "120"))
ALLOW_ORIGINS = os.getenv("GHIDRA_MCP_ALLOW_ORIGINS", "*")

mcp = FastMCP("ThreatScope Ghidra MCP")


def _request(method: str, path: str, params: dict | None = None, json: Any = None) -> Any:
    """Make request to Ghidra HTTP service."""
    url = f"{GHIDRA_HTTP_URL}{path}"
    try:
        response = httpx.request(method, url, params=params, json=json, timeout=REQUEST_TIMEOUT)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Failed to reach Ghidra service at {url}: {e}") from e

    if response.status_code == 409:
        raise RuntimeError("No binary loaded. Upload and analyze first.")
    if response.status_code == 404:
        target = (
            (params or json or {}).get("target") or path.split("/")[-2]
            if "/decompile" in path or "/disassemble" in path
            else path.split("/")[-1]
        )
        raise RuntimeError(
            f"Function '{target}' not found. "
            "The binary may be stripped. Use list_functions to get actual function names "
            "(e.g., FUN_00401000) or try using an address like '0x401000'."
        )
    if response.status_code >= 400:
        raise RuntimeError(f"Ghidra error {response.status_code}: {response.text}")

    return response.json()


# --- Function Tools ---


@mcp.tool()
def list_functions(offset: int = 0, limit: int = 50) -> list[dict[str, Any]]:
    """Get list of functions in the binary.

    Args:
        offset: Starting index for pagination
        limit: Maximum number of functions to return

    Returns:
        List of functions with name, address, offset, size, signature
    """
    return _request("GET", "/functions", params={"offset": offset, "limit": limit})


@mcp.tool()
def get_function_details(target: str) -> dict[str, Any]:
    """Get detailed information about a function.

    Args:
        target: Function name (e.g., "main", "FUN_00401000") or address (e.g., "0x401000")

    Returns:
        Function details including signature, calling convention, parameters
    """
    return _request("GET", f"/functions/{target}")


@mcp.tool()
def decompile_function(target: str) -> dict[str, Any]:
    """Decompile a function to C code.

    Args:
        target: Function name or address

    Returns:
        Decompiled C code with function name and address
    """
    return _request("GET", f"/functions/{target}/decompile")


@mcp.tool()
def disassemble_function(target: str, max_instructions: int = 100) -> dict[str, Any]:
    """Get assembly instructions for a function.

    Args:
        target: Function name or address
        max_instructions: Maximum number of instructions to return

    Returns:
        Assembly instructions with address, mnemonic, operands, bytes
    """
    return _request(
        "GET",
        f"/functions/{target}/disassemble",
        params={"max_instructions": max_instructions},
    )


@mcp.tool()
def function_xrefs(target: str) -> dict[str, Any]:
    """Get cross-references for a function (callers and callees).

    Args:
        target: Function name or address

    Returns:
        Dict with callers (functions that call this) and callees (functions this calls)
    """
    return _request("GET", f"/functions/{target}/xrefs")


@mcp.tool()
def get_callgraph(target: str, depth: int = 3) -> dict[str, Any]:
    """Get call graph starting from a function.

    Args:
        target: Function name or address
        depth: Maximum depth to traverse (default: 3)

    Returns:
        Hierarchical call graph structure
    """
    return _request("GET", f"/functions/{target}/callgraph", params={"max_depth": depth})


# --- String Tools ---


@mcp.tool()
def list_strings(min_length: int = 4) -> list[dict[str, Any]]:
    """Get strings from the binary.

    Args:
        min_length: Minimum string length to include

    Returns:
        List of strings with address, value, type, length
    """
    return _request("GET", "/strings", params={"min_length": min_length})


@mcp.tool()
def search_strings(pattern: str, max_results: int = 100) -> list[dict[str, Any]]:
    """Search strings by regex pattern.

    Args:
        pattern: Regular expression pattern to match
        max_results: Maximum number of results

    Returns:
        Matching strings with address and value
    """
    return _request(
        "GET", "/strings/search", params={"pattern": pattern, "max_results": max_results}
    )


# --- Memory & Structure Tools ---


@mcp.tool()
def read_memory(address: str, length: int = 256) -> dict[str, Any]:
    """Read memory at specified address.

    Args:
        address: Memory address (e.g., "0x401000")
        length: Number of bytes to read

    Returns:
        Memory content in hex and ASCII representation
    """
    return _request("GET", f"/memory/{address}", params={"length": length})


@mcp.tool()
def get_imports() -> list[dict[str, Any]]:
    """Get imported functions.

    Returns:
        List of imports with name, address, library
    """
    return _request("GET", "/imports")


@mcp.tool()
def get_exports() -> list[dict[str, Any]]:
    """Get exported symbols.

    Returns:
        List of exports with name and address
    """
    return _request("GET", "/exports")


@mcp.tool()
def get_sections() -> list[dict[str, Any]]:
    """Get program sections/segments.

    Returns:
        List of sections with name, address range, size, permissions
    """
    return _request("GET", "/sections")


@mcp.tool()
def get_binary_info() -> dict[str, Any]:
    """Get binary metadata.

    Returns:
        Binary info including format, architecture, bits, endianness
    """
    return _request("GET", "/info")


@mcp.tool()
def get_global_callgraph() -> dict[str, Any]:
    """Get global call graph with all functions.

    Returns:
        Complete call graph with nodes and edges
    """
    return _request("GET", "/callgraph")


@mcp.tool()
def run_script(code: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a Python script in the Ghidra context.

    The script has access to program, flat_api, listing, func_manager,
    symbol_table, memory, args, and results dict.

    Args:
        code: Python code to execute
        args: Optional arguments passed to the script

    Returns:
        Dict with success, results, and optionally error

    Example:
        code = '''
        for func in func_manager.getFunctions(True):
            if 'connect' in func.getName().lower():
                results['found'] = func.getName()
                break
        '''
    """
    return _request("POST", "/script/run", json={"code": code, "args": args})


@mcp.tool()
def clear_flow_overrides(target: str | None = None) -> dict[str, Any]:
    """Clear incorrect flow overrides that prevent proper control flow analysis.

    Args:
        target: Optional function name/address. If None, clears all.

    Returns:
        Dict with cleared count and details
    """
    params = {"target": target} if target else None
    return _request("POST", "/utils/clear_flow_overrides", params=params)


@mcp.tool()
def find_orphan_code(min_size: int = 10) -> list[dict[str, Any]]:
    """Find potential orphan code regions not in any function.

    Args:
        min_size: Minimum size in bytes for orphan regions

    Returns:
        List of orphan code regions with address and size
    """
    return _request("GET", "/utils/orphan_code", params={"min_size": min_size})


def _build_http_app(path: str = "/mcp"):
    """Build HTTP app with CORS middleware."""
    if ALLOW_ORIGINS.strip() == "*":
        allow_origins = ["*"]
    else:
        allow_origins = [o.strip() for o in ALLOW_ORIGINS.split(",") if o.strip()]

    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=[
                "mcp-protocol-version",
                "mcp-session-id",
                "Authorization",
                "Content-Type",
            ],
            expose_headers=["mcp-session-id"],
        )
    ]

    return mcp.http_app(path=path, middleware=middleware, stateless_http=True)


if __name__ == "__main__":
    app = _build_http_app()
    uvicorn.run(app, host=MCP_HOST, port=MCP_PORT)
