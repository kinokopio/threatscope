"""Utility tools for AI agents - SDK MCP Server implementation.

Provides basic capabilities like encoding/decoding, hashing, and binary analysis
as in-process MCP tools for use with claude-agent-sdk.
"""

import base64
import hashlib
import subprocess
import zlib
from typing import Any

from claude_agent_sdk import create_sdk_mcp_server, tool


@tool("decode_base64", "Decode Base64 encoded string", {"data": str})
async def decode_base64(args: dict[str, Any]) -> dict:
    """Decode Base64 string."""
    try:
        result = base64.b64decode(args["data"]).decode("utf-8", errors="replace")
        return {"content": [{"type": "text", "text": result}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


@tool("encode_base64", "Encode string to Base64", {"data": str})
async def encode_base64(args: dict[str, Any]) -> dict:
    """Encode string to Base64."""
    result = base64.b64encode(args["data"].encode()).decode()
    return {"content": [{"type": "text", "text": result}]}


@tool("decode_hex", "Decode hex string to text", {"data": str})
async def decode_hex(args: dict[str, Any]) -> dict:
    """Decode hex string."""
    try:
        result = bytes.fromhex(args["data"]).decode("utf-8", errors="replace")
        return {"content": [{"type": "text", "text": result}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


@tool("encode_hex", "Encode string to hex", {"data": str})
async def encode_hex(args: dict[str, Any]) -> dict:
    """Encode string to hex."""
    result = args["data"].encode().hex()
    return {"content": [{"type": "text", "text": result}]}


@tool(
    "xor_decrypt",
    "XOR decrypt data with key",
    {"data_hex": str, "key": str},
)
async def xor_decrypt(args: dict[str, Any]) -> dict:
    """XOR decrypt data."""
    try:
        data = bytes.fromhex(args["data_hex"])
        key = args["key"]
        # Key can be hex or string
        if all(c in "0123456789abcdefABCDEF" for c in key) and len(key) % 2 == 0:
            try:
                key_bytes = bytes.fromhex(key)
            except ValueError:
                key_bytes = key.encode()
        else:
            key_bytes = key.encode()

        result = bytes([d ^ key_bytes[i % len(key_bytes)] for i, d in enumerate(data)])

        # Try to decode as UTF-8, fallback to hex
        try:
            text = result.decode("utf-8")
            return {"content": [{"type": "text", "text": text}]}
        except UnicodeDecodeError:
            return {"content": [{"type": "text", "text": result.hex()}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


@tool(
    "calculate_hash",
    "Calculate hash of data (md5, sha1, sha256)",
    {"data": str, "algorithm": str},
)
async def calculate_hash(args: dict[str, Any]) -> dict:
    """Calculate hash value."""
    algo = args.get("algorithm", "sha256").lower()
    data = args["data"].encode()

    if algo == "md5":
        result = hashlib.md5(data).hexdigest()
    elif algo == "sha1":
        result = hashlib.sha1(data).hexdigest()
    else:
        result = hashlib.sha256(data).hexdigest()

    return {"content": [{"type": "text", "text": result}]}


@tool("rot13", "Apply ROT13 transformation", {"data": str})
async def rot13(args: dict[str, Any]) -> dict:
    """Apply ROT13 transformation."""
    import codecs

    result = codecs.encode(args["data"], "rot_13")
    return {"content": [{"type": "text", "text": result}]}


@tool("decompress_zlib", "Decompress zlib data (hex input)", {"data_hex": str})
async def decompress_zlib(args: dict[str, Any]) -> dict:
    """Decompress zlib data."""
    try:
        data = bytes.fromhex(args["data_hex"])
        result = zlib.decompress(data)
        try:
            text = result.decode("utf-8")
            return {"content": [{"type": "text", "text": text}]}
        except UnicodeDecodeError:
            return {"content": [{"type": "text", "text": result.hex()}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


# Linux binary analysis tools


@tool(
    "strings_search",
    "Extract strings from binary file",
    {"file_path": str, "min_length": int},
)
async def strings_search(args: dict[str, Any]) -> dict:
    """Extract strings from binary."""
    try:
        min_len = args.get("min_length", 4)
        result = subprocess.run(
            ["strings", "-n", str(min_len), args["file_path"]],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout[:50000]  # Limit output size
        return {"content": [{"type": "text", "text": output}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "Error: Command timed out"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


@tool(
    "grep_binary",
    "Search pattern in binary file",
    {"file_path": str, "pattern": str, "context_lines": int},
)
async def grep_binary(args: dict[str, Any]) -> dict:
    """Search pattern in binary."""
    try:
        ctx = args.get("context_lines", 0)
        cmd = ["grep", "-a", "-n"]
        if ctx > 0:
            cmd.extend(["-C", str(ctx)])
        cmd.extend([args["pattern"], args["file_path"]])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout[:20000]
        return {"content": [{"type": "text", "text": output}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "Error: Command timed out"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


@tool(
    "hexdump",
    "Hex dump of file section",
    {"file_path": str, "offset": int, "length": int},
)
async def hexdump(args: dict[str, Any]) -> dict:
    """Hex dump file section."""
    try:
        cmd = ["hexdump", "-C"]
        if "offset" in args and args["offset"]:
            cmd.extend(["-s", str(args["offset"])])
        if "length" in args and args["length"]:
            cmd.extend(["-n", str(args["length"])])
        else:
            cmd.extend(["-n", "512"])  # Default limit
        cmd.append(args["file_path"])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {"content": [{"type": "text", "text": result.stdout}]}
    except subprocess.TimeoutExpired:
        return {"content": [{"type": "text", "text": "Error: Command timed out"}]}
    except Exception as e:
        return {"content": [{"type": "text", "text": f"Error: {e}"}]}


def create_utils_mcp_server():
    """Create the utilities MCP server with all tools.

    Returns:
        SDK MCP server instance for use with ClaudeAgentOptions.
    """
    return create_sdk_mcp_server(
        name="utils",
        version="1.0.0",
        tools=[
            decode_base64,
            encode_base64,
            decode_hex,
            encode_hex,
            xor_decrypt,
            calculate_hash,
            rot13,
            decompress_zlib,
            strings_search,
            grep_binary,
        ],
    )
