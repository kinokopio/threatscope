#!/usr/bin/env python3
"""
Test script to verify Ghidra MCP endpoint is working.

Run this script to check if the MCP server is accessible and tools are registered.

Usage:
    python scripts/test_ghidra_mcp.py [ghidra_url]

    Default ghidra_url: http://localhost:8000
"""

import asyncio
import sys

import httpx


async def test_ghidra_mcp(base_url: str = "http://localhost:8000"):
    """Test Ghidra MCP endpoint."""
    mcp_url = f"{base_url}/mcp"

    print(f"Testing Ghidra MCP at: {mcp_url}")
    print("=" * 60)

    async with httpx.AsyncClient(timeout=30) as client:
        # Test 1: Health check
        print("\n[Test 1] Health check...")
        try:
            response = await client.get(f"{base_url}/health")
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.json()}")
        except Exception as e:
            print(f"  ERROR: {e}")
            return False

        # Test 2: MCP Initialize
        print("\n[Test 2] MCP Initialize...")
        try:
            response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "test-client", "version": "1.0.0"},
                    },
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            print(f"  Status: {response.status_code}")
            print(f"  Headers: {dict(response.headers)}")
            if response.status_code == 200:
                print(f"  Response: {response.text[:500]}")
            else:
                print(f"  Response: {response.text}")
        except Exception as e:
            print(f"  ERROR: {e}")

        # Test 3: List tools
        print("\n[Test 3] List MCP tools...")
        try:
            response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
            print(f"  Status: {response.status_code}")
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "result" in data and "tools" in data["result"]:
                        tools = data["result"]["tools"]
                        print(f"  Found {len(tools)} tools:")
                        for tool in tools:
                            print(f"    - {tool['name']}")
                    else:
                        print(f"  Response: {data}")
                except Exception:
                    print(f"  Response (raw): {response.text[:500]}")
            else:
                print(f"  Response: {response.text}")
        except Exception as e:
            print(f"  ERROR: {e}")

        # Test 4: Check if MCP endpoint exists
        print("\n[Test 4] Check MCP endpoint (OPTIONS)...")
        try:
            response = await client.options(mcp_url)
            print(f"  Status: {response.status_code}")
            print(f"  Allow: {response.headers.get('allow', 'N/A')}")
        except Exception as e:
            print(f"  ERROR: {e}")

        # Test 5: Try GET on MCP endpoint
        print("\n[Test 5] GET MCP endpoint...")
        try:
            response = await client.get(mcp_url)
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.text[:200]}")
        except Exception as e:
            print(f"  ERROR: {e}")

    print("\n" + "=" * 60)
    print("Test completed. Check the output above for issues.")
    return True


async def test_claude_sdk_connection(base_url: str = "http://localhost:8000"):
    """Test Claude SDK can connect to Ghidra MCP."""
    import os

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\n[Claude SDK Test] Skipped - ANTHROPIC_API_KEY not set")
        return True

    print("\n" + "=" * 60)
    print("[Claude SDK Test] Testing connection...")
    print("=" * 60)

    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
        from claude_agent_sdk.types import AssistantMessage, ToolUseBlock, ResultMessage

        mcp_url = f"{base_url}/mcp"

        options = ClaudeAgentOptions(
            model="claude-sonnet-4-20250514",
            system_prompt="You are a test assistant. List available tools by calling list_functions.",
            mcp_servers={
                "ghidra": {
                    "type": "http",
                    "url": mcp_url,
                }
            },
            allowed_tools=["mcp__ghidra__*"],
            max_turns=2,
        )

        print(f"Connecting to MCP server at: {mcp_url}")

        async with ClaudeSDKClient(options=options) as client:
            await client.query("What tools are available? Try to list functions.")

            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, ToolUseBlock):
                            print(f"  Tool called: {block.name}")
                            print(f"  Tool input: {block.input}")
                elif isinstance(msg, ResultMessage):
                    if msg.is_error:
                        print(f"  ERROR: {msg.result}")
                    else:
                        print(f"  Success! Turns: {msg.num_turns}")

        print("\nClaude SDK test completed!")
        return True

    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback

        traceback.print_exc()
        return False


async def main():
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"

    await test_ghidra_mcp(base_url)
    await test_claude_sdk_connection(base_url)


if __name__ == "__main__":
    asyncio.run(main())
