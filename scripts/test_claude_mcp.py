#!/usr/bin/env python3
"""
Test script to verify Claude SDK can connect to Ghidra MCP.

Run inside the backend container:
    docker exec -it threatscope_backend python /app/scripts/test_claude_mcp.py
"""

import asyncio
import os
import sys

sys.path.insert(0, "/app")


async def test_mcp_connection():
    """Test MCP connection via Claude SDK."""
    ghidra_url = os.environ.get("THREATSCOPE_GHIDRA_URL", "http://ghidra:8000")
    mcp_url = f"{ghidra_url}/mcp/"

    print(f"Testing MCP connection to: {mcp_url}")
    print("=" * 60)

    # Test 1: Direct HTTP test
    print("\n[Test 1] Direct HTTP test...")
    try:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
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
                print(f"  Response length: {len(response.text)} bytes")
                if "list_functions" in response.text:
                    print("  ✓ Tools found in response!")
                else:
                    print("  ✗ No tools in response")
            else:
                print(f"  Response: {response.text[:500]}")
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback

        traceback.print_exc()

    # Test 2: Claude SDK connection
    print("\n[Test 2] Claude SDK connection...")
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("  ANTHROPIC_API_KEY not set, skipping")
        return

    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
        from claude_agent_sdk.types import (
            AssistantMessage,
            ToolUseBlock,
            ResultMessage,
            SystemMessage,
        )

        options = ClaudeAgentOptions(
            model="claude-sonnet-4-20250514",
            system_prompt="You are a test assistant. Try to list available tools.",
            mcp_servers={
                "ghidra": {
                    "type": "http",
                    "url": mcp_url,
                }
            },
            allowed_tools=["mcp__ghidra__*"],
            max_turns=2,
        )

        print(f"  Connecting with allowed_tools: {options.allowed_tools}")

        async with ClaudeSDKClient(options=options) as client:
            await client.query("List the available Ghidra tools.")

            async for msg in client.receive_response():
                if isinstance(msg, SystemMessage):
                    print(f"  [System] {msg.subtype}: {msg.data}")
                elif isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, ToolUseBlock):
                            print(f"  [Tool Call] {block.name}")
                            print(f"    Input: {block.input}")
                elif isinstance(msg, ResultMessage):
                    print(f"  [Result] Error: {msg.is_error}, Turns: {msg.num_turns}")
                    if msg.result:
                        print(f"    Result: {msg.result[:200]}...")

        print("\n  ✓ Claude SDK test completed!")

    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(test_mcp_connection())
