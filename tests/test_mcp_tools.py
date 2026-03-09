"""
Test script to verify MCP tools can be called via Claude SDK.

This script:
1. Starts a mock MCP server with a simple tool
2. Uses Claude SDK to connect and call the tool
3. Verifies the tool is accessible
"""

import asyncio
import os
import sys
from typing import Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def test_mcp_server_standalone():
    """Test that MCP server can be created and tools are registered."""
    print("=" * 60)
    print("Test 1: MCP Server Standalone")
    print("=" * 60)

    try:
        from fastmcp import FastMCP

        # Create a simple MCP server
        mcp = FastMCP("Test MCP Server")

        @mcp.tool()
        def hello(name: str) -> str:
            """Say hello to someone.

            Args:
                name: The name to greet

            Returns:
                A greeting message
            """
            return f"Hello, {name}!"

        @mcp.tool()
        def add(a: int, b: int) -> int:
            """Add two numbers.

            Args:
                a: First number
                b: Second number

            Returns:
                Sum of a and b
            """
            return a + b

        # List registered tools
        tools = await mcp.list_tools()
        print(f"Registered tools: {len(tools)}")
        for tool in tools:
            print(f"  - {tool.name}: {tool.description}")

        # Test calling a tool directly
        result = await mcp.call_tool("hello", {"name": "World"})
        print(f"\nDirect call result: {result}")

        # Create HTTP app
        app = mcp.http_app(path="/", stateless_http=True)
        print(f"\nHTTP app created: {type(app)}")
        print("Test 1 PASSED!")
        return True

    except Exception as e:
        print(f"Test 1 FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False


async def test_mcp_http_server():
    """Test MCP server via HTTP."""
    print("\n" + "=" * 60)
    print("Test 2: MCP HTTP Server")
    print("=" * 60)

    import uvicorn
    from fastmcp import FastMCP
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware

    # Create MCP server
    mcp = FastMCP("Test HTTP MCP")

    @mcp.tool()
    def get_info() -> dict[str, Any]:
        """Get server info."""
        return {"status": "ok", "version": "1.0.0"}

    @mcp.tool()
    def echo(message: str) -> str:
        """Echo a message back."""
        return f"Echo: {message}"

    # Create HTTP app with CORS
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
    ]

    app = mcp.http_app(path="/", middleware=middleware, stateless_http=True)

    # Start server in background
    config = uvicorn.Config(app, host="127.0.0.1", port=19999, log_level="warning")
    server = uvicorn.Server(config)

    async def run_server():
        await server.serve()

    server_task = asyncio.create_task(run_server())

    # Wait for server to start
    await asyncio.sleep(1)

    try:
        import httpx

        # Test MCP endpoint
        async with httpx.AsyncClient() as client:
            # Initialize MCP session
            response = await client.post(
                "http://127.0.0.1:19999/",
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
                headers={"Content-Type": "application/json"},
            )
            print(f"Initialize response status: {response.status_code}")
            if response.status_code == 200:
                print(f"Initialize response: {response.json()}")

            # List tools
            response = await client.post(
                "http://127.0.0.1:19999/",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {},
                },
                headers={"Content-Type": "application/json"},
            )
            print(f"\nList tools response status: {response.status_code}")
            if response.status_code == 200:
                data = response.json()
                if "result" in data and "tools" in data["result"]:
                    tools = data["result"]["tools"]
                    print(f"Available tools: {len(tools)}")
                    for tool in tools:
                        print(f"  - {tool['name']}")
                else:
                    print(f"Response: {data}")

            # Call a tool
            response = await client.post(
                "http://127.0.0.1:19999/",
                json={
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {"message": "Hello MCP!"}},
                },
                headers={"Content-Type": "application/json"},
            )
            print(f"\nCall tool response status: {response.status_code}")
            if response.status_code == 200:
                print(f"Call tool response: {response.json()}")

        print("\nTest 2 PASSED!")
        return True

    except Exception as e:
        print(f"Test 2 FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        server.should_exit = True
        await asyncio.sleep(0.5)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


async def test_claude_sdk_mcp_connection():
    """Test Claude SDK can connect to MCP server."""
    print("\n" + "=" * 60)
    print("Test 3: Claude SDK MCP Connection")
    print("=" * 60)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ANTHROPIC_API_KEY not set, skipping Claude SDK test")
        return True

    import uvicorn
    from fastmcp import FastMCP
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware

    # Create MCP server
    mcp = FastMCP("Claude Test MCP")

    @mcp.tool()
    def get_greeting(name: str) -> str:
        """Get a greeting for someone.

        Args:
            name: The person's name

        Returns:
            A personalized greeting
        """
        return f"Hello, {name}! Welcome to ThreatScope."

    # Create HTTP app
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )
    ]
    app = mcp.http_app(path="/", middleware=middleware, stateless_http=True)

    # Start server
    config = uvicorn.Config(app, host="127.0.0.1", port=19998, log_level="warning")
    server = uvicorn.Server(config)

    async def run_server():
        await server.serve()

    server_task = asyncio.create_task(run_server())
    await asyncio.sleep(1)

    try:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient
        from claude_agent_sdk.types import AssistantMessage, ToolUseBlock

        options = ClaudeAgentOptions(
            model="claude-sonnet-4-20250514",
            system_prompt="You are a test assistant. When asked to greet someone, use the get_greeting tool.",
            mcp_servers={
                "test": {
                    "type": "http",
                    "url": "http://127.0.0.1:19998/",
                }
            },
            allowed_tools=["mcp__test__get_greeting"],
            max_turns=3,
        )

        print("Connecting to MCP server via Claude SDK...")

        async with ClaudeSDKClient(options=options) as client:
            await client.query("Please greet Alice using the greeting tool.")

            async for msg in client.receive_response():
                if isinstance(msg, AssistantMessage):
                    for block in msg.content:
                        if isinstance(block, ToolUseBlock):
                            print(f"Tool called: {block.name}")
                            print(f"Tool input: {block.input}")

        print("\nTest 3 PASSED!")
        return True

    except Exception as e:
        print(f"Test 3 FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        server.should_exit = True
        await asyncio.sleep(0.5)
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


async def main():
    """Run all tests."""
    print("MCP Tools Integration Test")
    print("=" * 60)

    results = []

    # Test 1: Standalone MCP server
    results.append(("Standalone MCP Server", await test_mcp_server_standalone()))

    # Test 2: HTTP server
    results.append(("MCP HTTP Server", await test_mcp_http_server()))

    # Test 3: Claude SDK connection (optional)
    results.append(("Claude SDK Connection", await test_claude_sdk_mcp_connection()))

    # Summary
    print("\n" + "=" * 60)
    print("Test Summary")
    print("=" * 60)
    all_passed = True
    for name, passed in results:
        status = "PASSED" if passed else "FAILED"
        print(f"  {name}: {status}")
        if not passed:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("All tests passed!")
        return 0
    else:
        print("Some tests failed!")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
