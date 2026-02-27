"""GhidraAgent - AI-driven deep reverse engineering analysis using claude-agent-sdk."""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Callable

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ClaudeSDKError,
    CLIConnectionError,
    CLINotFoundError,
    HookMatcher,
    ProcessError,
    TextBlock,
    ResultMessage,
    ToolUseBlock,
    create_sdk_mcp_server,
    tool,
)

from ai.base import AgentConfig, AgentResult, BaseAgent
from ai.memory_store import MemoryStore
from ai.utils_tools import create_utils_mcp_server
from ghidra_service.client import GhidraClient

logger = logging.getLogger(__name__)

# Default timeout for AI analysis (5 minutes for complex binary analysis)
DEFAULT_AI_TIMEOUT = 300


def create_memory_tools_server(memory_store: MemoryStore):
    """Create memory tools MCP server for the agent.

    Args:
        memory_store: MemoryStore instance for persistence.

    Returns:
        SDK MCP server with memory tools.
    """
    from datetime import datetime

    @tool(
        "memory_save_finding",
        "Save an important finding to persistent memory",
        {"type": str, "summary": str, "evidence": dict, "severity": str},
    )
    async def save_finding(args: dict[str, Any]) -> dict:
        finding = {
            "id": f"finding_{len(memory_store.get_findings()) + 1:03d}",
            "type": args["type"],
            "summary": args["summary"],
            "evidence": args.get("evidence", {}),
            "severity": args.get("severity", "medium"),
            "discovered_at": datetime.now().isoformat(),
        }
        findings = memory_store.get_findings()
        findings.append(finding)
        memory_store.save_findings(findings)
        return {"content": [{"type": "text", "text": f"Saved finding: {finding['id']}"}]}

    @tool(
        "memory_get_findings",
        "Get previously saved findings",
        {"filter_type": str},
    )
    async def get_findings(args: dict[str, Any]) -> dict:
        findings = memory_store.get_findings()
        filter_type = args.get("filter_type")
        if filter_type:
            findings = [f for f in findings if f.get("type") == filter_type]
        return {"content": [{"type": "text", "text": json.dumps(findings, indent=2)}]}

    @tool(
        "memory_cache_function",
        "Cache function analysis result",
        {"name": str, "analysis": dict},
    )
    async def cache_function(args: dict[str, Any]) -> dict:
        memory_store.cache_function(args["name"], args["analysis"])
        return {"content": [{"type": "text", "text": f"Cached function: {args['name']}"}]}

    @tool("memory_get_function", "Get cached function analysis", {"name": str})
    async def get_function(args: dict[str, Any]) -> dict:
        result = memory_store.get_function(args["name"])
        if result:
            return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
        return {"content": [{"type": "text", "text": "Function not cached"}]}

    @tool("memory_list_cached_functions", "List all cached function names", {})
    async def list_cached_functions(args: dict[str, Any]) -> dict:
        functions = memory_store.list_cached_functions()
        return {"content": [{"type": "text", "text": json.dumps(functions)}]}

    @tool(
        "memory_save_checkpoint",
        "Save analysis checkpoint",
        {"phase": str, "summary": str},
    )
    async def save_checkpoint(args: dict[str, Any]) -> dict:
        state = {
            "current_phase": args["phase"],
            "context_summary": args["summary"],
            "analyzed_functions": memory_store.list_cached_functions(),
        }
        memory_store.save_checkpoint(state)
        return {"content": [{"type": "text", "text": "Checkpoint saved"}]}

    @tool("memory_restore_checkpoint", "Restore analysis checkpoint", {})
    async def restore_checkpoint(args: dict[str, Any]) -> dict:
        state = memory_store.restore_checkpoint()
        if state:
            return {"content": [{"type": "text", "text": json.dumps(state, indent=2)}]}
        return {"content": [{"type": "text", "text": "No checkpoint found"}]}

    return create_sdk_mcp_server(
        name="memory",
        version="1.0.0",
        tools=[
            save_finding,
            get_findings,
            cache_function,
            get_function,
            list_cached_functions,
            save_checkpoint,
            restore_checkpoint,
        ],
    )


def create_pre_compact_hook(memory_store: MemoryStore):
    """Create PreCompact hook for context compression.

    This hook is called before Claude compresses context, allowing us to
    save critical findings and provide guidance on what to preserve.

    Args:
        memory_store: MemoryStore instance for persistence.

    Returns:
        Async hook function.
    """

    async def pre_compact_hook(input_data, tool_use_id, context):
        """Hook called before context compression."""
        _ = input_data.get("trigger", "auto")  # Available for future use

        # Get current findings and cached functions
        findings = memory_store.get_findings()
        cached_functions = memory_store.list_cached_functions()

        # Build findings summary
        findings_summary = (
            "\n".join(
                [
                    f"- [{f.get('severity', 'unknown')}] {f.get('type', 'unknown')}: {f.get('summary', '')}"
                    for f in findings[:10]
                ]
            )
            if findings
            else "No findings yet"
        )

        return {
            "hookSpecificOutput": {
                "hookEventName": "PreCompact",
                "additionalContext": f"""
When compressing context, please preserve:

## Key Findings (from local memory)
{findings_summary}

## Analyzed Functions ({len(cached_functions)} total)
{", ".join(cached_functions[:20])}

## Compression Guidelines
1. Preserve all ATT&CK technique mappings
2. Preserve key IoCs (domains, IPs, URLs)
3. Preserve current analysis path and next steps
4. Decompiled code can be discarded (recoverable from memory)
""",
            }
        }

    return pre_compact_hook


class GhidraAgent(BaseAgent):
    """AI agent for deep binary analysis using Ghidra and claude-agent-sdk.

    This agent uses Claude to autonomously analyze binaries with Ghidra tools,
    making intelligent decisions about which functions to analyze and how to
    interpret the results.
    """

    def __init__(
        self,
        config: AgentConfig,
        project_dir: str | Path = ".",
        ghidra_url: str = "http://localhost:8000",
        ai_timeout: int = DEFAULT_AI_TIMEOUT,
    ):
        """Initialize GhidraAgent.

        Args:
            config: Agent configuration.
            project_dir: Project directory for memory storage.
            ghidra_url: URL of Ghidra HTTP service.
            ai_timeout: Timeout in seconds for AI analysis (default: 300s).
        """
        super().__init__(config)
        self.project_dir = Path(project_dir)
        self.ghidra_url = ghidra_url
        self.ai_timeout = ai_timeout
        self.memory_store: MemoryStore | None = None
        self.ghidra_client: GhidraClient | None = None

    @property
    def name(self) -> str:
        return "ghidra_agent"

    async def analyze(
        self,
        context: dict[str, Any],
        progress_callback: Callable[[str, str, str, dict | None], Any] | None = None,
    ) -> AgentResult:
        """Perform deep analysis using Ghidra with AI-driven exploration.

        Args:
            context: Analysis context containing:
                - static_results: Results from static analysis
                - file_path: Path to the binary file
                - sample_hash: SHA256 hash of the sample
            progress_callback: Optional async callback for progress updates.
                Signature: (step_id, step_name, status, preview_data) -> None

        Returns:
            AgentResult with deep analysis findings.
        """
        self._progress_callback = progress_callback
        static_results = context.get("static_results", {})
        file_path = context.get("file_path", "")
        sample_hash = context.get("sample_hash", "")

        if not sample_hash:
            sample_hash = static_results.get("hashes", {}).get("sha256", "unknown")

        # Initialize memory store
        self.memory_store = MemoryStore(self.project_dir, sample_hash)

        # Initialize Ghidra client
        self.ghidra_client = GhidraClient(self.ghidra_url)

        # Check for previous analysis
        cached_functions = self.memory_store.list_cached_functions()
        previous_findings = self.memory_store.get_findings()

        # Try to connect to Ghidra service
        ghidra_available = False
        ghidra_info = {}
        try:
            print(f"=== GHIDRA_AGENT: Connecting to Ghidra at: {self.ghidra_url} ===", flush=True)
            logger.info(f"=== GHIDRA_AGENT: Connecting to Ghidra at: {self.ghidra_url} ===")
            self.ghidra_client.health_check()
            print("=== GHIDRA_AGENT: Health check passed! ===", flush=True)
            logger.info("=== GHIDRA_AGENT: Health check passed! ===")
            ghidra_available = True

            # If file provided and not already loaded, upload it
            if file_path and Path(file_path).exists():
                try:
                    print(f"=== GHIDRA_AGENT: Uploading {file_path} ===", flush=True)
                    self.ghidra_client.upload(file_path)
                    print("=== GHIDRA_AGENT: Running analysis ===", flush=True)
                    self.ghidra_client.analyze()
                    ghidra_info = self.ghidra_client.get_info()
                    print(f"=== GHIDRA_AGENT: Got info: {ghidra_info} ===", flush=True)
                except Exception as e:
                    print(f"=== GHIDRA_AGENT: Failed to load binary: {e} ===", flush=True)
                    logger.warning(f"Failed to load binary: {e}")
        except Exception as e:
            print(f"=== GHIDRA_AGENT: Service not available: {e} ===", flush=True)
            logger.warning(f"Ghidra service not available: {e}")
        # If Ghidra is available, run AI-driven analysis
        if ghidra_available and ghidra_info:
            try:
                ai_results = await self._run_ai_analysis(
                    static_results=static_results,
                    file_path=file_path,
                    cached_functions=cached_functions,
                    previous_findings=previous_findings,
                    ghidra_info=ghidra_info,
                )
                return AgentResult(
                    success=True,
                    data={
                        "status": "completed",
                        "ghidra_available": True,
                        "ghidra_info": ghidra_info,
                        "ai_analysis": ai_results,
                        "cached_functions": self.memory_store.list_cached_functions(),
                        "findings_count": len(self.memory_store.get_findings()),
                    },
                )
            except asyncio.TimeoutError:
                logger.error(f"AI analysis timed out after {self.ai_timeout}s")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, "AI analysis timed out"
                )
            except (CLINotFoundError, CLIConnectionError) as e:
                logger.error(f"Claude SDK not available: {e}")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, f"Claude SDK error: {e}"
                )
            except ProcessError as e:
                logger.error(f"Claude process error (exit {e.exit_code}): {e}")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, f"Process error: {e}"
                )
            except ClaudeSDKError as e:
                logger.error(f"Claude SDK error: {e}")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, f"SDK error: {e}"
                )
            except ValueError as e:
                logger.error(f"Configuration error: {e}")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, f"Config error: {e}"
                )
            except Exception as e:
                logger.error(f"AI analysis failed: {e}")
                return await self._fallback_analysis(
                    static_results, cached_functions, ghidra_info, str(e)
                )

        # Ghidra not available - return ready status
        return AgentResult(
            success=True,
            data={
                "status": "ghidra_unavailable",
                "ghidra_available": False,
                "cached_functions": cached_functions,
                "previous_findings_count": len(previous_findings),
                "message": "Ghidra service not available. Start Ghidra service for full analysis.",
            },
        )

    async def _run_ai_analysis(
        self,
        static_results: dict,
        file_path: str,
        cached_functions: list[str],
        previous_findings: list[dict],
        ghidra_info: dict,
    ) -> dict[str, Any]:
        """Run AI-driven analysis using claude-agent-sdk.

        Args:
            static_results: Static analysis results.
            file_path: Path to binary file.
            cached_functions: Previously analyzed functions.
            previous_findings: Previous findings from memory.
            ghidra_info: Ghidra binary info.

        Returns:
            AI analysis results.

        Raises:
            ValueError: If ANTHROPIC_API_KEY is not set.
            asyncio.TimeoutError: If analysis times out.
            ClaudeSDKError: If SDK encounters an error.
        """
        # Check for API key first to fail fast
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")

        # Build the analysis prompt
        prompt = self._build_analysis_prompt(
            static_results=static_results,
            file_path=file_path,
            cached_functions=cached_functions,
            previous_findings=previous_findings,
            ghidra_info=ghidra_info,
        )

        # Load system prompt
        system_prompt = self.load_system_prompt()

        # Create MCP servers
        utils_server = create_utils_mcp_server()
        memory_server = create_memory_tools_server(self.memory_store)

        # Configure agent options
        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model="claude-sonnet-4-20250514",
            mcp_servers={
                "ghidra": {
                    "type": "http",
                    "url": f"{self.ghidra_url}/mcp",
                },
                "utils": utils_server,
                "memory": memory_server,
            },
            allowed_tools=[
                # Ghidra tools
                "mcp__ghidra__list_functions",
                "mcp__ghidra__decompile_function",
                "mcp__ghidra__disassemble_function",
                "mcp__ghidra__get_function_details",
                "mcp__ghidra__list_strings",
                "mcp__ghidra__search_strings",
                "mcp__ghidra__function_xrefs",
                "mcp__ghidra__get_callgraph",
                "mcp__ghidra__read_memory",
                "mcp__ghidra__get_imports",
                "mcp__ghidra__get_exports",
                "mcp__ghidra__get_sections",
                # Utility tools
                "mcp__utils__decode_base64",
                "mcp__utils__encode_base64",
                "mcp__utils__decode_hex",
                "mcp__utils__encode_hex",
                "mcp__utils__xor_decrypt",
                "mcp__utils__calculate_hash",
                "mcp__utils__strings_search",
                "mcp__utils__grep_binary",
                "mcp__utils__hexdump",
                # Memory tools
                "mcp__memory__memory_save_finding",
                "mcp__memory__memory_get_findings",
                "mcp__memory__memory_cache_function",
                "mcp__memory__memory_get_function",
                "mcp__memory__memory_list_cached_functions",
                "mcp__memory__memory_save_checkpoint",
                "mcp__memory__memory_restore_checkpoint",
            ],
            max_turns=self.config.max_iterations,
            hooks={
                "PreCompact": [
                    HookMatcher(matcher=None, hooks=[create_pre_compact_hook(self.memory_store)])
                ]
            },
        )

        # Tool name to human-readable description mapping
        tool_descriptions = {
            "mcp__ghidra__list_functions": "Listing functions",
            "mcp__ghidra__decompile_function": "Decompiling function",
            "mcp__ghidra__disassemble_function": "Disassembling function",
            "mcp__ghidra__get_function_details": "Getting function details",
            "mcp__ghidra__list_strings": "Listing strings",
            "mcp__ghidra__search_strings": "Searching strings",
            "mcp__ghidra__function_xrefs": "Getting cross-references",
            "mcp__ghidra__get_callgraph": "Building call graph",
            "mcp__ghidra__read_memory": "Reading memory",
            "mcp__ghidra__get_imports": "Getting imports",
            "mcp__ghidra__get_exports": "Getting exports",
            "mcp__ghidra__get_sections": "Getting sections",
            "mcp__memory__memory_save_finding": "Saving finding",
            "mcp__memory__memory_cache_function": "Caching function analysis",
        }

        async def _call_ai() -> dict[str, Any]:
            """Inner function for AI call."""
            result_text = ""
            tool_call_count = 0
            functions_analyzed = 0
            findings_saved = 0
            
            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                async for msg in client.receive_response():
                    # Handle assistant messages (AI responses with potential tool use)
                    if isinstance(msg, AssistantMessage):
                        if not hasattr(msg, 'content') or not msg.content:
                            continue
                        for block in msg.content:
                            if isinstance(block, ToolUseBlock):
                                tool_call_count += 1
                                tool_name = block.name
                                tool_input = block.input or {}
                                
                                # Get human-readable description
                                description = tool_descriptions.get(
                                    tool_name, 
                                    tool_name.replace("mcp__", "").replace("__", ": ").replace("_", " ").title()
                                )
                                
                                # Extract relevant info for preview
                                preview_data = {
                                    "tool": tool_name,
                                    "tool_call_count": tool_call_count,
                                }
                                
                                # Add context based on tool type
                                if "function" in tool_name.lower():
                                    func_name = tool_input.get("name") or tool_input.get("function_name", "")
                                    if func_name:
                                        description = f"{description}: {func_name}"
                                        preview_data["function"] = func_name
                                        functions_analyzed += 1
                                elif "string" in tool_name.lower():
                                    pattern = tool_input.get("pattern", "")
                                    if pattern:
                                        description = f"{description}: {pattern}"
                                        preview_data["pattern"] = pattern
                                elif "save" in tool_name.lower() or "finding" in tool_name.lower():
                                    findings_saved += 1
                                
                                # Send progress notification
                                if self._progress_callback:
                                    try:
                                        await self._progress_callback(
                                            "ghidra_tool",
                                            description,
                                            "running",
                                            preview_data,
                                        )
                                    except Exception as e:
                                        logger.debug(f"Progress callback failed: {e}")
                                
                                logger.info(f"AI tool call #{tool_call_count}: {description}")
                            
                            elif isinstance(block, TextBlock):
                                result_text = block.text
                    
                    # Handle result message (final stats, no content attribute)
                    elif isinstance(msg, ResultMessage):
                        # ResultMessage has num_turns, total_cost_usd, duration_ms, session_id
                        # but NOT content - it's the final summary message
                        logger.info(f"AI analysis result: turns={getattr(msg, 'num_turns', 'N/A')}, cost=${getattr(msg, 'total_cost_usd', 0):.4f}")
                        
                        # Send completion notification
                        if self._progress_callback:
                            try:
                                await self._progress_callback(
                                    "ghidra_tool",
                                    "AI Analysis Complete",
                                    "completed",
                                    {
                                        "tool_call_count": tool_call_count,
                                        "functions_analyzed": functions_analyzed,
                                        "findings_saved": findings_saved,
                                        "num_turns": getattr(msg, 'num_turns', 0),
                                        "cost_usd": getattr(msg, 'total_cost_usd', 0),
                                    },
                                )
                            except Exception as e:
                                logger.debug(f"Progress callback failed: {e}")
            # Send final summary
            if self._progress_callback:
                try:
                    await self._progress_callback(
                        "ghidra_ai",
                        "AI Analysis Complete",
                        "completed",
                        {
                            "total_tool_calls": tool_call_count,
                            "functions_analyzed": functions_analyzed,
                            "findings_saved": findings_saved,
                        },
                    )
                except Exception as e:
                    logger.debug(f"Progress callback failed: {e}")
            
            logger.info(f"AI analysis completed: {tool_call_count} tool calls, {functions_analyzed} functions analyzed")
            # Parse JSON result
            try:
                # Extract JSON from response
                if "```json" in result_text:
                    start = result_text.find("```json") + 7
                    end = result_text.find("```", start)
                    if end > start:
                        result_text = result_text[start:end].strip()
                elif "```" in result_text:
                    start = result_text.find("```") + 3
                    end = result_text.find("```", start)
                    if end > start:
                        result_text = result_text[start:end].strip()

                return json.loads(result_text)
            except json.JSONDecodeError:
                # Return raw text if not valid JSON
                return {
                    "raw_analysis": result_text,
                    "analyzed_functions": [],
                    "key_findings": self.memory_store.get_findings(),
                }

        # Run with timeout
        return await asyncio.wait_for(_call_ai(), timeout=self.ai_timeout)

    async def _fallback_analysis(
        self,
        static_results: dict,
        cached_functions: list[str],
        ghidra_info: dict,
        error_message: str = "AI analysis unavailable",
    ) -> AgentResult:
        """Fallback to rule-based analysis when AI is unavailable.

        Args:
            static_results: Static analysis results.
            cached_functions: Previously analyzed functions.
            ghidra_info: Ghidra binary info.
            error_message: Reason for fallback.

        Returns:
            AgentResult with rule-based analysis.
        """
        results = {
            "analyzed_functions": [],
            "key_findings": [],
            "suspicious_functions": [],
        }

        try:
            # Get function list
            functions = self.ghidra_client.list_functions(limit=500)

            # Identify interesting functions
            targets = self._identify_targets(static_results, functions)

            # Analyze each target
            for target in targets[:20]:
                if target in cached_functions:
                    cached = self.memory_store.get_function(target)
                    if cached:
                        results["analyzed_functions"].append(cached)
                        continue

                try:
                    decomp = self.ghidra_client.decompile_function(target)
                    if not decomp:
                        continue

                    xrefs = self.ghidra_client.get_function_xrefs(target)

                    func_analysis = {
                        "name": decomp.get("name", target),
                        "address": decomp.get("address", ""),
                        "code": decomp.get("code", "")[:4000],
                        "callers": xrefs.get("callers", []) if xrefs else [],
                        "callees": xrefs.get("callees", []) if xrefs else [],
                    }

                    self.memory_store.cache_function(target, func_analysis)
                    results["analyzed_functions"].append(func_analysis)

                except Exception as e:
                    logger.warning(f"Failed to analyze {target}: {e}")

            # Find suspicious patterns
            results["suspicious_functions"] = self._find_suspicious(
                results["analyzed_functions"], static_results
            )

        except Exception as e:
            logger.error(f"Fallback analysis failed: {e}")

        return AgentResult(
            success=True,
            data={
                "status": "fallback",
                "ghidra_available": True,
                "ghidra_info": ghidra_info,
                "analysis_results": results,
                "message": f"Used rule-based fallback: {error_message}",
            },
        )

    def _build_analysis_prompt(
        self,
        static_results: dict,
        file_path: str,
        cached_functions: list[str],
        previous_findings: list[dict],
        ghidra_info: dict,
    ) -> str:
        """Build the analysis prompt for the AI agent."""
        parts = [
            "Analyze this binary using the available Ghidra tools.",
            "",
            "## Binary Information",
            f"```json\n{json.dumps(ghidra_info, indent=2)}\n```",
            "",
            "## Static Analysis Results",
            f"```json\n{json.dumps(static_results, indent=2, ensure_ascii=False)[:8000]}\n```",
            "",
            f"## Sample File Path\n{file_path}",
            "",
        ]

        if cached_functions:
            parts.extend(
                [
                    f"## Previously Analyzed Functions ({len(cached_functions)})",
                    "Check memory_get_function before re-analyzing these:",
                    ", ".join(cached_functions[:30]),
                    "",
                ]
            )

        if previous_findings:
            findings_summary = "\n".join(
                [
                    f"- [{f.get('severity', 'unknown')}] {f.get('type', 'unknown')}: {f.get('summary', '')}"
                    for f in previous_findings[:10]
                ]
            )
            parts.extend(
                [
                    "## Previous Findings",
                    findings_summary,
                    "",
                ]
            )

        parts.extend(
            [
                "## Instructions",
                "1. Use memory_get_function to check if a function was already analyzed",
                "2. Use memory_save_finding to save important discoveries",
                "3. Use memory_cache_function after analyzing each function",
                "4. Focus on suspicious functions identified in static analysis",
                "5. Output final results as JSON with: analyzed_functions, callgraph, analysis_path, key_findings",
            ]
        )

        return "\n".join(parts)

    def _identify_targets(self, static_results: dict, functions: list[dict]) -> list[str]:
        """Identify interesting functions to analyze."""
        targets = []

        # Priority 1: Entry points
        entry_names = ["main", "WinMain", "DllMain", "_start", "entry"]
        for func in functions:
            if func.get("name") in entry_names:
                targets.append(func["name"])

        # Priority 2: Functions with suspicious imports
        suspicious_apis = static_results.get("function_categories", {})
        for category in ["Networking", "Cryptography", "Evasion", "Process"]:
            if category in suspicious_apis:
                for func in functions:
                    name = func.get("name", "")
                    if name.startswith("FUN_") and name not in targets:
                        targets.append(name)
                        if len(targets) >= 30:
                            break

        # Priority 3: Auto-named functions
        for func in functions:
            name = func.get("name", "")
            if name.startswith("FUN_") and name not in targets:
                targets.append(name)
                if len(targets) >= 50:
                    break

        return targets

    def _find_suspicious(self, analyzed: list[dict], static_results: dict) -> list[dict]:
        """Find suspicious patterns in analyzed functions."""
        suspicious = []

        suspicious_strings = set()
        strings_data = static_results.get("strings", {})
        for key in ["urls", "ips", "domains", "suspicious"]:
            suspicious_strings.update(strings_data.get(key, []))

        for func in analyzed:
            code = func.get("code", "")
            reasons = []

            if any(api in code for api in ["socket", "connect", "send", "recv"]):
                reasons.append("network_operations")

            if any(api in code for api in ["crypt", "aes", "encrypt", "decrypt"]):
                reasons.append("crypto_operations")

            if any(api in code for api in ["exec", "fork", "system", "popen"]):
                reasons.append("process_operations")

            if any(api in code for api in ["fopen", "fwrite", "unlink", "chmod"]):
                reasons.append("file_operations")

            for s in suspicious_strings:
                if s and len(s) > 4 and s in code:
                    reasons.append(f"contains_suspicious_string:{s[:30]}")
                    break

            if reasons:
                suspicious.append(
                    {
                        "name": func.get("name"),
                        "address": func.get("address"),
                        "reasons": reasons,
                    }
                )

        return suspicious

    def get_analysis_tools(self) -> list[dict]:
        """Get the list of tools available to this agent."""
        return [
            # Ghidra tools
            {"name": "list_functions", "description": "Get function list with pagination"},
            {"name": "get_function_details", "description": "Get function metadata"},
            {"name": "decompile_function", "description": "Decompile function to C code"},
            {"name": "disassemble_function", "description": "Get assembly instructions"},
            {"name": "function_xrefs", "description": "Get cross-references"},
            {"name": "get_callgraph", "description": "Get call graph from function"},
            {"name": "list_strings", "description": "Get strings from binary"},
            {"name": "search_strings", "description": "Search strings by pattern"},
            {"name": "read_memory", "description": "Read memory at address"},
            {"name": "get_imports", "description": "Get imported functions"},
            {"name": "get_exports", "description": "Get exported symbols"},
            {"name": "get_sections", "description": "Get program sections"},
            # Utility tools
            {"name": "decode_base64", "description": "Decode Base64 string"},
            {"name": "decode_hex", "description": "Decode hex string"},
            {"name": "xor_decrypt", "description": "XOR decrypt data"},
            {"name": "calculate_hash", "description": "Calculate hash"},
            # Memory tools
            {"name": "memory_save_finding", "description": "Save key finding"},
            {"name": "memory_get_findings", "description": "Get saved findings"},
            {"name": "memory_cache_function", "description": "Cache function analysis"},
            {"name": "memory_get_function", "description": "Get cached function"},
        ]
