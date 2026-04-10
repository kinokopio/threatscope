"""GhidraAgent - AI-driven deep reverse engineering analysis using claude-agent-sdk."""

import asyncio
import json
import logging
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
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    UserMessage,
)

from src.threatscope.analysis.agents.base import AgentConfig, AgentResult, BaseAgent
from src.threatscope.analysis.agents.ghidra_hooks import (
    create_post_tool_use_hook,
    create_pre_compact_hook,
)
from src.threatscope.analysis.agents.ghidra_prompts import (
    build_analysis_prompt,
    load_system_prompt,
)
from src.threatscope.analysis.agents.ghidra_tools import create_memory_tools_server
from src.threatscope.analysis.agents.memory_store import MemoryStore
from src.threatscope.analysis.agents.models import GhidraAnalysisOutput
from src.threatscope.analysis.agents.threat_intel_tools import create_threat_intel_mcp_server
from src.threatscope.analysis.agents.utils_tools import create_utils_mcp_server
from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService
from src.threatscope.ghidra.client import GhidraClient

try:
    from langfuse import observe as langfuse_observe

    LANGFUSE_AVAILABLE = True
except ImportError:
    LANGFUSE_AVAILABLE = False

    def langfuse_observe(*args, **kwargs):
        def decorator(func):
            return func

        if args and callable(args[0]):
            return args[0]
        return decorator


logger = logging.getLogger(__name__)

DEFAULT_AI_TIMEOUT = 600


class GhidraAgent(BaseAgent):
    """AI agent for deep binary analysis using Ghidra and claude-agent-sdk."""

    def __init__(
        self,
        config: AgentConfig,
        project_dir: str | Path = ".",
        ghidra_url: str = "http://localhost:8000",
        ai_timeout: int = DEFAULT_AI_TIMEOUT,
        enable_gdb: bool = False,
        threat_intel_service: ThreatIntelService | None = None,
    ):
        super().__init__(config)
        self.project_dir = Path(project_dir)
        self.ghidra_url = ghidra_url
        self.ai_timeout = ai_timeout
        self.enable_gdb = enable_gdb
        self.threat_intel_service = threat_intel_service
        self.memory_store: MemoryStore | None = None
        self.ghidra_client: GhidraClient | None = None
        self._progress_callback: Callable | None = None
        self._selected_skills: list[str] | None = None

    @property
    def name(self) -> str:
        return "ghidra_agent"

    @langfuse_observe(name="ghidra-deep-analysis", as_type="span")
    async def analyze(
        self,
        context: dict[str, Any],
        progress_callback: Callable[[str, str, str, dict | None], Any] | None = None,
        skills: list[str] | None = None,
    ) -> AgentResult:
        """Perform deep analysis using Ghidra with AI-driven exploration."""
        self._progress_callback = progress_callback
        self._selected_skills = skills
        static_results = context.get("static_results", {})
        file_path = context.get("file_path", "")
        sample_hash = context.get("sample_hash", "")

        if not sample_hash:
            sample_hash = static_results.get("hashes", {}).get("sha256", "unknown")

        self.memory_store = MemoryStore(self.project_dir, sample_hash)
        self.memory_store.clear()
        logger.info(f"Cleared previous analysis cache for sample {sample_hash[:16]}...")

        self.ghidra_client = GhidraClient(self.ghidra_url)

        cached_functions = self.memory_store.list_cached_functions()
        previous_findings = self.memory_store.get_findings()

        ghidra_available, ghidra_info = await self._connect_ghidra(file_path)

        if ghidra_available and ghidra_info:
            try:
                if self._progress_callback:
                    await self._safe_callback(
                        "ghidra_ai_start",
                        "Starting AI-driven deep analysis",
                        "running",
                        {
                            "function_count": ghidra_info.get("function_count", 0),
                            "estimated_time": "2-10 minutes depending on complexity",
                        },
                    )

                ai_results = await self._run_ai_analysis(
                    static_results=static_results,
                    file_path=file_path,
                    cached_functions=cached_functions,
                    previous_findings=previous_findings,
                    ghidra_info=ghidra_info,
                )

                if self._progress_callback:
                    await self._safe_callback(
                        "ghidra_ai_start", "AI analysis completed", "completed", {}
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

    async def _safe_callback(
        self, step_id: str, step_name: str, status: str, data: dict | None
    ) -> None:
        """Safely call progress callback, ignoring errors."""
        if self._progress_callback:
            try:
                await self._progress_callback(step_id, step_name, status, data)
            except Exception as e:
                logger.debug(f"Progress callback failed: {e}")

    async def _connect_ghidra(self, file_path: str) -> tuple[bool, dict]:
        """Connect to Ghidra and load binary."""
        ghidra_available = False
        ghidra_info = {}

        try:
            await self._safe_callback(
                "ghidra_connect",
                "Connecting to Ghidra service",
                "running",
                {"url": self.ghidra_url},
            )

            logger.info(f"Connecting to Ghidra at: {self.ghidra_url}")
            await asyncio.to_thread(self.ghidra_client.health_check)
            logger.info("Ghidra health check passed")
            ghidra_available = True

            await self._safe_callback(
                "ghidra_connect",
                "Connected to Ghidra service",
                "completed",
                {"url": self.ghidra_url},
            )

            if file_path and Path(file_path).exists():
                try:
                    file_size = Path(file_path).stat().st_size
                    file_size_mb = file_size / (1024 * 1024)

                    await self._safe_callback(
                        "ghidra_upload",
                        f"Uploading binary ({file_size_mb:.1f} MB)",
                        "running",
                        {"file_size_bytes": file_size, "file_size_mb": round(file_size_mb, 2)},
                    )

                    logger.info(f"Uploading {file_path} ({file_size_mb:.1f} MB)")
                    await asyncio.to_thread(self.ghidra_client.upload, file_path)
                    logger.info("Upload completed")

                    await self._safe_callback(
                        "ghidra_upload",
                        "Binary uploaded successfully",
                        "completed",
                        {"file_size_mb": round(file_size_mb, 2)},
                    )

                    await self._safe_callback(
                        "ghidra_analyze",
                        "Running Ghidra auto-analysis (this may take several minutes)",
                        "running",
                        {"estimated_time": "1-10 minutes depending on file size"},
                    )

                    logger.info("Running Ghidra analysis")
                    await asyncio.to_thread(self.ghidra_client.analyze)
                    logger.info("Ghidra analysis completed")

                    await self._safe_callback(
                        "ghidra_analyze", "Ghidra auto-analysis complete", "completed", None
                    )

                    ghidra_info = await asyncio.to_thread(self.ghidra_client.get_info)
                    logger.info(f"Got Ghidra info: {ghidra_info}")

                    await self._safe_callback(
                        "ghidra_info",
                        "Retrieved binary metadata",
                        "completed",
                        {
                            "format": ghidra_info.get("format"),
                            "architecture": ghidra_info.get("processor"),
                            "function_count": ghidra_info.get("function_count"),
                        },
                    )

                except Exception as e:
                    logger.warning(f"Failed to load binary: {e}")
                    await self._safe_callback(
                        "ghidra_error", f"Failed to load binary: {e}", "error", {"error": str(e)}
                    )

        except Exception as e:
            logger.warning(f"Ghidra service not available: {e}")
            await self._safe_callback(
                "ghidra_connect", "Ghidra service not available", "error", {"error": str(e)}
            )

        return ghidra_available, ghidra_info

    async def _run_ai_analysis(
        self,
        static_results: dict,
        file_path: str,
        cached_functions: list[str],
        previous_findings: list[dict],
        ghidra_info: dict,
    ) -> dict[str, Any]:
        """Run AI-driven analysis using claude-agent-sdk."""
        from src.threatscope.core.config import get_settings

        settings = get_settings()
        if not settings.llm.api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured in .env or environment")

        prompt = build_analysis_prompt(
            static_results=static_results,
            file_path=file_path,
            cached_functions=cached_functions,
            previous_findings=previous_findings,
            ghidra_info=ghidra_info,
        )

        system_prompt = load_system_prompt(self.project_dir, "ghidra_agent")

        mcp_servers, allowed_tools = self._build_mcp_config(settings)
        plugins = self._build_plugins_config()

        options = ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=settings.llm.model,
            mcp_servers=mcp_servers,
            allowed_tools=allowed_tools,
            disallowed_tools=[
                "Bash",
                "Read",
                "Write",
                "Edit",
                "Glob",
                "Grep",
                "WebFetch",
                "Task",
            ],
            plugins=plugins,
            max_turns=self.config.max_iterations,
            cwd=str(self.project_dir),
            output_format={
                "type": "json_schema",
                "schema": GhidraAnalysisOutput.model_json_schema(),
            },
            hooks={
                "PreCompact": [
                    HookMatcher(matcher=None, hooks=[create_pre_compact_hook(self.memory_store)])
                ],
                "PostToolUse": [HookMatcher(matcher=None, hooks=[create_post_tool_use_hook()])],
            },
        )

        return await self._execute_ai_session(options, prompt, mcp_servers, allowed_tools)

    def _build_mcp_config(self, settings) -> tuple[dict[str, Any], list[str]]:
        """Build MCP servers configuration and allowed tools list."""
        utils_server = create_utils_mcp_server()
        memory_server = create_memory_tools_server(self.memory_store)

        mcp_servers: dict[str, Any] = {
            "ghidra": {"type": "http", "url": f"{self.ghidra_url}/mcp/"},
            "utils": utils_server,
            "memory": memory_server,
        }

        allowed_tools = ["Skill", "mcp__ghidra__*", "mcp__utils__*", "mcp__memory__*"]

        if self.threat_intel_service:
            threat_intel_server = create_threat_intel_mcp_server(self.threat_intel_service)
            mcp_servers["threat_intel"] = threat_intel_server
            allowed_tools.append("mcp__threat_intel__*")
            logger.info("Threat intelligence tools enabled")

        if self.enable_gdb:
            gdb_enabled = self._setup_gdb(settings, mcp_servers)
            if gdb_enabled:
                allowed_tools.append("mcp__gdb__*")

        return mcp_servers, allowed_tools

    def _setup_gdb(self, settings, mcp_servers: dict) -> bool:
        """Setup GDB MCP server if available."""
        gdb_settings = settings.gdb

        if gdb_settings.service_mode in ("http", "sse"):
            import httpx

            try:
                health_url = gdb_settings.mcp_url.replace("/sse", "/health").replace(
                    "/mcp", "/health"
                )
                httpx.get(health_url, timeout=3.0)
            except Exception as e:
                logger.warning(
                    f"GDB MCP server not reachable at {gdb_settings.mcp_url}, disabling: {e}"
                )
                return False

        if gdb_settings.service_mode == "http":
            mcp_servers["gdb"] = {"type": "http", "url": gdb_settings.mcp_url}
        elif gdb_settings.service_mode == "sse":
            mcp_servers["gdb"] = {"type": "sse", "url": gdb_settings.mcp_url}
        else:
            mcp_servers["gdb"] = {
                "type": "stdio",
                "command": gdb_settings.mcp_command,
                "env": {"GDB_PATH": gdb_settings.gdb_path},
            }

        logger.info(f"GDB dynamic analysis enabled (mode: {gdb_settings.service_mode})")
        return True

    def _build_plugins_config(self) -> list[dict[str, str]]:
        """Build plugins configuration for selected skills."""
        plugins = []
        skills_dir = self.project_dir / ".claude" / "skills"

        if not skills_dir.exists():
            return plugins

        if self._selected_skills:
            for skill_name in self._selected_skills:
                skill_path = skills_dir / skill_name
                plugin_json = skill_path / ".claude-plugin" / "plugin.json"
                if plugin_json.exists():
                    plugins.append({"type": "local", "path": str(skill_path)})
                    logger.info(f"Loading skill plugin: {skill_name}")
                else:
                    logger.warning(f"Skill '{skill_name}' not found or missing plugin.json")
        else:
            for skill_dir in skills_dir.iterdir():
                if skill_dir.is_dir():
                    plugin_json = skill_dir / ".claude-plugin" / "plugin.json"
                    if plugin_json.exists():
                        plugins.append({"type": "local", "path": str(skill_dir)})
                        logger.info(f"Loading skill plugin: {skill_dir.name}")

        return plugins

    async def _execute_ai_session(
        self,
        options: ClaudeAgentOptions,
        prompt: str,
        mcp_servers: dict,
        allowed_tools: list[str],
    ) -> dict[str, Any]:
        """Execute the AI analysis session."""
        result_text = ""
        tool_call_count = 0
        functions_analyzed = 0
        findings_saved = 0

        logger.info("=" * 60)
        logger.info("Starting AI Analysis Session")
        logger.info("=" * 60)
        logger.info(f"Model: {options.model}")
        logger.info(f"Max turns: {options.max_turns}")
        logger.info(f"MCP servers: {list(mcp_servers.keys())}")
        logger.info(f"Ghidra MCP URL: {mcp_servers['ghidra']['url']}")
        logger.info(f"Allowed tools: {allowed_tools}")
        if options.plugins:
            logger.info(f"Plugins: {[p.get('path', '').split('/')[-1] for p in options.plugins]}")
        if self.enable_gdb:
            logger.info("GDB dynamic analysis: ENABLED")

        logger.info("-" * 60)
        logger.info("[System Prompt Preview]")
        system_prompt = options.system_prompt or ""
        logger.info(system_prompt[:500] + "..." if len(system_prompt) > 500 else system_prompt)

        logger.info("-" * 60)
        logger.info("[User Prompt Preview]")
        logger.info(prompt[:1000] + "..." if len(prompt) > 1000 else prompt)
        logger.info("-" * 60)

        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            async for msg in client.receive_response():
                if isinstance(msg, SystemMessage):
                    if msg.subtype == "init":
                        mcp_status = msg.data.get("mcp_servers", [])
                        logger.info(f"[MCP Connection Status] {mcp_status}")
                        for server in mcp_status:
                            if server.get("status") != "connected":
                                logger.warning(
                                    f"MCP server '{server.get('name')}' status: {server.get('status')}"
                                )
                    continue

                if isinstance(msg, AssistantMessage):
                    (
                        tool_call_count,
                        functions_analyzed,
                        findings_saved,
                        result_text,
                    ) = await self._handle_assistant_message(
                        msg, tool_call_count, functions_analyzed, findings_saved, result_text
                    )

                elif isinstance(msg, UserMessage):
                    self._handle_user_message(msg, tool_call_count)

                elif isinstance(msg, ResultMessage):
                    result = await self._handle_result_message(
                        msg, tool_call_count, functions_analyzed, findings_saved, result_text
                    )
                    if result is not None:
                        return result

        await self._safe_callback(
            "ghidra_ai",
            "AI Analysis Complete",
            "completed",
            {
                "total_tool_calls": tool_call_count,
                "functions_analyzed": functions_analyzed,
                "findings_saved": findings_saved,
            },
        )

        logger.info(
            f"AI analysis completed: {tool_call_count} tool calls, {functions_analyzed} functions analyzed"
        )

        if result_text:
            try:
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
                logger.warning("Failed to parse JSON from text response")

        memory_findings = self.memory_store.get_findings()
        normalized_findings = self._deduplicate_findings(memory_findings)

        return {
            "raw_analysis": result_text,
            "analyzed_functions": [],
            "key_findings": normalized_findings,
        }

    async def _handle_assistant_message(
        self,
        msg: AssistantMessage,
        tool_call_count: int,
        functions_analyzed: int,
        findings_saved: int,
        result_text: str,
    ) -> tuple[int, int, int, str]:
        """Handle assistant message from the AI."""
        if not hasattr(msg, "content") or not msg.content:
            return tool_call_count, functions_analyzed, findings_saved, result_text

        for block in msg.content:
            if isinstance(block, ToolUseBlock):
                tool_call_count += 1
                tool_name = block.name
                tool_input = block.input or {}

                description = self._get_tool_description(tool_name, tool_input)

                if "function" in tool_name.lower():
                    func_name = (
                        tool_input.get("name")
                        or tool_input.get("function_name", "")
                        or tool_input.get("target", "")
                    )
                    if func_name:
                        description = f"{description}: {func_name}"
                        functions_analyzed += 1
                elif "save" in tool_name.lower() or "finding" in tool_name.lower():
                    findings_saved += 1

                logger.info("-" * 50)
                logger.info(f"[Tool #{tool_call_count}] {tool_name}")
                logger.info(f"  Description: {description}")
                input_str = json.dumps(tool_input, ensure_ascii=False)
                logger.info(
                    f"  Input: {input_str[:500]}..."
                    if len(input_str) > 500
                    else f"  Input: {input_str}"
                )

                await self._safe_callback(
                    "ghidra_tool",
                    description,
                    "running",
                    {"tool": tool_name, "tool_call_count": tool_call_count},
                )

            elif isinstance(block, TextBlock):
                if block.text:
                    result_text = block.text
                    thinking_preview = (
                        block.text[:200] + "..." if len(block.text) > 200 else block.text
                    )
                    logger.info(f"[AI Thinking] {thinking_preview}")

        return tool_call_count, functions_analyzed, findings_saved, result_text

    def _handle_user_message(self, msg: UserMessage, tool_call_count: int) -> None:
        """Handle user message (tool results)."""
        if hasattr(msg, "tool_use_result") and msg.tool_use_result:
            tool_result = msg.tool_use_result
            if isinstance(tool_result, dict):
                result_str = json.dumps(tool_result, ensure_ascii=False)
                is_error = tool_result.get("is_error", False)
            else:
                result_str = str(tool_result)
                is_error = False
            result_preview = result_str[:800] + "..." if len(result_str) > 800 else result_str
            if is_error:
                logger.warning(f"[Tool Result ERROR] {result_preview}")
            else:
                logger.info(f"[Tool Result] {result_preview}")

        if hasattr(msg, "content") and msg.content:
            for block in msg.content if isinstance(msg.content, list) else []:
                if isinstance(block, ToolResultBlock):
                    result_content = str(block.content) if hasattr(block, "content") else str(block)
                    result_preview = (
                        result_content[:800] + "..."
                        if len(result_content) > 800
                        else result_content
                    )
                    is_error = getattr(block, "is_error", False)
                    if is_error:
                        logger.warning(f"[Tool Result ERROR] {result_preview}")
                    else:
                        logger.info(f"[Tool Result] {result_preview}")

    async def _handle_result_message(
        self,
        msg: ResultMessage,
        tool_call_count: int,
        functions_analyzed: int,
        findings_saved: int,
        result_text: str,
    ) -> dict[str, Any] | None:
        """Handle result message from the AI."""
        logger.info("=" * 60)
        logger.info("AI Analysis Complete")
        logger.info("=" * 60)
        logger.info(f"  Total tool calls: {tool_call_count}")
        logger.info(f"  Turns used: {getattr(msg, 'num_turns', 'N/A')}")
        logger.info(f"  Cost: ${getattr(msg, 'total_cost_usd', 0):.4f}")
        logger.info(f"  Input tokens: {getattr(msg, 'input_tokens', 'N/A')}")
        logger.info(f"  Output tokens: {getattr(msg, 'output_tokens', 'N/A')}")

        if hasattr(msg, "structured_output") and msg.structured_output:
            logger.info("Using structured output from Claude")
            structured_result = msg.structured_output

            if isinstance(structured_result, dict):
                if "$defs" in structured_result:
                    defs_value = structured_result.get("$defs", "")
                    if isinstance(defs_value, str):
                        try:
                            structured_result = json.loads(defs_value)
                            logger.info("Parsed structured output from $defs string")
                        except json.JSONDecodeError:
                            logger.warning("Failed to parse $defs as JSON")
                            structured_result = None
                    elif isinstance(defs_value, dict):
                        structured_result = defs_value

            if structured_result and isinstance(structured_result, dict):
                if "analyzed_functions" in structured_result or "key_findings" in structured_result:
                    await self._safe_callback(
                        "ghidra_tool",
                        "AI Analysis Complete",
                        "completed",
                        {
                            "tool_call_count": tool_call_count,
                            "functions_analyzed": len(
                                structured_result.get("analyzed_functions", [])
                            ),
                            "findings_saved": len(structured_result.get("key_findings", [])),
                            "num_turns": getattr(msg, "num_turns", 0),
                            "cost_usd": getattr(msg, "total_cost_usd", 0),
                        },
                    )
                    return structured_result
                else:
                    logger.warning(
                        f"Structured output missing expected keys: {list(structured_result.keys())}"
                    )

        await self._safe_callback(
            "ghidra_tool",
            "AI Analysis Complete",
            "completed",
            {
                "tool_call_count": tool_call_count,
                "functions_analyzed": functions_analyzed,
                "findings_saved": findings_saved,
                "num_turns": getattr(msg, "num_turns", 0),
                "cost_usd": getattr(msg, "total_cost_usd", 0),
            },
        )

        return None

    def _get_tool_description(self, tool_name: str, tool_input: dict) -> str:
        """Get human-readable description for a tool call."""
        tool_descriptions = {
            "mcp__ghidra__list_functions": "Listing functions",
            "mcp__ghidra__decompile_function": "Decompiling function",
            "mcp__ghidra__disassemble_function": "Disassembling function",
            "mcp__ghidra__get_function_details": "Getting function details",
            "mcp__ghidra__list_strings": "Listing strings",
            "mcp__ghidra__search_strings": "Searching strings",
            "mcp__ghidra__function_xrefs": "Getting cross-references",
            "mcp__ghidra__get_callgraph": "Building call graph",
            "mcp__ghidra__read_memory": "Reading memory (static)",
            "mcp__ghidra__get_imports": "Getting imports",
            "mcp__ghidra__get_exports": "Getting exports",
            "mcp__ghidra__get_sections": "Getting sections",
            "mcp__memory__memory_save_finding": "Saving finding",
            "mcp__memory__memory_cache_function": "Caching function analysis",
            "mcp__gdb__gdb_start_session": "Starting GDB session",
            "mcp__gdb__gdb_stop_session": "Stopping GDB session",
            "mcp__gdb__gdb_set_breakpoint": "Setting breakpoint",
            "mcp__gdb__gdb_continue": "Continuing execution",
            "mcp__gdb__gdb_step": "Stepping into",
            "mcp__gdb__gdb_next": "Stepping over",
            "mcp__gdb__gdb_interrupt": "Interrupting execution",
            "mcp__gdb__gdb_get_backtrace": "Getting backtrace",
            "mcp__gdb__gdb_get_registers": "Reading registers",
            "mcp__gdb__gdb_get_variables": "Getting variables",
            "mcp__gdb__gdb_evaluate_expression": "Evaluating expression",
            "mcp__gdb__gdb_read_memory": "Reading memory (dynamic)",
            "mcp__gdb__gdb_write_memory": "Writing memory",
            "mcp__gdb__gdb_disassemble": "Disassembling (dynamic)",
            "mcp__gdb__gdb_set_watchpoint": "Setting watchpoint",
            "mcp__threat_intel__query_hash": "Querying hash threat intel",
            "mcp__threat_intel__query_ioc": "Querying IOC threat intel",
        }

        return tool_descriptions.get(
            tool_name,
            tool_name.replace("mcp__", "").replace("__", ": ").replace("_", " ").title(),
        )

    async def _fallback_analysis(
        self,
        static_results: dict,
        cached_functions: list[str],
        ghidra_info: dict,
        error_message: str = "AI analysis unavailable",
    ) -> AgentResult:
        """Fallback to rule-based analysis when AI is unavailable."""
        results: dict[str, Any] = {
            "analyzed_functions": [],
            "key_findings": [],
            "suspicious_functions": [],
        }

        try:
            functions = self.ghidra_client.list_functions(limit=500)
            targets = self._identify_targets(static_results, functions)

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
                "ai_analysis": results,
                "message": f"Used rule-based fallback: {error_message}",
            },
        )

    def _identify_targets(self, static_results: dict, functions: list[dict]) -> list[str]:
        """Identify interesting functions to analyze."""
        targets = []

        entry_names = ["main", "WinMain", "DllMain", "_start", "entry"]
        for func in functions:
            if func.get("name") in entry_names:
                targets.append(func["name"])

        capa_result = static_results.get("capa", {})
        capabilities = capa_result.get("capabilities", [])
        has_suspicious_caps = any(
            any(
                kw in cap.get("namespace", "").lower()
                for kw in ["network", "crypto", "anti", "persistence"]
            )
            for cap in capabilities
        )
        if has_suspicious_caps:
            for func in functions:
                name = func.get("name", "")
                if name.startswith("FUN_") and name not in targets:
                    targets.append(name)
                    if len(targets) >= 30:
                        break

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

        suspicious_strings: set[str] = set()
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

    def _deduplicate_findings(self, findings: list[dict]) -> list[dict]:
        """Deduplicate and normalize findings from memory."""
        if not findings:
            return []

        grouped: dict[str, list[dict]] = {}
        for f in findings:
            raw_type = f.get("type") or f.get("category") or "unknown"
            normalized_type = raw_type.lower().replace("_", "").strip()

            type_mappings = {
                "c2infrastructure": "c2",
                "c2domain": "c2",
                "c2communication": "c2",
                "commandcontrol": "c2",
                "networkcommunication": "network",
                "networkcapabilities": "network",
                "networkservice": "network",
                "asyncnetworkio": "network",
                "networkio": "network",
                "persistencemechanism": "persistence",
                "persistencedaemon": "persistence",
                "hostfingerprinting": "reconnaissance",
                "hostidentification": "reconnaissance",
                "informationgathering": "reconnaissance",
                "taskexecution": "execution",
                "taskprocessing": "execution",
                "commandexecution": "execution",
                "systemexecution": "execution",
                "systeminteraction": "execution",
                "beaconimplementation": "c2",
                "beaconinfrastructure": "c2",
            }
            canonical_type = type_mappings.get(normalized_type, normalized_type)

            if canonical_type not in grouped:
                grouped[canonical_type] = []
            grouped[canonical_type].append(f)

        result = []
        finding_id = 1

        for canonical_type, group in grouped.items():

            def has_chinese(text: str) -> bool:
                return any("\u4e00" <= c <= "\u9fff" for c in str(text))

            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            group.sort(
                key=lambda x: (
                    0 if has_chinese(x.get("summary", "")) else 1,
                    severity_order.get(x.get("severity", "medium").lower(), 2),
                )
            )

            best = group[0]

            all_evidence = []
            for f in group:
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    for k, v in ev.items():
                        if v:
                            all_evidence.append(f"{k}: {v}")
                elif isinstance(ev, list):
                    all_evidence.extend([str(e) for e in ev if e])
                elif ev:
                    all_evidence.append(str(ev))

            seen_evidence = set()
            unique_evidence = []
            for e in all_evidence:
                e_normalized = e.lower()[:50]
                if e_normalized not in seen_evidence:
                    seen_evidence.add(e_normalized)
                    unique_evidence.append(e)

            normalized = {
                "id": f"finding_{finding_id:03d}",
                "title": best.get("title")
                or best.get("type")
                or best.get("summary", "Finding")[:50],
                "category": best.get("category") or best.get("type", "Unknown"),
                "description": best.get("description") or best.get("summary", ""),
                "severity": best.get("severity", "MEDIUM").upper(),
                "evidence": unique_evidence[:10],
                "impact": best.get("impact"),
                "recommendation": best.get("recommendation"),
            }
            result.append(normalized)
            finding_id += 1

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 2))

        return result

    def get_analysis_tools(self) -> list[dict]:
        """Get the list of tools available to this agent."""
        return [
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
            {"name": "decode_base64", "description": "Decode Base64 string"},
            {"name": "decode_hex", "description": "Decode hex string"},
            {"name": "xor_decrypt", "description": "XOR decrypt data"},
            {"name": "calculate_hash", "description": "Calculate hash"},
            {"name": "memory_save_finding", "description": "Save key finding"},
            {"name": "memory_get_findings", "description": "Get saved findings"},
            {"name": "memory_cache_function", "description": "Cache function analysis"},
            {"name": "memory_get_function", "description": "Get cached function"},
            {"name": "query_hash", "description": "Query hash threat intelligence"},
            {"name": "query_ioc", "description": "Query IOC threat intelligence"},
        ]
