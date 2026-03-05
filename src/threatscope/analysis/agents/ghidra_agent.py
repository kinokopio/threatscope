"""GhidraAgent - AI-driven deep reverse engineering analysis using claude-agent-sdk."""

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, Callable, Literal

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
    create_sdk_mcp_server,
    tool,
)
from pydantic import BaseModel, Field

from src.threatscope.analysis.agents.base import AgentConfig, AgentResult, BaseAgent
from src.threatscope.analysis.agents.memory_store import MemoryStore
from src.threatscope.analysis.agents.utils_tools import create_utils_mcp_server
from src.threatscope.ghidra.client import GhidraClient

# Try to import Langfuse observe decorator
try:
    from langfuse import observe as langfuse_observe

    LANGFUSE_AVAILABLE = True
except ImportError:
    LANGFUSE_AVAILABLE = False

    # Create a no-op decorator if langfuse not available
    def langfuse_observe(*args, **kwargs):
        def decorator(func):
            return func

        if args and callable(args[0]):
            return args[0]
        return decorator


logger = logging.getLogger(__name__)

# Default timeout for AI analysis (10 minutes for complex binary analysis)
DEFAULT_AI_TIMEOUT = 600

# =============================================================================
# Structured Output Models for Ghidra Analysis
# =============================================================================


class AnalyzedFunction(BaseModel):
    """A function analyzed by the Ghidra agent."""

    name: str = Field(description="Function name")
    address: str = Field(description="Hex address like 0x12345678 or 'unknown'")
    purpose: str = Field(description="Brief description of what this function does")
    analysis: str | None = Field(
        default=None, description="Detailed analysis of the function behavior"
    )
    risk: Literal["critical", "high", "medium", "low"] = Field(description="Risk level")


class KeyFinding(BaseModel):
    """A key finding from the analysis."""

    id: str = Field(description="Unique ID like finding_001")
    title: str = Field(description="Short title of the finding")
    category: str = Field(description="Category (e.g., Persistence, Network, Evasion)")
    description: str = Field(description="Detailed description of the finding")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Severity level")
    evidence: list[str] = Field(default_factory=list, description="Evidence items")
    impact: str | None = Field(default=None, description="Impact description")
    recommendation: str | None = Field(default=None, description="Remediation advice")


class MalwareClassification(BaseModel):
    """Malware classification result."""

    type: str = Field(description="Malware type (e.g., Trojan, Miner, Ransomware)")
    family: str | None = Field(default=None, description="Malware family if identified")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = Field(description="Overall severity")


class GhidraAnalysisOutput(BaseModel):
    """Structured output schema for Ghidra AI analysis."""

    analyzed_functions: list[AnalyzedFunction] = Field(
        default_factory=list, description="List of analyzed functions with their details"
    )
    key_findings: list[KeyFinding] = Field(
        default_factory=list, description="Key security findings from the analysis"
    )
    malware_classification: MalwareClassification | None = Field(
        default=None, description="Malware classification if malicious"
    )
    analysis_path: list[str] = Field(
        default_factory=list,
        description="Steps taken during analysis (e.g., 'Step 1: Analyzed entry point')",
    )
    attack_chain: str | None = Field(
        default=None,
        description="Attack flow chain: FuncA (purpose) -> FuncB (purpose) -> FuncC (purpose)",
    )


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
        "Save an important finding to persistent memory. Avoid duplicates - check existing findings first.",
        {"type": str, "summary": str, "evidence": dict, "severity": str},
    )
    async def save_finding(args: dict[str, Any]) -> dict:
        findings = memory_store.get_findings()
        new_type = args["type"]
        new_summary = args["summary"]

        # Deduplication: check if similar finding already exists
        for existing in findings:
            existing_type = existing.get("type", "")
            existing_summary = existing.get("summary", "")

            # Check for similar type (case-insensitive, ignore underscores)
            type_similar = (
                existing_type.lower().replace("_", "") == new_type.lower().replace("_", "")
                or existing_type.lower() in new_type.lower()
                or new_type.lower() in existing_type.lower()
            )

            # Check for similar summary (contains key phrases)
            summary_similar = (
                existing_summary.lower()[:50] == new_summary.lower()[:50]
                or (len(existing_summary) > 20 and existing_summary[:20] in new_summary)
                or (len(new_summary) > 20 and new_summary[:20] in existing_summary)
            )

            if type_similar and summary_similar:
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Finding already exists: {existing.get('id')}. Skipped duplicate.",
                        }
                    ]
                }

        finding = {
            "id": f"finding_{len(findings) + 1:03d}",
            "type": new_type,
            "summary": new_summary,
            "evidence": args.get("evidence", {}),
            "severity": args.get("severity", "medium"),
            "discovered_at": datetime.now().isoformat(),
        }
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
                    f"- [{f.get('severity', 'unknown')}] "
                    f"{f.get('type', 'unknown')}: {f.get('summary', '')}"
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


MAX_TOOL_RESULT_CHARS = 100000


def create_post_tool_use_hook():
    """Create PostToolUse hook to truncate large MCP tool results.

    This prevents token limit errors when tools like get_exports return
    massive results (400K+ characters).
    """

    async def post_tool_use_hook(input_data, tool_use_id, context):
        tool_response = input_data.get("tool_response", "")
        tool_name = input_data.get("tool_name", "")

        if not isinstance(tool_response, str):
            tool_response = str(tool_response)

        if len(tool_response) > MAX_TOOL_RESULT_CHARS:
            truncated = tool_response[:MAX_TOOL_RESULT_CHARS]
            warning = (
                f"\n\n[TRUNCATED: Result was {len(tool_response):,} chars, "
                f"showing first {MAX_TOOL_RESULT_CHARS:,}. "
                f"Use offset/limit parameters to paginate large results.]"
            )
            logger.warning(
                f"Truncating large tool result from {tool_name}: "
                f"{len(tool_response):,} -> {MAX_TOOL_RESULT_CHARS:,} chars"
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "updatedMCPToolOutput": truncated + warning,
                }
            }

        return {}

    return post_tool_use_hook


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
        enable_gdb: bool = False,
    ):
        super().__init__(config)
        self.project_dir = Path(project_dir)
        self.ghidra_url = ghidra_url
        self.ai_timeout = ai_timeout
        self.enable_gdb = enable_gdb
        self.memory_store: MemoryStore | None = None
        self.ghidra_client: GhidraClient | None = None
        self._progress_callback: Callable | None = None

    @property
    def name(self) -> str:
        return "ghidra_agent"

    @langfuse_observe(name="ghidra-deep-analysis", as_type="span")
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

        # Initialize memory store and clear previous analysis
        self.memory_store = MemoryStore(self.project_dir, sample_hash)
        self.memory_store.clear()
        logger.info(f"Cleared previous analysis cache for sample {sample_hash[:16]}...")

        # Initialize Ghidra client
        self.ghidra_client = GhidraClient(self.ghidra_url)

        # Check for previous analysis
        cached_functions = self.memory_store.list_cached_functions()
        previous_findings = self.memory_store.get_findings()

        # Try to connect to Ghidra service
        ghidra_available = False
        ghidra_info = {}
        try:
            # Step 1: Connect to Ghidra
            if self._progress_callback:
                try:
                    await self._progress_callback(
                        "ghidra_connect",
                        "Connecting to Ghidra service",
                        "running",
                        {"url": self.ghidra_url},
                    )
                except Exception:
                    pass

            logger.info(f"Connecting to Ghidra at: {self.ghidra_url}")
            self.ghidra_client.health_check()
            logger.info("Ghidra health check passed")
            ghidra_available = True

            # If file provided and not already loaded, upload it
            if file_path and Path(file_path).exists():
                try:
                    # Step 2: Upload binary (can take time for large files)
                    file_size = Path(file_path).stat().st_size
                    file_size_mb = file_size / (1024 * 1024)

                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_upload",
                                f"Uploading binary ({file_size_mb:.1f} MB)",
                                "running",
                                {
                                    "file_size_bytes": file_size,
                                    "file_size_mb": round(file_size_mb, 2),
                                },
                            )
                        except Exception:
                            pass

                    logger.info(f"Uploading {file_path} ({file_size_mb:.1f} MB)")
                    self.ghidra_client.upload(file_path)

                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_upload",
                                "Binary uploaded successfully",
                                "completed",
                                {"file_size_mb": round(file_size_mb, 2)},
                            )
                        except Exception:
                            pass

                    # Step 3: Run Ghidra auto-analysis (can take several minutes)
                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_analyze",
                                "Running Ghidra auto-analysis (this may take several minutes)",
                                "running",
                                {"estimated_time": "1-10 minutes depending on file size"},
                            )
                        except Exception:
                            pass

                    logger.info("Running Ghidra analysis")
                    self.ghidra_client.analyze()

                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_analyze",
                                "Ghidra auto-analysis complete",
                                "completed",
                                None,
                            )
                        except Exception:
                            pass

                    # Step 4: Get binary info
                    ghidra_info = self.ghidra_client.get_info()
                    logger.info(f"Got Ghidra info: {ghidra_info}")

                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_info",
                                "Retrieved binary metadata",
                                "completed",
                                {
                                    "format": ghidra_info.get("format"),
                                    "architecture": ghidra_info.get("processor"),
                                    "function_count": ghidra_info.get("function_count"),
                                },
                            )
                        except Exception:
                            pass

                except Exception as e:
                    logger.warning(f"Failed to load binary: {e}")
                    if self._progress_callback:
                        try:
                            await self._progress_callback(
                                "ghidra_error",
                                f"Failed to load binary: {e}",
                                "error",
                                {"error": str(e)},
                            )
                        except Exception:
                            pass
        except Exception as e:
            logger.warning(f"Ghidra service not available: {e}")
            if self._progress_callback:
                try:
                    await self._progress_callback(
                        "ghidra_connect",
                        "Ghidra service not available",
                        "error",
                        {"error": str(e)},
                    )
                except Exception:
                    pass

        # If Ghidra is available, run AI-driven analysis
        if ghidra_available and ghidra_info:
            try:
                # Notify AI analysis starting
                if self._progress_callback:
                    try:
                        await self._progress_callback(
                            "ghidra_ai_start",
                            "Starting AI-driven deep analysis",
                            "running",
                            {
                                "function_count": ghidra_info.get("function_count", 0),
                                "estimated_time": "2-10 minutes depending on complexity",
                            },
                        )
                    except Exception:
                        pass

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
        from src.threatscope.core.config import get_settings

        settings = get_settings()
        if not settings.llm.api_key:
            raise ValueError("ANTHROPIC_API_KEY not configured in .env or environment")

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

        # Build MCP servers configuration
        mcp_servers: dict[str, Any] = {
            "ghidra": {
                "type": "http",
                "url": f"{self.ghidra_url}/mcp/",
            },
            "utils": utils_server,
            "memory": memory_server,
        }

        # Build allowed tools list - use wildcards for MCP servers
        allowed_tools = [
            "mcp__ghidra__*",
            "mcp__utils__*",
            "mcp__memory__*",
        ]

        # Add GDB MCP server if enabled
        if self.enable_gdb:
            gdb_settings = settings.gdb
            if gdb_settings.service_mode == "http":
                mcp_servers["gdb"] = {
                    "type": "http",
                    "url": gdb_settings.mcp_url,
                }
            elif gdb_settings.service_mode == "sse":
                mcp_servers["gdb"] = {
                    "type": "sse",
                    "url": gdb_settings.mcp_url,
                }
            else:
                mcp_servers["gdb"] = {
                    "type": "stdio",
                    "command": gdb_settings.mcp_command,
                    "env": {"GDB_PATH": gdb_settings.gdb_path},
                }
            allowed_tools.append("mcp__gdb__*")
            logger.info(f"GDB dynamic analysis enabled (mode: {gdb_settings.service_mode})")

        # Configure agent options with structured output
        options = ClaudeAgentOptions(
            tools=[],
            system_prompt=system_prompt,
            model=settings.llm.model,
            mcp_servers=mcp_servers,
            allowed_tools=allowed_tools,
            max_turns=self.config.max_iterations,
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

        # Tool name to human-readable description mapping
        tool_descriptions = {
            # Ghidra tools (static analysis)
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
            # Memory tools
            "mcp__memory__memory_save_finding": "Saving finding",
            "mcp__memory__memory_cache_function": "Caching function analysis",
            # GDB tools (dynamic analysis)
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
        }

        async def _call_ai() -> dict[str, Any]:
            """Inner function for AI call with detailed logging."""
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
            logger.info(f"Allowed tools: {len(allowed_tools)} tools")
            if self.enable_gdb:
                logger.info("GDB dynamic analysis: ENABLED")

            # Log system prompt (first 500 chars)
            logger.info("-" * 60)
            logger.info("[System Prompt Preview]")
            logger.info(system_prompt[:500] + "..." if len(system_prompt) > 500 else system_prompt)

            # Log user prompt (first 1000 chars)
            logger.info("-" * 60)
            logger.info("[User Prompt Preview]")
            logger.info(prompt[:1000] + "..." if len(prompt) > 1000 else prompt)
            logger.info("-" * 60)

            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                async for msg in client.receive_response():
                    # Handle system messages (MCP connection status)
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

                    # Handle assistant messages (AI responses with potential tool use)
                    if isinstance(msg, AssistantMessage):
                        if not hasattr(msg, "content") or not msg.content:
                            continue
                        for block in msg.content:
                            if isinstance(block, ToolUseBlock):
                                tool_call_count += 1
                                tool_name = block.name
                                tool_input = block.input or {}

                                # Get human-readable description
                                description = tool_descriptions.get(
                                    tool_name,
                                    tool_name.replace("mcp__", "")
                                    .replace("__", ": ")
                                    .replace("_", " ")
                                    .title(),
                                )

                                # Extract relevant info for preview
                                preview_data = {
                                    "tool": tool_name,
                                    "tool_call_count": tool_call_count,
                                }

                                # Add context based on tool type
                                if "function" in tool_name.lower():
                                    func_name = (
                                        tool_input.get("name")
                                        or tool_input.get("function_name", "")
                                        or tool_input.get("target", "")
                                    )
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
                                elif "breakpoint" in tool_name.lower():
                                    location = tool_input.get("location", "")
                                    if location:
                                        description = f"{description}: {location}"
                                        preview_data["location"] = location
                                elif "memory" in tool_name.lower():
                                    address = tool_input.get("address", "")
                                    if address:
                                        description = f"{description}: {address}"
                                        preview_data["address"] = address

                                # Detailed logging
                                logger.info("-" * 50)
                                logger.info(f"[Tool #{tool_call_count}] {tool_name}")
                                logger.info(f"  Description: {description}")
                                logger.info(
                                    f"  Input: {json.dumps(tool_input, ensure_ascii=False)[:500]}"
                                )

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

                            elif isinstance(block, TextBlock):
                                result_text = block.text
                                if block.text and len(block.text) > 0:
                                    # Log AI's thinking/response
                                    text_preview = (
                                        block.text[:1000] + "..."
                                        if len(block.text) > 1000
                                        else block.text
                                    )
                                    logger.info(f"[AI Thinking] {text_preview}")

                            elif isinstance(block, ToolResultBlock):
                                # Log tool result
                                result_content = (
                                    str(block.content) if hasattr(block, "content") else str(block)
                                )
                                result_preview = (
                                    result_content[:500] + "..."
                                    if len(result_content) > 500
                                    else result_content
                                )
                                tool_id = getattr(block, "tool_use_id", "unknown")
                                is_error = getattr(block, "is_error", False)
                                if is_error:
                                    logger.warning(
                                        f"[Tool Result ERROR] {tool_id}: {result_preview}"
                                    )
                                else:
                                    logger.info(f"[Tool Result] {result_preview}")

                    # Handle user messages (contains tool results)
                    elif isinstance(msg, UserMessage):
                        # Check for tool_use_result
                        if hasattr(msg, "tool_use_result") and msg.tool_use_result:
                            tool_result = msg.tool_use_result
                            if isinstance(tool_result, dict):
                                result_str = json.dumps(tool_result, ensure_ascii=False)
                                is_error = tool_result.get("is_error", False)
                            else:
                                result_str = str(tool_result)
                                is_error = False
                            result_preview = (
                                result_str[:800] + "..." if len(result_str) > 800 else result_str
                            )
                            if is_error:
                                logger.warning(f"[Tool Result ERROR] {result_preview}")
                            else:
                                logger.info(f"[Tool Result] {result_preview}")

                        # Also check content for ToolResultBlock
                        if hasattr(msg, "content") and msg.content:
                            for block in msg.content if isinstance(msg.content, list) else []:
                                if isinstance(block, ToolResultBlock):
                                    result_content = (
                                        str(block.content)
                                        if hasattr(block, "content")
                                        else str(block)
                                    )
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

                    # Handle result message - check for structured output first
                    elif isinstance(msg, ResultMessage):
                        logger.info("=" * 60)
                        logger.info("AI Analysis Complete")
                        logger.info("=" * 60)
                        logger.info(f"  Total tool calls: {tool_call_count}")
                        logger.info(f"  Turns used: {getattr(msg, 'num_turns', 'N/A')}")
                        logger.info(f"  Cost: ${getattr(msg, 'total_cost_usd', 0):.4f}")
                        logger.info(f"  Input tokens: {getattr(msg, 'input_tokens', 'N/A')}")
                        logger.info(f"  Output tokens: {getattr(msg, 'output_tokens', 'N/A')}")

                        # Try structured output first (preferred)
                        if hasattr(msg, "structured_output") and msg.structured_output:
                            logger.info("Using structured output from Claude")
                            structured_result = msg.structured_output

                            # Handle case where structured_output contains $defs (schema) instead of data
                            # This happens when Claude returns the schema format instead of actual data
                            if isinstance(structured_result, dict):
                                if "$defs" in structured_result:
                                    # Try to parse the $defs value as JSON
                                    defs_value = structured_result.get("$defs", "")
                                    if isinstance(defs_value, str):
                                        try:
                                            structured_result = json.loads(defs_value)
                                            logger.info(
                                                "Parsed structured output from $defs string"
                                            )
                                        except json.JSONDecodeError:
                                            logger.warning("Failed to parse $defs as JSON")
                                            structured_result = None
                                    elif isinstance(defs_value, dict):
                                        structured_result = defs_value

                            # Validate we have the expected structure
                            if structured_result and isinstance(structured_result, dict):
                                if (
                                    "analyzed_functions" in structured_result
                                    or "key_findings" in structured_result
                                ):
                                    # Send completion notification
                                    if self._progress_callback:
                                        try:
                                            await self._progress_callback(
                                                "ghidra_tool",
                                                "AI Analysis Complete",
                                                "completed",
                                                {
                                                    "tool_call_count": tool_call_count,
                                                    "functions_analyzed": len(
                                                        structured_result.get(
                                                            "analyzed_functions", []
                                                        )
                                                    ),
                                                    "findings_saved": len(
                                                        structured_result.get("key_findings", [])
                                                    ),
                                                    "num_turns": getattr(msg, "num_turns", 0),
                                                    "cost_usd": getattr(msg, "total_cost_usd", 0),
                                                },
                                            )
                                        except Exception as e:
                                            logger.debug(f"Progress callback failed: {e}")

                                    return structured_result
                                else:
                                    logger.warning(
                                        f"Structured output missing expected keys: {list(structured_result.keys())}"
                                    )

                        # Send completion notification for non-structured
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
                                        "num_turns": getattr(msg, "num_turns", 0),
                                        "cost_usd": getattr(msg, "total_cost_usd", 0),
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

            logger.info(
                f"AI analysis completed: {tool_call_count} tool calls, "
                f"{functions_analyzed} functions analyzed"
            )

            # Fallback: Parse JSON from text response
            if result_text:
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
                    logger.warning("Failed to parse JSON from text response")

            # Last resort: return findings from memory, deduplicated and normalized
            memory_findings = self.memory_store.get_findings()
            normalized_findings = self._deduplicate_findings(memory_findings)

            return {
                "raw_analysis": result_text,
                "analyzed_functions": [],
                "key_findings": normalized_findings,
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
        results: dict[str, Any] = {
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
            "## ⚠️ CRITICAL: 所有输出必须使用中文 (Chinese Output Required)",
            "- purpose, analysis, description, evidence, attack_chain 等所有文本字段必须使用中文",
            "- 技术术语可以保留英文（如函数名、地址、API名称）",
            '- 示例: purpose: "建立与C2服务器的网络连接" (正确) vs "Establish network connection" (错误)',
            "",
            "## ⚠️ MANDATORY: You MUST use mcp__ghidra__decompile_function tool",
            "- analyzed_functions MUST contain functions you actually decompiled",
            "- Do NOT just read function names from symbols - you MUST see the actual code",
            "- If you don't call mcp__ghidra__decompile_function, analyzed_functions will be EMPTY = FAILURE",
            "- Call mcp__ghidra__decompile_function for at least 3-5 key functions",
            "",
            "## ⚠️ IMPORTANT: How to handle decompile_function errors",
            "- If decompile_function('main') fails, the binary may be stripped",
            "- Use list_functions to get actual function names (e.g., FUN_00401000)",
            "- Try decompile_function with ADDRESS: decompile_function('0x401000')",
            "- Try other entry points: '_start', 'entry', or addresses from list_functions",
            "- DO NOT give up and switch to strings_search - keep trying with different targets",
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
                    "Check mcp__memory__memory_get_function before re-analyzing these:",
                    ", ".join(cached_functions[:30]),
                    "",
                ]
            )

        if previous_findings:
            findings_summary = "\n".join(
                [
                    f"- [{f.get('severity', 'unknown')}] "
                    f"{f.get('type', 'unknown')}: {f.get('summary', '')}"
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

        # Build suspicious functions list from capa capabilities
        suspicious_funcs = []
        capa_result = static_results.get("capa", {})
        capabilities = capa_result.get("capabilities", [])
        for cap in capabilities:
            if any(
                kw in cap.get("namespace", "").lower()
                for kw in ["network", "crypto", "anti", "persistence"]
            ):
                suspicious_funcs.append(cap.get("name", ""))
        parts.extend(
            [
                "## Investigation Protocol (MANDATORY)",
                "",
                "### 1. MUST Decompile Functions (CRITICAL)",
                "- You MUST call mcp__ghidra__decompile_function for key functions",
                "- analyzed_functions array MUST contain functions you decompiled",
                "- Reading symbols alone is NOT enough - see the actual code",
                "",
                "### 2. Evidence Verification",
                "- Any function flagged as suspicious MUST be verified with mcp__ghidra__decompile_function",
                "- Do NOT trust static analysis classifications blindly",
                "",
                "### 3. Upstream Tracing",
                "- For ANY suspicious function, MUST call mcp__ghidra__function_xrefs to find its callers",
                "- Trace until you find: entry point, exported function, or thread creation",
                "- Build complete chain: decrypt -> inject -> communicate",
                "",
            ]
        )

        if suspicious_funcs:
            parts.extend(
                [
                    "## Suspicious Functions to Investigate",
                    "These were flagged by static analysis - VERIFY with decompile_function:",
                    ", ".join(suspicious_funcs[:20]),
                    "",
                ]
            )

        parts.extend(
            [
                "## Required Tool Usage",
                "",
                "### Step 1: List functions and find entry points",
                "- Call mcp__ghidra__list_functions to see available functions",
                "- Identify main, _start, or exported functions",
                "",
                "### Step 2: Decompile key functions (MANDATORY)",
                "- Call mcp__ghidra__decompile_function for entry points",
                "- Call mcp__ghidra__decompile_function for suspicious functions",
                "- You MUST decompile at least 3-5 functions",
                '- Example: mcp__ghidra__decompile_function(target="main")',
                "",
                "### Step 3: Trace call chains",
                "- Call mcp__ghidra__function_xrefs to understand relationships",
                "- Build attack chain from entry to malicious behavior",
                "",
                "## CRITICAL: Final Output Format (所有文本使用中文!)",
                "After completing your analysis, you MUST output a JSON object with this EXACT structure:",
                "```json",
                "{",
                '  "analyzed_functions": [',
                '    {"name": "func_name", "address": "0x...", "purpose": "用中文描述函数用途", "analysis": "用中文详细分析", "risk": "critical|high|medium|low"}',
                "  ],",
                '  "key_findings": [',
                '    {"id": "finding_001", "title": "中文标题", "category": "中文类别", "description": "用中文详细描述", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "evidence": ["中文证据1", "中文证据2"]}',
                "  ],",
                '  "attack_chain": "函数A (中文用途) → 函数B (中文用途) → 函数C (中文用途)",',
                '  "analysis_path": ["步骤1: 中文描述", "步骤2: 中文描述"]',
                "}",
                "```",
                "",
                "## Output Requirements:",
                "- analyzed_functions MUST NOT be empty - include functions you decompiled with mcp__ghidra__decompile_function",
                "- evidence MUST be an array of strings, never a single string",
                "- risk uses lowercase: critical, high, medium, low",
                "- severity uses UPPERCASE: CRITICAL, HIGH, MEDIUM, LOW",
                "- **所有 purpose, analysis, title, description, evidence, attack_chain 必须使用中文**",
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

        # Priority 2: Functions based on capa capabilities
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
        """Deduplicate and normalize findings from memory.

        Groups similar findings by type/category and merges their evidence.
        Prefers Chinese content over English when both exist.

        Args:
            findings: Raw findings from memory store.

        Returns:
            Deduplicated and normalized findings list.
        """
        if not findings:
            return []

        # Group findings by normalized type
        grouped: dict[str, list[dict]] = {}
        for f in findings:
            # Normalize type: lowercase, remove underscores, strip common prefixes
            raw_type = f.get("type") or f.get("category") or "unknown"
            normalized_type = raw_type.lower().replace("_", "").strip()

            # Map common variations to canonical types
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

        # Merge each group into a single finding
        result = []
        finding_id = 1

        for canonical_type, group in grouped.items():
            # Prefer Chinese content (contains CJK characters)
            def has_chinese(text: str) -> bool:
                return any("\u4e00" <= c <= "\u9fff" for c in str(text))

            # Sort: Chinese content first, then by severity
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            group.sort(
                key=lambda x: (
                    0 if has_chinese(x.get("summary", "")) else 1,
                    severity_order.get(x.get("severity", "medium").lower(), 2),
                )
            )

            # Use the best (first) finding as base
            best = group[0]

            # Collect all evidence from the group
            all_evidence = []
            for f in group:
                ev = f.get("evidence", {})
                if isinstance(ev, dict):
                    # Convert dict evidence to list of strings
                    for k, v in ev.items():
                        if v:
                            all_evidence.append(f"{k}: {v}")
                elif isinstance(ev, list):
                    all_evidence.extend([str(e) for e in ev if e])
                elif ev:
                    all_evidence.append(str(ev))

            # Deduplicate evidence
            seen_evidence = set()
            unique_evidence = []
            for e in all_evidence:
                e_normalized = e.lower()[:50]
                if e_normalized not in seen_evidence:
                    seen_evidence.add(e_normalized)
                    unique_evidence.append(e)

            # Build normalized finding
            normalized = {
                "id": f"finding_{finding_id:03d}",
                "title": best.get("title")
                or best.get("type")
                or best.get("summary", "Finding")[:50],
                "category": best.get("category") or best.get("type", "Unknown"),
                "description": best.get("description") or best.get("summary", ""),
                "severity": best.get("severity", "MEDIUM").upper(),
                "evidence": unique_evidence[:10],  # Limit to 10 evidence items
                "impact": best.get("impact"),
                "recommendation": best.get("recommendation"),
            }
            result.append(normalized)
            finding_id += 1

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        result.sort(key=lambda x: severity_order.get(x.get("severity", "MEDIUM"), 2))

        return result

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
