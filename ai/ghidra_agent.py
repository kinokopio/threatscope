"""GhidraAgent - AI-driven deep reverse engineering analysis."""

import json
from pathlib import Path
from typing import Any

from ai.base import AgentConfig, AgentResult, BaseAgent
from ai.memory_store import MemoryStore


class GhidraAgent(BaseAgent):
    """AI agent for deep binary analysis using Ghidra.

    This agent uses Ghidra tools to perform reverse engineering analysis,
    guided by static analysis results. It maintains context through a
    local memory store for incremental analysis.
    """

    def __init__(
        self,
        config: AgentConfig,
        project_dir: str | Path = ".",
    ):
        """Initialize GhidraAgent.

        Args:
            config: Agent configuration.
            project_dir: Project directory for memory storage.
        """
        super().__init__(config)
        self.project_dir = Path(project_dir)
        self.memory_store: MemoryStore | None = None

    @property
    def name(self) -> str:
        return "ghidra_agent"

    async def analyze(self, context: dict[str, Any]) -> AgentResult:
        """Perform deep analysis using Ghidra.

        Args:
            context: Analysis context containing:
                - static_results: Results from static analysis
                - file_path: Path to the binary file
                - sample_hash: SHA256 hash of the sample

        Returns:
            AgentResult with deep analysis findings.
        """
        static_results = context.get("static_results", {})
        file_path = context.get("file_path", "")
        sample_hash = context.get("sample_hash", "")

        if not sample_hash:
            # Try to get from static results
            sample_hash = static_results.get("hashes", {}).get("sha256", "unknown")

        # Initialize memory store
        self.memory_store = MemoryStore(self.project_dir, sample_hash)

        # Check for previous analysis
        cached_functions = self.memory_store.list_cached_functions()
        previous_findings = self.memory_store.get_findings()
        checkpoint = self.memory_store.restore_checkpoint()

        # Build analysis prompt
        prompt = self._build_prompt(
            static_results=static_results,
            file_path=file_path,
            cached_functions=cached_functions,
            previous_findings=previous_findings,
            checkpoint=checkpoint,
        )

        # In a real implementation, this would call the LLM with MCP tools
        # For now, return a placeholder result
        return AgentResult(
            success=True,
            data={
                "status": "ready",
                "prompt_length": len(prompt),
                "cached_functions": cached_functions,
                "previous_findings_count": len(previous_findings),
                "has_checkpoint": checkpoint is not None,
                "message": "GhidraAgent ready. Requires Ghidra service and LLM integration.",
            },
        )

    def _build_prompt(
        self,
        static_results: dict,
        file_path: str,
        cached_functions: list[str],
        previous_findings: list[dict],
        checkpoint: dict | None,
    ) -> str:
        """Build the analysis prompt.

        Args:
            static_results: Static analysis results.
            file_path: Path to the binary.
            cached_functions: List of already analyzed functions.
            previous_findings: Previous findings from memory.
            checkpoint: Previous analysis checkpoint.

        Returns:
            Formatted prompt string.
        """
        # Load base system prompt
        system_prompt = self.load_system_prompt()

        # Build context section
        context_parts = [
            "## Static Analysis Results",
            f"```json\n{json.dumps(static_results, indent=2, ensure_ascii=False)[:8000]}\n```",
            "",
            f"## Sample File Path\n{file_path}",
            "",
        ]

        # Add cached function info
        if cached_functions:
            context_parts.extend([
                f"## Previously Analyzed Functions ({len(cached_functions)})",
                ", ".join(cached_functions[:50]),
                "Use memory_get_function to retrieve cached analysis.",
                "",
            ])

        # Add previous findings
        if previous_findings:
            findings_summary = "\n".join([
                f"- [{f.get('severity', 'unknown')}] {f.get('type', 'unknown')}: {f.get('summary', '')}"
                for f in previous_findings[:10]
            ])
            context_parts.extend([
                "## Previous Findings",
                findings_summary,
                "",
            ])

        # Add checkpoint info
        if checkpoint:
            context_parts.extend([
                "## Analysis Checkpoint",
                f"Phase: {checkpoint.get('current_phase', 'unknown')}",
                f"Summary: {checkpoint.get('context_summary', 'N/A')}",
                "",
            ])

        return system_prompt + "\n\n" + "\n".join(context_parts)

    def get_analysis_tools(self) -> list[dict]:
        """Get the list of tools available to this agent.

        Returns:
            List of tool definitions for MCP integration.
        """
        return [
            # Ghidra tools
            {"name": "list_functions", "description": "Get function list"},
            {"name": "decompile_function", "description": "Decompile function"},
            {"name": "disassemble_function", "description": "Get assembly"},
            {"name": "get_function_details", "description": "Get function metadata"},
            {"name": "function_xrefs", "description": "Get cross-references"},
            {"name": "get_callgraph", "description": "Get call graph"},
            {"name": "list_strings", "description": "Get strings"},
            {"name": "search_strings", "description": "Search strings"},
            {"name": "read_memory", "description": "Read memory"},
            {"name": "get_imports", "description": "Get imports"},
            {"name": "get_exports", "description": "Get exports"},
            {"name": "get_sections", "description": "Get sections"},
            # Utility tools
            {"name": "decode_base64", "description": "Decode Base64"},
            {"name": "decode_hex", "description": "Decode hex"},
            {"name": "xor_decrypt", "description": "XOR decrypt"},
            {"name": "calculate_hash", "description": "Calculate hash"},
            # Memory tools
            {"name": "memory_save_finding", "description": "Save finding"},
            {"name": "memory_get_findings", "description": "Get findings"},
            {"name": "memory_cache_function", "description": "Cache function"},
            {"name": "memory_get_function", "description": "Get cached function"},
            {"name": "memory_list_cached_functions", "description": "List cached"},
            {"name": "memory_save_checkpoint", "description": "Save checkpoint"},
            {"name": "memory_restore_checkpoint", "description": "Restore checkpoint"},
        ]
