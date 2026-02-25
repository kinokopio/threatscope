"""GhidraAgent - AI-driven deep reverse engineering analysis."""

import json
import logging
from pathlib import Path
from typing import Any

from ai.base import AgentConfig, AgentResult, BaseAgent
from ai.memory_store import MemoryStore
from ghidra_service.client import GhidraClient

logger = logging.getLogger(__name__)


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
        ghidra_url: str = "http://localhost:8000",
    ):
        """Initialize GhidraAgent.

        Args:
            config: Agent configuration.
            project_dir: Project directory for memory storage.
            ghidra_url: URL of Ghidra HTTP service.
        """
        super().__init__(config)
        self.project_dir = Path(project_dir)
        self.ghidra_url = ghidra_url
        self.memory_store: MemoryStore | None = None
        self.ghidra_client: GhidraClient | None = None

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
            self.ghidra_client.health_check()
            ghidra_available = True

            # If file provided and not already loaded, upload it
            if file_path and Path(file_path).exists():
                try:
                    self.ghidra_client.upload(file_path)
                    self.ghidra_client.analyze()
                    ghidra_info = self.ghidra_client.get_info()
                except Exception as e:
                    logger.warning(f"Failed to load binary: {e}")
        except Exception as e:
            logger.warning(f"Ghidra service not available: {e}")

        # Perform analysis if Ghidra is available
        analysis_results = {}
        if ghidra_available and ghidra_info:
            analysis_results = await self._perform_analysis(
                static_results, cached_functions
            )

        # Build prompt for LLM (for future integration)
        prompt = self._build_prompt(
            static_results=static_results,
            file_path=file_path,
            cached_functions=cached_functions,
            previous_findings=previous_findings,
            ghidra_info=ghidra_info,
        )

        return AgentResult(
            success=True,
            data={
                "status": "ready" if ghidra_available else "ghidra_unavailable",
                "ghidra_available": ghidra_available,
                "ghidra_info": ghidra_info,
                "cached_functions": cached_functions,
                "previous_findings_count": len(previous_findings),
                "analysis_results": analysis_results,
                "prompt_length": len(prompt),
                "message": (
                    "Analysis complete"
                    if analysis_results
                    else "GhidraAgent ready. Connect to Ghidra service for full analysis."
                ),
            },
        )

    async def _perform_analysis(
        self, static_results: dict, cached_functions: list[str]
    ) -> dict[str, Any]:
        """Perform automated analysis using Ghidra.

        This is a rule-based analysis that identifies key functions
        based on static analysis hints.
        """
        if not self.ghidra_client:
            return {}

        results = {
            "analyzed_functions": [],
            "key_findings": [],
            "suspicious_functions": [],
        }

        try:
            # Get function list
            functions = self.ghidra_client.list_functions(limit=500)

            # Identify interesting functions based on static analysis
            interesting_targets = self._identify_targets(static_results, functions)

            # Analyze each target
            for target in interesting_targets[:20]:  # Limit to 20 functions
                if target in cached_functions:
                    # Use cached result
                    cached = self.memory_store.get_function(target)
                    if cached:
                        results["analyzed_functions"].append(cached)
                        continue

                try:
                    # Decompile function
                    decomp = self.ghidra_client.decompile_function(target)
                    if not decomp:
                        continue

                    # Get xrefs
                    xrefs = self.ghidra_client.get_function_xrefs(target)

                    # Build analysis result
                    func_analysis = {
                        "name": decomp.get("name", target),
                        "address": decomp.get("address", ""),
                        "code": decomp.get("code", "")[:4000],  # Truncate
                        "callers": xrefs.get("callers", []) if xrefs else [],
                        "callees": xrefs.get("callees", []) if xrefs else [],
                    }

                    # Cache the result
                    self.memory_store.cache_function(target, func_analysis)
                    results["analyzed_functions"].append(func_analysis)

                except Exception as e:
                    logger.warning(f"Failed to analyze {target}: {e}")

            # Identify suspicious patterns
            results["suspicious_functions"] = self._find_suspicious(
                results["analyzed_functions"], static_results
            )

        except Exception as e:
            logger.error(f"Analysis failed: {e}")

        return results

    def _identify_targets(
        self, static_results: dict, functions: list[dict]
    ) -> list[str]:
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
                # Find functions that might use these APIs
                for func in functions:
                    name = func.get("name", "")
                    if name.startswith("FUN_") and name not in targets:
                        targets.append(name)
                        if len(targets) >= 30:
                            break

        # Priority 3: Auto-named functions (FUN_*)
        for func in functions:
            name = func.get("name", "")
            if name.startswith("FUN_") and name not in targets:
                targets.append(name)
                if len(targets) >= 50:
                    break

        return targets

    def _find_suspicious(
        self, analyzed: list[dict], static_results: dict
    ) -> list[dict]:
        """Find suspicious patterns in analyzed functions."""
        suspicious = []

        # Get suspicious strings from static analysis
        suspicious_strings = set()
        strings_data = static_results.get("strings", {})
        for key in ["urls", "ips", "domains", "suspicious"]:
            suspicious_strings.update(strings_data.get(key, []))

        for func in analyzed:
            code = func.get("code", "")
            reasons = []

            # Check for network operations
            if any(api in code for api in ["socket", "connect", "send", "recv"]):
                reasons.append("network_operations")

            # Check for crypto operations
            if any(api in code for api in ["crypt", "aes", "encrypt", "decrypt"]):
                reasons.append("crypto_operations")

            # Check for process operations
            if any(api in code for api in ["exec", "fork", "system", "popen"]):
                reasons.append("process_operations")

            # Check for file operations
            if any(api in code for api in ["fopen", "fwrite", "unlink", "chmod"]):
                reasons.append("file_operations")

            # Check for suspicious strings in code
            for s in suspicious_strings:
                if s and len(s) > 4 and s in code:
                    reasons.append(f"contains_suspicious_string:{s[:30]}")
                    break

            if reasons:
                suspicious.append({
                    "name": func.get("name"),
                    "address": func.get("address"),
                    "reasons": reasons,
                })

        return suspicious

    def _build_prompt(
        self,
        static_results: dict,
        file_path: str,
        cached_functions: list[str],
        previous_findings: list[dict],
        ghidra_info: dict,
    ) -> str:
        """Build the analysis prompt for LLM."""
        system_prompt = self.load_system_prompt()

        context_parts = [
            "## Binary Information",
            f"```json\n{json.dumps(ghidra_info, indent=2)}\n```" if ghidra_info else "Not loaded",
            "",
            "## Static Analysis Results",
            f"```json\n{json.dumps(static_results, indent=2, ensure_ascii=False)[:8000]}\n```",
            "",
            f"## Sample File Path\n{file_path}",
            "",
        ]

        if cached_functions:
            context_parts.extend([
                f"## Previously Analyzed Functions ({len(cached_functions)})",
                ", ".join(cached_functions[:50]),
                "",
            ])

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

        return system_prompt + "\n\n" + "\n".join(context_parts)

    def get_analysis_tools(self) -> list[dict]:
        """Get the list of tools available to this agent."""
        return [
            # Ghidra tools
            {"name": "list_functions", "description": "Get function list with pagination"},
            {"name": "get_function_details", "description": "Get function metadata"},
            {"name": "decompile_function", "description": "Decompile function to C code"},
            {"name": "disassemble_function", "description": "Get assembly instructions"},
            {"name": "function_xrefs", "description": "Get cross-references (callers/callees)"},
            {"name": "get_callgraph", "description": "Get call graph from function"},
            {"name": "list_strings", "description": "Get strings from binary"},
            {"name": "search_strings", "description": "Search strings by pattern"},
            {"name": "read_memory", "description": "Read memory at address"},
            {"name": "get_imports", "description": "Get imported functions"},
            {"name": "get_exports", "description": "Get exported symbols"},
            {"name": "get_sections", "description": "Get program sections"},
            {"name": "get_binary_info", "description": "Get binary metadata"},
            {"name": "get_global_callgraph", "description": "Get complete call graph"},
            # Utility tools
            {"name": "decode_base64", "description": "Decode Base64 string"},
            {"name": "decode_hex", "description": "Decode hex string"},
            {"name": "xor_decrypt", "description": "XOR decrypt data"},
            {"name": "calculate_hash", "description": "Calculate hash (MD5/SHA1/SHA256)"},
            # Memory tools
            {"name": "memory_save_finding", "description": "Save key finding"},
            {"name": "memory_get_findings", "description": "Get saved findings"},
            {"name": "memory_cache_function", "description": "Cache function analysis"},
            {"name": "memory_get_function", "description": "Get cached function"},
            {"name": "memory_list_cached_functions", "description": "List cached functions"},
            {"name": "memory_save_checkpoint", "description": "Save analysis checkpoint"},
            {"name": "memory_restore_checkpoint", "description": "Restore checkpoint"},
        ]
