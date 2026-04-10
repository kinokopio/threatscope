"""MCP tools for Ghidra agent memory and utilities."""

import json
from datetime import datetime, timezone
from typing import Any

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

from src.threatscope.analysis.agents.memory_store import MemoryStore


def create_memory_tools_server(memory_store: MemoryStore):
    """Create memory tools MCP server for persistent analysis state."""

    @tool(
        "memory_save_finding",
        "Save an important finding to persistent memory. Avoid duplicates - check existing findings first.",
        {"type": str, "summary": str, "evidence": dict, "severity": str},
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True),
    )
    async def save_finding(args: dict[str, Any]) -> dict[str, Any]:
        try:
            findings = memory_store.get_findings()
            new_type = args["type"]
            new_summary = args["summary"]

            for existing in findings:
                existing_type = existing.get("type", "")
                existing_summary = existing.get("summary", "")

                type_similar = (
                    existing_type.lower().replace("_", "") == new_type.lower().replace("_", "")
                    or existing_type.lower() in new_type.lower()
                    or new_type.lower() in existing_type.lower()
                )

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
                "discovered_at": datetime.now(timezone.utc).isoformat(),
            }
            findings.append(finding)
            memory_store.save_findings(findings)
            return {"content": [{"type": "text", "text": f"Saved finding: {finding['id']}"}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to save finding: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_get_findings",
        "Get previously saved findings. Optionally filter by type.",
        {"filter_type": str},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    async def get_findings(args: dict[str, Any]) -> dict[str, Any]:
        try:
            findings = memory_store.get_findings()
            filter_type = args.get("filter_type")
            if filter_type:
                findings = [f for f in findings if f.get("type") == filter_type]
            return {"content": [{"type": "text", "text": json.dumps(findings, indent=2)}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to get findings: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_cache_function",
        "Cache function analysis result for later retrieval.",
        {"name": str, "analysis": dict},
        annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True),
    )
    async def cache_function(args: dict[str, Any]) -> dict[str, Any]:
        try:
            memory_store.cache_function(args["name"], args["analysis"])
            return {"content": [{"type": "text", "text": f"Cached function: {args['name']}"}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to cache function: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_get_function",
        "Get cached function analysis by name.",
        {"name": str},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    async def get_function(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = memory_store.get_function(args["name"])
            if result:
                return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
            return {"content": [{"type": "text", "text": "Function not cached"}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to get function: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_list_cached_functions",
        "List all cached function names.",
        {},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    async def list_cached_functions(args: dict[str, Any]) -> dict[str, Any]:
        try:
            functions = memory_store.list_cached_functions()
            return {"content": [{"type": "text", "text": json.dumps(functions)}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to list functions: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_save_checkpoint",
        "Save analysis checkpoint with current phase and summary.",
        {"phase": str, "summary": str},
        annotations=ToolAnnotations(readOnlyHint=False, idempotentHint=True),
    )
    async def save_checkpoint(args: dict[str, Any]) -> dict[str, Any]:
        try:
            state = {
                "current_phase": args["phase"],
                "context_summary": args["summary"],
                "analyzed_functions": memory_store.list_cached_functions(),
            }
            memory_store.save_checkpoint(state)
            return {"content": [{"type": "text", "text": "Checkpoint saved"}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to save checkpoint: {e}"}],
                "is_error": True,
            }

    @tool(
        "memory_restore_checkpoint",
        "Restore analysis checkpoint.",
        {},
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    async def restore_checkpoint(args: dict[str, Any]) -> dict[str, Any]:
        try:
            state = memory_store.restore_checkpoint()
            if state:
                return {"content": [{"type": "text", "text": json.dumps(state, indent=2)}]}
            return {"content": [{"type": "text", "text": "No checkpoint found"}]}
        except Exception as e:
            return {
                "content": [{"type": "text", "text": f"Failed to restore checkpoint: {e}"}],
                "is_error": True,
            }

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
