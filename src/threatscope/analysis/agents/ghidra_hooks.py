"""Hooks for Ghidra AI analysis agent."""

import logging

from src.threatscope.analysis.agents.memory_store import MemoryStore

logger = logging.getLogger(__name__)

MAX_TOOL_RESULT_CHARS = 100000


def create_pre_compact_hook(memory_store: MemoryStore):
    """Create PreCompact hook for context compression.

    Saves critical findings before Claude compresses context.
    """

    async def pre_compact_hook(input_data, tool_use_id, context):
        findings = memory_store.get_findings()
        cached_functions = memory_store.list_cached_functions()

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
                "hookEventName": input_data["hook_event_name"],
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


def create_post_tool_use_hook():
    """Create PostToolUse hook to add context about large tool results.

    Adds a warning message when tools return massive results.
    """

    async def post_tool_use_hook(input_data, tool_use_id, context):
        tool_response = input_data.get("tool_response", "")
        tool_name = input_data.get("tool_name", "")

        if not isinstance(tool_response, str):
            tool_response = str(tool_response)

        if len(tool_response) > MAX_TOOL_RESULT_CHARS:
            logger.warning(f"Large tool result from {tool_name}: {len(tool_response):,} chars")
            return {
                "hookSpecificOutput": {
                    "hookEventName": input_data["hook_event_name"],
                    "additionalContext": (
                        f"Note: The {tool_name} result was {len(tool_response):,} characters. "
                        f"Consider using offset/limit parameters to paginate large results."
                    ),
                }
            }

        return {}

    return post_tool_use_hook
