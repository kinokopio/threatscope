"""Langfuse observability integration for AI agents.

This module provides tracing for Claude Agent SDK calls via Langfuse.
Uses langsmith's Claude Agent SDK integration which automatically traces
all tool calls, model runs, and conversation flows.

Configuration via environment variables:
    LANGFUSE_PUBLIC_KEY: Your Langfuse public key
    LANGFUSE_SECRET_KEY: Your Langfuse secret key
    LANGFUSE_BASE_URL: Langfuse server URL (default: https://cloud.langfuse.com)
"""

import logging
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langfuse import Langfuse

logger = logging.getLogger(__name__)

_langfuse_client: "Langfuse | None" = None
_initialized: bool = False


def init_langfuse() -> "Langfuse | None":
    """Initialize Langfuse observability with Claude Agent SDK instrumentation.

    This function:
    1. Checks if Langfuse credentials are configured
    2. Sets up langsmith OTEL environment variables
    3. Initializes and verifies the Langfuse client
    4. Configures Claude Agent SDK instrumentation

    The langsmith integration automatically traces:
    - Chain runs for each conversation stream
    - Model runs for each assistant turn
    - All tool calls (built-in, MCP, SDK tools)

    Returns:
        Langfuse client if successfully initialized, None otherwise.

    Example:
        # In app startup
        from src.threatscope.core.observability import init_langfuse
        langfuse = init_langfuse()
        if langfuse:
            print("Langfuse tracing enabled")
    """
    global _langfuse_client, _initialized

    if _initialized:
        return _langfuse_client

    _initialized = True

    # Check if Langfuse is configured
    public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
    secret_key = os.environ.get("LANGFUSE_SECRET_KEY")

    if not public_key or not secret_key:
        logger.info("Langfuse not configured (missing LANGFUSE_PUBLIC_KEY or LANGFUSE_SECRET_KEY)")
        return None

    try:
        # Step 1: Set up langsmith OTEL environment variables (BEFORE importing langfuse)
        # These enable OpenTelemetry export to Langfuse
        os.environ["LANGSMITH_OTEL_ENABLED"] = "true"
        os.environ["LANGSMITH_OTEL_ONLY"] = "true"
        os.environ["LANGSMITH_TRACING"] = "true"

        # Step 2: Import and initialize Langfuse client
        from langfuse import get_client

        _langfuse_client = get_client()

        # Step 3: Verify connection
        if _langfuse_client.auth_check():
            logger.info("Langfuse client is authenticated and ready!")
        else:
            logger.warning("Langfuse authentication failed - check your API keys")
            _langfuse_client = None
            return None

        # Step 4: Configure Claude Agent SDK instrumentation via langsmith
        # This patches ClaudeSDKClient to automatically trace all calls
        try:
            from langsmith.integrations.claude_agent_sdk import configure_claude_agent_sdk

            if configure_claude_agent_sdk():
                logger.info("Claude Agent SDK instrumentation enabled")
            else:
                logger.warning("Failed to configure Claude Agent SDK instrumentation")
        except ImportError:
            logger.warning(
                "langsmith[claude-agent-sdk] not available. "
                "Install with: pip install 'langsmith[claude-agent-sdk]' 'langsmith[otel]'"
            )
        except Exception as e:
            logger.warning(f"Failed to configure Claude Agent SDK instrumentation: {e}")

        base_url = os.environ.get("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
        logger.info(f"Langfuse observability enabled ({base_url})")
        return _langfuse_client

    except ImportError as e:
        logger.warning(
            f"Langfuse not installed: {e}. "
            "Install with: pip install langfuse"
        )
        return None
    except Exception as e:
        logger.warning(f"Failed to initialize Langfuse: {e}")
        return None


def get_langfuse() -> "Langfuse | None":
    """Get the initialized Langfuse client.

    Returns:
        Langfuse client if initialized, None otherwise.
    """
    return _langfuse_client


def flush_langfuse() -> None:
    """Flush any pending Langfuse events.

    Call this before application shutdown to ensure all traces are sent.
    """
    if _langfuse_client is not None:
        try:
            _langfuse_client.flush()
            logger.debug("Langfuse events flushed")
        except Exception as e:
            logger.warning(f"Failed to flush Langfuse events: {e}")


def shutdown_langfuse() -> None:
    """Shutdown Langfuse client and flush pending events.

    Call this during application shutdown.
    """
    global _langfuse_client, _initialized

    if _langfuse_client is not None:
        try:
            _langfuse_client.flush()
            _langfuse_client.shutdown()
            logger.info("Langfuse client shutdown complete")
        except Exception as e:
            logger.warning(f"Error during Langfuse shutdown: {e}")
        finally:
            _langfuse_client = None
            _initialized = False
