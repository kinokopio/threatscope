"""Langfuse observability integration for AI agents.

This module provides OpenTelemetry-based tracing for all Anthropic/Claude API calls.
When enabled, all LLM interactions are automatically traced and sent to Langfuse.

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
    """Initialize Langfuse observability with OpenTelemetry instrumentation.

    This function:
    1. Checks if Langfuse credentials are configured
    2. Instruments the Anthropic SDK with OpenTelemetry
    3. Initializes and verifies the Langfuse client

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
        # Import Langfuse and OpenTelemetry instrumentation
        from langfuse import get_client
        from opentelemetry.instrumentation.anthropic import AnthropicInstrumentor

        # Instrument Anthropic SDK - this automatically traces all API calls
        if not AnthropicInstrumentor().is_instrumented_by_opentelemetry:
            AnthropicInstrumentor().instrument()
            logger.debug("Anthropic SDK instrumented with OpenTelemetry")

        # Get Langfuse client
        _langfuse_client = get_client()

        # Verify connection
        if _langfuse_client.auth_check():
            base_url = os.environ.get("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
            logger.info(f"Langfuse observability enabled ({base_url})")
            return _langfuse_client
        else:
            logger.warning("Langfuse authentication failed - check your API keys")
            _langfuse_client = None
            return None

    except ImportError as e:
        logger.warning(
            f"Langfuse dependencies not installed: {e}. "
            "Install with: pip install langfuse opentelemetry-instrumentation-anthropic"
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
