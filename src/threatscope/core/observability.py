"""Langfuse observability integration for AI agents.

This module provides tracing for AI agent calls via Langfuse v3 SDK.
Uses @observe decorator for automatic function tracing.

Configuration via environment variables:
    LANGFUSE_PUBLIC_KEY: Your Langfuse public key
    LANGFUSE_SECRET_KEY: Your Langfuse secret key
    LANGFUSE_HOST: Langfuse server URL (default: https://cloud.langfuse.com)
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
    """Initialize Langfuse observability using v3 SDK.

    This function:
    1. Checks if Langfuse credentials are configured
    2. Initializes the Langfuse client

    After initialization, use @observe decorator in your code:

        from langfuse import observe

        @observe(name="my-function")
        async def my_function():
            ...

    Returns:
        Langfuse client if successfully initialized, None otherwise.
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
        from langfuse import get_client

        # Get host from environment and set it
        host = os.environ.get("LANGFUSE_HOST") or os.environ.get("LANGFUSE_BASE_URL")
        if host:
            os.environ.setdefault("LANGFUSE_HOST", host)

        # Initialize Langfuse client using v3 get_client()
        _langfuse_client = get_client()

        # Verify connection
        if _langfuse_client.auth_check():
            logger.info(f"Langfuse observability enabled ({host or 'https://cloud.langfuse.com'})")
            return _langfuse_client
        else:
            logger.warning("Langfuse authentication failed - check your API keys")
            _langfuse_client = None
            return None

    except ImportError as e:
        logger.warning(f"Langfuse not installed: {e}. Install with: pip install langfuse")
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

