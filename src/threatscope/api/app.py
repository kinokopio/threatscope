"""FastAPI application factory with proper lifespan management.

This module provides the main FastAPI application with:
- Lifespan context manager for startup/shutdown
- CORS middleware configuration
- Exception handlers
- Router registration
"""

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.threatscope.api.router import router as analysis_router
from src.threatscope.api.schemas import HealthResponse
from src.threatscope.core.config import get_settings
from src.threatscope.core.dependencies import shutdown_dependencies
from src.threatscope.shared.exceptions import ThreatScopeError

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager.

    Handles startup and shutdown events properly using the modern
    lifespan pattern instead of deprecated on_event decorators.
    """
    # Startup
    logger.info("Starting ThreatScope API...")
    settings = get_settings()

    # Start scheduler if needed
    try:
        # Note: In production, you'd want to properly initialize
        # the scheduler here with proper dependency injection
        logger.info(f"Environment: {settings.environment}")
        logger.info(f"Debug mode: {settings.debug}")
    except Exception as e:
        logger.error(f"Startup error: {e}")

    yield

    # Shutdown
    logger.info("Shutting down ThreatScope API...")
    await shutdown_dependencies()
    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        Configured FastAPI application instance.
    """
    settings = get_settings()

    # Configure OpenAPI based on environment
    openapi_url = "/openapi.json" if settings.show_docs else None
    docs_url = "/docs" if settings.show_docs else None
    redoc_url = "/redoc" if settings.show_docs else None

    app = FastAPI(
        title="ThreatScope API",
        description="AI-driven malware analysis framework",
        version="0.2.0",
        lifespan=lifespan,
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
    )

    # Configure CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register exception handlers
    _register_exception_handlers(app)

    # Register routers
    app.include_router(analysis_router)

    # Health check endpoint (at root level)
    @app.get("/health", response_model=HealthResponse, tags=["health"])
    async def health_check() -> HealthResponse:
        """Health check endpoint."""
        return HealthResponse(
            status="healthy",
            version="0.2.0",
            services={
                "api": True,
                "database": True,  # TODO: Actually check database
            },
        )

    return app


def _register_exception_handlers(app: FastAPI) -> None:
    """Register custom exception handlers."""

    @app.exception_handler(ThreatScopeError)
    async def threatscope_exception_handler(
        request: Request, exc: ThreatScopeError
    ) -> JSONResponse:
        """Handle ThreatScope-specific exceptions."""
        logger.warning(f"ThreatScope error: {exc.error_code} - {exc.message}")
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_dict(),
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions."""
        logger.exception(f"Unexpected error: {exc}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_ERROR",
                "message": "An unexpected error occurred",
                "details": {"type": type(exc).__name__},
            },
        )


# Create default app instance
app = create_app()
