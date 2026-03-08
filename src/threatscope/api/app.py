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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
)

from dotenv import load_dotenv

# Load .env file BEFORE importing settings
load_dotenv()

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402

from src.threatscope.api.router import router as analysis_router  # noqa: E402
from src.threatscope.api.schemas import HealthResponse  # noqa: E402
from src.threatscope.core.config import get_settings  # noqa: E402
from src.threatscope.core.dependencies import (  # noqa: E402
    set_ghidra_pool,
    shutdown_dependencies,
)
from src.threatscope.core.observability import init_langfuse, shutdown_langfuse  # noqa: E402
from src.threatscope.shared.exceptions import ThreatScopeError  # noqa: E402

logger = logging.getLogger(__name__)


_mcp_app = None


def get_mcp_app():
    global _mcp_app
    if _mcp_app is None:
        from src.threatscope.api.mcp_server import mcp

        _mcp_app = mcp.http_app(path="/")
    return _mcp_app


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager."""
    from src.threatscope.ghidra.pool import GhidraInstancePool, PoolConfig  # noqa: E402

    mcp_app = get_mcp_app()

    async with mcp_app.lifespan(app):
        logger.info("Starting ThreatScope API...")
        settings = get_settings()

        init_langfuse()

        ghidra_pool: GhidraInstancePool | None = None
        if settings.analysis.enable_ghidra_analysis:
            if settings.ghidra.service_mode == "docker":
                logger.info(f"Starting Ghidra instance pool (size: {settings.ghidra.pool_size})...")
                pool_config = PoolConfig(
                    pool_size=settings.ghidra.pool_size,
                    docker_image=settings.ghidra.docker_image,
                    base_http_port=settings.ghidra.base_http_port,
                    base_mcp_port=settings.ghidra.base_mcp_port,
                    memory_limit=settings.ghidra.memory_limit,
                    startup_timeout=settings.ghidra.startup_timeout,
                )
                ghidra_pool = GhidraInstancePool(pool_config)
                if await ghidra_pool.initialize():
                    stats = ghidra_pool.get_stats()
                    logger.info(f"Ghidra pool initialized: {stats['total']} instances ready")
                else:
                    logger.warning(
                        "Failed to initialize Ghidra pool - deep analysis will be unavailable"
                    )
                    ghidra_pool = None
            else:
                logger.info("Ghidra in subprocess mode - using single instance (no Docker pool)")
                logger.warning(
                    "For multi-file concurrent analysis, use docker mode with pool_size > 1"
                )

        set_ghidra_pool(ghidra_pool)
        app.state.ghidra_pool = ghidra_pool

        logger.info(f"Environment: {settings.environment}")
        logger.info(f"Debug mode: {settings.debug}")

        yield

        logger.info("Shutting down ThreatScope API...")

        if ghidra_pool is not None:
            logger.info("Shutting down Ghidra pool...")
            await ghidra_pool.shutdown()

        shutdown_langfuse()
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

    # Register v1 API routes
    from src.threatscope.api.v1.router import router as v1_router

    app.include_router(v1_router, prefix="/api/v1")

    # Mount MCP server at /api/v1/mcp
    app.mount("/api/v1/mcp", get_mcp_app())

    # Register legacy routes (backward compatibility)
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
                "database": True,
            },
        )

    # Deprecation warning middleware
    @app.middleware("http")
    async def deprecation_warning(request: Request, call_next):
        response = await call_next(request)
        if not request.url.path.startswith("/api/v1") and request.url.path not in [
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
        ]:
            response.headers["X-API-Deprecated"] = "true"
            response.headers["X-API-Migrate-To"] = "/api/v1"
        return response

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
