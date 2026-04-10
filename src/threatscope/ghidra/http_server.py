"""
Ghidra HTTP Server - FastAPI service for binary analysis.

Provides REST endpoints for Ghidra analysis operations.
"""

import hashlib
import logging
import os
import threading
import uuid
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from src.threatscope.ghidra.analyzer import GhidraAnalyzer
from src.threatscope.ghidra.mcp_server import mcp

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOW_ORIGINS = os.getenv("GHIDRA_MCP_ALLOW_ORIGINS", "*")
if ALLOW_ORIGINS.strip() == "*":
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in ALLOW_ORIGINS.split(",") if o.strip()]

mcp_middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=[
            "mcp-protocol-version",
            "mcp-session-id",
            "Authorization",
            "Content-Type",
        ],
        expose_headers=["mcp-session-id"],
    )
]

mcp_app = mcp.http_app(path="/", middleware=mcp_middleware, stateless_http=True)

app = FastAPI(
    title="ThreatScope Ghidra Service",
    version="1.0.0",
    description="Binary analysis service using Ghidra/pyghidra",
    lifespan=mcp_app.lifespan,
)

app.mount("/mcp/", mcp_app)

# Global analyzer state (single instance per service)
analyzer: GhidraAnalyzer | None = None
analyzer_lock = threading.RLock()

# Upload directory
UPLOAD_DIR = os.environ.get("GHIDRA_UPLOAD_DIR", "/tmp/ghidra_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


def _safe_path(filename: str) -> str:
    """Create safe path guarded against traversal."""
    path = os.path.normpath(os.path.join(UPLOAD_DIR, filename))
    if os.path.commonpath([UPLOAD_DIR, path]) != UPLOAD_DIR:
        raise HTTPException(status_code=400, detail="Invalid path")
    return path


def require_analyzer() -> GhidraAnalyzer:
    """Get current analyzer or raise error."""
    if analyzer is None:
        raise HTTPException(status_code=409, detail="No binary loaded. POST /upload first.")
    return analyzer


def _close_analyzer() -> None:
    """Close current analyzer."""
    global analyzer
    if analyzer is None:
        return
    try:
        analyzer.close()
    finally:
        analyzer = None


# --- Health & Lifecycle ---


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)) -> dict[str, Any]:
    """Upload binary file for analysis."""
    global analyzer

    # Stream to temp file while computing hash
    tmp_path = _safe_path(f".tmp_{uuid.uuid4().hex}")
    hasher = hashlib.sha256()

    try:
        with open(tmp_path, "wb") as f:
            while chunk := await file.read(1024 * 1024):
                hasher.update(chunk)
                f.write(chunk)

        sha256 = hasher.hexdigest()
        final_path = _safe_path(sha256)

        # Move to final location
        if os.path.exists(final_path):
            os.remove(tmp_path)
        else:
            os.replace(tmp_path, final_path)

        # Open with Ghidra
        with analyzer_lock:
            _close_analyzer()
            analyzer = GhidraAnalyzer(final_path)
            if not analyzer.open():
                analyzer = None
                raise HTTPException(500, "Failed to open binary with Ghidra")

        return {"status": "ok", "sha256": sha256, "filename": file.filename}

    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise HTTPException(500, f"Upload failed: {e}")


@app.post("/close")
def close_binary() -> dict[str, str]:
    """Close current binary and release resources."""
    with analyzer_lock:
        _close_analyzer()
    return {"status": "closed"}


# --- Analysis ---


@app.post("/analyze")
def run_analysis() -> dict[str, str]:
    """Trigger Ghidra auto-analysis."""
    with analyzer_lock:
        return require_analyzer().analyze()


@app.get("/info")
def get_info() -> dict[str, Any]:
    """Get binary metadata."""
    with analyzer_lock:
        return require_analyzer().get_info()


# --- Functions ---


@app.get("/functions")
def list_functions(offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
    """Get function list with pagination."""
    with analyzer_lock:
        return require_analyzer().get_functions(offset, limit)


@app.get("/functions/{target}")
def get_function_details(target: str) -> dict[str, Any]:
    """Get function details by name or address."""
    with analyzer_lock:
        result = require_analyzer().get_function_details(target)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


@app.get("/functions/{target}/decompile")
def decompile_function(target: str) -> dict[str, Any]:
    """Decompile a function."""
    with analyzer_lock:
        result = require_analyzer().decompile_function(target)
        if result is None:
            raise HTTPException(404, f"Decompilation failed: {target}")
        return result


@app.get("/functions/{target}/disassemble")
def disassemble_function(target: str, max_instructions: int = 100) -> dict[str, Any]:
    """Get assembly for a function."""
    with analyzer_lock:
        result = require_analyzer().disassemble_function(target, max_instructions)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


@app.get("/functions/{target}/xrefs")
def get_function_xrefs(target: str) -> dict[str, Any]:
    """Get cross-references for a function."""
    with analyzer_lock:
        result = require_analyzer().get_function_xrefs(target)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


@app.get("/functions/{target}/callgraph")
def get_function_callgraph(target: str, max_depth: int = 3) -> dict[str, Any]:
    """Get call graph starting from a function."""
    with analyzer_lock:
        result = require_analyzer().get_callgraph(target, max_depth)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


@app.post("/functions/decompile_batch")
def decompile_batch(targets: list[str]) -> list[dict[str, Any]]:
    """Batch decompile multiple functions."""
    with analyzer_lock:
        return require_analyzer().decompile_batch(targets)


@app.post("/functions/xrefs_batch")
def get_xrefs_batch(targets: list[str]) -> list[dict[str, Any]]:
    """Batch get cross-references for multiple functions."""
    with analyzer_lock:
        return require_analyzer().get_function_xrefs_batch(targets)


@app.get("/functions/with_callers")
def get_functions_with_callers(min_callers: int = 1, limit: int = 100) -> list[dict[str, Any]]:
    """Get functions that have at least min_callers callers."""
    with analyzer_lock:
        return require_analyzer().get_functions_with_callers(min_callers, limit)


# --- Strings ---


@app.get("/strings")
def list_strings(min_length: int = 4, limit: int = 1000) -> list[dict[str, Any]]:
    """Get strings from binary."""
    with analyzer_lock:
        return require_analyzer().get_strings(min_length, limit)


@app.get("/strings/search")
def search_strings(pattern: str, max_results: int = 100) -> list[dict[str, Any]]:
    """Search strings by regex pattern."""
    with analyzer_lock:
        return require_analyzer().search_strings(pattern, max_results)


# --- Call Graph ---


@app.get("/callgraph")
def get_global_callgraph() -> dict[str, Any]:
    """Get global call graph."""
    with analyzer_lock:
        return require_analyzer().get_global_callgraph()


# --- Memory & Sections ---


@app.get("/memory/{address}")
def read_memory(address: str, length: int = 256) -> dict[str, Any]:
    """Read memory at address."""
    with analyzer_lock:
        result = require_analyzer().read_memory(address, length)
        if result is None:
            raise HTTPException(404, f"Cannot read memory at: {address}")
        return result


@app.get("/imports")
def get_imports() -> list[dict[str, Any]]:
    """Get imported functions."""
    with analyzer_lock:
        return require_analyzer().get_imports()


@app.get("/exports")
def get_exports() -> list[dict[str, Any]]:
    """Get exported symbols."""
    with analyzer_lock:
        return require_analyzer().get_exports()


@app.get("/sections")
def get_sections() -> list[dict[str, Any]]:
    """Get program sections."""
    with analyzer_lock:
        return require_analyzer().get_sections()


# --- Entry Points & Variables ---


@app.get("/entry_points")
def get_entry_points() -> list[dict[str, Any]]:
    """Get program entry points."""
    with analyzer_lock:
        return require_analyzer().get_entry_points()


@app.get("/functions/{target}/variables")
def get_function_variables(target: str) -> dict[str, Any]:
    """Get function variables (parameters and locals)."""
    with analyzer_lock:
        result = require_analyzer().get_function_variables(target)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


@app.get("/functions/{target}/hash")
def get_function_hash(target: str) -> dict[str, Any]:
    """Get SHA-256 hash of normalized function opcodes."""
    with analyzer_lock:
        result = require_analyzer().get_function_hash(target)
        if result is None:
            raise HTTPException(404, f"Function not found: {target}")
        return result


# --- Search & Globals ---


@app.post("/search/bytes")
def search_byte_patterns(pattern_hex: str, max_results: int = 100) -> list[dict[str, Any]]:
    """Search for byte patterns in memory."""
    with analyzer_lock:
        return require_analyzer().search_byte_patterns(pattern_hex, max_results)


@app.get("/globals")
def list_globals(limit: int = 500) -> list[dict[str, Any]]:
    """Get global variables."""
    with analyzer_lock:
        return require_analyzer().list_globals(limit)


# --- Script Execution & Utilities ---


class ScriptRequest(BaseModel):
    """Request model for script execution."""

    code: str
    args: dict[str, Any] | None = None


@app.post("/script/run")
def run_script(request: ScriptRequest) -> dict[str, Any]:
    """Execute a Python script in the Ghidra context."""
    with analyzer_lock:
        return require_analyzer().run_script(request.code, request.args)


@app.post("/utils/clear_flow_overrides")
def clear_flow_overrides(target: str | None = None) -> dict[str, Any]:
    """Clear incorrect flow overrides that prevent proper control flow analysis."""
    with analyzer_lock:
        return require_analyzer().clear_flow_overrides(target)


@app.get("/utils/orphan_code")
def find_orphan_code(min_size: int = 10) -> list[dict[str, Any]]:
    """Find potential orphan code regions not in any function."""
    with analyzer_lock:
        return require_analyzer().find_orphan_code(min_size)


# --- Entry Point ---

if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("GHIDRA_HTTP_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
