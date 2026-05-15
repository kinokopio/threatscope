# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Python Backend

```bash
# Install dependencies (API + AI extras)
uv sync --extra api --extra ai
# Install all extras
uv sync --extra all

# Run API server (development)
uv run uvicorn src.threatscope.api:app --host 0.0.0.0 --port 8000 --reload

# Run tests
uv run pytest
# Run a single test file
uv run pytest tests/test_api_v1.py
# Run a single test
uv run pytest tests/test_api_v1.py::test_name

# Lint and format
uv run ruff check .
uv run ruff format .
```

### Frontend

```bash
cd frontend
npm install
npm run dev        # Dev server on port 5173
npm run build      # Production build (tsc -b && vite build)
npm run lint       # ESLint
npm run preview    # Preview production build
```

### Docker (full stack)

```bash
docker-compose up -d    # Build and start all services
docker-compose down     # Stop all services
```

## Architecture

ThreatScope is an AI-driven malware analysis framework: upload a PE/ELF binary, run it through a multi-phase analysis pipeline, view results in a React dashboard. It also exposes an MCP server for external AI agents to trigger and query analyses.

### Analysis Pipeline (`src/threatscope/analysis/coordinator.py`)

The pipeline runs in 4 sequential phases:

1. **Phase 1 — File Identification** (parallel): hash calculation + diec file type detection. Only PE/ELF files proceed.
2. **Phase 2 — Static + Dynamic** (all parallel): FLARE-CAPA capability detection, string/URL/IP extraction, YARA rule scanning, threat intelligence lookups (MalwareBazaar/ThreatFox/URLhaus), and Tracee syscall tracing.
3. **Phase 3 — Ghidra Deep Analysis**: `GhidraAgent` (Claude AI + Ghidra MCP tools) decompiles and reverse-engineers the binary.
4. **Phase 4 — Report Generation**: `ReportBuilder` assembles a structured Pydantic report with verdict, confidence, severity, MITRE ATT&CK mapping, IOCs, and recommendations.

### Backend (`src/threatscope/`)

- **`api/`**: FastAPI app factory (`app.py`), versioned REST routes under `/api/v1/` (tasks, system, skills), and an MCP server mount at `/api/v1/mcp`.
- **`analysis/`**: Core pipeline — `coordinator.py` orchestrates phases; `scheduler.py` manages the async task queue; `repository.py` handles SQLite persistence (`tasks.db`); `agents/` contains Claude-SDK-based AI agents; `services/` wraps the individual analysis tools; `tools/` contains the leaf-level static/dynamic analysis implementations.
- **`ghidra/`**: Ghidra integration — `manager.py` starts/stops the Docker/subprocess-based Ghidra service; `pool.py` manages a pool of Ghidra instances; `mcp_server.py` exposes Ghidra operations as MCP tools for the AI agent; `client.py` is the HTTP client.
- **`core/config.py`**: All configuration via `pydantic-settings` with `THREATSCOPE_` env var prefix and `__` as the nested delimiter. Singleton via `lru_cache`.
- **`skills/`**: Dynamic loader for AI prompt/skill files from the `prompts/` directory.

### Frontend (`frontend/src/`)

React 19 SPA with React Router 7, TanStack Query v5, Tailwind CSS v4, and shadcn/ui (Radix primitives).

- `App.tsx`: Root layout — sidebar + routes: `/` (upload), `/tasks` (active analyses), `/history`, `/report/:id`, `/mcp`, `/skills`.
- `lib/api.ts`: Axios client targeting `/api/v1`. In development, Vite proxies `/api` to `localhost:8000`.
- `hooks/`: TanStack Query hooks for tasks, stats, and skills.
- The UI uses Chinese labels — the intended audience is Chinese-speaking users.

### Docker Services

| Service | Internal Port | Role |
|---|---|---|
| `nginx` | 80 | Reverse proxy: `/api/*` → backend, `/` → frontend |
| `frontend` | — | Nginx-served React SPA |
| `backend` | 8000 | FastAPI application |
| `ghidra` | 8000 | Ghidra HTTP + MCP server |
| `diec` | 8000 | Die/diec file type identification service |
| `gdb` | 8081 | GDB MCP server (SSE mode) for dynamic debugging |
| `gdb-target` | — | Isolated Ubuntu sandbox for running malware samples |

### Key Technologies

- **AI**: `claude-agent-sdk` (Anthropic) for `GhidraAgent` and `MalwareAnalysisAgent`. Observability via Langfuse (`@observe` decorator).
- **MCP**: Both the main API and the Ghidra service expose MCP servers via `fastmcp`, so external AI agents can use ThreatScope as a tool.
- **Tooling**: `uv` for Python dependency management; `ruff` for linting/formatting (line-length 100); `pytest-asyncio` in auto mode.

## Configuration

Copy `.env.example` to `.env`. Key variables:
- `ANTHROPIC_API_KEY` — required for AI agents
- `THREATSCOPE_GHIDRA_*` — Ghidra service connection settings
- `THREATSCOPE_LANGFUSE_*` — optional Langfuse observability
- All nested settings use `__` as the delimiter (e.g., `THREATSCOPE_GHIDRA__HOST`)
