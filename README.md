# ThreatScope

AI-driven malware analysis framework with Ghidra integration.

## Features

- **Static Analysis**: Hash calculation, string extraction, ELF parsing, YARA scanning
- **Dynamic Analysis**: Syscall tracing with Tracee, network monitoring
- **AI-Powered Analysis**: Claude-based agents for deep binary analysis
- **Ghidra Integration**: Automated reverse engineering and decompilation
- **MITRE ATT&CK Mapping**: Automatic technique identification
- **Modern Web UI**: React-based dashboard for analysis management

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+ (for frontend)
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/threatscope.git
cd threatscope

# Install Python dependencies
uv sync --extra api --extra ai

# Install frontend dependencies
cd frontend && npm install && cd ..
```

### Running

**Start the API server:**

```bash
uv run uvicorn src.threatscope.api:app --host 0.0.0.0 --port 8000 --reload
```

**Start the frontend (in a separate terminal):**

```bash
cd frontend && npm run dev
```

**Access the application:**

- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Configuration

Create a `.env` file in the project root:

```env
# Anthropic API Key (required for AI analysis)
ANTHROPIC_API_KEY=sk-ant-...

# Optional: Ghidra settings
THREATSCOPE_GHIDRA_BASE_URL=http://localhost:8000
THREATSCOPE_GHIDRA_POOL_SIZE=1

# Optional: Analysis settings
THREATSCOPE_ANALYSIS_ENABLE_DYNAMIC_ANALYSIS=true
THREATSCOPE_ANALYSIS_ENABLE_GHIDRA_ANALYSIS=true
```

## Project Structure

```
threatscope/
├── src/threatscope/          # Main Python package
│   ├── api/                  # FastAPI REST API
│   ├── analysis/             # Analysis engine
│   │   ├── agents/           # AI agents (Ghidra, Malware)
│   │   ├── services/         # Analysis services
│   │   ├── tools/            # Static & dynamic analysis tools
│   │   ├── coordinator.py    # Analysis orchestration
│   │   ├── repository.py     # Database operations
│   │   └── scheduler.py      # Task scheduling
│   ├── core/                 # Configuration & dependencies
│   ├── ghidra/               # Ghidra service integration
│   └── shared/               # Shared utilities & exceptions
├── frontend/                 # React frontend
│   ├── src/
│   │   ├── pages/            # Page components
│   │   ├── features/         # Feature modules
│   │   └── shared/           # Shared components & hooks
│   └── package.json
├── rules/                    # YARA rules
├── docker/                   # Docker configurations
├── tests/                    # Test suite
└── pyproject.toml            # Python project config
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/analyze` | Submit file for analysis |
| GET | `/tasks` | List all analysis tasks |
| GET | `/tasks/{id}` | Get task status and results |
| DELETE | `/tasks/{id}` | Delete a task |
| GET | `/health` | Health check |

## Development

```bash
# Run tests
uv run pytest

# Format code
uv run ruff format .

# Lint code
uv run ruff check .
```

## Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d
```

## License

MIT License - see [LICENSE](LICENSE) for details.
