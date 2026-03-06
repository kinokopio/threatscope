FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    gdbserver \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY docker/gdb-mcp/pyproject.toml .
COPY docker/gdb-mcp/src/ src/

RUN pip install --no-cache-dir .

ENV GDB_PATH=/usr/bin/gdb \
    GDB_MCP_LOG_LEVEL=INFO \
    GDB_MCP_MODE=sse \
    GDB_MCP_HOST=0.0.0.0 \
    GDB_MCP_PORT=8081 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8081/sse || exit 1

ENTRYPOINT ["gdb-mcp-server", "--mode", "sse"]
