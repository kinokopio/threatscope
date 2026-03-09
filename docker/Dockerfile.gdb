FROM python:3.12-slim-bookworm

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/kinokopio/gdb-mcp.git /app/gdb-mcp

WORKDIR /app/gdb-mcp

RUN pip install --no-cache-dir -e .

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GDB_PATH=/usr/bin/gdb \
    GDB_MCP_MODE=sse \
    GDB_MCP_HOST=0.0.0.0 \
    GDB_MCP_PORT=8081

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8081/health || exit 1

CMD ["python", "-m", "gdb_mcp.server", "--mode", "sse", "--host", "0.0.0.0", "--port", "8081"]
