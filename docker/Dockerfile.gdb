FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    gdbserver \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir git+https://github.com/kinokopio/gdb-mcp.git

ENV GDB_PATH=/usr/bin/gdb \
    GDB_MCP_LOG_LEVEL=INFO \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8081/sse || exit 1

CMD ["gdb-mcp-server", "--mode", "sse", "--host", "0.0.0.0", "--port", "8081"]
