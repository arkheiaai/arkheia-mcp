FROM python:3.12-slim

LABEL maintainer="arkheia.ai"
LABEL description="Arkheia MCP Trust Server -- Product 1"

RUN useradd -m -u 1000 arkheia

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server/ /app/mcp_server/
# mcp_server.receipts drives the SAME audit rail as the proxy and the registry
# (proxy.audit.writer: JSONL + secrets redaction + tamper-evident hash chain)
# rather than growing a third one. That import must exist in the image or the
# server will not boot -- tests/test_mcp_packaging_floor.py derives the required
# COPY set from the actual first-party imports, so a new cross-package import
# fails there rather than at `docker run`. Both paths are stdlib-only.
COPY proxy/__init__.py /app/proxy/
COPY proxy/audit/ /app/proxy/audit/

RUN chown -R arkheia:arkheia /app
USER arkheia

# ARKHEIA_PROXY_URL must point to the running proxy
ENV ARKHEIA_PROXY_URL=http://localhost:8099

# MCP server runs via stdio by default (for Claude Desktop / Claude Code)
CMD ["python", "-m", "mcp_server.server"]
