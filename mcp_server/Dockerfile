FROM python:3.12-slim

LABEL maintainer="arkheia.ai"
LABEL description="Arkheia MCP Trust Server -- Product 1"

RUN useradd -m -u 1000 arkheia

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server/ /app/mcp_server/

RUN chown -R arkheia:arkheia /app
USER arkheia

# ARKHEIA_PROXY_URL must point to the running proxy
ENV ARKHEIA_PROXY_URL=http://localhost:8099

# MCP server runs via stdio by default (for Claude Desktop / Claude Code)
CMD ["python", "-m", "mcp_server.server"]
