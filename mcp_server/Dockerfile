FROM python:3.12-slim

LABEL maintainer="arkheia.ai"
LABEL description="Arkheia MCP Trust Server -- Product 1"

RUN useradd -m -u 1000 arkheia

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_server/ /app/mcp_server/

# mcp_server.tools.memory imports proxy.audit.redactor to scrub caller-supplied
# text before it reaches sqlite -- the SAME redaction implementation the audit
# log uses, not a second one (see mcp_server/tools/memory.py). That import
# must exist in the image or the server dies in ModuleNotFoundError on boot.
# Same fix, same reasoning, as registry_server/Dockerfile's proxy.audit.writer
# copy: tests/test_docker_context_floor.py derives the required COPY set from
# the actual import graph, so a new cross-package import fails there rather
# than at `docker run`. Both files are stdlib-only.
COPY proxy/__init__.py /app/proxy/__init__.py
COPY proxy/audit/ /app/proxy/audit/

RUN chown -R arkheia:arkheia /app
USER arkheia

# ARKHEIA_PROXY_URL must point to the running proxy
ENV ARKHEIA_PROXY_URL=http://localhost:8098

# MCP server runs via stdio by default (for Claude Desktop / Claude Code)
CMD ["python", "-m", "mcp_server.server"]
