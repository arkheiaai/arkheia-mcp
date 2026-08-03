FROM python:3.12-slim

WORKDIR /app

# Dependencies come from registry_server/requirements.txt so that a scanner can
# read them and the pins match the sibling services. This previously COPYed the
# ROOT requirements.txt and then installed a hardcoded inline list instead --
# the copied file was never installed, so the image's real dependency set was a
# Dockerfile literal invisible to pip-audit / Snyk / Aikido.
COPY registry_server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY registry_server/ ./registry_server/
COPY profiles/ ./profiles/
# registry_server.receipts drives the SAME audit rail as the proxy
# (proxy.audit.writer: JSONL + secrets redaction + tamper-evident hash chain)
# rather than growing a second one. That import must exist in the image or the
# server will not boot -- tests/test_registry_dockerfile_floor.py derives the
# required COPY set from the actual imports, so a new cross-package import
# fails there rather than at `docker run`. Both files are stdlib-only.
COPY proxy/__init__.py ./proxy/
COPY proxy/audit/ ./proxy/audit/

RUN useradd -m -u 1000 arkheia \
    && mkdir -p /var/log/arkheia \
    && chown -R arkheia:arkheia /app /var/log/arkheia
USER arkheia

ENV ARKHEIA_REGISTRY_PROFILE_DIR=/app/profiles
ENV ARKHEIA_REGISTRY_BASE_URL=http://localhost:8200
ENV ARKHEIA_REGISTRY_AUDIT_LOG=/var/log/arkheia/registry-audit.jsonl
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import httpx; httpx.get('http://localhost:8200/health').raise_for_status()"

CMD ["uvicorn", "registry_server.main:app", "--host", "0.0.0.0", "--port", "8200"]
