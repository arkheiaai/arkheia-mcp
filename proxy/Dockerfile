FROM python:3.12-slim

LABEL maintainer="arkheia.ai"
LABEL description="Arkheia Enterprise Proxy -- fabrication detection for enterprise AI"

# Non-root user for security
RUN useradd -m -u 1000 arkheia

WORKDIR /app

# Install dependencies first (layer caching)
COPY proxy/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY proxy/ /app/proxy/
COPY profiles/ /app/profiles/

# Runtime directories
RUN mkdir -p /var/log/arkheia /etc/arkheia && \
    chown -R arkheia:arkheia /var/log/arkheia /etc/arkheia /app

USER arkheia

# Config is injected at runtime -- no secrets in image
# Mount arkheia-proxy.yaml at /etc/arkheia/arkheia-proxy.yaml or set ARKHEIA_CONFIG
ENV ARKHEIA_PROFILES_DIR=/app/profiles
ENV ARKHEIA_AUDIT_LOG=/var/log/arkheia/audit.jsonl

EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8099/admin/health').raise_for_status()"

CMD ["python", "-m", "proxy.main"]
