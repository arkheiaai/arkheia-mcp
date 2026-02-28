FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir fastapi uvicorn[standard] pyyaml httpx

COPY registry_server/ ./registry_server/
COPY profiles/ ./profiles/

RUN useradd -m -u 1000 arkheia && chown -R arkheia:arkheia /app
USER arkheia

ENV ARKHEIA_REGISTRY_PROFILE_DIR=/app/profiles
ENV ARKHEIA_REGISTRY_BASE_URL=http://localhost:8200
EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import httpx; httpx.get('http://localhost:8200/health').raise_for_status()"

CMD ["uvicorn", "registry_server.main:app", "--host", "0.0.0.0", "--port", "8200"]
