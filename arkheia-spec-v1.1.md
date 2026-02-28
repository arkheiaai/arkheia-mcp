# Arkheia — Technical Specification v1.1
**Date:** 2026-02-28  
**Status:** Agent-ready build spec  
**Scope:** Product 1 (MCP Trust Server) + Product 2 (Enterprise Proxy)  
**Supersedes:** v1.0 (2026-02-27)

---

## Change Notes from v1.0

- Concurrent request target raised: 500 → **10,000 simultaneous** (enterprise realistic floor)
- Explicit scope statement added: browser-native AI (shadow AI) is **out of scope for v1** — documented, not silently missing
- Shadow AI advisory section added
- Full repository layout defined for agent orientation
- Profile YAML schema fully specified
- Secrets handling mandated (no plaintext in config or env files)
- Agent build instructions added per phase
- Ambiguous characters in v1.0 were encoding artefacts (UTF-8 em-dashes and arrows rendered as `â€"`, `â†'`, `â"‚` etc.) — this document uses ASCII equivalents throughout

---

## 0. Scope Boundary (Read First)

### What Arkheia v1 intercepts
- API calls from orchestrators, agent frameworks, and enterprise applications routed through the proxy
- MCP tool calls where the orchestrator has been configured with the MCP Trust Server

### What Arkheia v1 does NOT intercept (explicit, not a gap)
- Users typing prompts directly into browser-based AI clients (ChatGPT, Claude.ai, Copilot, Gemini)
- Employees using personal API keys that bypass the corporate proxy
- Air-gapped or mobile AI usage outside the enterprise network

**Agent instruction:** Do not attempt to solve browser interception in this build. When surfaced in UI or docs, display this statement:
> "Arkheia Enterprise Proxy intercepts API-driven AI traffic. Browser-native AI usage (ChatGPT web, Claude.ai, Copilot) requires a complementary network DLP or endpoint agent — this is outside the scope of the current release."

---

## 1. Repository Layout

Agents must orient to this structure before writing any file. Do not create files outside it without justification.

```
arkheia/
  proxy/                        # Product 2 — Enterprise Proxy (FastAPI)
    main.py                     # Entry point, lifespan, app factory
    config.py                   # Pydantic settings, loads arkheia-proxy.yaml + env
    router/
      profile_router.py         # ProfileRouter class (multi-profile, atomic reload)
    detection/
      engine.py                 # Detection engine interface (wraps existing logic)
      features.py               # Feature extraction (DO NOT REPLACE — extend only)
    endpoints/
      detect.py                 # POST /detect/verify
      admin.py                  # Admin endpoints (health, rollback, manual pull)
    registry/
      client.py                 # Profile registry pull client
      validator.py              # Checksum + schema + smoke test validation
    audit/
      writer.py                 # Async audit log writer (JSONL)
    middleware/
      interception.py           # Transparent proxy interception middleware
    tests/
      test_detect.py
      test_router.py
      test_registry.py
      test_load.py              # Load testing suite (locust or httpx async)
    arkheia-proxy.yaml          # Config template (no secrets)
    Dockerfile
    requirements.txt

  mcp_server/                   # Product 1 — MCP Trust Server
    server.py                   # MCP tool definitions (arkheia_verify, arkheia_audit_log)
    proxy_client.py             # HTTP client to POST /detect/verify on proxy
    tests/
      test_mcp_tools.py

  profiles/                     # Model profile YAMLs (shared)
    schema.yaml                 # Profile schema definition (source of truth)
    claude-sonnet-4-6.yaml      # Example — do not modify if already validated
    llama-3-70b.yaml
    gpt-4o.yaml

  registry_server/              # Phase 3 only — Arkheia-hosted registry
    main.py
    storage.py
    auth.py

  docs/
    AGENT_BUILD_GUIDE.md        # This document (for agents)
    DEPLOYMENT.md

  docker-compose.yaml           # Proxy + MCP server together
  .env.example                  # Shows required env var names, no values
```

---

## 2. Secrets Handling (Mandatory)

**No plaintext secrets anywhere in the repository.** This includes `.env` files.

### Required pattern

All secrets are injected via environment variables. The config reads them with Pydantic:

```python
# config.py
from pydantic_settings import BaseSettings
from pydantic import SecretStr

class Settings(BaseSettings):
    arkheia_api_key: SecretStr  # registry auth
    # No other secrets required

    model_config = {"env_file": None}  # do not load .env — use OS env only
```

### For local development

Use a secrets manager CLI (Doppler, AWS SSM, or at minimum Windows Credential Manager via `keyring`). Never use a `.env` file with real values. The repo contains only `.env.example`:

```
# .env.example — copy this, fill values into your secrets manager, never commit values
ARKHEIA_API_KEY=
```

### In docker-compose

```yaml
environment:
  - ARKHEIA_API_KEY=${ARKHEIA_API_KEY}  # injected from host OS env, not from file
```

**Agent instruction:** If you need to write a key to a file for any reason, stop and raise it as a question. Do not write `.env` files with real values under any circumstances.

---

## 3. Detection Engine Interface

The detection engine already exists. Agents must wrap it, not replace it.

```python
# detection/engine.py

from dataclasses import dataclass
from typing import Optional
import uuid
from datetime import datetime, timezone

@dataclass
class DetectionResult:
    risk_level: str          # LOW | MEDIUM | HIGH | UNKNOWN
    confidence: float        # 0.0 to 1.0
    features_triggered: list[str]
    model_id: str
    profile_version: str
    timestamp: str           # ISO8601
    detection_id: str        # UUID

class DetectionEngine:
    """
    Thin wrapper around existing detection logic.
    DO NOT reimplement feature extraction — import from features.py.
    """

    def __init__(self, profile_router):
        self.router = profile_router

    async def verify(self, prompt: str, response: str, model_id: str) -> DetectionResult:
        detection_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        profile = self.router.get(model_id)

        if profile is None:
            return DetectionResult(
                risk_level="UNKNOWN",
                confidence=0.0,
                features_triggered=[],
                model_id=model_id,
                profile_version="none",
                timestamp=timestamp,
                detection_id=detection_id
            )

        # Delegate to existing feature extraction
        result = await _run_existing_detection(prompt, response, profile)

        return DetectionResult(
            risk_level=result.risk_level,
            confidence=result.confidence,
            features_triggered=result.features_triggered,
            model_id=model_id,
            profile_version=profile.version,
            timestamp=timestamp,
            detection_id=detection_id
        )
```

---

## 4. Profile YAML Schema

All model profiles must conform to this schema. The `validator.py` enforces it before any profile is applied.

```yaml
# profiles/schema.yaml — this is the definition, not an example

metadata:
  model_id: string          # exact identifier, e.g. "llama-3-70b"
  model_family: string      # e.g. "llama", "claude", "gpt"
  version: string           # MAJOR.MINOR, e.g. "2.1"
  updated_at: datetime      # ISO8601
  author: string            # e.g. "arkheia-lab"

thresholds:
  high_risk: float          # confidence above this = HIGH (e.g. 0.85)
  medium_risk: float        # confidence above this = MEDIUM (e.g. 0.55)

features:
  - name: string            # e.g. "mean_logprob"
    enabled: boolean
    weight: float           # contribution to confidence score
    params: object          # feature-specific parameters

  # Standard feature set (all optional, enable per profile):
  # mean_logprob, response_length_ratio, jitter_coefficient,
  # latency_pattern, k_factor, token_entropy, rhythm_breaker (Grok-specific)

smoke_test:
  prompt: string            # known prompt
  response: string          # known response for this prompt
  expected_risk: string     # LOW | MEDIUM | HIGH
  # Profile validation fails if smoke test result does not match expected_risk
```

### Example profile

```yaml
# profiles/llama-3-70b.yaml
metadata:
  model_id: "llama-3-70b"
  model_family: "llama"
  version: "2.0"
  updated_at: "2026-02-27T00:00:00Z"
  author: "arkheia-lab"

thresholds:
  high_risk: 0.85
  medium_risk: 0.55

features:
  - name: mean_logprob
    enabled: true
    weight: 0.4
    params:
      window_size: 50

  - name: response_length_ratio
    enabled: true
    weight: 0.3
    params: {}

  - name: k_factor
    enabled: true
    weight: 0.3
    params:
      baseline_tokens: 100

smoke_test:
  prompt: "What is the capital of France?"
  response: "The capital of France is Paris."
  expected_risk: "LOW"
```

---

## 5. `/detect/verify` Endpoint

**This is the most important thing to build first. Everything else depends on it.**

```python
# endpoints/detect.py
from fastapi import APIRouter, Request
from pydantic import BaseModel
from typing import Optional
import hashlib

router = APIRouter()

class VerifyRequest(BaseModel):
    prompt: str
    response: str
    model_id: str
    session_id: Optional[str] = None

class VerifyResponse(BaseModel):
    risk_level: str
    confidence: float
    features_triggered: list[str]
    model_id: str
    profile_version: str
    timestamp: str
    detection_id: str
    error: Optional[str] = None

@router.post("/detect/verify", response_model=VerifyResponse)
async def detect_verify(req: VerifyRequest, request: Request):
    engine = request.app.state.engine
    audit = request.app.state.audit_writer

    # Input validation — always return 200, never 4xx/5xx
    if not req.model_id:
        return VerifyResponse(risk_level="UNKNOWN", confidence=0.0,
            features_triggered=[], model_id="", profile_version="none",
            timestamp=_now(), detection_id=_uuid(), error="model_id_missing")

    if not req.response:
        return VerifyResponse(risk_level="UNKNOWN", confidence=0.0,
            features_triggered=[], model_id=req.model_id, profile_version="none",
            timestamp=_now(), detection_id=_uuid(), error="response_empty")

    result = await engine.verify(req.prompt, req.response, req.model_id)

    # Async audit log — does not block response
    await audit.write({
        "detection_id": result.detection_id,
        "timestamp": result.timestamp,
        "session_id": req.session_id,
        "model_id": result.model_id,
        "profile_version": result.profile_version,
        "risk_level": result.risk_level,
        "confidence": result.confidence,
        "features_triggered": result.features_triggered,
        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),
        "response_length": len(req.response),
        "action_taken": "pass",   # proxy middleware updates this for warn/block
        "source": "proxy"
    })

    return VerifyResponse(**result.__dict__)
```

**Error contract:** All responses are HTTP 200. Detection failures surface in `risk_level: UNKNOWN` and `error` field. This is intentional — detection must never crash the pipeline it monitors.

---

## 6. Multi-Profile Router

```python
# router/profile_router.py
import asyncio
import yaml
import os
from pathlib import Path
from typing import Optional
import copy

class ProfileRouter:
    def __init__(self, profile_dir: str):
        self._profiles: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.profile_dir = profile_dir
        self.load_all()

    def load_all(self):
        profiles = {}
        for f in Path(self.profile_dir).glob("*.yaml"):
            if f.name == "schema.yaml":
                continue
            with open(f) as fh:
                data = yaml.safe_load(fh)
            model_id = data["metadata"]["model_id"]
            profiles[model_id] = data
        self._profiles = profiles

    def get(self, model_id: str) -> Optional[dict]:
        # 1. Exact match
        if model_id in self._profiles:
            return self._profiles[model_id]

        # 2. Prefix match (e.g. "claude-sonnet" matches "claude-sonnet-4-6")
        for key in self._profiles:
            if key.startswith(model_id) or model_id.startswith(key):
                return self._profiles[key]

        # 3. Family match (e.g. "claude" matches any claude profile)
        family = model_id.split("-")[0]
        candidates = [v for k, v in self._profiles.items()
                      if v["metadata"]["model_family"] == family]
        if candidates:
            # Use highest version
            return sorted(candidates,
                key=lambda x: x["metadata"]["version"], reverse=True)[0]

        return None

    async def reload(self, profile_dir: Optional[str] = None):
        """Atomic swap — zero dropped requests."""
        new_profiles = {}
        target = profile_dir or self.profile_dir
        for f in Path(target).glob("*.yaml"):
            if f.name == "schema.yaml":
                continue
            with open(f) as fh:
                data = yaml.safe_load(fh)
            new_profiles[data["metadata"]["model_id"]] = data

        async with self._lock:
            self._profiles = new_profiles
```

---

## 7. Profile Registry Client

```python
# registry/client.py
import httpx
import hashlib
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from pydantic import SecretStr

class RegistryClient:
    def __init__(self, base_url: str, api_key: SecretStr,
                 profile_dir: str, router, validator):
        self.base_url = base_url
        self.api_key = api_key
        self.profile_dir = profile_dir
        self.router = router
        self.validator = validator
        self.last_pull: Optional[datetime] = None

    async def pull(self):
        params = {}
        if self.last_pull:
            params["since"] = self.last_pull.isoformat()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self.base_url}/profiles",
                params=params,
                headers={"Authorization": f"Bearer {self.api_key.get_secret_value()}"}
            )
            resp.raise_for_status()
            data = resp.json()

        for profile_meta in data["profiles"]:
            await self._download_and_apply(client, profile_meta)

        self.last_pull = datetime.now(timezone.utc)

    async def _download_and_apply(self, client, meta: dict):
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(meta["download_url"],
                headers={"Authorization": f"Bearer {self.api_key.get_secret_value()}"})
            resp.raise_for_status()
            content = resp.content

        # Validate checksum
        actual = hashlib.sha256(content).hexdigest()
        if actual != meta["checksum"]:
            raise ValueError(f"Checksum mismatch for {meta['model_id']}")

        # Validate schema + smoke test
        profile_data = self.validator.validate(content)

        # Write to profile dir
        path = Path(self.profile_dir) / f"{meta['model_id']}.yaml"
        # Keep previous version as .bak for rollback
        if path.exists():
            path.rename(str(path) + ".bak")
        path.write_bytes(content)

        # Atomic swap in router
        await self.router.reload()

    async def start_scheduled_pull(self, interval_hours: int):
        while True:
            await asyncio.sleep(interval_hours * 3600)
            try:
                await self.pull()
            except Exception as e:
                # Log, do not crash — continue with current profiles
                pass  # replace with structured logging
```

---

## 8. MCP Trust Server

```python
# mcp_server/server.py
import mcp
from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types
from proxy_client import ProxyClient

app = Server("arkheia-trust-server")
proxy = ProxyClient("http://localhost:8099")

@app.tool()
async def arkheia_verify(prompt: str, response: str, model: str) -> dict:
    """
    Verify whether an AI response shows signs of fabrication.
    Call this on every model response before acting on it.

    Args:
        prompt:   The original prompt sent to the model
        response: The model's response to evaluate
        model:    The model identifier (e.g. 'llama-3-70b', 'gpt-4o')

    Returns:
        risk_level:          LOW / MEDIUM / HIGH / UNKNOWN
        confidence:          0.0 to 1.0
        features_triggered:  Which signals fired
        detection_id:        Reference ID for audit log correlation
    """
    try:
        result = await proxy.verify(prompt=prompt, response=response, model_id=model)
        return result
    except Exception:
        return {
            "risk_level": "UNKNOWN",
            "confidence": 0.0,
            "features_triggered": [],
            "error": "proxy_unavailable"
        }

@app.tool()
async def arkheia_audit_log(session_id: str | None = None, limit: int = 50) -> dict:
    """
    Retrieve structured audit evidence.

    Args:
        session_id: Scope to a specific session (None = all recent)
        limit:      Max events to return (default 50, max 500)

    Returns:
        events:  List of detection events with full detail
        summary: Aggregate counts by risk level
    """
    limit = min(limit, 500)
    try:
        return await proxy.get_audit_log(session_id=session_id, limit=limit)
    except Exception:
        return {"events": [], "summary": {}, "error": "proxy_unavailable"}

async def main():
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
```

```python
# mcp_server/proxy_client.py
import httpx
from typing import Optional

class ProxyClient:
    def __init__(self, base_url: str):
        self.base_url = base_url

    async def verify(self, prompt: str, response: str, model_id: str,
                     session_id: Optional[str] = None) -> dict:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{self.base_url}/detect/verify",
                json={"prompt": prompt, "response": response,
                      "model_id": model_id, "session_id": session_id}
            )
            return resp.json()

    async def get_audit_log(self, session_id: Optional[str] = None,
                            limit: int = 50) -> dict:
        params = {"limit": limit}
        if session_id:
            params["session_id"] = session_id
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{self.base_url}/audit/log", params=params)
            return resp.json()
```

---

## 9. Admin Endpoints

```python
# endpoints/admin.py
from fastapi import APIRouter, Request
from pathlib import Path

router = APIRouter(prefix="/admin")

@router.get("/health")
async def health(request: Request):
    router = request.app.state.profile_router
    return {
        "status": "ok",
        "profiles_loaded": len(router._profiles),
        "profile_ids": list(router._profiles.keys()),
        "last_registry_pull": request.app.state.registry_client.last_pull
    }

@router.post("/registry/pull")
async def manual_pull(request: Request):
    try:
        await request.app.state.registry_client.pull()
        return {"status": "ok"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

@router.post("/profiles/{model_id}/rollback")
async def rollback_profile(model_id: str, request: Request):
    profile_dir = request.app.state.settings.detection.profile_dir
    path = Path(profile_dir) / f"{model_id}.yaml"
    bak = Path(str(path) + ".bak")

    if not bak.exists():
        return {"status": "error", "detail": "no backup available"}

    path.write_bytes(bak.read_bytes())
    await request.app.state.profile_router.reload()
    return {"status": "ok", "message": f"Rolled back {model_id}"}
```

---

## 10. Performance Requirements

Updated from v1.0.

| Metric | Target | Notes |
|--------|--------|-------|
| Detection latency p50 | < 10ms | |
| Detection latency p99 | < 50ms | |
| Concurrent requests | **10,000 simultaneous** | Raised from 500 — enterprise floor |
| Profile load at startup | < 2s for 20 profiles | |
| Profile atomic reload | < 500ms, zero dropped requests | |
| Audit log write latency | < 5ms (async, non-blocking) | |
| Registry pull timeout | 30s | Fail gracefully, retain current profiles |
| Memory per loaded profile | < 10MB | |
| Uptime target | 99.9% | Enterprise SLA |

### Load testing implementation (locust)

```python
# proxy/tests/test_load.py
from locust import HttpUser, task, between
import random

MODELS = ["llama-3-70b", "gpt-4o", "claude-sonnet-4-6"]

class ArkhieiaProxyUser(HttpUser):
    wait_time = between(0.001, 0.01)  # simulate high concurrency

    @task
    def verify(self):
        self.client.post("/detect/verify", json={
            "prompt": "What is the capital of France?",
            "response": "Paris.",
            "model_id": random.choice(MODELS)
        })
```

Run with: `locust -f tests/test_load.py --headless -u 10000 -r 500 --host http://localhost:8099`

---

## 11. Failure Mode Contracts

| Failure | Behaviour | Log action |
|---------|-----------|------------|
| Detection engine crash | Pass all traffic through | Log `detection_offline`, fire webhook alert |
| Registry unreachable | Continue with current profiles | Log warning after 48h without successful pull |
| Profile checksum mismatch | Retain old profile | Log error + alert |
| Profile schema invalid | Retain old profile | Log error + alert |
| Smoke test failure | Reject profile update | Log error + alert |
| MCP proxy unreachable | Return `UNKNOWN` risk | MCP server logs, does not throw |
| No profile for model | Return `UNKNOWN` | Surfaced to caller as information |

---

## 12. Proxy Interception Middleware

```python
# middleware/interception.py
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
import httpx
import asyncio

class AIInterceptionMiddleware(BaseHTTPMiddleware):
    """
    Transparent proxy: forwards to upstream AI endpoint,
    runs detection concurrently, injects warnings if HIGH risk.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        body = await request.body()
        model_id = _extract_model_id(body)

        # Forward to upstream AI simultaneously with detection
        upstream_task = asyncio.create_task(self._forward(request, body))
        response = await upstream_task

        response_body = await response.aread()
        prompt = _extract_prompt(body)

        # Non-blocking detection
        engine = request.app.state.engine
        result = await engine.verify(prompt, response_body.decode(), model_id)

        if result.risk_level == "HIGH":
            settings = request.app.state.settings
            if settings.detection.high_risk_action == "block":
                return Response(
                    content='{"error":"arkheia_blocked","risk_level":"HIGH"}',
                    status_code=200,  # still 200 — never break pipeline unexpectedly
                    headers={"X-Arkheia-Risk": "HIGH"}
                )
            else:  # warn
                modified = b"[ARKHEIA: HIGH RISK] " + response_body
                return Response(content=modified,
                    headers={"X-Arkheia-Risk": "HIGH"})

        return Response(content=response_body,
            headers={"X-Arkheia-Risk": result.risk_level})

    async def _forward(self, request: Request, body: bytes):
        # Implementation: extract target URL from request, forward via httpx
        pass
```

---

## 13. Claude System Prompt Integration

Paste this verbatim into any Claude deployment to activate Product 1:

```
You have access to the arkheia_verify tool. Call it on every response you receive 
from any model or tool before acting on that response or surfacing it to the user.

Rules:
- HIGH risk: do not surface the response. Log detection_id, request clarification from source.
- UNKNOWN risk: flag for human review. Include detection_id in your response.
- MEDIUM risk: surface with a brief confidence note.
- LOW risk: surface normally.

Never skip this verification step, even for responses that appear obviously correct.
```

---

## 14. Build Sequence for Agents

### Phase 1 — Core (must complete before anything else is useful)

**Step 1.1:** Build `/detect/verify` endpoint  
- File: `proxy/endpoints/detect.py`  
- Dependency: detection engine wrapper (`detection/engine.py`)  
- Test: `POST /detect/verify` with a known prompt/response/model_id returns valid JSON  

**Step 1.2:** Build `ProfileRouter`  
- File: `proxy/router/profile_router.py`  
- Test: loads all YAMLs, exact match works, prefix match works, unknown returns None  

**Step 1.3:** Wire up FastAPI app  
- File: `proxy/main.py`  
- Include router, engine, audit writer in `app.state` on startup  

**Step 1.4:** Build MCP Trust Server  
- Files: `mcp_server/server.py`, `mcp_server/proxy_client.py`  
- Test: call `arkheia_verify` tool, confirm it reaches `/detect/verify`  

**Step 1.5:** Integration test  
- Claude Code -> MCP server -> proxy -> detection result  
- Confirm audit log written, detection_id returned  

### Phase 2 — Hardening

**Step 2.1:** Registry client (pull, validate, atomic swap)  
**Step 2.2:** Admin endpoints (health, manual pull, rollback)  
**Step 2.3:** Load test at 10,000 concurrent (must pass before Phase 3)  
**Step 2.4:** Failure mode tests (kill engine mid-request, point registry at bad URL)  

### Phase 3 — Distribution (do not start until Phase 2 passes load test)

**Step 3.1:** Registry server  
**Step 3.2:** Docker packaging  
**Step 3.3:** Customer API key provisioning  
**Step 3.4:** First enterprise pilot deployment  

---

## 15. What Is Already Built

| Component | Status | Agent instruction |
|-----------|--------|-------------------|
| Detection engine | Done | Wrap in `engine.py`, do not rewrite |
| Model profiles (YAML) | Done + growing | Add schema validation, do not alter existing profiles |
| Audit log writer | Done | Integrate into `/detect/verify`, do not replace |
| MCP protocol layer | Done | SDK installed, extend `server.py` skeleton |
| Proxy network interception | Done at localhost:8099 | Add middleware layer on top |
| Async request handling | Done (FastAPI + asyncio) | Keep FastAPI, do not introduce new frameworks |
| `/detect/verify` endpoint | **NOT BUILT** | Start here |
| Multi-profile router | **NOT BUILT** | Step 1.2 |
| Profile registry client | **NOT BUILT** | Phase 2 |
| Profile registry server | **NOT BUILT** | Phase 3 |
| Admin endpoints | **NOT BUILT** | Phase 2 |
| Load testing suite | **NOT BUILT** | Phase 2 |

---

## 16. Configuration Reference

```yaml
# arkheia-proxy.yaml (no secrets — all via OS environment)

proxy:
  host: 0.0.0.0
  port: 8099
  log_level: INFO

detection:
  profile_dir: /etc/arkheia/profiles
  high_risk_action: warn     # warn | block
  unknown_action: pass       # pass | warn | block

registry:
  url: https://registry.arkheia.ai
  api_key: ${ARKHEIA_API_KEY}    # injected from environment, never hardcoded
  pull_on_startup: true
  pull_interval_hours: 24
  pin_major_version: null        # null = always latest

audit:
  log_path: /var/log/arkheia/audit.jsonl
  retention_days: 365
  include_prompt_hash: true      # sha256 only — prompt text never written

mcp_server:
  enabled: true
  port: 8100
  proxy_url: http://localhost:8099
```

**The only secret is `ARKHEIA_API_KEY`. It is never written to any file.**
