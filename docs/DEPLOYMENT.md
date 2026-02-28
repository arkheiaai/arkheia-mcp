# Arkheia Enterprise Proxy — Deployment Guide

---

## Prerequisites

- Python 3.12+
- pip / venv
- Docker + Docker Compose (optional, recommended for production)
- Linux, macOS, or Windows (WSL2 recommended for production)

---

## Installation

```bash
git clone <your-repo-url> arkheia-mcp
cd arkheia-mcp
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Verify:
```bash
pytest                           # 83 passed, 2 skipped expected
```

---

## Configuration

### The only secret

| Variable | Required | Description |
|----------|----------|-------------|
| `ARKHEIA_API_KEY` | Optional | License key for pulling profile updates from the Arkheia registry. Leave empty to use bundled profiles only. |

Set it in the OS environment — **never** in a file:
```bash
export ARKHEIA_API_KEY=ak_live_...      # Linux/macOS
setx ARKHEIA_API_KEY ak_live_...        # Windows (persistent)
```

### Structural config (`proxy/arkheia-proxy.yaml`)

All non-secret options live here. Key settings:

| Key | Default | Description |
|-----|---------|-------------|
| `proxy.port` | `8099` | Port the proxy listens on |
| `proxy.log_level` | `INFO` | `DEBUG` / `INFO` / `WARNING` |
| `detection.profile_dir` | `../profiles` | Path to profile YAML files |
| `detection.high_risk_action` | `warn` | `warn` or `block` on HIGH detections |
| `detection.unknown_action` | `pass` | `pass`, `warn`, or `block` on UNKNOWN |
| `detection.interception_enabled` | `false` | Enable transparent `/v1/*` proxy mode |
| `detection.upstream_url` | `` | Upstream AI API base URL (e.g. `https://api.openai.com`) |
| `registry.pull_on_startup` | `false` | Pull latest profiles on startup (requires API key) |
| `registry.pull_interval_hours` | `24` | How often to pull profile updates |
| `audit.log_path` | `../audit.jsonl` | Where to write the audit log |
| `audit.retention_days` | `365` | Days to retain audit entries |

Override any setting with environment variables:
- `ARKHEIA_PROFILES_DIR` — overrides `detection.profile_dir`
- `ARKHEIA_AUDIT_LOG` — overrides `audit.log_path`
- `ARKHEIA_UPSTREAM_URL` — overrides `detection.upstream_url`
- `ARKHEIA_INTERCEPTION_ENABLED=true` — enables interception middleware

---

## Running the Proxy (standalone)

```bash
uvicorn proxy.main:app --host 0.0.0.0 --port 8099
```

Health check:
```bash
curl http://localhost:8099/admin/health
# {"status":"ok","profiles_loaded":25,...}
```

---

## Running the MCP Server

The MCP server communicates over stdio — it is launched by Claude Desktop, not run directly.

Point it at the proxy:
```bash
export ARKHEIA_PROXY_URL=http://localhost:8099
python -m mcp_server.server
```

### Claude Desktop configuration

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "arkheia": {
      "command": "/path/to/arkheia-mcp/.venv/bin/python",
      "args": ["-m", "mcp_server.server"],
      "env": {
        "ARKHEIA_PROXY_URL": "http://localhost:8099"
      }
    }
  }
}
```

---

## Docker

```bash
docker compose up
```

The proxy starts on port 8099. The MCP server has no port — Claude Desktop launches it via stdio.

Inject the API key from the host environment:
```bash
ARKHEIA_API_KEY=ak_live_... docker compose up
```

Never add `ARKHEIA_API_KEY` to `docker-compose.yaml` or any committed file.

---

## Routing Enterprise AI Traffic Through the Proxy

The proxy intercepts `/v1/*` paths when `interception_enabled: true` and `upstream_url` is set.

### OpenAI-compatible clients

```bash
export OPENAI_BASE_URL=http://your-proxy-host:8099/v1
export ANTHROPIC_BASE_URL=http://your-proxy-host:8099
```

Or in `arkheia-proxy.yaml`:
```yaml
detection:
  interception_enabled: true
  upstream_url: https://api.openai.com
  high_risk_action: warn     # or: block
```

The middleware:
- Intercepts all `/v1/*` requests
- Forwards to `upstream_url` transparently
- Runs detection on the response
- Adds `X-Arkheia-Risk: LOW|MEDIUM|HIGH|UNKNOWN` header to every response
- On HIGH + warn: prepends `[ARKHEIA WARNING: HIGH RISK DETECTED]` to the response body
- On HIGH + block: returns `{"error":"arkheia_blocked","risk_level":"HIGH"}` (still HTTP 200)

Clients that do not route through `/v1/*` can use the explicit `POST /detect/verify` endpoint directly.

### Scope boundary

> Arkheia Enterprise Proxy intercepts API-driven AI traffic. Browser-native AI usage
> (ChatGPT web, Claude.ai, Copilot) requires a complementary network DLP or endpoint
> agent — this is outside the scope of the current release.

---

## Monitoring

### Health endpoint

```bash
curl http://localhost:8099/admin/health
```

```json
{
  "status": "ok",
  "profiles_loaded": 25,
  "profile_ids": ["claude-sonnet-4-6", "gpt-4o", ...],
  "last_registry_pull": "2026-02-28T10:00:00+00:00"
}
```

Alert if `profiles_loaded == 0` (no profiles = no detection).

### Audit log

Each line of `audit.jsonl` is a JSON object:

```json
{
  "detection_id": "uuid4",
  "timestamp": "ISO8601",
  "session_id": "optional",
  "model_id": "gpt-4o",
  "risk_level": "LOW",
  "confidence": 0.0,
  "features_triggered": [],
  "prompt_hash": "sha256-hex",
  "response_length": 142,
  "action_taken": "pass",
  "source": "proxy",
  "error": null
}
```

Prompt and response text are **never** written to the audit log.

**Alert thresholds** (recommended):
- HIGH detections > 5% of traffic in a 1-hour window
- `error` field non-null > 1% of detections (profile coverage gap)
- `profiles_loaded` drops to 0 at any time

### Manual registry pull

```bash
curl -X POST http://localhost:8099/admin/registry/pull
# requires ARKHEIA_API_KEY set in proxy environment
```

### Profile rollback

```bash
curl -X POST http://localhost:8099/admin/profiles/gpt-4o/rollback
```

---

## Reverse Proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name arkheia.your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:8099;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 60s;
    }
}
```

---

## Scaling

The proxy is **stateless between requests** — profiles are loaded in-memory at startup.

To scale horizontally:
1. Run N replicas behind a load balancer
2. Mount a shared volume (NFS, EFS, etc.) for `profiles/` so all replicas share the same YAML files
3. Audit log: point all replicas at a shared JSONL path, or ship to a centralised sink (Loki, Elasticsearch, S3) via a log forwarder

Profile reloads are triggered per-instance via `POST /admin/registry/pull`. In a multi-instance setup, call this on all instances after a profile update, or use a shared profile volume and reload via the API on each.

---

## Running Tests

```bash
pytest                          # all tests
pytest proxy/tests/             # proxy only
pytest mcp_server/tests/        # MCP server only
pytest -v --tb=short            # verbose output
```

Expected result: **83 passed, 2 skipped** (load tests require live server), **1 xfailed** (known audit-write gap, documented), **3 warnings** (benign async mock).
