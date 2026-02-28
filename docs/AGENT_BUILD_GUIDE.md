# Arkheia MCP Trust Server — Agent Build Guide

## Overview

This guide covers how to configure Claude Desktop (or any MCP-compatible orchestrator)
to use the Arkheia MCP Trust Server for fabrication detection.

---

## Architecture

```
Claude Desktop (or AI agent)
        │  MCP stdio transport
        ▼
┌─────────────────────────┐
│   MCP Trust Server      │  mcp_server/server.py
│   arkheia_verify        │  (FastMCP, stdio)
│   arkheia_audit_log     │
└────────────┬────────────┘
             │  HTTP POST /detect/verify
             ▼
┌─────────────────────────┐
│   Enterprise Proxy      │  proxy/main.py
│   POST /detect/verify   │  (FastAPI, port 8099)
│   GET  /audit/log       │
│   GET  /admin/health    │
└────────────┬────────────┘
             │  in-process
             ▼
┌─────────────────────────┐
│   Detection Engine      │  proxy/detection/engine.py
│   + Profile Router      │  proxy/router/profile_router.py
│   + Audit Writer        │  proxy/audit/writer.py
└─────────────────────────┘
```

---

## Quick Start

### 1. Install dependencies

```bash
cd /path/to/arkheia-mcp
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Start the Enterprise Proxy

```bash
cd proxy
uvicorn main:app --host 0.0.0.0 --port 8099
```

Verify:
```bash
curl http://localhost:8099/admin/health
```

Expected response:
```json
{"status": "ok", "profiles_loaded": 6, "engine": "ready", "audit": "running"}
```

### 3. Configure Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`
(macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

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

Replace `/path/to/arkheia-mcp/` with the actual path.

### 4. Verify the MCP server

After restarting Claude Desktop, the following tools will be available:

- `arkheia_verify(prompt, response, model)` — run fabrication detection
- `arkheia_audit_log(limit?, session_id?)` — retrieve recent audit entries

---

## System Prompt for Agents

Paste this into the system prompt for any Claude agent that should use Arkheia:

```
You have access to the Arkheia fabrication detection system via two MCP tools:

  arkheia_verify(prompt, response, model)
    → Returns risk_level (LOW/MEDIUM/HIGH/UNKNOWN), confidence, and features_triggered.

  arkheia_audit_log(limit=20)
    → Returns the last N detection events.

## Usage Policy

Before acting on any response from an external AI model (not yourself), call
arkheia_verify with the prompt you sent, the response you received, and the
model ID string (e.g. "gpt-4o", "claude-sonnet-4-6").

Risk handling:
  LOW     → proceed normally
  MEDIUM  → note the uncertainty; consider asking for clarification
  HIGH    → treat the information as potentially fabricated; seek verification
  UNKNOWN → proxy unavailable or unrecognised model; proceed with caution

You do NOT need to call arkheia_verify on your own responses.
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARKHEIA_PROXY_URL` | MCP server only | `http://localhost:8099` | Where the proxy is listening |
| `ARKHEIA_API_KEY` | Proxy only (optional) | `` | License key for registry profile pull |
| `ARKHEIA_CONFIG` | Optional | (auto-discover) | Path to `arkheia-proxy.yaml` |
| `ARKHEIA_PROFILES_DIR` | Optional | `../profiles` | Override profile directory |
| `ARKHEIA_AUDIT_LOG` | Optional | `../audit.jsonl` | Override audit log path |

**ARKHEIA_API_KEY** is the only secret. Set it in the OS environment only — never
in any file. The proxy reads it via `pydantic-settings`; it is never logged or
returned in any API response.

---

## Running Tests

```bash
cd /path/to/arkheia-mcp
pytest                         # run all tests
pytest proxy/tests/            # proxy only
pytest mcp_server/tests/       # MCP server only
pytest -v --tb=short           # verbose with short tracebacks
```

Expected: **50 passed, 2 skipped** (load tests require a live proxy).

---

## Profile Directory Layout

```
profiles/
  claude-sonnet-4-6.yaml       # real detection profiles from arkheia-model-lab
  gpt-4o.yaml
  grok-3-mini-fast.yaml
  gemini-2.5-flash.yaml
  ...
  schema.yaml                  # schema reference (not loaded as a profile)
```

Profiles are loaded at startup and hot-reloaded via `POST /admin/registry/pull`
(requires `ARKHEIA_API_KEY`). The reload is atomic — active requests are never
disrupted.

---

## Docker

```bash
docker compose up
```

- Proxy: `http://localhost:8099`
- MCP server: stdio only (no port — launched by Claude Desktop)

Set `ARKHEIA_API_KEY` in the host environment before running compose.

---

## Audit Log

The audit log is a JSONL file at `ARKHEIA_AUDIT_LOG` (default: `audit.jsonl`).

Each line is a JSON object with:
- `detection_id` — UUID4
- `timestamp` — ISO8601 UTC
- `session_id` — optional, from the caller
- `model_id` — model that produced the response
- `risk_level` — LOW / MEDIUM / HIGH / UNKNOWN
- `confidence` — 0.0–1.0
- `features_triggered` — list of feature names
- `prompt_hash` — SHA-256 of the prompt (never the prompt itself)
- `response_length` — character count (never the response itself)
- `action_taken` — `pass` / `warn` / `block`
- `source` — always `"proxy"`

Prompt and response text are **never** written to the audit log.

---

## Phase 2 Roadmap (not yet built)

- Load test at 10,000 concurrent requests (Locust, `proxy/tests/test_load.py`)
- Admin endpoint authentication (bearer token middleware)
- Registry client: scheduled pulls via `asyncio` background task
- Streaming support: per-chunk detection (speculative, feasibility TBD)
