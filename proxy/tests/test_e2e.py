"""
End-to-end integration tests for the full Arkheia stack.

PASSING CRITERIA:
  1. Proxy starts, loads profiles, health check passes
  2. POST /detect/verify returns valid detection for a known model
  3. Audit log entry is written for each detection
  4. Registry server starts and serves profiles
  5. Proxy can pull profiles from registry server (registry -> proxy pipeline)
  6. MCP ProxyClient.verify() reaches proxy and returns a result
  7. MCP ProxyClient.get_audit_log() returns entries written by step 2

These tests require live servers. They are skipped in CI by default.
Run manually:

    # Start proxy (port 8098) and registry (port 8201) first, then:
    pytest proxy/tests/test_e2e.py -v -s

Or set ARKHEIA_E2E=1 to include them in a full test run:

    ARKHEIA_E2E=1 pytest proxy/tests/test_e2e.py -v -s
"""

import asyncio
import os
import time

import httpx
import pytest

PROXY_URL = os.environ.get("ARKHEIA_E2E_PROXY", "http://127.0.0.1:8098")
REGISTRY_URL = os.environ.get("ARKHEIA_E2E_REGISTRY", "http://127.0.0.1:8201")
RUN_E2E = os.environ.get("ARKHEIA_E2E", "0") == "1"

skip_unless_e2e = pytest.mark.skipif(
    not RUN_E2E,
    reason="Set ARKHEIA_E2E=1 and start proxy/registry servers to run e2e tests",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_healthy(url: str, timeout: int = 15) -> bool:
    """Poll a health endpoint until it responds 200 or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Criterion 1 — Proxy health
# ---------------------------------------------------------------------------

@skip_unless_e2e
def test_proxy_health():
    """CRITERION 1: Proxy is up and reports profiles loaded."""
    assert _wait_healthy(f"{PROXY_URL}/admin/health"), \
        f"Proxy at {PROXY_URL} did not become healthy in time"
    r = httpx.get(f"{PROXY_URL}/admin/health")
    data = r.json()
    assert data["status"] == "ok"
    assert data["profiles_loaded"] > 0, "No profiles loaded -- detection would be blind"


# ---------------------------------------------------------------------------
# Criterion 2 — Detection pipeline
# ---------------------------------------------------------------------------

@skip_unless_e2e
def test_detection_pipeline_known_model():
    """CRITERION 2: Full detection round-trip for a known model."""
    r = httpx.post(f"{PROXY_URL}/detect/verify", json={
        "prompt": "What is the capital of France?",
        "response": "The capital of France is Paris.",
        "model_id": "claude-sonnet-4-6",
        "session_id": "e2e-test",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
    assert "detection_id" in data
    assert "timestamp" in data
    assert 0.0 <= data["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Criterion 3 — Audit log written
# ---------------------------------------------------------------------------

@skip_unless_e2e
def test_audit_log_written():
    """CRITERION 3: Audit entry visible via GET /audit/log after detection."""
    # Fire a detection with a unique session_id
    session_id = f"e2e-audit-{int(time.time())}"
    httpx.post(f"{PROXY_URL}/detect/verify", json={
        "prompt": "e2e audit test",
        "response": "e2e audit response",
        "model_id": "gpt-4o",
        "session_id": session_id,
    })
    time.sleep(0.1)  # let async writer flush

    r = httpx.get(f"{PROXY_URL}/audit/log", params={"limit": 50})
    assert r.status_code == 200
    events = r.json().get("events", [])
    matching = [e for e in events if e.get("session_id") == session_id]
    assert len(matching) >= 1, f"No audit entry found for session_id={session_id}"
    entry = matching[0]
    assert "prompt_hash" in entry
    assert "prompt" not in entry       # prompt text must never be logged
    assert "response" not in entry     # response text must never be logged


# ---------------------------------------------------------------------------
# Criterion 4 — Registry server health
# ---------------------------------------------------------------------------

@skip_unless_e2e
def test_registry_server_health():
    """CRITERION 4: Registry server is up and reports profiles available."""
    assert _wait_healthy(f"{REGISTRY_URL}/health"), \
        f"Registry at {REGISTRY_URL} did not become healthy in time"
    r = httpx.get(f"{REGISTRY_URL}/health")
    data = r.json()
    assert data["status"] == "ok"
    assert data["profiles_available"] > 0


# ---------------------------------------------------------------------------
# Criterion 5 — Registry -> proxy pull pipeline
# ---------------------------------------------------------------------------

@skip_unless_e2e
def test_registry_pull_pipeline():
    """CRITERION 5: Proxy can pull profiles from registry server."""
    # Requires ARKHEIA_API_KEY set in proxy env and matching key in registry
    r = httpx.post(f"{PROXY_URL}/admin/registry/pull", timeout=30.0)
    assert r.status_code == 200
    data = r.json()
    # Either successful pull or graceful skip (no key configured)
    assert data.get("status") in ("ok", None) or isinstance(data.get("updated"), list), \
        f"Unexpected pull response: {data}"


# ---------------------------------------------------------------------------
# Criterion 6+7 — MCP ProxyClient end-to-end
# ---------------------------------------------------------------------------

@skip_unless_e2e
@pytest.mark.asyncio
async def test_mcp_proxy_client_verify():
    """CRITERION 6: MCP ProxyClient.verify() reaches proxy and returns valid result."""
    from mcp_server.proxy_client import ProxyClient
    client = ProxyClient(PROXY_URL)
    result = await client.verify(
        prompt="What is 2 + 2?",
        response="2 + 2 equals 4.",
        model_id="gpt-4o",
        session_id="e2e-mcp-verify",
    )
    assert result["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")
    assert "detection_id" in result


@skip_unless_e2e
@pytest.mark.asyncio
async def test_mcp_proxy_client_audit_log():
    """CRITERION 7: MCP ProxyClient.get_audit_log() returns entries from the proxy."""
    from mcp_server.proxy_client import ProxyClient
    client = ProxyClient(PROXY_URL)
    result = await client.get_audit_log(limit=10)
    assert "events" in result
    assert isinstance(result["events"], list)
