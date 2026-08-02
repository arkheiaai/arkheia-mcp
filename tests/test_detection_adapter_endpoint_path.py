"""
PRESENCE IS NOT EFFECT.

`tests/test_detection_adapter_push.py` proves that `push_event` produces a
signature the real receiver accepts. That is not the same claim as "the signed
push happens on the production path". A correct signer that nothing calls
protects nothing — the same shape as `verify_integrity` in this repo, which has
zero production callers.

So this module drives the REAL endpoint, `POST /detect/verify`, through the real
FastAPI app, and asserts that a request the real governance adapter would ACCEPT
crosses the transport boundary as a result — and that the real audit rail carries
the outcome.
"""
from __future__ import annotations

import json
import uuid as _uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from tests import _receiver_oracle as oracle

from proxy.audit.writer import AuditWriter
from proxy.detection.engine import DetectionEngine, DetectionResult
from proxy.main import create_app

KEY_ID = "mcp-v1"
SECRET = "test-secret-32-bytes-minimum-len"
URL = "http://adapter:7070"
ENDPOINT = f"{URL}/v1/events/proxy"


def _result(risk="HIGH", detection_id=None) -> DetectionResult:
    return DetectionResult(
        risk_level=risk,
        confidence=0.91,
        features_triggered=["entropy_mean"],
        model_id="claude-sonnet-5",
        profile_version="2.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=detection_id or str(_uuid.uuid4()),
        gate_action="advise",
    )


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DETECTION_ADAPTER_URL", URL)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", KEY_ID)

    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir(exist_ok=True)

    with patch("proxy.main.settings") as mock_settings:
        from pydantic import SecretStr

        mock_settings.detection.profile_dir = str(profiles_dir)
        mock_settings.proxy.log_level = "WARNING"
        mock_settings.audit.log_path = str(tmp_path / "audit.jsonl")
        mock_settings.audit.retention_days = 90
        mock_settings.registry.url = ""
        mock_settings.arkheia_api_key = SecretStr("")
        mock_settings.synesis = MagicMock()
        mock_settings.synesis.enabled = False

        app = create_app()
        c = TestClient(app, raise_server_exceptions=False)
        c.__enter__()

        engine = AsyncMock(spec=DetectionEngine)
        engine.verify = AsyncMock(return_value=_result())
        app.state.engine = engine

        settings = MagicMock()
        settings.detection.high_risk_action = "warn"
        settings.detection.unknown_action = "pass"
        app.state.settings = settings

        # NOTE: app.state.audit_writer is deliberately NOT replaced. The lifespan
        # already started a REAL AuditWriter on tmp_path/audit.jsonl; a stub here
        # would be exactly the "drives a helper, not the writer" failure the
        # receipt probe exists to prevent.
        assert isinstance(app.state.audit_writer, AuditWriter)
        yield c, app, tmp_path
        try:
            c.__exit__(None, None, None)
        except RuntimeError:  # already exited by the test
            pass


def _post(client):
    return client.post(
        "/detect/verify",
        json={
            "prompt": "Summarise the Q3 incident report.",
            "response": "The outage was caused by a cascading auth failure.",
            "model_id": "claude-sonnet-5",
        },
    )


def test_the_real_endpoint_emits_a_push_the_real_receiver_would_accept(client):
    c, app, _ = client
    captured: list[httpx.Request] = []

    def cap(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    with respx.mock:
        route = respx.post(ENDPOINT).mock(side_effect=cap)
        resp = _post(c)

    # the endpoint's advisory contract is untouched
    assert resp.status_code == 200

    assert route.call_count == 1, "the production path emitted no governance push"
    req = captured[0]
    assert req.method == "POST"
    assert str(req.url) == ENDPOINT

    # would the live adapter accept what the live endpoint sent? raises if not.
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", req.content, dict(req.headers))

    body = json.loads(req.content)
    missing = [f for f in oracle.PROXY_EVENT_REQUIRED if f not in body]
    assert missing == []
    assert body["detection"]["fabrication_risk"] == "HIGH"
    assert body["detection"]["classification"] == "FABRICATED"
    assert body["model"]["model_id"] == "claude-sonnet-5"
    assert body["context"]["action_taken"] == "warn"


def test_an_unknown_verdict_is_not_published_as_a_clean_low(client):
    """
    Regression pin for the caller-side coercion. `detect_verify` used to send
    `"LOW"` for anything outside the four bands, so an engine failure reached the
    governance plane as a confident clean verdict.
    """
    c, app, _ = client
    app.state.engine.verify = AsyncMock(return_value=_result(risk="UNKNOWN"))
    captured: list[httpx.Request] = []

    with respx.mock:
        respx.post(ENDPOINT).mock(
            side_effect=lambda r: (captured.append(r), httpx.Response(200))[1]
        )
        assert _post(c).status_code == 200

    body = json.loads(captured[0].content)
    assert body["detection"]["fabrication_risk"] == "UNKNOWN"
    assert body["detection"]["classification"] != "AUTHENTIC"
    assert body["detection"]["classification"] == "UNCERTAIN"
    assert body["context"]["risk_level_raw"] == "UNKNOWN"


def test_a_rejected_push_from_the_real_path_lands_on_the_real_audit_rail(client):
    """
    End-to-end `receipted`: the endpoint's own AuditWriter must carry a record
    that the governance plane REFUSED the event — otherwise the only trace of a
    dark rail is a log line.
    """
    c, app, tmp_path = client

    with respx.mock:
        respx.post(ENDPOINT).mock(
            return_value=httpx.Response(401, text='{"error":{"code":"UNKNOWN_KEY_ID"}}')
        )
        assert _post(c).status_code == 200

    # lifespan shutdown drains the writer queue and flushes to disk
    c.__exit__(None, None, None)

    log = tmp_path / "audit.jsonl"
    rows = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    pushes = [r for r in rows if r.get("source") == "governance_push"]
    assert len(pushes) == 1, f"expected 1 push receipt, saw {len(pushes)} of {len(rows)} rows"
    assert pushes[0]["delivery_status"] == "rejected"
    assert pushes[0]["http_status"] == 401
    assert "UNKNOWN_KEY_ID" in pushes[0]["error"]

    # control: the DETECTION receipt is there too, and they are distinct records
    detections = [r for r in rows if r.get("source") == "proxy"]
    assert len(detections) == 1
    assert detections[0]["detection_id"] == pushes[0]["detection_id"]
