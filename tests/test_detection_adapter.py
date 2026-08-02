"""
Tests for proxy/detection_adapter.py — governance adapter push (arkheia-mcp).

These are the ORIGINAL eight cases, kept under their original names because the
flow ledger cites them. Two things changed on 2026-07-26:

1. **The `importlib.reload` in every test is gone.** It existed only because the
   module froze `DETECTION_ADAPTER_*` into module-level constants at import time;
   `push_event` now reads them at CALL time, so the reload is unnecessary — and it
   was actively harmful: reloading rebinds every class in the module, so
   `isinstance(x, PushOutcome)` in a sibling test module that imported the class
   earlier silently became False. That failure only appeared in a full-suite run.

2. **The three "must not raise" cases asserted nothing at all**, and
   `test_schedule_push_no_loop` recorded a call into a list it never inspected —
   so it passed on an interpreter where the push never happened. Each now pins
   the outcome. Deeper coverage (does the signature AUTHENTICATE, does the push
   ARRIVE) lives in `tests/test_detection_adapter_push.py`.
"""
from unittest.mock import patch

import httpx
import pytest

import proxy.detection_adapter as mod

PAYLOAD = {"model_id": "gpt-4o", "risk_level": "LOW", "confidence": 0.1}
SECRET = "test-secret-32chars-longXXXXXXXX"
ENDPOINT = "http://adapter:7070/v1/events/proxy"


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_push_event_no_url(monkeypatch):
    """If DETECTION_ADAPTER_URL is empty, push_event returns immediately without HTTP call."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "secret")

    with patch("httpx.AsyncClient") as mock_client:
        outcome = await mod.push_event("tenant", "src", "mcp_detection", PAYLOAD)
        mock_client.assert_not_called()
    assert outcome.status == mod.PushOutcome.SKIPPED


@pytest.mark.asyncio
async def test_push_event_no_secret(monkeypatch):
    """If DETECTION_ADAPTER_HMAC_SECRET is empty, push_event returns immediately."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://localhost:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "")

    with patch("httpx.AsyncClient") as mock_client:
        outcome = await mod.push_event("tenant", "src", "mcp_detection", PAYLOAD)
        mock_client.assert_not_called()
    assert outcome.status == mod.PushOutcome.SKIPPED


@pytest.mark.asyncio
async def test_push_event_success(monkeypatch, respx_mock):
    """push_event calls /v1/events/proxy when configured."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"ok": True}))

    outcome = await mod.push_event(
        "tenant-1", "gpt-4o", "mcp_detection", PAYLOAD, risk_level="LOW"
    )

    assert respx_mock.calls.call_count == 1
    assert outcome.status == mod.PushOutcome.DELIVERED
    assert outcome.http_status == 200


@pytest.mark.asyncio
async def test_push_event_hmac_headers(monkeypatch, respx_mock):
    """Outbound request must include X-Arkheia-Key-Id, Timestamp, Signature headers."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", "mcp-test-v1")

    captured_headers = {}

    def capture(request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200)

    respx_mock.post(ENDPOINT).mock(side_effect=capture)

    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)

    assert "x-arkheia-key-id" in captured_headers
    assert "x-arkheia-timestamp" in captured_headers
    assert "x-arkheia-signature" in captured_headers
    assert captured_headers["x-arkheia-key-id"] == "mcp-test-v1"
    # NOTE: header PRESENCE is all this case ever asserted, and presence is not
    # authentication — the module shipped for months with a signature the real
    # receiver rejects and this test stayed green. Whether the signature actually
    # verifies is proven in tests/test_detection_adapter_push.py against a
    # transcription of the receiver.


@pytest.mark.asyncio
async def test_push_event_4xx_fail_open(monkeypatch, respx_mock, caplog):
    """400 response from adapter must NOT raise — fail-open, but LOUD."""
    import logging

    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(400, text="bad request"))

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)

    assert outcome.status == mod.PushOutcome.REJECTED
    assert outcome.http_status == 400
    assert any(mod.FAILURE_MARKER in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_push_event_network_error_fail_open(monkeypatch, respx_mock):
    """Network error must NOT raise — fail-open, and reported as FAILED."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    respx_mock.post(ENDPOINT).mock(side_effect=httpx.ConnectError("connection refused"))

    outcome = await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)

    assert outcome.status == mod.PushOutcome.FAILED
    assert "ConnectError" in outcome.error


@pytest.mark.asyncio
async def test_push_event_timeout_fail_open(monkeypatch, respx_mock):
    """Timeout must NOT raise — fail-open, and reported as FAILED."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    respx_mock.post(ENDPOINT).mock(side_effect=httpx.TimeoutException("timeout"))

    outcome = await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)

    assert outcome.status == mod.PushOutcome.FAILED
    assert "TimeoutException" in outcome.error


def test_schedule_push_no_loop(monkeypatch):
    """
    schedule_push works synchronously when called outside an event loop.

    The original body patched `push_event`, appended to a `called` list, and
    asserted NOTHING — so it passed on Python 3.14, where `asyncio.get_event_loop()`
    raises and the push silently never happened. Assert the dispatch occurred.
    """
    import respx

    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    with respx.mock:
        route = respx.post(ENDPOINT).mock(return_value=httpx.Response(200))
        outcome = mod.schedule_push("tenant", "model", "mcp_detection", PAYLOAD)

    assert route.call_count == 1, "schedule_push dispatched nothing"
    assert outcome.status == mod.PushOutcome.DELIVERED
