"""
Tests for proxy/detection_adapter.py — governance adapter push (arkheia-mcp).
"""
import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio


# ── helpers ──────────────────────────────────────────────────────────────────

PAYLOAD = {"model_id": "gpt-4o", "risk_level": "LOW", "confidence": 0.1}


# ── tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_push_event_no_url(monkeypatch):
    """If DETECTION_ADAPTER_URL is empty, push_event returns immediately without HTTP call."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "secret")

    # Re-import after env patch
    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    with patch("httpx.AsyncClient") as mock_client:
        await mod.push_event("tenant", "src", "mcp_detection", PAYLOAD)
        mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_push_event_no_secret(monkeypatch):
    """If DETECTION_ADAPTER_HMAC_SECRET is empty, push_event returns immediately."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://localhost:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    with patch("httpx.AsyncClient") as mock_client:
        await mod.push_event("tenant", "src", "mcp_detection", PAYLOAD)
        mock_client.assert_not_called()


@pytest.mark.asyncio
async def test_push_event_success(monkeypatch, respx_mock):
    """push_event calls /v1/events/proxy when configured."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    import httpx
    respx_mock.post("http://adapter:7070/v1/events/proxy").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD, risk_level="LOW")

    assert respx_mock.calls.call_count == 1


@pytest.mark.asyncio
async def test_push_event_hmac_headers(monkeypatch, respx_mock):
    """Outbound request must include X-Arkheia-Key-Id, Timestamp, Signature headers."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", "mcp-test-v1")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    import httpx
    captured_headers = {}

    def capture(request):
        captured_headers.update(dict(request.headers))
        return httpx.Response(200)

    respx_mock.post("http://adapter:7070/v1/events/proxy").mock(side_effect=capture)

    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)

    assert "x-arkheia-key-id" in captured_headers
    assert "x-arkheia-timestamp" in captured_headers
    assert "x-arkheia-signature" in captured_headers
    assert captured_headers["x-arkheia-key-id"] == "mcp-test-v1"


@pytest.mark.asyncio
async def test_push_event_4xx_fail_open(monkeypatch, respx_mock):
    """400 response from adapter must NOT raise — fail-open."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    import httpx
    respx_mock.post("http://adapter:7070/v1/events/proxy").mock(
        return_value=httpx.Response(400, text="bad request")
    )

    # Must not raise
    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)


@pytest.mark.asyncio
async def test_push_event_network_error_fail_open(monkeypatch, respx_mock):
    """Network error must NOT raise — fail-open."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    import httpx
    respx_mock.post("http://adapter:7070/v1/events/proxy").mock(
        side_effect=httpx.ConnectError("connection refused")
    )

    # Must not raise
    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)


@pytest.mark.asyncio
async def test_push_event_timeout_fail_open(monkeypatch, respx_mock):
    """Timeout must NOT raise — fail-open."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    import httpx
    respx_mock.post("http://adapter:7070/v1/events/proxy").mock(
        side_effect=httpx.TimeoutException("timeout")
    )

    # Must not raise
    await mod.push_event("tenant-1", "gpt-4o", "mcp_detection", PAYLOAD)


def test_schedule_push_no_loop(monkeypatch):
    """schedule_push works synchronously when called outside an event loop."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "test-secret-32chars-longXXXXXXXX")

    import importlib
    import proxy.detection_adapter as mod
    importlib.reload(mod)

    called = []

    async def _fake_push(*args, **kwargs):
        called.append(True)

    with patch.object(mod, "push_event", _fake_push):
        # Should not raise even with no running loop
        mod.schedule_push("tenant", "model", "mcp_detection", PAYLOAD)
