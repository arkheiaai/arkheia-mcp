"""
Tests for Grok and Gemini passthrough endpoints.

PASSING CRITERIA:
  1. POST /proxy/grok/v1/chat/completions: successful response → HTTP 200, X-Arkheia-Risk present
  2. POST /proxy/grok/v1/chat/completions: LOW detection → X-Arkheia-Risk: LOW, body unchanged
  3. POST /proxy/grok/v1/chat/completions: upstream 4xx → relayed with X-Arkheia-Risk: SKIP
  4. POST /proxy/grok/v1/chat/completions: upstream network error → HTTP 502, X-Arkheia-Risk: ERROR
  5. POST /v1beta/models/gemini-2.5-flash:generateContent: successful → LOW risk, body unchanged
  6. POST /v1beta/models/gemini-2.5-flash:generateContent: upstream error → 502, X-Arkheia-Risk: ERROR
  7. Non-text response (no extractable content) → X-Arkheia-Risk: SKIP
  8. _extract_openai_text: valid completion → returns content string
  9. _extract_openai_text: malformed JSON → returns None
  10. _extract_gemini_text: valid response → returns text string
  11. _extract_gemini_text: malformed → returns None
  12. _extract_gemini_model: extracts model name from path
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
import uuid as _uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.endpoints.passthrough import (
    router,
    _extract_openai_text,
    _extract_openai_prompt,
    _extract_gemini_text,
    _extract_gemini_prompt,
    _extract_gemini_model,
    _extract_grok_model,
)
from proxy.detection.engine import DetectionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OPENAI_RESPONSE = {
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "model": "grok-4-fast-non-reasoning",
    "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": "Four"},
        "finish_reason": "stop",
    }],
    "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
}

OPENAI_REQUEST = {
    "model": "grok-4-fast-non-reasoning",
    "messages": [{"role": "user", "content": "What is 2+2?"}],
}

GEMINI_RESPONSE = {
    "candidates": [{
        "content": {
            "parts": [{"text": "Four"}],
            "role": "model",
        },
        "finishReason": "STOP",
    }],
    "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 1},
    "modelVersion": "gemini-2.5-flash",
}

GEMINI_REQUEST = {
    "contents": [{"role": "user", "parts": [{"text": "What is 2+2?"}]}]
}


def _make_detection_result(risk_level: str = "LOW") -> DetectionResult:
    return DetectionResult(
        risk_level=risk_level,
        confidence=0.7,
        features_triggered=["unique_word_ratio"] if risk_level != "UNKNOWN" else [],
        model_id="grok-4-fast-non-reasoning",
        profile_version="1.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(_uuid.uuid4()),
    )


def _make_mock_response(body: bytes, status_code: int = 200):
    """Build a mock httpx.Response."""
    mock = MagicMock()
    mock.content = body
    mock.status_code = status_code
    mock.headers = {"content-type": "application/json"}
    return mock


def _make_app(risk_level: str = "LOW") -> FastAPI:
    """Minimal FastAPI app with passthrough router and mocked app state."""
    app = FastAPI()
    app.include_router(router)

    engine = MagicMock()
    engine.verify = AsyncMock(return_value=_make_detection_result(risk_level))

    audit = MagicMock()
    audit.write = AsyncMock()

    app.state.engine = engine
    app.state.audit_writer = audit

    return app


# ---------------------------------------------------------------------------
# Unit tests: text extractors
# ---------------------------------------------------------------------------

def test_extract_openai_text_valid():
    body = json.dumps(OPENAI_RESPONSE).encode()
    assert _extract_openai_text(body) == "Four"


def test_extract_openai_text_malformed():
    assert _extract_openai_text(b"not json") is None


def test_extract_openai_text_missing_choices():
    assert _extract_openai_text(json.dumps({"choices": []}).encode()) is None


def test_extract_gemini_text_valid():
    body = json.dumps(GEMINI_RESPONSE).encode()
    assert _extract_gemini_text(body) == "Four"


def test_extract_gemini_text_malformed():
    assert _extract_gemini_text(b"not json") is None


def test_extract_gemini_model_standard():
    assert _extract_gemini_model("models/gemini-2.5-flash:generateContent") == "gemini-2.5-flash"


def test_extract_gemini_model_no_action():
    assert _extract_gemini_model("models/gemini-2.5-pro") == "gemini-2.5-pro"


def test_extract_gemini_model_empty():
    result = _extract_gemini_model("")
    assert isinstance(result, str)


def test_extract_openai_prompt():
    body = json.dumps(OPENAI_REQUEST).encode()
    assert "2+2" in _extract_openai_prompt(body)


def test_extract_gemini_prompt():
    body = json.dumps(GEMINI_REQUEST).encode()
    assert "2+2" in _extract_gemini_prompt(body)


def test_extract_grok_model():
    body = json.dumps(OPENAI_REQUEST).encode()
    assert _extract_grok_model(body) == "grok-4-fast-non-reasoning"


# ---------------------------------------------------------------------------
# Integration tests: Grok passthrough
# ---------------------------------------------------------------------------

@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_grok_passthrough_low_risk(mock_client_cls):
    """Successful Grok call → HTTP 200, body unchanged, X-Arkheia-Risk: LOW."""
    response_body = json.dumps(OPENAI_RESPONSE).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(response_body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app("LOW")
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post(
        "/proxy/grok/v1/chat/completions",
        json=OPENAI_REQUEST,
        headers={"Authorization": "Bearer xai-test-key"},
    )

    assert resp.status_code == 200
    assert resp.headers["x-arkheia-risk"] == "LOW"
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "Four"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_grok_passthrough_upstream_4xx(mock_client_cls):
    """Upstream 4xx → relayed as-is with X-Arkheia-Risk: SKIP."""
    error_body = json.dumps({"error": {"message": "invalid model"}}).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(error_body, 400))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/proxy/grok/v1/chat/completions", json=OPENAI_REQUEST)

    assert resp.status_code == 400
    assert resp.headers["x-arkheia-risk"] == "SKIP"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_grok_passthrough_network_error(mock_client_cls):
    """Network error reaching upstream → HTTP 502, X-Arkheia-Risk: ERROR."""
    import httpx as _httpx
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(side_effect=_httpx.ConnectError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/proxy/grok/v1/chat/completions", json=OPENAI_REQUEST)

    assert resp.status_code == 502
    assert resp.headers["x-arkheia-risk"] == "ERROR"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_grok_passthrough_no_choices(mock_client_cls):
    """Response with no choices → cannot extract text → X-Arkheia-Risk: SKIP."""
    body = json.dumps({"id": "x", "choices": []}).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/proxy/grok/v1/chat/completions", json=OPENAI_REQUEST)

    assert resp.status_code == 200
    assert resp.headers["x-arkheia-risk"] == "SKIP"


# ---------------------------------------------------------------------------
# Integration tests: Gemini passthrough
# ---------------------------------------------------------------------------

@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_gemini_passthrough_low_risk(mock_client_cls):
    """Successful Gemini call → HTTP 200, body unchanged, X-Arkheia-Risk: LOW."""
    response_body = json.dumps(GEMINI_RESPONSE).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(response_body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app("LOW")
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post(
        "/v1beta/models/gemini-2.5-flash:generateContent",
        json=GEMINI_REQUEST,
        params={"key": "test-api-key"},
    )

    assert resp.status_code == 200
    assert resp.headers["x-arkheia-risk"] == "LOW"
    data = resp.json()
    assert data["candidates"][0]["content"]["parts"][0]["text"] == "Four"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_gemini_passthrough_network_error(mock_client_cls):
    """Network error → HTTP 502, X-Arkheia-Risk: ERROR."""
    import httpx as _httpx
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(side_effect=_httpx.ConnectError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/v1beta/models/gemini-2.5-flash:generateContent", json=GEMINI_REQUEST)

    assert resp.status_code == 502
    assert resp.headers["x-arkheia-risk"] == "ERROR"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_gemini_passthrough_audit_written(mock_client_cls):
    """On successful detection, audit.write is called once."""
    response_body = json.dumps(GEMINI_RESPONSE).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(response_body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app("LOW")
    audit_writer = app.state.audit_writer
    client = TestClient(app, raise_server_exceptions=True)

    client.post(
        "/v1beta/models/gemini-2.5-flash:generateContent",
        json=GEMINI_REQUEST,
        params={"key": "test-api-key"},
    )

    audit_writer.write.assert_called_once()
    record = audit_writer.write.call_args[0][0]
    assert record["source"] == "passthrough"
    assert record["risk_level"] == "LOW"


# ---------------------------------------------------------------------------
# Integration tests: Together AI passthrough
# ---------------------------------------------------------------------------

TOGETHER_REQUEST = {
    "model": "moonshotai/Kimi-K2.5",
    "messages": [{"role": "user", "content": "What is 2+2?"}],
    "max_tokens": 2048,
}

TOGETHER_RESPONSE = {
    "id": "chatcmpl-together-123",
    "object": "chat.completion",
    "model": "moonshotai/Kimi-K2.5",
    "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": "Four"},
        "finish_reason": "stop",
    }],
    "usage": {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11},
}


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_together_passthrough_low_risk(mock_client_cls):
    """Successful Together AI call → HTTP 200, body unchanged, X-Arkheia-Risk: LOW."""
    response_body = json.dumps(TOGETHER_RESPONSE).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(response_body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app("LOW")
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post(
        "/proxy/together/v1/chat/completions",
        json=TOGETHER_REQUEST,
        headers={"Authorization": "Bearer together-test-key"},
    )

    assert resp.status_code == 200
    assert resp.headers["x-arkheia-risk"] == "LOW"
    data = resp.json()
    assert data["choices"][0]["message"]["content"] == "Four"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_together_passthrough_upstream_4xx(mock_client_cls):
    """Upstream 4xx → relayed as-is with X-Arkheia-Risk: SKIP."""
    error_body = json.dumps({"error": {"message": "invalid model"}}).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(error_body, 400))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/proxy/together/v1/chat/completions", json=TOGETHER_REQUEST)

    assert resp.status_code == 400
    assert resp.headers["x-arkheia-risk"] == "SKIP"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_together_passthrough_network_error(mock_client_cls):
    """Network error reaching upstream → HTTP 502, X-Arkheia-Risk: ERROR."""
    import httpx as _httpx
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(side_effect=_httpx.ConnectError("refused"))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app()
    client = TestClient(app, raise_server_exceptions=True)

    resp = client.post("/proxy/together/v1/chat/completions", json=TOGETHER_REQUEST)

    assert resp.status_code == 502
    assert resp.headers["x-arkheia-risk"] == "ERROR"


@patch("proxy.endpoints.passthrough.httpx.AsyncClient")
def test_together_passthrough_audit_written(mock_client_cls):
    """On successful detection, audit.write is called with source=passthrough."""
    response_body = json.dumps(TOGETHER_RESPONSE).encode()
    mock_client = AsyncMock()
    mock_client.request = AsyncMock(return_value=_make_mock_response(response_body))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_client_cls.return_value = mock_client

    app = _make_app("LOW")
    audit_writer = app.state.audit_writer
    client = TestClient(app, raise_server_exceptions=True)

    client.post(
        "/proxy/together/v1/chat/completions",
        json=TOGETHER_REQUEST,
        headers={"Authorization": "Bearer together-test-key"},
    )

    audit_writer.write.assert_called_once()
    record = audit_writer.write.call_args[0][0]
    assert record["source"] == "passthrough"
    assert record["risk_level"] == "LOW"
