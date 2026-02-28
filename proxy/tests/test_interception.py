"""
Tests for AIInterceptionMiddleware.

PASSING CRITERIA:
  1. /v1/chat/completions request: X-Arkheia-Risk header is present on response
  2. LOW risk: response body passes through unchanged, header = LOW
  3. HIGH risk + warn: response body is prepended with b"[ARKHEIA WARNING"
  4. HIGH risk + block: response body is {"error":"arkheia_blocked",...}, header = HIGH
  5. UNKNOWN risk: body passes through, header = UNKNOWN
  6. Engine None: body passes through, header = UNAVAILABLE
  7. Non-/v1/ path: middleware does not intercept (no X-Arkheia-Risk header)
  8. Exception in detection: middleware recovers, header = ERROR
"""

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import uuid as _uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.middleware.interception import AIInterceptionMiddleware, _extract_model_id, _extract_prompt
from proxy.detection.engine import DetectionResult


# ---------------------------------------------------------------------------
# Helper: build a DetectionResult for a given risk level
# ---------------------------------------------------------------------------

def _make_result(risk_level: str) -> DetectionResult:
    return DetectionResult(
        risk_level=risk_level,
        confidence=0.8 if risk_level != "UNKNOWN" else 0.0,
        features_triggered=[] if risk_level == "UNKNOWN" else ["unique_word_ratio"],
        model_id="gpt-4o",
        profile_version="1.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(_uuid.uuid4()),
    )


# ---------------------------------------------------------------------------
# Fixture factories
# ---------------------------------------------------------------------------

def _make_app(risk_level: str = "LOW", high_risk_action: str = "warn",
              engine_none: bool = False, raise_in_engine: bool = False) -> FastAPI:
    """
    Build a minimal FastAPI app with AIInterceptionMiddleware attached.

    The app has:
      - GET/POST /v1/chat/completions  -> returns a fixed JSON body
      - GET /health                    -> returns {"ok": true} (non-/v1/ path)
    """
    app = FastAPI()

    # Fake /v1/ route
    @app.post("/v1/chat/completions")
    async def chat():
        return {"choices": [{"message": {"content": "Paris"}}]}

    # Fake non-/v1/ route
    @app.get("/health")
    async def health():
        return {"ok": True}

    # Wire middleware AFTER routes so TestClient sees it
    app.add_middleware(AIInterceptionMiddleware)

    # Set up app.state
    if engine_none:
        app.state.engine = None
    elif raise_in_engine:
        engine = AsyncMock()
        engine.verify.side_effect = RuntimeError("simulated engine crash")
        app.state.engine = engine
    else:
        engine = AsyncMock()
        engine.verify = AsyncMock(return_value=_make_result(risk_level))
        app.state.engine = engine

    settings = MagicMock()
    settings.detection.upstream_url = None   # standalone mode
    settings.detection.high_risk_action = high_risk_action
    app.state.settings = settings

    return app


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAIInterceptionMiddleware:

    def test_v1_path_has_risk_header(self):
        """CRITERION 1: /v1/chat/completions response carries X-Arkheia-Risk header."""
        app = _make_app(risk_level="LOW")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert "x-arkheia-risk" in resp.headers

    def test_low_risk_body_passes_through(self):
        """CRITERION 2: LOW risk leaves body unchanged and sets header = LOW."""
        app = _make_app(risk_level="LOW")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "LOW"
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "Paris"

    def test_high_risk_warn_prepends_warning(self):
        """CRITERION 3: HIGH risk + warn prepends [ARKHEIA WARNING to response body."""
        app = _make_app(risk_level="HIGH", high_risk_action="warn")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "HIGH"
        assert resp.content.startswith(b"[ARKHEIA WARNING")

    def test_high_risk_block_returns_blocked_body(self):
        """CRITERION 4: HIGH risk + block returns arkheia_blocked JSON, header = HIGH."""
        app = _make_app(risk_level="HIGH", high_risk_action="block")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "HIGH"
        data = resp.json()
        assert data["error"] == "arkheia_blocked"
        assert data["risk_level"] == "HIGH"

    def test_unknown_risk_body_passes_through(self):
        """CRITERION 5: UNKNOWN risk leaves body unchanged and sets header = UNKNOWN."""
        app = _make_app(risk_level="UNKNOWN")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "UNKNOWN"
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "Paris"

    def test_engine_none_returns_unavailable(self):
        """CRITERION 6: When engine is None, body passes through with header = UNAVAILABLE."""
        app = _make_app(engine_none=True)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "UNAVAILABLE"
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "Paris"

    def test_non_v1_path_not_intercepted(self):
        """CRITERION 7: Non-/v1/ paths bypass middleware (no X-Arkheia-Risk header)."""
        app = _make_app(risk_level="LOW")
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/health")
        assert "x-arkheia-risk" not in resp.headers
        assert resp.json()["ok"] is True

    def test_engine_exception_returns_error_header(self):
        """CRITERION 8: If detection raises, middleware recovers and sets header = ERROR."""
        app = _make_app(raise_in_engine=True)
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
            )
        assert resp.headers.get("x-arkheia-risk") == "ERROR"


# ---------------------------------------------------------------------------
# Unit tests for helper functions
# ---------------------------------------------------------------------------

class TestHelperFunctions:

    def test_extract_model_id_messages_format(self):
        body = json.dumps({"model": "gpt-4o", "messages": []}).encode()
        assert _extract_model_id(body) == "gpt-4o"

    def test_extract_model_id_missing_returns_unknown(self):
        body = json.dumps({"messages": []}).encode()
        assert _extract_model_id(body) == "unknown"

    def test_extract_model_id_invalid_json(self):
        assert _extract_model_id(b"not json") == "unknown"

    def test_extract_prompt_from_messages(self):
        body = json.dumps({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "What is 2+2?"},
            ],
        }).encode()
        result = _extract_prompt(body)
        assert "What is 2+2?" in result
        assert "You are helpful" not in result

    def test_extract_prompt_from_prompt_field(self):
        body = json.dumps({"model": "gpt-3.5-turbo-instruct", "prompt": "Say hi"}).encode()
        assert _extract_prompt(body) == "Say hi"

    def test_extract_prompt_invalid_json(self):
        assert _extract_prompt(b"bad json") == ""

    def test_extract_prompt_multiple_user_messages(self):
        body = json.dumps({
            "messages": [
                {"role": "user", "content": "First"},
                {"role": "assistant", "content": "Reply"},
                {"role": "user", "content": "Second"},
            ]
        }).encode()
        result = _extract_prompt(body)
        assert "First" in result
        assert "Second" in result
        assert "Reply" not in result
