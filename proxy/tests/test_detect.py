"""
Tests for POST /detect/verify

PASSING CRITERIA:
  1. Valid request with known profile model returns HTTP 200 with valid JSON
  2. risk_level is one of: LOW, MEDIUM, HIGH, UNKNOWN
  3. Empty model_id returns HTTP 200 with UNKNOWN and error="model_id_missing"
  4. Empty response returns HTTP 200 with UNKNOWN and error="response_empty"
  5. Unknown model_id returns HTTP 200 with UNKNOWN and error="no_profile_for_model"
     (this is information, not an error state)
  6. detection_id is a valid UUID4
  7. timestamp is a valid ISO8601 datetime string
  8. All responses are HTTP 200 -- never 4xx or 5xx from validation failures
  9. Audit log is written for each detection (checked via AuditWriter.read_recent)
"""

import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from proxy.main import create_app
from proxy.audit.writer import AuditWriter
from proxy.detection.engine import DetectionEngine
from proxy.router.profile_router import ProfileRouter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_engine():
    """Engine that returns LOW for any model, UNKNOWN for 'no-such-model'."""
    from proxy.detection.engine import DetectionResult
    import uuid as _uuid
    from datetime import datetime, timezone

    engine = AsyncMock(spec=DetectionEngine)

    async def _verify(prompt, response, model_id):
        if model_id == "no-such-model":
            return DetectionResult(
                risk_level="UNKNOWN",
                confidence=0.0,
                features_triggered=[],
                model_id=model_id,
                profile_version="none",
                timestamp=datetime.now(timezone.utc).isoformat(),
                detection_id=str(_uuid.uuid4()),
                error="no_profile_for_model",
            )
        return DetectionResult(
            risk_level="LOW",
            confidence=0.8,
            features_triggered=["unique_word_ratio"],
            model_id=model_id,
            profile_version="1.0",
            timestamp=datetime.now(timezone.utc).isoformat(),
            detection_id=str(_uuid.uuid4()),
        )

    engine.verify.side_effect = _verify
    return engine


@pytest.fixture
def mock_audit():
    audit = AsyncMock(spec=AuditWriter)
    audit.write = AsyncMock()
    return audit


@pytest.fixture
def client(mock_engine, mock_audit, tmp_path):
    """TestClient with mocked engine and audit writer."""
    app = create_app()
    with TestClient(app, raise_server_exceptions=True) as c:
        # Override AFTER lifespan startup has run (lifespan sets real objects first)
        app.state.engine = mock_engine
        app.state.audit_writer = mock_audit
        app.state.settings = MagicMock()
        yield c


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestDetectVerifyEndpoint:

    def test_valid_request_returns_200(self, client):
        """CRITERION 1: Valid request returns HTTP 200."""
        resp = client.post("/detect/verify", json={
            "prompt": "What is the capital of France?",
            "response": "The capital of France is Paris.",
            "model_id": "claude-sonnet-4-6",
        })
        assert resp.status_code == 200

    def test_response_has_valid_risk_level(self, client):
        """CRITERION 2: risk_level is one of the four valid values."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "test response",
            "model_id": "claude-sonnet-4-6",
        })
        data = resp.json()
        assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN")

    def test_empty_model_id_returns_unknown(self, client):
        """CRITERION 3: Empty model_id -> UNKNOWN, error=model_id_missing."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "test response",
            "model_id": "",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "UNKNOWN"
        assert data["error"] == "model_id_missing"

    def test_empty_response_returns_unknown(self, client):
        """CRITERION 4: Empty response -> UNKNOWN, error=response_empty."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "",
            "model_id": "claude-sonnet-4-6",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "UNKNOWN"
        assert data["error"] == "response_empty"

    def test_unknown_model_returns_unknown(self, client):
        """CRITERION 5: Unknown model -> UNKNOWN (information, not error)."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some response text here",
            "model_id": "no-such-model",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "UNKNOWN"

    def test_detection_id_is_valid_uuid(self, client):
        """CRITERION 6: detection_id is a valid UUID4."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some response",
            "model_id": "claude-sonnet-4-6",
        })
        data = resp.json()
        detection_id = data["detection_id"]
        parsed = uuid.UUID(detection_id, version=4)
        assert str(parsed) == detection_id

    def test_timestamp_is_iso8601(self, client):
        """CRITERION 7: timestamp is parseable ISO8601."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some response",
            "model_id": "claude-sonnet-4-6",
        })
        data = resp.json()
        ts = data["timestamp"]
        # Should parse without error
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt is not None

    def test_all_errors_return_200(self, client):
        """CRITERION 8: No detection failure returns 4xx or 5xx."""
        bad_payloads = [
            {"prompt": "", "response": "", "model_id": ""},
            {"prompt": "x", "response": "", "model_id": "x"},
            {"prompt": "", "response": "x", "model_id": ""},
        ]
        for payload in bad_payloads:
            resp = client.post("/detect/verify", json=payload)
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code} for {payload}"

    def test_audit_written_on_valid_request(self, client, mock_audit):
        """CRITERION 9: Audit log write called for each detection."""
        client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some response text here",
            "model_id": "claude-sonnet-4-6",
        })
        mock_audit.write.assert_called_once()
        record = mock_audit.write.call_args[0][0]
        assert "detection_id" in record
        assert "prompt_hash" in record
        assert "response_length" in record
        # Prompt text must NOT be in audit record
        assert "prompt" not in record
        assert "response" not in record

    def test_response_has_all_required_fields(self, client):
        """All required spec fields present in response."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some response",
            "model_id": "gpt-4o",
        })
        data = resp.json()
        required = {"risk_level", "confidence", "features_triggered",
                    "model_id", "profile_version", "timestamp", "detection_id"}
        assert required.issubset(set(data.keys()))

    def test_confidence_in_valid_range(self, client):
        """Confidence is always 0.0 to 1.0."""
        resp = client.post("/detect/verify", json={
            "prompt": "test",
            "response": "some longer response with more words to classify",
            "model_id": "claude-sonnet-4-6",
        })
        data = resp.json()
        assert 0.0 <= data["confidence"] <= 1.0
