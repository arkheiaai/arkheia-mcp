"""
F6/F8/F9 readiness lane: positive classifier verdicts and gate_action containment.

This file covers the missing boundary between "the endpoint surfaced gate_action" and
"the forensic/governance rails can prove which action was actually authorised".
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.detection.engine import DetectionResult
from proxy.detection.features import classify_with_profile
from proxy.endpoints import detect as detect_endpoint


def _classifier_profile(gate_action: str = "advise") -> dict:
    return {
        "model": "classifier-proof",
        "version": "f6",
        "gate_action": gate_action,
        "performance": {"precision": 0.99, "f1": 0.98, "false_positive_rate": 0.01},
        "detection": {
            "strategy": "single_feature",
            "min_required_features": 1,
            "features": {
                "word_count": {
                    "enabled": True,
                    "weight": 1.0,
                    "polarity": "positive",
                    "threshold_low": 10,
                    "threshold_medium": 20,
                },
            },
        },
    }


def _result(risk_level: str = "HIGH", gate_action: str = "advise") -> DetectionResult:
    return DetectionResult(
        risk_level=risk_level,
        confidence=0.91 if risk_level == "HIGH" else 0.89,
        features_triggered=["word_count"],
        model_id="classifier-proof",
        profile_version="f6",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(uuid.uuid4()),
        evidence_depth_limited=False,
        detection_method="profile_single_feature",
        profile_model_id="classifier-proof",
        gate_action=gate_action,
    )


class _AuditRecorder:
    def __init__(self) -> None:
        self.records: list[dict] = []

    async def write(self, record: dict) -> None:
        self.records.append(record)


class _Settings:
    class detection:
        high_risk_action = "block"
        unknown_action = "pass"


def _client(result: DetectionResult, audit: _AuditRecorder) -> TestClient:
    app = FastAPI()
    app.include_router(detect_endpoint.router)
    engine = AsyncMock()
    engine.verify = AsyncMock(return_value=result)
    app.state.engine = engine
    app.state.audit_writer = audit
    app.state.settings = _Settings()
    return TestClient(app, raise_server_exceptions=False)


def test_positive_class_classifier_proves_exact_high_and_low() -> None:
    profile = _classifier_profile()

    low = classify_with_profile(profile, {"word_count": 5, "token_count": 500})
    high = classify_with_profile(profile, {"word_count": 50, "token_count": 500})

    assert low is not None
    assert low["risk"] == "LOW"
    assert low["confidence"] == 1.0
    assert low["features_triggered"] == ["word_count"]

    assert high is not None
    assert high["risk"] == "HIGH"
    assert high["confidence"] == 1.0
    assert high["features_triggered"] == ["word_count"]


def test_scored_high_carries_gate_action_to_audit_and_governance(monkeypatch) -> None:
    pushes: list[dict] = []
    audit = _AuditRecorder()
    client = _client(_result("HIGH", gate_action="advise"), audit)

    def _capture_push(**kwargs):
        pushes.append(kwargs)

    monkeypatch.setattr(detect_endpoint, "schedule_push", _capture_push)

    response = client.post("/detect/verify", json={
        "prompt": "p",
        "response": " ".join(["word"] * 50),
        "model_id": "classifier-proof",
    })

    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "HIGH"
    assert body["action"] == "block"
    assert body["gate_action"] == "advise"
    assert response.headers["X-Arkheia-Action"] == "block"
    assert response.headers["X-Arkheia-Gate-Action"] == "advise"

    assert len(audit.records) == 1
    assert audit.records[0]["action_taken"] == body["action"]
    assert audit.records[0]["gate_action"] == body["gate_action"]

    assert len(pushes) == 1
    assert pushes[0]["payload"]["action_taken"] == body["action"]
    assert pushes[0]["payload"]["gate_action"] == body["gate_action"]


def test_validation_red_path_audit_records_advisory_gate_action(monkeypatch) -> None:
    pushes: list[dict] = []
    audit = _AuditRecorder()
    client = _client(_result("HIGH", gate_action="block"), audit)
    monkeypatch.setattr(detect_endpoint, "schedule_push", lambda **kwargs: pushes.append(kwargs))

    response = client.post("/detect/verify", json={
        "prompt": "p",
        "response": "non-empty",
        "model_id": "",
    })

    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "UNKNOWN"
    assert body["error"] == "model_id_missing"
    assert body["action"] == "pass"
    assert body["gate_action"] == "advise"
    assert response.headers["X-Arkheia-Gate-Action"] == "advise"

    assert len(audit.records) == 1
    assert audit.records[0]["action_taken"] == "pass"
    assert audit.records[0]["gate_action"] == "advise"
    assert pushes == []
