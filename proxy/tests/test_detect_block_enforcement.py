"""
Regression tests for the "block is silently decorative at /detect/verify" defect.

DEFECT (confirmed against origin/master):
  detect_verify() computes a governance action for HIGH risk via _determine_action()
  (from settings.detection.high_risk_action, e.g. "block") and writes it into BOTH the
  audit record and the governance push as action_taken="block". The engine also computes
  a per-profile DetectionResult.gate_action ("block" when the profile has *earned* it),
  and features.py explicitly states: "Consumers must only block when
  result['gate_action'] == 'block'."

  BUT the HTTP response returned to the caller (VerifyResponse) carries NEITHER the
  policy action NOR gate_action, and there is no distinguishing status/header. So the
  response a caller receives is IDENTICAL whether high_risk_action is "block" or not,
  and the caller cannot honor the "only block when gate_action == block" contract because
  it never receives gate_action. A customer who configures block-on-HIGH gets ZERO
  enforcement signal at this endpoint, while the audit/governance trail asserts a block
  was applied.

These tests assert the caller receives a machine-actionable block signal. They FAIL on
the pre-fix endpoint (RED) and pass once the endpoint surfaces the decision to the caller
via structured fields + headers (never via body-prepend).

The endpoint's HTTP-200-always advisory contract is preserved: we assert 200 throughout.
"""

import uuid as _uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from proxy.main import create_app
from proxy.audit.writer import AuditWriter
from proxy.detection.engine import DetectionEngine, DetectionResult


def _high_result(gate_action: str = "block") -> DetectionResult:
    """A HIGH-risk DetectionResult whose profile has EARNED the block (gate_action=block)."""
    return DetectionResult(
        risk_level="HIGH",
        confidence=0.91,
        features_triggered=["entropy_mean", "reasoning_ratio"],
        model_id="claude-sonnet-5",
        profile_version="2.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(_uuid.uuid4()),
        gate_action=gate_action,
    )


@pytest.fixture
def make_client(tmp_path):
    """
    Factory: build a /detect/verify TestClient whose engine returns HIGH and whose
    settings.detection.high_risk_action is set to `high_risk_action`.
    """
    def _factory(high_risk_action: str, gate_action: str = "block"):
        profiles_dir = tmp_path / "profiles"
        profiles_dir.mkdir(exist_ok=True)

        with patch("proxy.main.settings") as mock_settings:
            mock_settings.detection.profile_dir = str(profiles_dir)
            mock_settings.proxy.log_level = "WARNING"
            mock_settings.audit.log_path = str(tmp_path / "audit.jsonl")
            mock_settings.audit.retention_days = 90
            mock_settings.registry.url = ""
            from pydantic import SecretStr
            mock_settings.arkheia_api_key = SecretStr("")
            mock_settings.synesis = MagicMock()
            mock_settings.synesis.enabled = False

            app = create_app()
            client = TestClient(app, raise_server_exceptions=False)
            client.__enter__()  # run lifespan startup

            # Override AFTER startup so we fully control engine + settings.
            engine = AsyncMock(spec=DetectionEngine)
            engine.verify = AsyncMock(return_value=_high_result(gate_action))
            app.state.engine = engine

            settings = MagicMock()
            settings.detection.high_risk_action = high_risk_action
            settings.detection.unknown_action = "pass"
            app.state.settings = settings
            # Keep audit as a harmless async mock (audit path is out of scope here).
            audit = AsyncMock(spec=AuditWriter)
            audit.write = AsyncMock()
            app.state.audit_writer = audit
            return client

    return _factory


def _post(client: TestClient):
    return client.post("/detect/verify", json={
        "prompt": "Summarize the Q3 incident report.",
        "response": "The outage was caused by a cascading failure in the auth service.",
        "model_id": "claude-sonnet-5",
    })


def _decision_surface(resp) -> dict:
    """The caller-visible decision-carrying surface (body action fields + action headers)."""
    body = resp.json()
    return {
        "action": body.get("action"),
        "gate_action": body.get("gate_action"),
        "hdr_risk": resp.headers.get("x-arkheia-risk"),
        "hdr_action": resp.headers.get("x-arkheia-action"),
    }


class TestBlockIsSurfacedToCaller:

    def test_high_block_response_carries_actionable_block_signal(self, make_client):
        """
        With HIGH risk and high_risk_action=block, the caller MUST receive a
        machine-actionable block signal (structured field and/or header) so it can enforce.

        RED pre-fix: no `action` field, no X-Arkheia-Action header -> no way to enforce.
        """
        client = make_client("block")
        try:
            resp = _post(client)
            assert resp.status_code == 200  # advisory contract preserved
            surface = _decision_surface(resp)
            # A caller must be able to see, from the response alone, that this was blocked.
            assert (
                surface["action"] == "block"
                or surface["hdr_action"] == "block"
            ), (
                "Caller received NO actionable block signal for high_risk_action=block. "
                f"decision surface = {surface}"
            )
        finally:
            client.__exit__(None, None, None)

    def test_gate_action_is_surfaced_to_caller(self, make_client):
        """
        features.py states consumers must only block when result['gate_action'] == 'block'.
        The endpoint must therefore surface gate_action to the caller.

        RED pre-fix: gate_action is computed by the engine but dropped by the endpoint.
        """
        client = make_client("block", gate_action="block")
        try:
            resp = _post(client)
            assert resp.status_code == 200
            body = resp.json()
            assert body.get("gate_action") == "block", (
                "gate_action (the profile-earned block signal consumers must key off) "
                f"is not surfaced to the caller. body keys = {sorted(body.keys())}"
            )
        finally:
            client.__exit__(None, None, None)

    def test_block_is_distinguishable_from_non_block(self, make_client):
        """
        The caller-visible decision surface for high_risk_action=block MUST differ from
        the non-blocking action (warn). Pre-fix both are empty -> indistinguishable (RED).
        """
        c_block = make_client("block")
        c_warn = make_client("warn")
        try:
            s_block = _decision_surface(_post(c_block))
            s_warn = _decision_surface(_post(c_warn))
            assert s_block != s_warn, (
                "A blocking config is INDISTINGUISHABLE from a non-blocking one at the "
                f"response layer. block={s_block} warn={s_warn}"
            )
        finally:
            c_block.__exit__(None, None, None)
            c_warn.__exit__(None, None, None)

    def test_block_signal_not_via_body_prepend(self, make_client):
        """
        HARD CONSTRAINT: the block signal must NOT corrupt the body via the
        [ARKHEIA WARNING ...] prepend pattern. Body stays valid JSON with detection fields.
        """
        client = make_client("block")
        try:
            resp = _post(client)
            assert not resp.content.startswith(b"[ARKHEIA WARNING"), (
                "Block was signalled by prepending to the body -- forbidden (corrupts responses)."
            )
            body = resp.json()  # must still be valid JSON
            assert body.get("risk_level") == "HIGH"
            assert "detection_id" in body
        finally:
            client.__exit__(None, None, None)
