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

HARDENING (adversarial-review follow-up):
  1. SAFE INTERLOCK: the AUTHORITATIVE block signal is gate_action / X-Arkheia-Gate-Action
     (the profile-EARNED action). action / X-Arkheia-Action is only POLICY intent and is
     NOT an authorization to block. On an UNEARNED profile (policy=block, earned=advise) a
     policy-keyed consumer would OVER-BLOCK; the tightened tests reject that and pin the
     old policy-keyed assertion as over-permissive.
  2. HEADER PROPAGATION: the X-Arkheia-* signal headers (the transport-layer enforcement
     mechanism) are asserted explicitly on both block and allow/advise responses, so they
     cannot regress silently behind body-only assertions.
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
    """A HIGH-risk DetectionResult.

    gate_action encodes whether the profile has EARNED a hard-block:
      - "block"  -> earned / validated profile (authoritative signal MAY be block)
      - "advise" -> unearned / evidence-limited profile (authoritative signal is NOT block)
    """
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


def _low_result(gate_action: str = "advise") -> DetectionResult:
    """A LOW-risk DetectionResult -> policy action resolves to "pass" (allow/advise)."""
    return DetectionResult(
        risk_level="LOW",
        confidence=0.95,
        features_triggered=["entropy_mean"],
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
    def _factory(high_risk_action: str, gate_action: str = "block", result=None):
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
            engine.verify = AsyncMock(
                return_value=result if result is not None else _high_result(gate_action)
            )
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
    """The caller-visible decision-carrying surface (body action fields + action headers).

    Two distinct signals are surfaced (see proxy/endpoints/detect.py):
      - action / hdr_action (X-Arkheia-Action)           = POLICY intent (NOT authorization)
      - gate_action / hdr_gate_action (X-Arkheia-Gate-Action) = AUTHORITATIVE authorized action
    Per features.py a consumer must hard-block ONLY when gate_action == "block".
    """
    body = resp.json()
    return {
        "action": body.get("action"),
        "gate_action": body.get("gate_action"),
        "hdr_risk": resp.headers.get("x-arkheia-risk"),
        "hdr_action": resp.headers.get("x-arkheia-action"),
        "hdr_gate_action": resp.headers.get("x-arkheia-gate-action"),
    }


class TestBlockIsSurfacedToCaller:

    def test_authoritative_block_signal_is_gate_action_not_policy(self, make_client):
        """
        SAFE INTERLOCK (tightened). The AUTHORITATIVE block signal a caller may enforce on
        is gate_action / X-Arkheia-Gate-Action -- the profile-EARNED action. action /
        X-Arkheia-Action is only the POLICY intent (it mirrors audit action_taken) and is
        NOT an authorization to block.

        features.py: "Consumers must only block when result['gate_action'] == 'block'."

          EARNED  (policy=block, earned=block ): authoritative signal IS block.
          UNEARNED(policy=block, earned=advise): authoritative signal is NOT block -- even
              though the policy intent still records block. A caller keying off the POLICY
              signal here would OVER-BLOCK on an unearned / evidence-limited profile.

        (This previously asserted `action == 'block' OR hdr_action == 'block'`, which blessed
        exactly that over-block: it passed the UNEARNED case it should have rejected. See
        test_old_policy_keyed_assertion_was_over_permissive below for the pinned red evidence.)
        """
        # EARNED: the profile has validated the hard-block -> authoritative signal == block.
        earned = make_client("block", gate_action="block")
        try:
            resp = _post(earned)
            assert resp.status_code == 200  # advisory contract preserved
            s = _decision_surface(resp)
            assert s["gate_action"] == "block", f"earned profile must signal block; surface={s}"
            assert s["hdr_gate_action"] == "block", f"X-Arkheia-Gate-Action must be block; surface={s}"
        finally:
            earned.__exit__(None, None, None)

        # UNEARNED: policy says block, but the profile has NOT earned a hard-block.
        unearned = make_client("block", gate_action="advise")
        try:
            resp = _post(unearned)
            assert resp.status_code == 200
            s = _decision_surface(resp)
            # The AUTHORITATIVE (earned) signal must NOT be block ...
            assert s["gate_action"] != "block", (
                f"UNEARNED profile must NOT signal an authoritative block; surface={s}"
            )
            assert s["hdr_gate_action"] != "block", (
                f"X-Arkheia-Gate-Action must NOT be block on an unearned profile; surface={s}"
            )
            # ... while the POLICY intent is still surfaced (intent != authorization).
            assert s["action"] == "block"
            assert s["hdr_action"] == "block"
        finally:
            unearned.__exit__(None, None, None)

    def test_old_policy_keyed_assertion_was_over_permissive(self, make_client):
        """
        RED EVIDENCE (pinned). The previous assertion accepted the POLICY signal
        (`action == 'block' OR hdr_action == 'block'`). On an UNEARNED profile
        (policy=block, earned=advise) that predicate is TRUE -- so the old test blessed a
        consumer that over-blocks on a profile that never earned a hard-block. This locks in
        the defect: the old predicate passes the very case the safe interlock rejects.
        """
        client = make_client("block", gate_action="advise")  # UNEARNED
        try:
            surface = _decision_surface(_post(client))
            old_policy_keyed_pass = (
                surface["action"] == "block" or surface["hdr_action"] == "block"
            )
            # The OLD (policy-keyed) predicate is satisfied -- i.e. it was over-permissive ...
            assert old_policy_keyed_pass is True, f"surface={surface}"
            # ... yet the AUTHORITATIVE (earned) signal says do NOT block.
            assert surface["gate_action"] != "block", f"surface={surface}"
            assert surface["hdr_gate_action"] != "block", f"surface={surface}"
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


class TestSignalHeadersPropagate:
    """
    FINDING 2: the HTTP signal headers are the headline transport-layer enforcement
    mechanism (a proxy/SDK sitting in front of the pipeline keys off them without parsing
    the body), yet every other test could pass on BODY fields alone -- so header
    propagation could regress silently. These assert the headers explicitly, on both a
    blocking HIGH response and an allow/advise response, and are proven to fail if the
    endpoint stops setting the headers (see the stripped-header demonstration in the PR).
    """

    def test_headers_present_and_correct_on_high_block(self, make_client):
        """Earned HIGH block: all three headers present with the exact expected values."""
        client = make_client("block", gate_action="block")
        try:
            resp = _post(client)
            assert resp.status_code == 200
            assert resp.headers.get("x-arkheia-risk") == "HIGH", dict(resp.headers)
            assert resp.headers.get("x-arkheia-action") == "block", dict(resp.headers)
            assert resp.headers.get("x-arkheia-gate-action") == "block", dict(resp.headers)
        finally:
            client.__exit__(None, None, None)

    def test_headers_correct_on_allow_advise(self, make_client):
        """
        LOW risk -> policy action resolves to "pass" and gate_action to "advise" even though
        high_risk_action is configured "block" (the action tracks the actual risk, not the
        static config). All three headers must reflect that allow/advise decision.
        """
        client = make_client("block", result=_low_result())
        try:
            resp = _post(client)
            assert resp.status_code == 200
            assert resp.headers.get("x-arkheia-risk") == "LOW", dict(resp.headers)
            assert resp.headers.get("x-arkheia-action") == "pass", dict(resp.headers)
            assert resp.headers.get("x-arkheia-gate-action") == "advise", dict(resp.headers)
        finally:
            client.__exit__(None, None, None)

    def test_gate_action_header_is_the_authoritative_block_signal(self, make_client):
        """
        Header-layer restatement of the safe interlock: on an UNEARNED profile
        (policy=block, earned=advise) the X-Arkheia-Action header may say block (policy
        intent), but the AUTHORITATIVE X-Arkheia-Gate-Action header must NOT -- a
        transport-layer consumer keys off X-Arkheia-Gate-Action.
        """
        client = make_client("block", gate_action="advise")
        try:
            resp = _post(client)
            assert resp.status_code == 200
            assert resp.headers.get("x-arkheia-action") == "block"       # policy intent
            assert resp.headers.get("x-arkheia-gate-action") == "advise"  # authoritative
        finally:
            client.__exit__(None, None, None)
