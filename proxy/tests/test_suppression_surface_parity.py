"""
F7 — is a SUPPRESSED verdict distinguishable from a SCORED CLEAN one, on every consumer?

THE QUESTION
------------
`check_mode_gate` / `check_empty_output_gate` return `LOW / 0.0 / features_used=0` and a
`gate_reason` saying which gate fired and why. Everything after that point decides
whether anyone ever learns a suppression happened.

Pre-fix, at `/detect/verify`, the answer was NO on every consumer at once. The endpoint
built its `VerifyResponse` from six fields of the engine's result and dropped
`evidence_depth_limited`, `detection_method` and the whole `metrics` dict — so the caller
received

    {"risk_level": "LOW", "confidence": 0.0, "features_triggered": [], "error": null}

for a response nothing was measured on. The MCP tool that consumes it documents
`LOW -- surface normally`. The audit record, the governance push and the
`X-Arkheia-Risk` header all carried the same bare LOW.

This suite drives the REAL endpoint with the REAL engine over the REAL shipped profiles
and asserts on what each consumer ACTUALLY receives — the caller's decoded body, the
response headers, and the SERIALIZED BYTES the governance push puts on the wire (read
off `httpx.Request.content`, i.e. below the JSON encoding and below the HMAC that is
computed over exactly those bytes, which is where a field that is built but not sent
looks correct).

Every suppression assertion is paired with a SCORED CLEAN LOW control on the same
endpoint, because "the field is present" proves nothing unless the field is also ABSENT
when the verdict was genuinely scored.

RED RUN (DONE.md v1.15), executed against origin/master @ 3037f0c + BU-1 on
python 3.12.13, BEFORE the carry-through landed:

    12 failed, 6 passed

verbatim failures:

    TestTheCallerCanTellSuppressedFromScored::test_pre_fix_the_only_distinction_was_an_absence_never_a_statement
    TestTheCallerCanTellSuppressedFromScored::test_the_suppression_reason_reaches_the_caller
    TestTheCallerCanTellSuppressedFromScored::test_a_scored_verdict_carries_no_reason
    TestTheCallerCanTellSuppressedFromScored::test_the_field_is_present_on_every_response_never_omitted
    TestTheCallerCanTellSuppressedFromScored::test_the_unknown_paths_carry_no_reason
    TestTheAuditRecordCanTellSuppressedFromScored::test_the_audit_record_carries_the_reason
    TestTheAuditRecordCanTellSuppressedFromScored::test_a_scored_audit_record_carries_none
    TestTheAuditRecordCanTellSuppressedFromScored::test_the_record_is_tied_to_the_verdict_the_caller_was_given
    TestTheAuditRecordCanTellSuppressedFromScored::test_the_audit_rail_is_never_more_reassuring_than_the_caller
    TestTheGovernancePushCanTellSuppressedFromScored::test_the_pushed_body_carries_the_reason
    TestTheGovernancePushCanTellSuppressedFromScored::test_a_scored_push_carries_none
    TestTheGovernancePushCanTellSuppressedFromScored::test_the_reason_is_on_the_serialized_bytes_not_just_the_dict

The 6 that PASSED pre-fix are the two premise checks, the two PINNED-not-fixed
observations (the `... else "LOW"` governance envelope; push_event serialising
outside its own try) and the two header-channel pins. The file discriminated
rather than being uniformly red.

DECLARED OVERLAP: `sweep/f2-mandatory-screening` independently surfaces
`evidence_depth_limited` / `detection_method` / `profile_model_id` at this same endpoint.
This branch adds `gate_reason` — the field that says WHICH gate fired and against WHICH
threshold, which no sibling carries. The two changes are semantically complementary and
will conflict textually in the `VerifyResponse` / `_audit_record` / push blocks.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from proxy.detection import features as F
from proxy.main import create_app

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: A model whose SHIPPED profile enables the mode gate at token_count_max=80.
GATED_MODEL = "gpt-5.3-codex"

#: Under 80 words -> DetectionEngine sets token_count = len(words) -> mode gate fires.
SHORT_RESPONSE = "Paris."

#: Comfortably over 80 words, so the gate does not fire and features are scored.
LONG_RESPONSE = " ".join(
    f"The capital city number {i} has a documented population and a founding date."
    for i in range(20)
)


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class _PushWire:
    """Captures the SERIALIZED bytes the governance push puts on the wire.

    Patches `httpx.AsyncClient.send`, so the body observed is `httpx.Request.content` —
    the exact bytes `push_event` signed. Nothing intermediate, no dict.
    """

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.arrived = threading.Event()

    async def send(self, request, *args, **kwargs):  # noqa: ANN001
        self.bodies.append(request.content)
        self.arrived.set()
        return httpx.Response(200, request=request, json={"ok": True})

    def await_one(self, timeout: float = 5.0) -> dict:
        """schedule_push is fire-and-forget (`asyncio.ensure_future`), so the push lands
        AFTER the HTTP response. Wait for it rather than racing it."""
        if not self.arrived.wait(timeout):
            raise AssertionError(
                "no governance push reached the wire within %.1fs — the parity claim "
                "would be vacuous" % timeout
            )
        assert len(self.bodies) == 1, f"expected exactly one push, got {len(self.bodies)}"
        return json.loads(self.bodies[0].decode())


@pytest.fixture
def wire(monkeypatch):
    w = _PushWire()
    # push_event returns early unless BOTH are configured; set them so the real
    # code path runs end to end.
    monkeypatch.setattr("proxy.detection_adapter.DETECTION_ADAPTER_URL",
                        "http://adapter.test")
    monkeypatch.setattr("proxy.detection_adapter.DETECTION_ADAPTER_HMAC_SECRET",
                        "test-secret")
    monkeypatch.setattr(httpx.AsyncClient, "send", w.send)
    return w


class _AuditRecorder:
    """Records the record dict handed to the audit rail. The DURABLE on-disk bytes are
    proven separately in test_suppression_receipts.py against a real AuditWriter."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    async def write(self, record: dict) -> None:
        self.records.append(record)


@pytest.fixture
def audit():
    return _AuditRecorder()


@pytest.fixture
def client(tmp_path, audit):
    """A REAL DetectionEngine over the REAL shipped profiles directory."""
    with (
        patch.dict("os.environ", {"ARKHEIA_ALLOW_PLAINTEXT_PROFILES": "true"}),
        patch("proxy.main.settings") as s,
    ):
        s.detection.profile_dir = str(_REPO_ROOT / "profiles")
        # Real STRING policy values. A MagicMock here reaches the push payload as
        # `action_taken` and blows the push up — see
        # TestThePushSerialisesOutsideItsOwnTryBlock, which is a real finding, not a
        # test artefact.
        s.detection.high_risk_action = "warn"
        s.detection.unknown_action = "pass"
        s.proxy.log_level = "WARNING"
        s.audit.log_path = str(tmp_path / "audit.jsonl")
        s.audit.retention_days = 90
        s.registry.url = ""
        from pydantic import SecretStr
        s.arkheia_api_key = SecretStr("")
        s.synesis = MagicMock()
        s.synesis.enabled = False
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as c:
            app.state.audit_writer = audit
            yield c


def _verify(client, response_text: str, model: str = GATED_MODEL):
    r = client.post("/detect/verify", json={
        "prompt": "What is the capital of France?",
        "response": response_text,
        "model_id": model,
    })
    assert r.status_code == 200
    return r


# ---------------------------------------------------------------------------
# 0. The premise. Without this, everything below is vacuous.
# ---------------------------------------------------------------------------

class TestThePremise:
    def test_the_short_response_really_is_suppressed_by_the_gate(self, client, audit):
        """Drive the real engine and prove the mode gate actually fired — otherwise the
        whole suite would be asserting parity on an ordinary scored LOW."""
        from proxy.router.profile_router import ProfileRouter
        from proxy.detection.features import check_mode_gate
        router = ProfileRouter(str(_REPO_ROOT / "profiles"))
        profile = router.get(GATED_MODEL)
        assert profile is not None, "shipped profile vanished; suite is vacuous"
        gate = check_mode_gate(profile, {"token_count": len(SHORT_RESPONSE.split())})
        assert gate is not None
        assert gate["metrics"]["gate_reason"] == "token_count_below_80"

    def test_the_long_response_really_is_scored(self, client):
        """The CONTROL must be a genuinely scored verdict, not a second suppression."""
        body = _verify(client, LONG_RESPONSE).json()
        assert body["features_triggered"] != [], (
            "the control response was not scored — pick a longer one or the negative "
            "controls below prove nothing"
        )


# ---------------------------------------------------------------------------
# 1. The CALLER
# ---------------------------------------------------------------------------

class TestTheCallerCanTellSuppressedFromScored:

    def test_pre_fix_the_only_distinction_was_an_absence_never_a_statement(self, client):
        """HONEST CHARACTERISATION OF THE PRE-FIX STATE — this test PASSES against
        origin/master and is not a closure test.

        The proxy sibling's headline defect was a suppressed verdict reaching the caller
        byte-identical to a scored clean one. The mcp side is NOT that: `confidence` and
        `features_triggered` differ, because the scored path cannot produce
        `confidence == 0.0` (the ratio is >= 1/3, or 0.5 when total_weight is 0) and
        cannot produce an empty `features_triggered` (features_used == 0 returns None ->
        UNKNOWN). So the two are distinguishable — by INFERENCE OVER A CONJUNCTION OF TWO
        ABSENCES that nothing documents.

        Nothing in the payload NAMES the suppression, the MCP tool contract documents
        five fields and none of them means "not assessed", and that tool's own guidance
        for this verdict is `LOW -- surface normally`. That is the defect this suite
        closes: a decision not to report was legible only to a reader who already knew
        the classifier's internals.

        POST-MERGE UPDATE (sweep/mcp-f7-fp-suppression x master): the property under test
        is "the caller can tell suppressed from scored by a STATEMENT, not by an absence" —
        and merging origin/master's screening-transparency work made that MORE true, not
        less. TWO fields now make the statement: `gate_reason` (this branch — names WHICH
        suppression gate fired) and `detection_method` (master — names WHETHER anything was
        scored at all). They are legitimate and complementary, not a collision; the original
        exact-match on `{"gate_reason"}` alone was incidental over-specification of a
        single-branch world, never the actual contract. The pin stays an EXACT set (not a
        membership check) precisely so it still goes red the moment an unaccounted third
        field starts naming the suppression.
        """
        supp = _verify(client, SHORT_RESPONSE).json()
        scored = _verify(client, LONG_RESPONSE).json()
        assert supp["risk_level"] == scored["risk_level"] == "LOW"
        # The inference that WAS available:
        assert supp["confidence"] == 0.0 and supp["features_triggered"] == []
        assert scored["confidence"] > 0.0 and scored["features_triggered"] != []
        # ...and the statement that was not. Exactly these two fields now name it —
        # `gate_reason` (WHICH gate) and `detection_method` (WHETHER anything was scored).
        naming = {k: v for k, v in supp.items()
                  if isinstance(v, str) and ("suppress" in v or "gate" in v
                                             or "token_count_below" in v)}
        assert set(naming) == {"gate_reason", "detection_method"}, (
            "either a marker is missing (regression) or a third, unaccounted field "
            f"now also names the suppression: {naming}"
        )

    def test_the_suppression_reason_reaches_the_caller(self, client):
        body = _verify(client, SHORT_RESPONSE).json()
        assert body["risk_level"] == "LOW"
        assert body["confidence"] == 0.0
        assert body["gate_reason"] == "token_count_below_80"
        assert F.is_suppression_reason(body["gate_reason"]) is True

    def test_a_scored_verdict_carries_no_reason(self, client):
        """NEGATIVE CONTROL. If a scored LOW also carried a gate_reason the field would
        not discriminate and the test above would be decorative."""
        body = _verify(client, LONG_RESPONSE).json()
        assert body["gate_reason"] is None

    def test_the_field_is_present_on_every_response_never_omitted(self, client):
        """An ABSENT field is indistinguishable from an older proxy that never set it,
        so `gate_reason` is always emitted — null when the verdict was scored."""
        for text in (SHORT_RESPONSE, LONG_RESPONSE):
            assert "gate_reason" in _verify(client, text).json()

    def test_the_unknown_paths_carry_no_reason(self, client):
        """UNKNOWN already explains itself via `error`; it must not borrow the
        suppression marker."""
        for payload, err in (
            ({"prompt": "p", "response": "r", "model_id": ""}, "model_id_missing"),
            ({"prompt": "p", "response": "", "model_id": GATED_MODEL}, "response_empty"),
            ({"prompt": "p", "response": "r" * 500, "model_id": "no-such-model-xyz"},
             "no_profile_for_model"),
        ):
            body = client.post("/detect/verify", json=payload).json()
            assert body["error"] == err
            assert body["gate_reason"] is None


# ---------------------------------------------------------------------------
# 2. The AUDIT rail
# ---------------------------------------------------------------------------

class TestTheAuditRecordCanTellSuppressedFromScored:
    """A suppression is a decision NOT to report something. If the forensic record says
    only `LOW`, the compliance artefact asserts a screening that never happened."""

    def test_the_audit_record_carries_the_reason(self, client, audit):
        _verify(client, SHORT_RESPONSE)
        assert len(audit.records) == 1
        rec = audit.records[0]
        assert rec["risk_level"] == "LOW"
        assert rec["gate_reason"] == "token_count_below_80"

    def test_a_scored_audit_record_carries_none(self, client, audit):
        _verify(client, LONG_RESPONSE)
        assert audit.records[0]["gate_reason"] is None

    def test_the_record_is_tied_to_the_verdict_the_caller_was_given(self, client, audit):
        body = _verify(client, SHORT_RESPONSE).json()
        assert audit.records[0]["detection_id"] == body["detection_id"]
        assert audit.records[0]["gate_reason"] == body["gate_reason"]

    def test_the_audit_rail_is_never_more_reassuring_than_the_caller(self, client, audit):
        """The class of defect this sweep exists to catch: the record holding a
        friendlier value than the caller was given."""
        for text in (SHORT_RESPONSE, LONG_RESPONSE):
            audit.records.clear()
            body = _verify(client, text).json()
            rec = audit.records[0]
            assert rec["risk_level"] == body["risk_level"]
            assert rec["confidence"] == body["confidence"]
            assert rec["gate_reason"] == body["gate_reason"]


# ---------------------------------------------------------------------------
# 3. The GOVERNANCE push — asserted on the bytes that were signed
# ---------------------------------------------------------------------------

class TestTheGovernancePushCanTellSuppressedFromScored:

    def test_the_pushed_body_carries_the_reason(self, client, wire):
        body = _verify(client, SHORT_RESPONSE).json()
        pushed = wire.await_one()
        assert pushed["payload"]["detection_id"] == body["detection_id"]
        assert pushed["payload"]["risk_level"] == "LOW"
        assert pushed["payload"]["gate_reason"] == "token_count_below_80"

    def test_a_scored_push_carries_none(self, client, wire):
        _verify(client, LONG_RESPONSE)
        pushed = wire.await_one()
        assert pushed["payload"]["gate_reason"] is None

    def test_the_reason_is_on_the_serialized_bytes_not_just_the_dict(self, client, wire):
        """A field built but not sent looks correct in a dict view. Assert on bytes."""
        _verify(client, SHORT_RESPONSE)
        wire.await_one()
        assert b'"gate_reason"' in wire.bodies[0]
        assert b'"token_count_below_80"' in wire.bodies[0]


class TestTheGovernanceEnvelopeBandIsPinnedNotFixed:
    """PINNED CURRENT BEHAVIOUR — NOT A FIX, and NOT this flow's to fix.

    `detect.py` pushes
        risk_level = response.risk_level if response.risk_level in
                     ("LOW","MEDIUM","HIGH","CRITICAL") else "LOW"
    — the `... else "LOW"` shape: an unrecognised band defaults to the safest-sounding
    value. UNKNOWN (engine unavailable, engine error, no profile — every couldn't-assess
    path) is published to the governance plane's envelope as a clean **LOW**, while the
    caller is correctly told UNKNOWN. The audit/governance rail receives a MORE
    REASSURING value than the caller.

    `sweep/mcp-governance-adapter-push` already carries the fix (pass the raw band and
    map UNKNOWN -> UNCERTAIN in the adapter, which needs the adapter-side change to go
    with it). It is pinned here, not duplicated, so the divergence is visible on this
    branch and this test goes red the moment that branch lands.
    """

    def test_unknown_is_published_to_the_envelope_as_low(self, client, wire):
        body = client.post("/detect/verify", json={
            "prompt": "p", "response": "r" * 400, "model_id": "no-such-model-xyz",
        }).json()
        assert body["risk_level"] == "UNKNOWN"
        pushed = wire.await_one()
        assert pushed["risk_level"] == "LOW", (
            "sweep/mcp-governance-adapter-push has landed — delete this pin"
        )
        assert pushed["payload"]["risk_level"] == "UNKNOWN"


class TestThePushSerialisesOutsideItsOwnTryBlock:
    """PINNED — NOT this flow's file to fix (`proxy/detection_adapter.py` is owned by
    `sweep/mcp-governance-adapter-push`). Found while building the wire harness.

    `push_event` documents "Fails open — never raises". It does not: `json.dumps(body_dict)`
    sits ABOVE the `try:`, so a payload value that is not JSON-serialisable raises
    straight out of the fire-and-forget task. The event is lost, the `logger.debug`
    fail-open line below never runs, and the only trace is asyncio's
    "Task exception was never retrieved". The reachable route is `action_taken`, which is
    whatever `settings.detection.high_risk_action` / `unknown_action` holds — a `str` in
    production, so this is a latent hole rather than a live outage, but it is a
    governance event silently lost by the one function contracted never to lose one.
    """

    @pytest.mark.asyncio
    async def test_a_non_serialisable_payload_escapes_the_fail_open_handler(
        self, monkeypatch
    ):
        import proxy.detection_adapter as da
        monkeypatch.setattr(da, "DETECTION_ADAPTER_URL", "http://adapter.test")
        monkeypatch.setattr(da, "DETECTION_ADAPTER_HMAC_SECRET", "s")
        with pytest.raises(TypeError):
            await da.push_event(
                tenant_id="t", source_id="m", event_type="mcp_detection",
                payload={"action_taken": object()}, risk_level="LOW",
            )


# ---------------------------------------------------------------------------
# 4. What is NOT closed here
# ---------------------------------------------------------------------------

class TestTheHeaderChannelStillCannotTell:
    """PINNED — the interception middleware is owned by `sweep/mcp-f10-interception`
    and is READ-ONLY on this branch.

    `proxy/middleware/interception.py` relays `X-Arkheia-Risk: <band>` and nothing else,
    so on the `/v1/*` enforcement path a suppressed LOW is byte-identical to a scored
    clean LOW for any header-only consumer. `/detect/verify`'s own `_signal()` has the
    same shape for the risk header. Stated so the omission is a decision, not an
    oversight.
    """

    def test_the_risk_header_is_identical_for_both(self, client):
        supp = _verify(client, SHORT_RESPONSE)
        scored = _verify(client, LONG_RESPONSE)
        assert supp.headers["X-Arkheia-Risk"] == "LOW"
        assert scored.headers["X-Arkheia-Risk"] == "LOW"

    def test_no_suppression_marker_is_mirrored_into_any_header(self, client):
        supp = _verify(client, SHORT_RESPONSE)
        joined = " ".join(f"{k}:{v}" for k, v in supp.headers.items()).lower()
        assert "token_count_below" not in joined
        assert "suppress" not in joined
