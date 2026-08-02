"""
Governance detection-adapter push (HMAC-signed) — run to ground.

Two properties matter here and they are DIFFERENT:

  * **The signature must authenticate** (integrity + origin) — proven against
    `tests/_receiver_oracle.py`, a transcription of the real receiver
    (`arkheia-synesis/services/detection-adapter/src/hmac_auth.rs`), frozen by a
    golden vector taken from the receiver's own unit-test fixture.

  * **The push must actually land** (delivery) — proven at the transport
    boundary, on the bytes and the response, not by observing that a function was
    called. And when it does NOT land, that must be VISIBLE: a 4xx swallowed at
    debug level is how the proxy's Synesis ingest rail stayed dark for twenty days
    behind a `400 MISSING_EVENT_ID`.

Assertion discipline (the defect class of this sweep):
  * no `pytest.raises(Exception)` — every raise pins `AuthError.code` exactly;
  * no `!= 200` / `is not None` — expected values are positively computed;
  * every absence assertion is PAIRED with a positive control in the same test,
    so "nothing happened because the harness was misaimed" cannot read as a pass.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid

import httpx
import pytest

from tests import _receiver_oracle as oracle

import proxy.detection_adapter as mod
from proxy.detection_adapter import PushOutcome

# The receiver's key id must match ours EXACTLY (checked before the signature).
KEY_ID = "mcp-v1"
SECRET = "test-secret-32-bytes-minimum-len"
URL = "http://adapter:7070"
ENDPOINT = f"{URL}/v1/events/proxy"

PAYLOAD = {
    "detection_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "model_id": "gpt-4o",
    "confidence": 0.81,
    "profile_version": "gpt-4o_v3.2",
    "features_triggered": ["logprob_entropy"],
    "prompt_hash": "a" * 64,
    "response_hash": "b" * 64,
    "action_taken": "warn",
}


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("DETECTION_ADAPTER_URL", URL)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", KEY_ID)


class Capture:
    """Records exactly what crossed the transport boundary."""

    def __init__(self, status: int = 200, body: str = "{}"):
        self.status = status
        self.body = body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, text=self.body)

    @property
    def only(self) -> httpx.Request:
        assert len(self.requests) == 1, (
            f"expected exactly 1 request at the transport boundary, saw "
            f"{len(self.requests)}"
        )
        return self.requests[0]

    def headers(self) -> dict:
        return dict(self.only.headers)

    def content(self) -> bytes:
        return self.only.content


async def _push(risk="LOW", payload=None, audit=None):
    return await mod.push_event(
        "acme-corp", "gpt-4o", "mcp_detection", payload or PAYLOAD, risk, audit
    )


# ══════════════════════════════════════════════════════════════════════════════
# A. The oracle itself is honest
# ══════════════════════════════════════════════════════════════════════════════

def test_oracle_matches_the_receivers_own_golden_vector():
    """
    The oracle is only useful if it is the RECEIVER's algorithm, not a restatement
    of ours. Pin it against the receiver's own unit-test fixture at a frozen
    timestamp: if someone edits the oracle to accommodate a broken sender, this
    fails first.
    """
    assert oracle.signing_string(
        oracle.GOLDEN_PATH, oracle.GOLDEN_TIMESTAMP, oracle.GOLDEN_BODY
    ) == oracle.GOLDEN_SIGNING_STRING
    assert oracle.sign(
        oracle.GOLDEN_SECRET, oracle.GOLDEN_PATH, oracle.GOLDEN_TIMESTAMP, oracle.GOLDEN_BODY
    ) == oracle.GOLDEN_SIGNATURE


def test_oracle_rejects_the_pre_fix_signing_construction():
    """
    Regression pin for the defect this flow was carrying.

    Until 2026-07-26 the sender signed ``f"{timestamp}.{body}"``. Prove that
    construction is REJECTED by the receiver — and, as the positive control in
    the same test, that the receiver's own construction over the SAME body and
    timestamp is accepted. Without the control this would pass against an oracle
    that rejects everything.
    """
    import hmac as _h

    body = oracle.GOLDEN_BODY
    ts = oracle.GOLDEN_TIMESTAMP
    old_message = f"{ts}.{body.decode()}".encode()
    old_sig = _h.new(oracle.GOLDEN_SECRET, old_message, hashlib.sha256).hexdigest()

    hdrs = {
        "X-Arkheia-Key-Id": KEY_ID,
        "X-Arkheia-Timestamp": str(ts),
        "X-Arkheia-Signature": old_sig,
    }
    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(oracle.GOLDEN_SECRET, KEY_ID, oracle.GOLDEN_PATH, body, hdrs, now=ts)
    assert ei.value.code == oracle.INVALID_SIGNATURE

    # positive control: the receiver's construction over identical inputs passes
    hdrs["X-Arkheia-Signature"] = oracle.GOLDEN_SIGNATURE
    oracle.verify(oracle.GOLDEN_SECRET, KEY_ID, oracle.GOLDEN_PATH, body, hdrs, now=ts)


# ══════════════════════════════════════════════════════════════════════════════
# B. Delivery — the push actually arrives, and the receiver accepts it
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_push_arrives_and_the_real_receiver_accepts_it(configured, respx_mock):
    """
    The load-bearing test. Not "a function was called" — the captured bytes and
    headers are fed to the receiver's verification algorithm and must pass it.
    """
    cap = Capture()
    respx_mock.post(ENDPOINT).mock(side_effect=cap)

    outcome = await _push()

    assert outcome.status == PushOutcome.DELIVERED
    assert outcome.http_status == 200

    req = cap.only
    assert req.method == "POST"
    assert str(req.url) == ENDPOINT

    # Would the real adapter accept this? Raises if not.
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", req.content, dict(req.headers))


@pytest.mark.asyncio
async def test_signature_covers_the_bytes_actually_transmitted(configured, respx_mock):
    """
    Guards against signing a re-serialised copy of the body. The signature must
    verify against `request.content` verbatim; a body that differs by so much as
    whitespace must not.
    """
    cap = Capture()
    respx_mock.post(ENDPOINT).mock(side_effect=cap)
    await _push()

    sent = cap.content()
    hdrs = cap.headers()

    # positive: the transmitted bytes verify
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", sent, hdrs)

    # negative: a semantically identical but differently-serialised body does not
    requoted = json.dumps(json.loads(sent), separators=(",", ":")).encode()
    assert requoted != sent, "fixture is vacuous — reserialisation produced identical bytes"
    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", requoted, hdrs)
    assert ei.value.code == oracle.INVALID_SIGNATURE


@pytest.mark.asyncio
async def test_body_satisfies_the_receivers_proxyevent_schema(configured, respx_mock):
    """
    A signature the receiver accepts still 400s if the body will not deserialise.
    `normalise.rs::ProxyEvent` has ten required fields; the pre-fix body carried
    one of them.
    """
    cap = Capture()
    respx_mock.post(ENDPOINT).mock(side_effect=cap)
    await _push()

    body = json.loads(cap.content())
    missing = [f for f in oracle.PROXY_EVENT_REQUIRED if f not in body]
    assert missing == [], f"ProxyEvent would fail to deserialise; missing {missing}"

    assert isinstance(body["tenant"], dict), "tenant is an OBJECT in ProxyTenant"
    assert body["tenant"]["tenant_id"] == "acme-corp"
    for f in oracle.PROXY_TENANT_REQUIRED:
        assert f in body["tenant"]
    for f in oracle.PROXY_INVOCATION_REQUIRED:
        assert f in body["invocation"]
    for f in oracle.PROXY_MODEL_REQUIRED:
        assert f in body["model"]
    for f in oracle.PROXY_DETECTION_REQUIRED:
        assert f in body["detection"]

    # serde types these as Uuid — a non-UUID fails the whole body
    assert str(uuid.UUID(body["event_id"])) == body["event_id"]
    assert str(uuid.UUID(body["invocation"]["invocation_id"])) == body["invocation"]["invocation_id"]
    assert body["event_id"] == PAYLOAD["detection_id"], "governance event must be tied to the detection"

    # serde types confidence as f32
    assert isinstance(body["detection"]["confidence"], float)
    assert body["detection"]["confidence"] == pytest.approx(0.81)
    assert body["detection"]["fabrication_risk"] == "LOW"
    assert body["model"]["model_id"] == "gpt-4o"


@pytest.mark.asyncio
async def test_all_three_signing_headers_are_present_with_exact_values(configured, respx_mock):
    """`handlers.rs::extract_signing_headers` 401s on any one of the three."""
    cap = Capture()
    respx_mock.post(ENDPOINT).mock(side_effect=cap)
    await _push()

    hdrs = cap.headers()
    key_id, ts, sig = oracle.extract_signing_headers(hdrs)
    assert key_id == KEY_ID
    assert len(sig) == 64 and bytes.fromhex(sig)
    assert hdrs["content-type"] == "application/json"

    # The sender's only contribution to replay defence is a FRESH timestamp; the
    # window is enforced by the receiver. Prove ours lands inside it.
    assert abs(int(time.time()) - ts) <= 5, "timestamp is not fresh; receiver would 401"


# ══════════════════════════════════════════════════════════════════════════════
# C. A push that FAILS is visible — the twenty-days-dark defect
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_receiver_rejection_is_logged_at_error_not_debug(configured, respx_mock, caplog):
    """
    A 401 from the governance plane means the record does not exist. It must not
    be a debug crumb. Paired positive control: a 200 emits NO error at all, so
    this cannot pass by logging errors unconditionally.
    """
    rejection = json.dumps(
        {"error": {"code": "INVALID_SIGNATURE", "message": "Signature verification failed"}}
    )
    respx_mock.post(ENDPOINT).mock(side_effect=Capture(status=401, body=rejection))

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()

    assert outcome.status == PushOutcome.REJECTED
    assert outcome.http_status == 401
    assert "INVALID_SIGNATURE" in outcome.error

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, f"expected exactly one ERROR, got {[r.message for r in errors]}"
    msg = errors[0].getMessage()
    assert mod.FAILURE_MARKER in msg
    assert "401" in msg
    assert outcome.event_id in msg, "the failure must name the event that was lost"

    # ── positive control: a delivered push logs no error ──
    caplog.clear()
    respx_mock.post(ENDPOINT).mock(side_effect=Capture(status=200))
    with caplog.at_level(logging.DEBUG, logger="proxy.detection_adapter"):
        ok = await _push()
    assert ok.status == PushOutcome.DELIVERED
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc, name",
    [
        (httpx.ConnectError("connection refused"), "ConnectError"),
        (httpx.TimeoutException("timed out"), "TimeoutException"),
    ],
)
async def test_transport_failure_is_visible_and_never_raises(
    configured, respx_mock, caplog, exc, name
):
    """Fail-open is kept — push_event returns — but the loss is at ERROR level."""
    respx_mock.post(ENDPOINT).mock(side_effect=exc)

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()  # must not raise

    assert outcome.status == PushOutcome.FAILED
    assert outcome.http_status is None
    assert name in outcome.error

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert mod.FAILURE_MARKER in errors[0].getMessage()


@pytest.mark.asyncio
async def test_a_5xx_is_also_reported_as_rejected_not_delivered(configured, respx_mock):
    """
    `assert status != 200` would pass for a 500 caused by our own bug. Pin the
    band: anything >= 400 is REJECTED and carries the exact code.
    """
    respx_mock.post(ENDPOINT).mock(side_effect=Capture(status=503, body="upstream down"))
    outcome = await _push()
    assert outcome.status == PushOutcome.REJECTED
    assert outcome.http_status == 503
    assert outcome.delivered is False


@pytest.mark.asyncio
async def test_a_2xx_that_is_not_200_still_counts_as_delivered(configured, respx_mock):
    respx_mock.post(ENDPOINT).mock(side_effect=Capture(status=202))
    outcome = await _push()
    assert outcome.status == PushOutcome.DELIVERED
    assert outcome.http_status == 202
    assert outcome.delivered is True


# ══════════════════════════════════════════════════════════════════════════════
# D. The signature authenticates — tamper, wrong key, wrong key id, replay
# ══════════════════════════════════════════════════════════════════════════════

async def _capture_signed(respx_mock):
    cap = Capture()
    respx_mock.post(ENDPOINT).mock(side_effect=cap)
    await _push()
    return cap.content(), cap.headers()


@pytest.mark.asyncio
async def test_tampered_body_fails_verification(configured, respx_mock):
    body, hdrs = await _capture_signed(respx_mock)

    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs)  # control

    tampered = body.replace(b'"fabrication_risk": "LOW"', b'"fabrication_risk": "HIGH"')
    assert tampered != body, "fixture is vacuous — nothing was tampered with"
    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", tampered, hdrs)
    assert ei.value.code == oracle.INVALID_SIGNATURE


@pytest.mark.asyncio
async def test_single_bit_body_tamper_fails_verification(configured, respx_mock):
    """A one-byte flip anywhere in the body must invalidate the signature."""
    body, hdrs = await _capture_signed(respx_mock)
    for idx in (0, len(body) // 2, len(body) - 1):
        mutated = bytearray(body)
        mutated[idx] ^= 0x01
        with pytest.raises(oracle.AuthError) as ei:
            oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", bytes(mutated), hdrs)
        assert ei.value.code == oracle.INVALID_SIGNATURE


@pytest.mark.asyncio
async def test_tampered_signature_fails(configured, respx_mock):
    body, hdrs = await _capture_signed(respx_mock)
    good = hdrs["x-arkheia-signature"]

    # flip one hex nibble
    flipped = ("0" if good[0] != "0" else "1") + good[1:]
    assert flipped != good
    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, {**hdrs, "x-arkheia-signature": flipped})
    assert ei.value.code == oracle.INVALID_SIGNATURE

    # non-hex garbage takes the hex-decode path, still InvalidSignature
    with pytest.raises(oracle.AuthError) as ei2:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, {**hdrs, "x-arkheia-signature": "zzzz"})
    assert ei2.value.code == oracle.INVALID_SIGNATURE

    # truncated signature — a prefix must not be accepted
    with pytest.raises(oracle.AuthError) as ei3:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, {**hdrs, "x-arkheia-signature": good[:32]})
    assert ei3.value.code == oracle.INVALID_SIGNATURE

    # control: untouched signature verifies
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs)


@pytest.mark.asyncio
async def test_wrong_key_fails(configured, respx_mock):
    body, hdrs = await _capture_signed(respx_mock)

    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(b"a-different-secret-of-the-same-len", KEY_ID, "/v1/events/proxy", body, hdrs)
    assert ei.value.code == oracle.INVALID_SIGNATURE

    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs)  # control


@pytest.mark.asyncio
async def test_wrong_key_id_fails_before_the_signature_is_even_checked(configured, respx_mock):
    """
    `verify` checks key-id FIRST. Corrupt BOTH the key id and the signature: the
    error must be UnknownKeyId, which is only true if the ordering is preserved.
    """
    body, hdrs = await _capture_signed(respx_mock)

    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(
            SECRET.encode(), "some-other-key-id", "/v1/events/proxy", body,
            {**hdrs, "x-arkheia-signature": "0" * 64},
        )
    assert ei.value.code == oracle.UNKNOWN_KEY_ID


@pytest.mark.asyncio
async def test_missing_header_is_rejected(configured, respx_mock):
    """Every one of the three headers is individually load-bearing."""
    body, hdrs = await _capture_signed(respx_mock)
    for header in ("x-arkheia-key-id", "x-arkheia-timestamp", "x-arkheia-signature"):
        stripped = {k: v for k, v in hdrs.items() if k != header}
        with pytest.raises(oracle.AuthError) as ei:
            oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, stripped)
        assert ei.value.code == oracle.MISSING_HEADER


@pytest.mark.asyncio
async def test_replay_is_detected_by_the_receiver_not_the_sender(configured, respx_mock):
    """
    SCOPE, stated rather than assumed: replay defence lives ENTIRELY in the
    receiver (`NonceStore` + the +/-60s window). The sender emits no nonce; its
    only contribution is a fresh timestamp. So this pins the property we actually
    depend on: an identical captured push, replayed, is refused.
    """
    body, hdrs = await _capture_signed(respx_mock)
    store = oracle.NonceStore()

    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs, nonces=store)
    with pytest.raises(oracle.AuthError) as ei:
        oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs, nonces=store)
    assert ei.value.code == oracle.REPLAY_DETECTED

    # control: a different store has not seen it — proves the first call was not
    # rejected for some unrelated reason
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs, nonces=oracle.NonceStore())


@pytest.mark.asyncio
async def test_stale_and_future_timestamps_are_refused(configured, respx_mock):
    body, hdrs = await _capture_signed(respx_mock)
    ts = int(hdrs["x-arkheia-timestamp"])

    for now, label in ((ts + 120, "stale"), (ts - 120, "future")):
        with pytest.raises(oracle.AuthError) as ei:
            oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs, now=now)
        assert ei.value.code == oracle.REPLAY_WINDOW_EXCEEDED, label

    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", body, hdrs, now=ts)  # control


# ══════════════════════════════════════════════════════════════════════════════
# E. No unsigned fallback
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["DETECTION_ADAPTER_URL", "DETECTION_ADAPTER_HMAC_SECRET"])
async def test_unconfigured_sends_nothing_rather_than_sending_unsigned(
    configured, respx_mock, monkeypatch, missing
):
    """
    The fail-open reasoning that is right for inference would be catastrophic
    here: an unauthenticated governance record is worse than none. With the key
    (or the URL) absent, ZERO bytes leave — and the paired control in the same
    test proves the route would have fired had it been configured.
    """
    cap = Capture()
    route = respx_mock.post(ENDPOINT).mock(side_effect=cap)

    monkeypatch.setenv(missing, "")
    outcome = await _push()
    assert outcome.status == PushOutcome.SKIPPED
    assert route.call_count == 0, "an unsigned/unaddressed push left the box"

    # ── positive control: restore config, the very same call now transmits ──
    monkeypatch.setenv("DETECTION_ADAPTER_URL", URL)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    ok = await _push()
    assert ok.status == PushOutcome.DELIVERED
    assert route.call_count == 1


@pytest.mark.asyncio
async def test_secret_is_never_placed_on_the_wire(configured, respx_mock):
    """The shared secret authenticates; it is never transmitted."""
    body, hdrs = await _capture_signed(respx_mock)
    blob = body + json.dumps(hdrs).encode()
    assert SECRET.encode() not in blob
    # control: something we DO expect on the wire is present, so the search works
    assert b"acme-corp" in body


def test_no_key_material_is_derived_or_cached_on_disk():
    """
    The sibling flow found a 'machine-bound' key derived from `sha256(b"")` in a
    0644 file. Ask the same question here and pin the answer: this module's key
    comes from one env var and nowhere else — no file, no derivation, no default.
    """
    import inspect

    src = inspect.getsource(mod)
    for forbidden in ("open(", "Path(", "expanduser", "COMPUTERNAME", "HOSTNAME", "pbkdf2", "\\.cache"):
        assert forbidden not in src, f"unexpected key-material path: {forbidden!r}"
    assert src.count('os.getenv("DETECTION_ADAPTER_HMAC_SECRET"') == 1
    # control: the getenv the assertion depends on really is how the key arrives
    assert 'os.getenv("DETECTION_ADAPTER_HMAC_SECRET", "")' in src


# ══════════════════════════════════════════════════════════════════════════════
# F. Risk-band honesty across the hop
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize(
    "band, expect_risk, expect_class",
    [
        ("LOW", "LOW", "AUTHENTIC"),
        ("MEDIUM", "MEDIUM", "UNCERTAIN"),
        ("HIGH", "HIGH", "FABRICATED"),
        ("CRITICAL", "CRITICAL", "FABRICATED"),
        ("UNKNOWN", "UNKNOWN", "UNCERTAIN"),
        ("", "UNKNOWN", "UNCERTAIN"),
    ],
)
def test_an_unknown_verdict_never_reads_as_a_clean_low(band, expect_risk, expect_class):
    """
    `normalise.rs::parse_risk` maps every unrecognised band to `Low` and
    `parse_classification` maps every unrecognised class to `Authentic`. The
    pre-fix caller coerced UNKNOWN -> "LOW" before the hop, so an engine failure
    was published to the governance plane as a confident clean verdict. The band
    still flattens to Low at their end (their enum, not ours) — but the
    classification must not claim AUTHENTIC, and the raw band must survive.
    """
    body = mod.build_proxy_event("t", "gpt-4o", "mcp_detection", dict(PAYLOAD), band)
    assert body["detection"]["fabrication_risk"] == expect_risk
    assert body["detection"]["classification"] == expect_class
    assert body["context"]["risk_level_raw"] == band


def test_non_uuid_detection_id_is_mapped_deterministically():
    """
    serde types `event_id` as `Uuid`; a non-UUID id would 400 the entire push.
    Map it, and map it stably so the same detection always resolves to the same
    governance event id.
    """
    p = dict(PAYLOAD, detection_id="not-a-uuid-at-all")
    a = mod.build_proxy_event("t", "m", "e", p)["event_id"]
    b = mod.build_proxy_event("t", "m", "e", p)["event_id"]
    assert a == b
    assert str(uuid.UUID(a)) == a
    # control: a genuine UUID is passed through unchanged, not re-derived
    assert mod.build_proxy_event("t", "m", "e", dict(PAYLOAD))["event_id"] == PAYLOAD["detection_id"]


# ══════════════════════════════════════════════════════════════════════════════
# G. schedule_push actually dispatches
# ══════════════════════════════════════════════════════════════════════════════

def test_schedule_push_from_sync_context_really_pushes(configured):
    """
    The pre-existing `test_schedule_push_no_loop` patched `push_event`, recorded
    the call in a list, and then ASSERTED NOTHING — it passed on an interpreter
    where `asyncio.get_event_loop()` raises and the push silently never happened.
    Assert the transport boundary instead.
    """
    import respx

    with respx.mock:
        cap = Capture()
        route = respx.post(ENDPOINT).mock(side_effect=cap)
        result = mod.schedule_push("acme-corp", "gpt-4o", "mcp_detection", PAYLOAD)

    assert route.call_count == 1, "schedule_push dispatched nothing from sync context"
    assert isinstance(result, PushOutcome)
    assert result.status == PushOutcome.DELIVERED
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", cap.content(), cap.headers())


@pytest.mark.asyncio
async def test_schedule_push_inside_a_running_loop_returns_a_completable_task(
    configured, respx_mock
):
    cap = Capture()
    route = respx_mock.post(ENDPOINT).mock(side_effect=cap)

    task = mod.schedule_push("acme-corp", "gpt-4o", "mcp_detection", PAYLOAD)
    assert isinstance(task, asyncio.Task)
    outcome = await task

    assert route.call_count == 1
    assert outcome.status == PushOutcome.DELIVERED
    oracle.verify(SECRET.encode(), KEY_ID, "/v1/events/proxy", cap.content(), cap.headers())
