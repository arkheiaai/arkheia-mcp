"""
`receipted` axis for the governance detection-adapter push.

IS A GOVERNANCE PUSH A DECISION THAT MUST LEAVE A RECORD?
---------------------------------------------------------
Yes, and not the one it already had. `/detect/verify` already writes an audit
record of WHAT WE DECIDED. It has never written anything about WHETHER THE
GOVERNANCE PLANE WAS TOLD. Those are different facts, and only the second one
distinguishes a rail that is working from a rail that is dark — which is the
entire lesson of the proxy's Synesis ingest push failing for twenty days behind a
swallowed 400. `n/a` would be the wrong answer here: an outbound governance
report is exactly the class of decision that must be reconstructible after the
fact.

So `push_event` now writes its OUTCOME through the production `AuditWriter`, and
these tests drive that real writer and read the artifact back off disk using
`proxy/tests/_receipt_probe.py` (landed by PR #18 — reused verbatim, not
reimplemented). The probe matters because a recording stub cannot observe
redaction, hash-chaining, or the writer dropping the record entirely.
"""
from __future__ import annotations

import json
import uuid

import httpx
import pytest

import proxy.detection_adapter as mod
from proxy.detection_adapter import PushOutcome
from proxy.tests._receipt_probe import ReceiptProbe, contains

KEY_ID = "mcp-v1"
SECRET = "test-secret-32-bytes-minimum-len"
URL = "http://adapter:7070"
ENDPOINT = f"{URL}/v1/events/proxy"
DETECTION_ID = "9c1f6c2e-3a71-4a58-8b6b-2f4e7d0a11c5"

PAYLOAD = {
    "detection_id": DETECTION_ID,
    "model_id": "gpt-4o",
    "confidence": 0.42,
    "profile_version": "gpt-4o_v3.2",
}


@pytest.fixture
def configured(monkeypatch):
    monkeypatch.setenv("DETECTION_ADAPTER_URL", URL)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", KEY_ID)


@pytest.fixture
async def probe(tmp_path):
    p = ReceiptProbe(tmp_path / "audit.jsonl")
    await p.start()
    yield p
    await p.stop()


async def _push(probe, risk="MEDIUM"):
    return await mod.push_event(
        "acme-corp", "gpt-4o", "mcp_detection", PAYLOAD, risk, probe.writer
    )


async def _drain(probe):
    """The push enqueues via the production API; wait for the real loop to land it."""
    import asyncio

    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)


# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_a_delivered_push_leaves_a_receipt_tied_to_its_event(
    configured, respx_mock, probe
):
    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200, json={"ok": True}))

    outcome = await _push(probe)
    await _drain(probe)

    assert outcome.status == PushOutcome.DELIVERED

    row = probe.require(outcome.event_id)          # raises, naming what WAS on disk
    assert row["delivery_status"] == PushOutcome.DELIVERED
    assert row["http_status"] == 200
    assert row["error"] is None
    assert row["source"] == "governance_push"
    assert row["event_type"] == "governance_detection_push"
    assert row["signed"] is True
    # The TARGET, not the base URL. A receipt holding the un-composed base cannot
    # answer the only question a misroute raises — what address did this attempt
    # use? — and a trailing slash in DETECTION_ADAPTER_URL used to make base and
    # target differ by a lost push.
    assert row["adapter_url"] == ENDPOINT
    assert row["key_id"] == KEY_ID
    assert row["model_id"] == "gpt-4o"
    assert row["risk_level"] == "MEDIUM"

    # ── vacuity guard: the lookup is by id, not "the only row on disk" ──
    assert probe.find(str(uuid.uuid4())) is None

    # ── tamper-evidence: the row on disk reproduces its own chain hash ──
    assert probe.recompute_this_hash(row) == row["this_hash"]
    chain = probe.verify_chain()
    assert chain["ok"] is True
    # ... and it verified something. A chain walk over zero records also reports
    # ok=True; "the gate must fail when it measures nothing" (DONE.md floor 9).
    assert chain["verified"] == 1
    assert chain["breaks"] == []


@pytest.mark.asyncio
async def test_a_REJECTED_push_leaves_a_receipt_that_records_the_rejection(
    configured, respx_mock, probe
):
    """
    The axis's real point. A receipt that only ever records successes is a rail
    that looks healthy while it is dark — the failure is the fact worth keeping.
    """
    respx_mock.post(ENDPOINT).mock(
        return_value=httpx.Response(
            401, text=json.dumps({"error": {"code": "INVALID_SIGNATURE"}})
        )
    )

    outcome = await _push(probe)
    await _drain(probe)

    assert outcome.status == PushOutcome.REJECTED

    row = probe.require(outcome.event_id)
    assert row["delivery_status"] == PushOutcome.REJECTED
    assert row["http_status"] == 401
    assert "INVALID_SIGNATURE" in row["error"]
    # the failure is on disk, in the bytes, not merely in a log line
    assert contains(probe.raw_bytes(), "INVALID_SIGNATURE")


@pytest.mark.asyncio
async def test_a_push_that_never_arrived_leaves_a_receipt(configured, respx_mock, probe):
    respx_mock.post(ENDPOINT).mock(side_effect=httpx.ConnectError("connection refused"))

    outcome = await _push(probe)
    await _drain(probe)

    assert outcome.status == PushOutcome.FAILED
    row = probe.require(outcome.event_id)
    assert row["delivery_status"] == PushOutcome.FAILED
    assert row["http_status"] is None
    assert "ConnectError" in row["error"]


@pytest.mark.asyncio
async def test_delivered_and_rejected_are_distinguishable_on_disk(
    configured, respx_mock, probe
):
    """
    Two pushes, two outcomes, one log. If the receipt could not tell them apart
    the record would be worthless — this is the assertion that stops
    `delivery_status` becoming a constant.
    """
    other_id = "1a2b3c4d-5e6f-4071-8899-aabbccddeeff"

    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200))
    ok = await mod.push_event(
        "acme-corp", "gpt-4o", "mcp_detection", PAYLOAD, "LOW", probe.writer
    )
    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(400, text="bad body"))
    bad = await mod.push_event(
        "acme-corp", "gpt-4o", "mcp_detection",
        dict(PAYLOAD, detection_id=other_id), "HIGH", probe.writer,
    )
    await _drain(probe)

    assert len(probe.rows()) == 2
    assert probe.require(ok.event_id)["delivery_status"] == PushOutcome.DELIVERED
    assert probe.require(ok.event_id)["http_status"] == 200
    assert probe.require(bad.event_id)["delivery_status"] == PushOutcome.REJECTED
    assert probe.require(bad.event_id)["http_status"] == 400
    assert bad.status == PushOutcome.REJECTED


@pytest.mark.asyncio
async def test_two_attempts_at_the_same_detection_are_separately_receipted(
    configured, respx_mock, probe
):
    """
    `detection_id` correlates a receipt to a decision; it does NOT identify the
    attempt. A retry must not produce two records a reader cannot tell apart —
    caught by `_receipt_probe.find()`, whose uniqueness assertion fired on the
    first draft of this suite.
    """
    respx_mock.post(ENDPOINT).mock(side_effect=httpx.ConnectError("refused"))
    first = await _push(probe)
    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200))
    second = await _push(probe)
    await _drain(probe)

    rows = probe.rows()
    assert len(rows) == 2
    assert first.event_id == second.event_id, "same detection, so same correlation id"
    assert rows[0]["detection_id"] == rows[1]["detection_id"] == first.event_id
    assert rows[0]["push_id"] != rows[1]["push_id"], "attempts are indistinguishable"
    assert [r["delivery_status"] for r in rows] == [PushOutcome.FAILED, PushOutcome.DELIVERED]


@pytest.mark.asyncio
async def test_an_unconfigured_push_writes_no_receipt_because_nothing_happened(
    configured, respx_mock, probe, monkeypatch
):
    """
    Absence assertion, paired with its control: with no secret there is no push
    and therefore no receipt; restore the secret and the very same call produces
    exactly one.
    """
    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200))
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "")

    outcome = await _push(probe)
    await _drain(probe)
    assert outcome.status == PushOutcome.SKIPPED
    assert probe.rows() == []

    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    await _push(probe)
    await _drain(probe)
    assert len(probe.rows()) == 1


@pytest.mark.asyncio
async def test_the_receipt_never_contains_the_signing_secret(configured, respx_mock, probe):
    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200))
    await _push(probe)
    await _drain(probe)

    raw = probe.raw_bytes()
    assert not contains(raw, SECRET)
    # control: the fields we DO expect are on disk, so the search is aimed right
    assert contains(raw, URL)
    assert contains(raw, KEY_ID)


@pytest.mark.asyncio
async def test_receipt_failure_is_itself_logged_not_swallowed(configured, respx_mock, caplog):
    """
    The last silence to close: if the receipt write blows up, the push must not
    pretend it was recorded.
    """
    import logging

    respx_mock.post(ENDPOINT).mock(return_value=httpx.Response(200))

    class ExplodingAudit:
        async def write(self, record):
            raise RuntimeError("disk full")

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await mod.push_event(
            "acme-corp", "gpt-4o", "mcp_detection", PAYLOAD, "LOW", ExplodingAudit()
        )

    assert outcome.status == PushOutcome.DELIVERED  # the push itself did land
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert mod.FAILURE_MARKER in errors[0]
    assert "disk full" in errors[0]
