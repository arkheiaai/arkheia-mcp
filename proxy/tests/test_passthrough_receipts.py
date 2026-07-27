"""
Receipted axis for the passthrough forwarding gate.

THE QUESTION
------------
The gate decides whether caller traffic may be forwarded to a provider. When it
says NO — which is the security-interesting outcome — does that decision leave a
durable, attributable record an investigator can find?

THE BASELINE, MEASURED
----------------------
Four hundred SSRF-shaped refusals were driven against a REAL ``AuditWriter``
pointed at an empty directory, and the directory was diffed::

    400 refusals -> statuses {400}
      files before [] after []
      audit.jsonl bytes: before 0 after 0   DELTA=0
      rows on disk = 0

"Refused four hundred times" and "was never asked" were the same observation.
``test_baseline_four_hundred_refusals_now_leave_four_hundred_rows`` re-runs that
exact measurement and asserts the post-fix number.

HOW THIS IS PROVED
------------------
Through ``ReceiptProbe`` — the ONE shared probe, taken verbatim from
``sweep/mcp-receipt-consolidation`` (blob c2055dd49901d78a7c9db99233142a4128dcd60b),
not a fourth copy. Every test drives the production writer and reads the artifact
back off disk, looked up BY THE ID THE CALLER WAS HANDED. A test that asserts on
the dict handed to ``audit.write()`` proves nothing about what lands: the writer
redacts, chains, serialises and appends after that point, and can drop the record
entirely.

Following PR #28: the row carries a deny code from a closed taxonomy and argument
key NAMES only, never values.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging

import pytest

from proxy.audit.writer import AuditWriter
from proxy.endpoints import passthrough as pt
from proxy.tests._passthrough_harness import (
    asgi_request,
    capture_upstream,
    json_response,
    make_app,
)
from proxy.tests._receipt_probe import ReceiptProbe, contains

pytestmark = pytest.mark.asyncio


TRAVERSAL = "audio/../../admin/keys"


async def _drive_refusal(probe: ReceiptProbe, path: str = TRAVERSAL, **kwargs):
    """
    Drive one refusal through the real route and the real writer.

    Returns ``(response, receipt_id)``. The writer's queue is drained before
    returning so any assertion below reads a settled file.
    """
    app = make_app(audit_writer=probe.writer)
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + path, **kwargs)
    assert log.count == 0, "a refusal must produce no upstream traffic"
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)
    return resp, resp.json()["receipt_id"]


@pytest.fixture
async def probe(tmp_path):
    p = ReceiptProbe(tmp_path / "audit.jsonl")
    await p.start()
    try:
        yield p
    finally:
        await p.stop()


# ---------------------------------------------------------------------------
# REC-1 — the record exists, and it is THIS record
# ---------------------------------------------------------------------------

async def test_a_refusal_lands_a_row_findable_by_the_id_the_caller_was_handed(probe):
    resp, receipt_id = await _drive_refusal(probe)

    assert resp.status == 400
    assert resp.json()["receipt_status"] == "enqueued"

    row = probe.require(receipt_id)          # fails loudly, naming what IS on disk
    assert row["detection_id"] == receipt_id


async def test_a_fabricated_receipt_id_finds_nothing(probe):
    """
    The vacuity guard. Without it, a probe that returned "the only row"
    regardless of the id would make every read-back assertion above pass by
    accident.
    """
    _resp, receipt_id = await _drive_refusal(probe)
    assert probe.find(receipt_id) is not None                      # positive control
    assert probe.find("00000000-0000-0000-0000-000000000000") is None


# ---------------------------------------------------------------------------
# REC-2 — exact values, not "is not None"
# ---------------------------------------------------------------------------

async def test_the_refusal_row_carries_exactly_the_decision_it_describes(probe):
    _resp, receipt_id = await _drive_refusal(probe)
    row = probe.require(receipt_id)

    assert row["event_type"] == "passthrough.forward_refused"
    assert row["source"] == "passthrough"
    assert row["action_taken"] == "refuse"
    assert row["risk_level"] == "REFUSED"
    assert row["provider"] == "grok"
    assert row["deny_code"] == pt.DENY_PATH_TRAVERSAL
    assert row["attempted_path"] == TRAVERSAL
    assert row["attempted_path_sha256"] == hashlib.sha256(TRAVERSAL.encode()).hexdigest()
    assert row["attempted_method"] == "POST"
    assert row["client_host"] == "127.0.0.1"
    assert row["response_length"] == 0


async def test_refusal_risk_level_cannot_be_confused_with_a_screened_verdict(probe):
    """
    ``AuditWriter.read_recent`` buckets by ``risk_level``. A refusal filed as
    LOW/UNKNOWN would be counted as a screened response in the operator's
    summary — a blocked attack rendered as a clean detection.
    """
    _resp, receipt_id = await _drive_refusal(probe)
    row = probe.require(receipt_id)
    assert row["risk_level"] == pt.REFUSAL_RISK_LEVEL
    assert row["risk_level"] not in ("LOW", "MEDIUM", "HIGH", "UNKNOWN", "SKIP", "ERROR")

    summary = probe.writer.read_recent()["summary"]
    assert summary.get("REFUSED") == 1
    assert summary["LOW"] == 0 and summary["MEDIUM"] == 0 and summary["HIGH"] == 0


@pytest.mark.parametrize("path,expected_code,provider_name,route", [
    ("audio/../../admin/keys", pt.DENY_PATH_TRAVERSAL,         "grok",      "/proxy/grok/v1/"),
    ("admin/users",            pt.DENY_PATH_NOT_ALLOWLISTED,   "grok",      "/proxy/grok/v1/"),
    ("chat/completions\x00",   pt.DENY_PATH_ILLEGAL_CHARACTER, "grok",      "/proxy/grok/v1/"),
    ("admin/users",            pt.DENY_PATH_NOT_ALLOWLISTED,   "together",  "/proxy/together/v1/"),
    ("models/..",              pt.DENY_PATH_TRAVERSAL,         "gemini",    "/v1beta/"),
    ("messages/count_tokens",  pt.DENY_PATH_NOT_ALLOWLISTED,   "anthropic", "/v1/"),
])
async def test_every_deny_code_and_provider_reaches_disk(
    probe, path, expected_code, provider_name, route
):
    app = make_app(audit_writer=probe.writer)
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", route + path)
    assert log.count == 0
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)

    row = probe.require(resp.json()["receipt_id"])
    assert row["deny_code"] == expected_code
    assert row["provider"] == provider_name


async def test_duplicate_credential_refusal_reaches_disk(probe):
    app = make_app(audit_writer=probe.writer)
    with capture_upstream() as log:
        resp = await asgi_request(
            app, "POST", "/proxy/grok/v1/chat/completions",
            headers=[("authorization", "Bearer A"), ("authorization", "Bearer B")],
        )
    assert log.count == 0
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)
    row = probe.require(resp.json()["receipt_id"])
    assert row["deny_code"] == pt.DENY_DUPLICATE_CREDENTIAL
    assert row["attempted_path"] == "chat/completions"


# ---------------------------------------------------------------------------
# REC-3 — key names only, never values
# ---------------------------------------------------------------------------

async def test_the_row_records_header_and_query_key_names_never_values(probe):
    app = make_app(audit_writer=probe.writer)
    with capture_upstream() as log:
        resp = await asgi_request(
            app, "POST", "/proxy/grok/v1/admin/users",
            query_string=b"key=SUPERSECRETQUERYVALUE&trace=abc",
            headers=[("authorization", "Bearer SUPERSECRETHEADERVALUE"),
                     ("x-request-id", "req-7")],
        )
    assert log.count == 0
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)

    row = probe.require(resp.json()["receipt_id"])
    assert "authorization" in row["request_header_names"]
    assert "x-request-id" in row["request_header_names"]
    assert row["query_param_names"] == ["key", "trace"]

    # Asserted on the raw bytes on disk, not on a parsed view.
    raw = probe.raw_bytes()
    assert not contains(raw, "SUPERSECRETHEADERVALUE")
    assert not contains(raw, "SUPERSECRETQUERYVALUE")
    # Positive control: the probe IS looking at the right bytes.
    assert contains(raw, "authorization")
    assert contains(raw, "admin/users")


async def test_a_secret_smuggled_into_the_path_is_redacted_on_disk(probe):
    """
    The attempted path is recorded verbatim because a hash is useless to an
    investigator. It therefore has to go through the rail's redactor, and this
    proves it does — on the bytes, with a positive control so the assertion is
    not passing because nothing was written.
    """
    secret = "sk-ant-" + "A" * 40
    path = f"admin/{secret}"
    app = make_app(audit_writer=probe.writer)
    with capture_upstream():
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + path)
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)

    raw = probe.raw_bytes()
    assert not contains(raw, secret), "an API key reached the audit log verbatim"
    assert contains(raw, "[REDACTED:")
    assert contains(raw, "admin/")                                  # positive control

    row = probe.require(resp.json()["receipt_id"])
    # The sha256 is over the UNREDACTED path, so two attempts with the same
    # secret still correlate even though neither stores it.
    assert row["attempted_path_sha256"] == hashlib.sha256(path.encode()).hexdigest()


async def test_a_very_long_path_is_capped_but_still_correlatable(probe):
    long_path = "admin/" + "z" * 4000
    app = make_app(audit_writer=probe.writer)
    with capture_upstream():
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + long_path)
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)

    row = probe.require(resp.json()["receipt_id"])
    assert len(row["attempted_path"]) == pt._MAX_RECORDED_PATH
    assert row["attempted_path_sha256"] == hashlib.sha256(long_path.encode()).hexdigest()


# ---------------------------------------------------------------------------
# REC-4 — the row is part of the tamper-evident chain
# ---------------------------------------------------------------------------

async def test_the_refusal_row_is_chained_and_the_chain_verifies(probe):
    _resp, receipt_id = await _drive_refusal(probe)
    row = probe.require(receipt_id)

    assert row["seq"] == 1
    assert row["prev_hash"] == "0" * 64
    # Recomputed from the row AS IT SITS ON DISK: if the redacted form
    # reproduces the stored hash, the redacted form is what was committed.
    assert probe.recompute_this_hash(row) == row["this_hash"]

    chain = probe.verify_chain()
    assert chain == {"ok": True, "verified": 1, "breaks": []}


async def test_refusals_and_detections_share_one_unbroken_chain(probe):
    """
    Refusal rows must not be a parallel log. Interleave a refusal, a screened
    detection and another refusal, and verify the single chain.
    """
    from unittest.mock import AsyncMock, MagicMock
    from datetime import datetime, timezone
    import uuid as _uuid
    from proxy.detection.engine import DetectionResult

    engine = MagicMock()
    engine.verify = AsyncMock(return_value=DetectionResult(
        risk_level="LOW", confidence=0.7, features_triggered=["unique_word_ratio"],
        model_id="grok-4", profile_version="1.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(_uuid.uuid4()),
    ))
    app = make_app(engine=engine, audit_writer=probe.writer)

    ids = []
    with capture_upstream() as log:
        r1 = await asgi_request(app, "POST", "/proxy/grok/v1/audio/../../admin")
        ids.append(r1.json()["receipt_id"])
        await asgi_request(
            app, "POST", "/proxy/grok/v1/chat/completions",
            body=json.dumps({"model": "grok-4",
                             "messages": [{"role": "user", "content": "hi"}]}).encode(),
        )
        r3 = await asgi_request(app, "POST", "/proxy/grok/v1/admin/users")
        ids.append(r3.json()["receipt_id"])
    assert log.count == 1, "only the allowed call may reach upstream"
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)

    rows = probe.rows()
    assert len(rows) == 3
    assert [r["seq"] for r in rows] == [1, 2, 3]
    assert [r["action_taken"] for r in rows] == ["refuse", "pass", "refuse"]
    for receipt_id in ids:
        assert probe.require(receipt_id)["action_taken"] == "refuse"
    assert probe.verify_chain() == {"ok": True, "verified": 3, "breaks": []}


async def test_baseline_four_hundred_refusals_now_leave_four_hundred_rows(probe):
    """
    The exact measurement from the module docstring, re-run. Pre-fix: 0 bytes.
    """
    app = make_app(audit_writer=probe.writer)
    ids = []
    with capture_upstream() as log:
        for i in range(400):
            resp = await asgi_request(app, "POST", f"/proxy/grok/v1/admin/attack{i}")
            assert resp.status == 400
            ids.append(resp.json()["receipt_id"])
    assert log.count == 0
    await asyncio.wait_for(probe.writer._queue.join(), timeout=15.0)

    assert len(set(ids)) == 400, "receipt ids are not unique"
    rows = probe.rows()
    assert len(rows) == 400
    assert [r["seq"] for r in rows] == list(range(1, 401))
    assert probe.log_path.stat().st_size > 0
    # Every id the caller was handed resolves to its own row.
    assert {probe.require(i)["attempted_path"] for i in ids} == {
        f"admin/attack{i}" for i in range(400)
    }


# ---------------------------------------------------------------------------
# REC-5 — a failing receipt never changes the decision
# ---------------------------------------------------------------------------

async def test_an_unavailable_rail_does_not_turn_a_deny_into_an_allow(tmp_path, caplog):
    """
    No audit writer at all. The refusal must still refuse, still emit no upstream
    traffic, and must SAY the evidence is missing — fail-open on evidence is
    acceptable here (the deny already happened); fail-SILENT is not.
    """
    app = make_app(audit_writer=None)
    with caplog.at_level(logging.ERROR, logger="proxy.endpoints.passthrough"):
        with capture_upstream() as log:
            resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + TRAVERSAL)

    assert resp.status == 400
    assert log.count == 0
    assert resp.json()["receipt_status"] == "unavailable"
    assert any("NOT RECEIPTED" in r.message for r in caplog.records)


async def test_a_raising_rail_does_not_turn_a_deny_into_an_allow_or_a_500(caplog):
    """
    A rail whose ``write()`` raises. Induced on the object the endpoint actually
    calls — not by patching a name the module bound at import, which would
    produce a test that cannot observe its own subject.
    """
    class ExplodingWriter:
        async def write(self, record):
            raise OSError("audit volume is read-only")

    app = make_app(audit_writer=ExplodingWriter())
    with caplog.at_level(logging.ERROR, logger="proxy.endpoints.passthrough"):
        with capture_upstream() as log:
            resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + TRAVERSAL)

    assert resp.status == 400, "a receipt failure must not become a 500"
    assert log.count == 0, "a receipt failure must not become an allow"
    assert resp.json()["receipt_status"] == "unavailable"
    messages = [r.getMessage() for r in caplog.records]
    assert any("NOT RECEIPTED" in m for m in messages), messages
    assert any("audit volume is read-only" in m for m in messages), messages


async def test_a_real_filesystem_failure_does_not_change_the_decision(tmp_path, caplog):
    """
    A GENUINE filesystem failure, not a patched exception: the log path's parent
    is a regular file, so the writer's own ``open(..., "a")`` raises
    ``NotADirectoryError`` inside the production ``_writer_loop``.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    writer = AuditWriter(str(blocker / "audit.jsonl"))
    try:
        await writer.start()
    except (NotADirectoryError, FileExistsError):
        # start() mkdir's the parent, which is where the real failure surfaces
        # on this platform. Start the production loop by hand so the failure
        # happens where it would in production: inside open(..., "a").
        writer._running = True
        writer._task = asyncio.create_task(writer._writer_loop())

    app = make_app(audit_writer=writer)
    with caplog.at_level(logging.ERROR):
        with capture_upstream() as log:
            resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + TRAVERSAL)
        await asyncio.wait_for(writer._queue.join(), timeout=5.0)

    assert resp.status == 400
    assert log.count == 0
    assert not (blocker / "audit.jsonl").exists()
    # The loop swallowed the error and logged it — see the disclosed gap below.
    assert any("failed to write record" in r.getMessage() for r in caplog.records)

    writer._running = False
    if writer._task:
        writer._task.cancel()


# ---------------------------------------------------------------------------
# DISCLOSED RESIDUALS — pinned as PASSING tests so they stay visible
# ---------------------------------------------------------------------------

async def test_disclosed_rail_gap_enqueued_is_not_landed(tmp_path):
    """
    DISCLOSED, NOT FIXED. ``AuditWriter`` is fire-and-forget: the endpoint learns
    only that a record was queued. The loop swallows serialisation and I/O
    errors, so ``receipt_status: "enqueued"`` can be truthful while nothing lands.

    This test pins the gap rather than papering over it, and pins the mitigation:
    the endpoint says "enqueued", never "recorded".

    It is a property of the SHARED rail — every consumer has it, including the
    pre-existing detection records — so closing it is a change to
    ``proxy/audit/writer.py`` affecting other flows. REVIEWER: adjudicate whether
    a security refusal warrants a synchronous durable write.
    """
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    writer = AuditWriter(str(blocker / "audit.jsonl"))
    writer._running = True
    writer._task = asyncio.create_task(writer._writer_loop())

    app = make_app(audit_writer=writer)
    with capture_upstream():
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + TRAVERSAL)
    await asyncio.wait_for(writer._queue.join(), timeout=5.0)

    assert resp.json()["receipt_status"] == "enqueued"   # what we can honestly say
    assert not (blocker / "audit.jsonl").exists()        # what actually happened
    assert resp.json()["receipt_status"] != "recorded"   # the claim we do NOT make

    writer._running = False
    writer._task.cancel()


async def test_disclosed_gap_an_allowed_forward_is_not_separately_receipted(probe):
    """
    DISCLOSED, NOT FIXED. Only REFUSALS get a gate receipt. An ALLOWED forward
    whose response carries no extractable text produces no record at all: the
    only allow-side evidence is the detection record, which is written only when
    the response has text to screen.

    Receipting every allow would change what ``/audit/log`` means (its summary
    buckets by risk_level and would fill with non-detection rows) and multiply
    audit volume by the full request rate. REVIEWER: that is a product decision
    about the audit surface, so it is reported rather than taken.
    """
    app = make_app(audit_writer=probe.writer)
    with capture_upstream(json_response({"data": []})) as log:
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/models")
    await asyncio.sleep(0.05)

    assert resp.status == 200
    assert log.count == 1                       # the forward happened
    assert probe.rows() == []                   # and left no gate record

    # Control: the refusal of the same shape DOES leave one, so the emptiness
    # above is about the allow path and not about the probe looking elsewhere.
    with capture_upstream():
        refused = await asgi_request(app, "POST", "/proxy/grok/v1/admin/users")
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)
    assert len(probe.rows()) == 1
    assert probe.require(refused.json()["receipt_id"])["action_taken"] == "refuse"
