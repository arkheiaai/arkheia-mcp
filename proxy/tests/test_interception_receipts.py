"""
F10 — receipted axis: does a BLOCK leave a durable, attributable record?

A block is the most consequential thing this middleware does: it withholds an
answer a customer paid for. If that decision leaves no evidence, nobody can
investigate it, nobody can contest it, and "the proxy blocked my request" is an
unanswerable support ticket.

MEASURED, NOT READ. Every assertion here runs against the REAL rail —
``proxy.audit.writer.AuditWriter`` — through ``proxy/tests/_receipt_probe.py``
(taken verbatim from ``sweep/mcp-receipt-consolidation``, blob
``c2055dd49901d78a7c9db99233142a4128dcd60b``), and reads the artifact back off
disk. No recording stub: a stub cannot observe redaction, chaining, or the
writer silently dropping the record, all of which happen after the caller's
``write()`` returns.
"""
from __future__ import annotations

import json

import httpx
import pytest

from proxy.audit.writer import AuditWriter
from proxy.tests._receipt_probe import ReceiptProbe, contains
from proxy.tests.test_interception_correctness import REQ, UPSTREAM_BODY, build, client

#: The complete set of decisions this flow may record. A record carrying
#: anything else means a new decision path landed without being classified.
ACTION_TAXONOMY = {"block", "warn", "pass", "refused", "unavailable", "error"}


async def drive(risk="HIGH", action="block", n=1, tmp_path=None,
                gate_action="block", **kw):
    """
    Drive N requests through the middleware with a LIVE AuditWriter attached,
    and hand back the probe plus the responses.

    ``gate_action`` defaults to ``"block"`` — the profile-EARNED gate — because
    a hard block is now authorised only by that signal. Passing ``"advise"``
    here drives the downgrade path instead.
    """
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(str(log))
    await writer.start()
    try:
        app, eng = build(risk=risk, action=action, audit=writer,
                         gate_action=gate_action, **kw)
        responses = []
        async with client(app) as c:
            for _ in range(n):
                responses.append(await c.post("/v1/chat/completions", json=REQ))
    finally:
        await writer.stop()
    return ReceiptProbe(log), responses


# ---------------------------------------------------------------------------
# The directory diff — "refused N times" and "was never asked" look identical
# ---------------------------------------------------------------------------

class TestBlockLeavesEvidence:

    async def test_a_hundred_blocks_leave_a_hundred_rows(self, tmp_path):
        """
        The pre-fix state wrote nothing at all: the middleware has no audit
        call site. One hundred withheld answers produced an empty directory.
        """
        before = sorted(p.name for p in tmp_path.iterdir())
        probe, responses = await drive(n=100, tmp_path=tmp_path)
        after = sorted(p.name for p in tmp_path.iterdir())

        assert all(b"arkheia_blocked" in r.content for r in responses), (
            "the run did not actually block, so the receipt count proves nothing"
        )
        assert before == [] and after == ["audit.jsonl"], (
            f"100 blocks changed the evidence directory from {before} to {after}"
        )
        assert len(probe.rows()) == 100

    async def test_each_block_is_found_by_the_id_the_caller_was_handed(self, tmp_path):
        """
        Looking up "the record on disk" passes even when the id the caller holds
        has nothing to do with the row that landed. The lookup must be BY the
        surfaced id.
        """
        probe, responses = await drive(n=5, tmp_path=tmp_path)
        for r in responses:
            surfaced = r.headers["x-arkheia-detection-id"]
            row = probe.require(surfaced)
            assert row["action_taken"] == "block"
            assert row["risk_level"] == "HIGH"

    async def test_a_fabricated_id_finds_nothing(self, tmp_path):
        """Vacuity guard: without this, ``require()`` could be returning any row."""
        probe, _ = await drive(n=3, tmp_path=tmp_path)
        assert probe.find("00000000-0000-0000-0000-000000000000") is None
        assert len(probe.rows()) == 3          # positive control: rows do exist


# ---------------------------------------------------------------------------
# What the record says
# ---------------------------------------------------------------------------

class TestRecordContent:

    async def test_action_taken_comes_from_a_closed_taxonomy(self, tmp_path):
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        for row in probe.rows():
            assert row["action_taken"] in ACTION_TAXONOMY, (
                f"unclassified decision {row['action_taken']!r}"
            )

    async def test_risk_level_does_not_understate_a_block(self, tmp_path):
        """
        ``/audit/log`` buckets its summary by ``risk_level``. A blocked HIGH
        recorded as anything softer would let a withheld answer be counted as a
        screened-clean one.
        """
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        assert probe.rows()[0]["risk_level"] == "HIGH"

    async def test_the_record_names_the_path_that_was_blocked(self, tmp_path):
        """An investigator needs the surface, not only the verdict."""
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        assert probe.rows()[0]["path"] == "/v1/chat/completions"

    async def test_the_record_identifies_the_enforcing_component(self, tmp_path):
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        assert probe.rows()[0]["source"] == "interception"

    async def test_prompt_and_response_text_never_reach_the_evidence_file(
        self, tmp_path
    ):
        """
        Asserted on the RAW on-disk bytes, not a parsed view — and paired with a
        positive control below, so "not found" cannot mean "looked in the wrong
        file".
        """
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        raw = probe.raw_bytes()
        assert not contains(raw, "THE-MODEL-ANSWER"), "response text on disk"
        assert not contains(raw, "hi ") and b'"prompt":' not in raw

    async def test_positive_control_the_hashes_are_on_disk(self, tmp_path):
        """The same bytes DO carry the hashes, so the probe was reading them."""
        import hashlib
        probe, _ = await drive(n=1, tmp_path=tmp_path)
        raw = probe.raw_bytes()
        assert contains(raw, hashlib.sha256(UPSTREAM_BODY).hexdigest())
        assert contains(raw, hashlib.sha256(b"hi").hexdigest())

    async def test_a_secret_in_the_prompt_is_redacted_by_the_rail(self, tmp_path):
        """
        Proves the record went through the production redactor rather than
        being hand-scrubbed at the call site.
        """
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(str(log))
        await writer.start()
        try:
            app, _ = build(risk="HIGH", action="block", gate_action="block",
                           audit=writer)
            async with client(app) as c:
                await c.post("/v1/chat/completions", json={
                    "model": "gpt-4o",
                    "messages": [{"role": "user", "content": "x"}],
                }, headers={"authorization": "Bearer sk-ant-SUPERSECRETVALUE123456"})
        finally:
            await writer.stop()
        probe = ReceiptProbe(log)
        assert not contains(probe.raw_bytes(), "sk-ant-SUPERSECRETVALUE123456")


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------

class TestChain:

    async def test_the_row_reproduces_its_own_chain_hash_as_it_sits_on_disk(
        self, tmp_path
    ):
        probe, _ = await drive(n=3, tmp_path=tmp_path)
        for row in probe.rows():
            assert probe.recompute_this_hash(row) == row["this_hash"]

    async def test_the_production_verifier_accepts_the_chain(self, tmp_path):
        probe, _ = await drive(n=3, tmp_path=tmp_path)
        result = probe.verify_chain()
        assert result["ok"] is True
        assert result["verified"] == 3


# ---------------------------------------------------------------------------
# Honesty about what the rail can promise
# ---------------------------------------------------------------------------

class TestStatusDoesNotOverclaim:

    async def test_the_caller_is_told_enqueued_not_recorded(self, tmp_path):
        """
        ``AuditWriter.write()`` can report queue saturation, but
        ``_writer_loop`` still swallows every later I/O error, so the endpoint
        cannot truthfully say a record LANDED. It says ``enqueued`` for the
        accepted-queue case, which is the most it can support. (Same correction
        PR #31 made on the sibling flow.)
        """
        probe, responses = await drive(n=1, tmp_path=tmp_path)
        assert json.loads(responses[0].content)["receipt"] == "enqueued"

    async def test_the_status_is_derived_from_the_call_not_asserted(self, tmp_path):
        """
        The same block, driven twice against the SAME code path, must produce
        two different statuses — because two different things happened. A
        hard-coded literal cannot do that, and that is the whole defect: the
        word was chosen carefully and then written where nothing had happened.
        """
        _, with_rail = await drive(n=1, tmp_path=tmp_path)
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            without_rail = await c.post("/v1/chat/completions", json=REQ)

        assert json.loads(with_rail[0].content)["receipt"] == "enqueued"
        assert json.loads(without_rail.content)["receipt"] == "no_audit_writer"

    async def test_a_full_queue_reports_queue_full_and_does_not_overclaim(
        self, tmp_path
    ):
        """
        Queue saturation is a visible receipt status, not a delivered claim.

        On a genuinely saturated rail — no monkeypatch, no stand-in, the
        shipped class with its real 10,000-slot queue filled — the caller is
        told ``queue_full`` for a record that was dropped before the background
        writer could ever see it.

        The writer's drain loop is deliberately NOT started, so the saturation
        is a fact for the whole test rather than a race against a drainer — the
        first draft of this test raced and said so, which is why it says this.
        """
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(str(log))

        n = 0
        while True:                            # saturate the REAL queue
            try:
                writer._queue.put_nowait({"detection_id": f"filler-{n}"})
            except Exception:
                break
            n += 1
        assert n >= 1000, f"the queue accepted only {n} records; wrong premise"

        # No monkeypatch: this is the production method on a saturated queue.
        assert await writer.write({
            "detection_id": "dropped-on-the-floor",
        }) == "queue_full"

        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       audit=writer)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        surfaced = r.headers["x-arkheia-detection-id"]
        assert json.loads(r.content)["receipt"] == "queue_full"
        assert ReceiptProbe(log).find(surfaced) is None, (
            "the record landed after all — the premise of this gap is wrong"
        )

    async def test_a_real_filesystem_failure_does_not_break_the_block(self, tmp_path):
        """
        The gap the wording admits to, pinned with a GENUINE filesystem failure
        — the log path is a DIRECTORY, so every ``open(..., "a")`` inside the
        production writer loop raises ``IsADirectoryError`` — not a
        monkeypatched exception.

        A receipt failure must never turn into a served fabrication: the block
        still holds, and the honest thing is that no row lands.
        """
        log = tmp_path / "audit.jsonl"
        log.mkdir()
        writer = AuditWriter(str(log))
        await writer.start()
        try:
            app, _ = build(risk="HIGH", action="block", gate_action="block",
                           audit=writer)
            async with client(app) as c:
                r = await c.post("/v1/chat/completions", json=REQ)
        finally:
            try:
                await writer.stop()
            except Exception:
                pass
        assert b"arkheia_blocked" in r.content, (
            "a failed audit write suppressed the block — the halt must not "
            "depend on the receipt landing"
        )
        assert log.is_dir() and list(log.iterdir()) == []


# ---------------------------------------------------------------------------
# What is NOT receipted, pinned so the gap stays visible
# ---------------------------------------------------------------------------

class TestScopeOfReceipting:

    async def test_a_low_risk_pass_through_is_not_receipted_here(self, tmp_path):
        """
        CURRENT BEHAVIOUR, PINNED. Receipting every allowed request would
        multiply audit volume by the full request rate and change what
        ``/audit/log``'s summary means. ``/detect/verify`` already receipts
        every scored triple on its own path. Whether the transport path should
        too is a product decision — REPORTED, not taken.
        """
        probe, responses = await drive(risk="LOW", action="block", n=3,
                                       tmp_path=tmp_path)
        assert all(r.headers["x-arkheia-risk"] == "LOW" for r in responses)
        assert probe.rows() == []

    async def test_a_warn_is_receipted(self, tmp_path):
        """
        A warn is a governed verdict the customer acts on, so it leaves a
        record even though the answer is delivered.
        """
        probe, responses = await drive(risk="HIGH", action="warn", n=2,
                                       tmp_path=tmp_path)
        rows = probe.rows()
        assert len(rows) == 2
        assert {r["action_taken"] for r in rows} == {"warn"}
        for r in responses:
            probe.require(r.headers["x-arkheia-detection-id"])


# ---------------------------------------------------------------------------
# Refusals leave evidence too
# ---------------------------------------------------------------------------

class TestRefusalReceipts:
    """
    A refusal is an adverse verdict against a caller who may be entirely
    legitimate. Without a record, "the proxy refused me" is unanswerable — and
    without the DENY CODE on that record, it is unanswerable even with one.

    Driven by configuring a ``file://`` upstream, which is refused on the
    config before any client exists, so no path normalisation by the test
    client can interfere.
    """

    async def _drive_refusal(self, tmp_path, n=1):
        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(str(log))
        await writer.start()
        try:
            app, _ = build(risk="LOW", audit=writer,
                           upstream_url="file:///etc/passwd")
            responses = []
            async with client(app) as c:
                for _ in range(n):
                    responses.append(await c.post("/v1/chat/completions", json=REQ))
        finally:
            await writer.stop()
        return ReceiptProbe(log), responses

    async def test_the_refusal_is_recorded_with_its_deny_code(self, tmp_path):
        probe, responses = await self._drive_refusal(tmp_path)
        payload = json.loads(responses[0].content)
        assert payload["deny_code"] == "upstream_scheme_not_allowed"
        row = probe.require(payload["detection_id"])
        assert row["deny_code"] == "upstream_scheme_not_allowed", (
            "a refusal record with no deny code cannot be triaged"
        )
        assert row["action_taken"] == "refused"
        assert row["reason"]

    async def test_a_refusal_is_not_counted_as_a_screened_request(self, tmp_path):
        """
        ``/audit/log`` buckets by ``risk_level``. A refusal filed as LOW would
        be counted in the summary as a request that was screened and found
        clean — the opposite of what happened.
        """
        probe, _ = await self._drive_refusal(tmp_path, n=4)
        assert {r["risk_level"] for r in probe.rows()} == {"REFUSED"}

    async def test_the_refused_surface_is_named(self, tmp_path):
        probe, _ = await self._drive_refusal(tmp_path)
        assert probe.rows()[0]["path"] == "/v1/chat/completions"
        assert probe.rows()[0]["method"] == "POST"

    async def test_no_file_was_read_by_the_refused_upstream(self, tmp_path):
        """
        The point of refusing a ``file://`` upstream: nothing is dereferenced.
        Asserted on the response bytes the caller actually received.
        """
        _, responses = await self._drive_refusal(tmp_path)
        assert b"root:" not in responses[0].content
        assert responses[0].status_code == 400
