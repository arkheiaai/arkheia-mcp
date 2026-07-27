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


async def drive(risk="HIGH", action="block", n=1, tmp_path=None, **kw):
    """
    Drive N requests through the middleware with a LIVE AuditWriter attached,
    and hand back the probe plus the responses.
    """
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(str(log))
    await writer.start()
    try:
        app, eng = build(risk=risk, action=action, audit=writer, **kw)
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
            app, _ = build(risk="HIGH", action="block", audit=writer)
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
        ``AuditWriter.write()`` drops silently when the queue is full and
        ``_writer_loop`` swallows every I/O error, so the endpoint cannot
        truthfully say a record LANDED. It says ``enqueued``, which is the most
        it can support. (Same correction PR #31 made on the sibling flow.)
        """
        probe, responses = await drive(n=1, tmp_path=tmp_path)
        assert json.loads(responses[0].content)["receipt"] == "enqueued"

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
            app, _ = build(risk="HIGH", action="block", audit=writer)
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
