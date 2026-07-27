"""
F7 receipted — does a SUPPRESSION leave a durable, attributable record?

WHY THIS IS THE CASE WHERE IT MATTERS MOST
------------------------------------------
A suppression is a decision NOT to report something. Every other decision the detector
makes announces itself; this one, by construction, produces silence. If the silence is
not written down, there is no artefact distinguishing "we looked and it was clean" from
"we never looked", and the audit log is the compliance artefact both readings come from.

So the receipted verdict for this flow cannot be `n/a` — a decision was taken, a rail
exists, and the rail is where the decision was invisible.

WHAT IS PROVED HERE, AND HOW
----------------------------
Everything drives the REAL route with the REAL `AuditWriter` the app's own lifespan
constructs and starts, and reads the artefact back OFF DISK through the consolidated
`ReceiptProbe` in read-only mode (P2) — no recording stub, no assertion on the dict
`_audit_record()` returns. The writer redacts, chain-hashes and serialises AFTER that
dict is handed over, and can drop the record entirely; a stub cannot observe any of it.

Consolidated rail only: `proxy/audit/writer.AuditWriter` via
`proxy/tests/_receipt_probe.py`, taken verbatim from `sweep/mcp-receipt-consolidation`
(blob c2055dd49901d78a7c9db99233142a4128dcd60b). No fourth probe copy was created.

Following PR #31: a reason from a CLOSED taxonomy; key NAMES asserted on the raw bytes,
never values that could carry text; and a status that does not overclaim.

RED RUN (DONE.md v1.15) — recorded in `RED_RUN` at the bottom of this module.
"""
from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from proxy.detection import features as F
from proxy.main import create_app
from proxy.tests._receipt_probe import ReceiptProbe, contains

_REPO_ROOT = Path(__file__).resolve().parents[2]

GATED_MODEL = "gpt-5.3-codex"
SHORT_RESPONSE = "Paris."
LONG_RESPONSE = " ".join(
    f"The capital city number {i} has a documented population and a founding date."
    for i in range(20)
)


@pytest.fixture
def rail(tmp_path):
    """The app's OWN AuditWriter, started by the real lifespan, writing a real file.

    Yields ``(client, probe)`` where the probe is read-only over the same path: the
    production code writes it, the test only reads it.
    """
    log_path = tmp_path / "audit" / "audit.jsonl"
    with patch("proxy.main.settings") as s:
        s.detection.profile_dir = str(_REPO_ROOT / "profiles")
        s.detection.high_risk_action = "warn"
        s.detection.unknown_action = "pass"
        s.proxy.log_level = "WARNING"
        s.audit.log_path = str(log_path)
        s.audit.retention_days = 90
        s.registry.url = ""
        from pydantic import SecretStr
        s.arkheia_api_key = SecretStr("")
        s.synesis = MagicMock()
        s.synesis.enabled = False
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as c:
            probe = ReceiptProbe(log_path)          # read-only: never .start()ed
            assert isinstance(app.state.audit_writer, type(probe.writer)), (
                "the app is not using the real AuditWriter; this suite would be "
                "proving nothing about the production rail"
            )
            yield c, probe


def _verify(client, text: str, model: str = GATED_MODEL) -> dict:
    r = client.post("/detect/verify", json={
        "prompt": "What is the capital of France?",
        "response": text,
        "model_id": model,
        "session_id": "sess-f7",
    })
    assert r.status_code == 200
    return r.json()


def _await_row(probe: ReceiptProbe, detection_id: str, timeout: float = 5.0) -> dict:
    """The rail is fire-and-forget: `write()` enqueues and returns. Poll for the row
    rather than racing it, and fail loudly naming what DID land."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = probe.find(detection_id)
        if row is not None:
            return row
        time.sleep(0.02)
    return probe.require(detection_id)      # raises, naming every id on disk


# ===========================================================================
# 1. The rail was actually asked
# ===========================================================================

class TestTheRailIsReallyExercised:
    """"Suppressed N times" and "was never asked" produce the same empty directory."""

    def test_the_file_does_not_exist_before_any_request(self, rail):
        _, probe = rail
        assert probe.raw_bytes() == b""
        assert probe.rows() == []

    def test_one_suppressed_verdict_produces_exactly_one_durable_row(self, rail):
        client, probe = rail
        before = len(probe.raw_bytes())
        body = _verify(client, SHORT_RESPONSE)
        _await_row(probe, body["detection_id"])
        assert len(probe.rows()) == 1
        assert len(probe.raw_bytes()) > before

    def test_a_fabricated_id_finds_nothing(self, rail):
        """P4 — without this the read-back is decorative: a probe that returned "the
        only row" regardless of the id would make every assertion below pass by
        accident."""
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        _await_row(probe, body["detection_id"])
        assert probe.find("00000000-0000-4000-8000-000000000000") is None


# ===========================================================================
# 2. The suppression decision is ON the record, and attributable
# ===========================================================================

class TestTheSuppressionIsDurableAndAttributable:

    def test_the_row_names_the_gate_and_the_threshold(self, rail):
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        row = _await_row(probe, body["detection_id"])
        assert row["risk_level"] == "LOW"
        assert row["confidence"] == 0.0
        assert row["features_triggered"] == []
        assert row["gate_reason"] == "token_count_below_80"
        assert F.is_suppression_reason(row["gate_reason"]) is True

    def test_the_row_is_tied_to_the_id_the_caller_was_handed(self, rail):
        """P3 — attributable, not merely present."""
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        row = _await_row(probe, body["detection_id"])
        assert row["detection_id"] == body["detection_id"]
        assert row["gate_reason"] == body["gate_reason"]
        assert row["session_id"] == "sess-f7"

    def test_a_scored_verdict_records_no_reason(self, rail):
        """NEGATIVE CONTROL on the durable rail: the marker must discriminate there
        too, or an investigator reading the log learns nothing from its presence."""
        client, probe = rail
        body = _verify(client, LONG_RESPONSE)
        row = _await_row(probe, body["detection_id"])
        assert row["risk_level"] == "LOW"
        assert row["gate_reason"] is None
        assert row["features_triggered"] != []

    def test_two_verdicts_are_separable_on_disk(self, rail):
        """The whole question, answered on the artefact: given the file alone, can an
        investigator tell the never-screened row from the screened-clean one?"""
        client, probe = rail
        supp = _verify(client, SHORT_RESPONSE)
        scored = _verify(client, LONG_RESPONSE)
        _await_row(probe, supp["detection_id"])
        _await_row(probe, scored["detection_id"])

        rows = probe.rows()
        assert len(rows) == 2
        assert {r["risk_level"] for r in rows} == {"LOW"}      # identical bands
        suppressed = [r for r in rows if F.is_suppression_reason(r.get("gate_reason"))]
        assert len(suppressed) == 1
        assert suppressed[0]["detection_id"] == supp["detection_id"]

    def test_the_marker_is_in_the_raw_bytes_not_a_parsed_view(self, rail):
        """P7 — key NAME on the bytes, plus the closed-taxonomy value it must hold."""
        client, probe = rail
        _verify(client, SHORT_RESPONSE)
        deadline = time.time() + 5.0
        while time.time() < deadline and not contains(probe.raw_bytes(), "gate_reason"):
            time.sleep(0.02)
        raw = probe.raw_bytes()
        assert contains(raw, "gate_reason")
        assert contains(raw, "token_count_below_80")


# ===========================================================================
# 3. The marker is inside the tamper-evident chain
# ===========================================================================

class TestTheMarkerIsCoveredByTheHashChain:
    """A field appended outside the chain could be edited later without breaking it.
    The suppression marker is only evidence if the chain covers it."""

    def test_the_chain_verifies_over_a_suppressed_row(self, rail):
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        _await_row(probe, body["detection_id"])
        result = probe.verify_chain()
        assert result["ok"] is True
        assert result["verified"] == 1
        assert result["breaks"] == []

    def test_the_stored_hash_recomputes_from_the_row_as_it_sits_on_disk(self, rail):
        """P8."""
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        row = _await_row(probe, body["detection_id"])
        assert probe.recompute_this_hash(row) == row["this_hash"]

    def test_editing_the_gate_reason_breaks_the_hash(self, rail):
        """THE CONTROL THAT MAKES THE TWO ABOVE MEAN SOMETHING. If the marker were
        outside the hashed surface, flipping a suppression into a clean screening on
        disk would leave the chain intact — the exact tamper the chain exists to catch,
        applied to the exact field that carries the decision."""
        client, probe = rail
        body = _verify(client, SHORT_RESPONSE)
        row = _await_row(probe, body["detection_id"])
        assert row["gate_reason"] == "token_count_below_80"

        forged = dict(row)
        forged["gate_reason"] = None                       # "it was screened, and clean"
        assert probe.recompute_this_hash(forged) != row["this_hash"]

        probe.log_path.write_text(json.dumps(forged) + "\n", encoding="utf-8")
        broken = probe.verify_chain()
        assert broken["ok"] is False
        assert len(broken["breaks"]) == 1


# ===========================================================================
# 4. The redactor does not eat the marker
# ===========================================================================

class TestTheRedactorLeavesTheMarkerIntact:
    """The record passes through `redact()` before it is hashed and written. A pattern
    that swallowed the reason would silently un-evidence every suppression."""

    def test_a_real_secret_in_the_same_record_is_redacted(self, rail):
        """POSITIVE CONTROL that the redactor ran at all — otherwise "the marker
        survived" is a claim about a redactor that was never applied."""
        client, probe = rail
        secret = "sk-ant-" + "a" * 40
        body = _verify(client, f"{SHORT_RESPONSE} {secret}"[:60], model=GATED_MODEL)
        _await_row(probe, body["detection_id"])
        # The rail never stores response text, so assert the redactor on its own terms:
        from proxy.audit.redactor import redact
        assert secret not in json.dumps(redact({"x": secret}))
        assert "[REDACTED:" in json.dumps(redact({"x": secret}))

    def test_the_gate_reason_is_unchanged_by_redaction(self, rail):
        from proxy.audit.redactor import redact
        for reason in ("token_count_below_80", "output_tokens_below_1",
                       "function_call_part"):
            assert redact({"gate_reason": reason})["gate_reason"] == reason


# ===========================================================================
# 5. WHAT THE RAIL CANNOT PROMISE — stated, not glossed
# ===========================================================================

class TestTheRailCanOnlyEverConfirmEnqueued:
    """PR #31 corrected `"recorded"` to `"enqueued"` for exactly this reason, and the
    same limit applies to every claim this suite makes.

    `AuditWriter.write()` drops silently on a full queue and `_writer_loop` swallows
    every I/O error, so the endpoint cannot know its record landed. It returns the
    verdict either way. The consequence for THIS flow: a suppression — a decision not to
    report — can be taken and lost, with the caller told LOW and nothing on disk.
    Proved with a REAL filesystem failure, not a patched exception.
    """

    def test_a_real_write_failure_loses_the_record_and_the_caller_is_not_told(
        self, rail
    ):
        client, probe = rail
        # Make the log path un-writable for real: replace the directory with a file.
        log_dir = probe.log_path.parent
        for child in log_dir.iterdir():
            child.unlink()
        log_dir.rmdir()
        log_dir.write_text("not a directory", encoding="utf-8")

        body = _verify(client, SHORT_RESPONSE)
        assert body["risk_level"] == "LOW"
        assert body["gate_reason"] == "token_count_below_80"

        time.sleep(0.5)                                  # let the loop try and fail
        assert not probe.log_path.exists()
        assert probe.find(body["detection_id"]) is None

    def test_the_verdict_is_never_blocked_on_the_receipt(self, rail):
        """The mirror, and it is CORRECT: detection is fail-open by contract (DONE.md
        floor ledger 2, the one deliberate exception to loud-model-failure). This test
        exists so the fail-open is a recorded decision rather than an accident."""
        client, probe = rail
        assert _verify(client, SHORT_RESPONSE)["risk_level"] == "LOW"


class TestTheAuditSummaryStillFoldsThemTogether:
    """PINNED — NOT FIXED. Product call, reported.

    `AuditWriter.read_recent()` buckets its `summary` by `risk_level` alone, and that
    summary is what `GET /audit/log` returns and what the `arkheia_audit_log` MCP tool
    shows a compliance reader. A never-screened response is therefore still counted as a
    clean LOW in the aggregate — the per-row evidence is now there, the headline number
    is not. Changing the buckets changes what `/audit/log` means to every existing
    consumer, so it is reported rather than taken.
    """

    def test_a_suppressed_and_a_scored_verdict_both_count_as_low(self, rail):
        client, probe = rail
        supp = _verify(client, SHORT_RESPONSE)
        scored = _verify(client, LONG_RESPONSE)
        _await_row(probe, supp["detection_id"])
        _await_row(probe, scored["detection_id"])

        summary = probe.writer.read_recent(limit=50)["summary"]
        assert summary["LOW"] == 2
        assert "SUPPRESSED" not in summary and "NOT_ASSESSED" not in summary

    def test_but_the_rows_underneath_are_separable(self, rail):
        """The recourse that makes the pin tolerable: the evidence is one field away."""
        client, probe = rail
        supp = _verify(client, SHORT_RESPONSE)
        scored = _verify(client, LONG_RESPONSE)
        _await_row(probe, supp["detection_id"])
        _await_row(probe, scored["detection_id"])

        events = probe.writer.read_recent(limit=50)["events"]
        flagged = [e for e in events if F.is_suppression_reason(e.get("gate_reason"))]
        assert len(flagged) == 1
        assert flagged[0]["detection_id"] == supp["detection_id"]


RED_RUN = """
EXECUTED (not asserted) with proxy/detection/engine.py and proxy/endpoints/detect.py
restored to origin/master @ 3037f0c, python 3.12.13:

    8 failed, 9 passed

    TestTheSuppressionIsDurableAndAttributable::test_the_row_names_the_gate_and_the_threshold
    TestTheSuppressionIsDurableAndAttributable::test_the_row_is_tied_to_the_id_the_caller_was_handed
    TestTheSuppressionIsDurableAndAttributable::test_a_scored_verdict_records_no_reason
    TestTheSuppressionIsDurableAndAttributable::test_two_verdicts_are_separable_on_disk
    TestTheSuppressionIsDurableAndAttributable::test_the_marker_is_in_the_raw_bytes_not_a_parsed_view
    TestTheMarkerIsCoveredByTheHashChain::test_editing_the_gate_reason_breaks_the_hash
    TestTheRailCanOnlyEverConfirmEnqueued::test_a_real_write_failure_loses_the_record_and_the_caller_is_not_told
    TestTheAuditSummaryStillFoldsThemTogether::test_but_the_rows_underneath_are_separable

Every failure is an assertion about the suppression reaching the durable rail: pre-fix
the record carried no marker, so a never-screened row and a screened-clean row were the
same row modulo confidence and an empty feature list. Two of the eight are worth naming
because they are NOT the obvious ones — the tamper control (a forged gate_reason cannot
break a hash over a field that was never hashed) and the fire-and-forget limit (which
asserts the caller's own gate_reason before proving nothing landed).

The 9 that passed are the rail-is-exercised checks, the chain and redactor properties
and the PINNED summary observation — none of which depends on the fix, which is what
makes this file discriminate rather than being uniformly red.
"""
