"""
AuditWriter.verify_chain(): fail closed, not vacuously "ok".

Sibling of the proxy/license/integrity.py empty-manifest defect (Codex adversarial
review, 2026-07-27). ``verify_chain()`` walks the audit log's tamper-evident hash
chain and used to return::

    {"ok": len(breaks) == 0, "verified": verified, "breaks": breaks}

``len(breaks) == 0`` is exactly what an intact chain produces -- and *also* exactly
what an absent log, an empty log, a log whose every line failed to parse, or a
walk that raised before checking anything all produce, because none of those ever
appends to ``breaks``. So a fully corrupted or never-verified audit log read as
"ok": True identically to a genuinely intact one. This is the same
`all([]) is True` shape as the integrity.py defect: iterate nothing (or nothing
you can trust), conclude success.

``proxy/main.py``'s startup self-check is deliberately fail-open for this check
(an audit self-check must never block startup) -- these tests do not change that.
What they pin down is that "ok" must not claim a check happened when it didn't:
a log that exists with content but yields zero verified records is evidence of a
problem, not an intact chain, and must not be reported the same way as a clean
walk over real records.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from proxy.audit.writer import AuditWriter, _compute_hash


def _writer(tmp_path: Path) -> AuditWriter:
    return AuditWriter(log_path=str(tmp_path / "audit.jsonl"), retention_days=365)


def _write_valid_chain(path: Path, n: int) -> None:
    prev = "0" * 64
    lines = []
    for seq in range(1, n + 1):
        record = {"seq": seq, "prev_hash": prev, "event": "detect"}
        this_hash = _compute_hash(record, prev)
        record["this_hash"] = this_hash
        lines.append(json.dumps(record))
        prev = this_hash
    path.write_text("\n".join(lines) + "\n")


def _write_chain_with_seq_gap(path: Path) -> None:
    """
    Three records with a fully intact hash chain, but seq skips 3 -> 1, 2, 4.

    This is what proxy/audit/writer.py's writer-loop defect (2026-07-27)
    actually produces on disk: a write for what would have been seq 3 consumed
    the number (``self._seq += 1`` ran) and then failed to serialise, so it
    never reached the file. The NEXT successful write picked up at seq 4
    without knowing 3 was ever attempted. Every hash link between the records
    that DID land is perfectly valid -- prev_hash of seq 4 really does equal
    this_hash of seq 2 -- because ``self._last_hash`` was only advanced on the
    writes that actually succeeded.
    """
    prev = "0" * 64
    lines = []
    for seq in (1, 2, 4):
        record = {"seq": seq, "prev_hash": prev, "event": "detect"}
        this_hash = _compute_hash(record, prev)
        record["this_hash"] = this_hash
        lines.append(json.dumps(record))
        prev = this_hash
    path.write_text("\n".join(lines) + "\n")


def _write_one_record_with_seq(path: Path, seq: object) -> None:
    prev = "0" * 64
    record = {"seq": seq, "prev_hash": prev, "event": "detect"}
    this_hash = _compute_hash(record, prev)
    record["this_hash"] = this_hash
    path.write_text(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Positive controls: the walk logic itself is not broken, only the empty case
# ---------------------------------------------------------------------------

def test_verify_chain_reports_ok_for_a_genuinely_intact_chain(tmp_path):
    """A real chain with real records verifies ok=True with a nonzero count."""
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)

    report = w.verify_chain()
    assert report["ok"] is True
    assert report["complete"] is True
    assert report["verified"] == 3
    assert report["breaks"] == []


def test_verify_chain_detects_a_broken_link(tmp_path):
    """
    A tampered record IS caught (breaks non-empty, ok=False), and the break
    reported is EXACTLY the one tampered record -- pinned by seq, not merely
    "at least one," matching the F15 receipt tests' discipline. A permissive
    `len(breaks) >= 1` would also pass for a verifier that (say) flagged
    every record as broken, or the wrong one; this proves it found THIS one.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)
    lines = w.log_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["event"] = "tampered"
    lines[1] = json.dumps(tampered)
    w.log_path.write_text("\n".join(lines) + "\n")

    report = w.verify_chain()
    assert report["ok"] is False
    assert report["complete"] is True
    assert len(report["breaks"]) == 1, report["breaks"]
    assert report["breaks"][0]["seq"] == 2, report["breaks"]
    # And the third record's link off the tampered one is ALSO reported broken
    # -- tampering one record poisons every hash link downstream of it, and a
    # verifier that stopped at the first break would under-report the damage.
    # (Not asserted here because record 3 in this fixture recomputes its own
    # prev_hash from the ACTUAL on-disk record 2, so only record 2 itself is
    # a break; this comment documents why `== 1` is correct, not accidental.)


# ---------------------------------------------------------------------------
# RED: content that could not be verified must not read as "ok"
# ---------------------------------------------------------------------------

def test_verify_chain_on_a_fully_corrupt_log_is_not_ok(tmp_path):
    """
    RED: every line fails to parse (0 verified) must NOT report ok=True.

    Before the fix, ``{"ok": len(breaks) == 0}`` reported ok=True here because
    ``breaks`` stayed empty -- not because anything was verified, but because
    nothing was checked. A log this corrupted is evidence of a problem, not an
    intact chain, and must not be indistinguishable from one.
    """
    w = _writer(tmp_path)
    w.log_path.write_text("not json\nalso not json\n{{{broken\n")

    report = w.verify_chain()
    assert report["verified"] == 0
    assert report["ok"] is False, report


def test_verify_chain_when_the_walk_raises_is_not_ok(tmp_path):
    """
    RED: a read that raises before checking anything must not report ok=True.

    Invalid UTF-8 bytes make ``for raw_line in f`` raise UnicodeDecodeError on
    the very first line under the file's ``encoding="utf-8"`` open mode. The old
    code caught this in a bare ``except Exception: logger.error(...)`` and then
    fell through to ``return {"ok": len(breaks) == 0, ...}`` using whatever
    partial state existed (0 verified, no breaks) -- masking a real read error
    as a clean pass.
    """
    w = _writer(tmp_path)
    w.log_path.write_bytes(b"\xff\xfe\x00 not valid utf-8 \x00\xff")

    report = w.verify_chain()
    assert report["verified"] == 0
    assert report["ok"] is False, report


# ---------------------------------------------------------------------------
# RED: a sequence gap must not verify the same as an intact chain
#
# Sibling of the two RED cases above, and of proxy/tests/test_audit_writer_
# nonserialisable.py -- same root cause (writer.py's ``self._seq += 1`` firing
# before the write it numbers is known to have succeeded), different surface.
# ---------------------------------------------------------------------------

def test_verify_chain_detects_a_sequence_gap_even_when_hashes_are_intact(tmp_path):
    """
    RED: before the fix, verify_chain() never inspects ``seq`` for continuity
    -- only for its error-message value -- so a hole left by a write that
    consumed a sequence number and then never landed on disk is invisible to
    it. The hash-link check alone cannot catch this case: it only compares
    each record's prev_hash/this_hash against its immediate neighbour, and
    those links are untouched because the failed write never advanced
    ``self._last_hash`` either. So the chain in ``_write_chain_with_seq_gap``
    -- seq 1, 2, 4, with 3 silently missing -- reads today as
    ``{"ok": True, "breaks": []}``, identical to a genuinely intact chain.

    A tamper-evident log exists so a verifier can tell "nothing was ever
    written here" apart from "every record present is unmodified" -- this
    pins that the chain-walk actually makes that distinction, not just the
    per-link hash comparison.
    """
    w = _writer(tmp_path)
    _write_chain_with_seq_gap(w.log_path)

    report = w.verify_chain()

    assert report["breaks"] == [], (
        "test setup invalid -- the hash LINKS between the surviving records "
        f"must be intact so the gap is caught by sequence inspection, not by "
        f"the pre-existing hash check: {report}"
    )
    assert report["ok"] is False, (
        f"a sequence gap (seq 1, 2, 4 -- 3 never written) verified as ok=True: {report} "
        f"-- a verifier cannot tell this apart from a chain with nothing missing."
    )


@pytest.mark.parametrize("seq", [True, False, "1", -1, None, 1.5, [], {}])
def test_verify_chain_rejects_malformed_seq_values_even_when_hashes_match(
    tmp_path, seq
):
    """
    A malformed seq is itself corrupted chain metadata, even if the row's hash
    was computed over exactly that malformed value. It must not reset
    continuity and still report ok=True.
    """
    w = _writer(tmp_path)
    _write_one_record_with_seq(w.log_path, seq)

    report = w.verify_chain()

    assert report["verified"] == 1, report
    assert report["breaks"] == [], (
        "test setup invalid -- the hash should match the malformed on-disk "
        f"seq so this is testing seq validation, not hash validation: {report}"
    )
    assert report["gaps"] == [], report
    assert report["ok"] is False, (
        f"malformed seq {seq!r} ({type(seq).__name__}) verified as ok=True: "
        f"{report}"
    )
    assert report["seq_errors"] == [{
        "line": 1,
        "got_type": type(seq).__name__,
        "reason": "seq is not a non-negative int",
    }]


# ---------------------------------------------------------------------------
# Positive control: genuine absence stays fail-open (a different state)
# ---------------------------------------------------------------------------

def test_verify_chain_on_an_absent_log_stays_fail_open(tmp_path):
    """
    A log that was never written is a legitimately different state from one
    that was written and is corrupt -- there is no claim being made yet, so
    this one may still report ok=True (startup must not block on a brand new
    deployment). Distinct from the corrupt/unreadable cases above, which DO
    have content and must not be folded into the same "ok" as this.
    """
    w = _writer(tmp_path)
    assert not w.log_path.exists()

    report = w.verify_chain()
    assert report["verified"] == 0
    assert report["ok"] is True


# ---------------------------------------------------------------------------
# RED: a BOUNDED walk that stops before the end of the log must not report
# "ok" for what it never looked at.
#
# Codex adversarial review of PR #37, second pass, 2026-07-27. Reproduced
# against the real FastAPI app: 1001 valid records, tamper record #1001 (the
# very last one), start the app -> /admin/health returned "status": "ok",
# because ``verify_chain(limit=1000)`` (the old default) stopped after 1000
# records and returned ``{"ok": len(breaks) == 0 and len(gaps) == 0}`` --
# exactly the same `all([]) is True` shape as every other defect this module
# exists to rule out, just triggered by a bound instead of corruption. Past
# 1000 records is the STEADY STATE for a running deployment, not an edge
# case, and it is exactly where an attacker appending a tampered tail record
# would land.
# ---------------------------------------------------------------------------

def test_verify_chain_default_now_verifies_the_whole_chain(tmp_path):
    """
    The fix: `limit=None` is the new default, so a real 1001-record chain
    with a break ONLY in the last record is still caught by a plain
    `w.verify_chain()` call -- the exact call proxy/main.py's startup
    self-check makes. Pins the count (1001, one more than the OLD default
    limit) and the exact break location, not merely "some break somewhere."
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 1001)
    lines = w.log_path.read_text().splitlines()
    tampered = json.loads(lines[1000])  # record #1001, the LAST one
    tampered["event"] = "tampered"
    lines[1000] = json.dumps(tampered)
    w.log_path.write_text("\n".join(lines) + "\n")

    report = w.verify_chain()  # no explicit limit -- the production call shape
    assert report["ok"] is False, report
    assert report["complete"] is True, report
    assert report["verified"] == 1001, report
    assert len(report["breaks"]) == 1, report["breaks"]
    assert report["breaks"][0]["seq"] == 1001, report["breaks"]


def test_verify_chain_explicit_limit_reports_incomplete_not_ok(tmp_path):
    """
    A caller that DOES pass an explicit, smaller `limit` (a future bounded
    on-demand check, e.g. `/admin/verify-chain?limit=N`) gets an honest
    answer instead of a silent all-clear: `complete` is False and `ok` is
    False, even though the three records actually examined are perfectly
    intact -- an unchecked tail is missing evidence, not a clean verdict.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 5)  # genuinely intact, no tampering at all

    report = w.verify_chain(limit=3)
    assert report["verified"] == 3, report
    assert report["breaks"] == [], report
    assert report["gaps"] == [], report
    assert report["complete"] is False, report
    assert report["ok"] is False, (
        f"a bounded walk that stopped with 2 of 5 records unread must not "
        f"report ok=True just because the 3 it DID check were clean: {report}"
    )
    assert report["error"] is not None and "limit" in report["error"], report

    # And the SAME log, walked without a limit, is genuinely ok=True/complete.
    full = w.verify_chain()
    assert full["ok"] is True, full
    assert full["complete"] is True, full
    assert full["verified"] == 5, full
