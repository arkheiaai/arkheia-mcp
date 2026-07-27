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


# ---------------------------------------------------------------------------
# Positive controls: the walk logic itself is not broken, only the empty case
# ---------------------------------------------------------------------------

def test_verify_chain_reports_ok_for_a_genuinely_intact_chain(tmp_path):
    """A real chain with real records verifies ok=True with a nonzero count."""
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)

    report = w.verify_chain()
    assert report["ok"] is True
    assert report["verified"] == 3
    assert report["breaks"] == []


def test_verify_chain_detects_a_broken_link(tmp_path):
    """A tampered record IS caught (breaks non-empty, ok=False)."""
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)
    lines = w.log_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["event"] = "tampered"
    lines[1] = json.dumps(tampered)
    w.log_path.write_text("\n".join(lines) + "\n")

    report = w.verify_chain()
    assert report["ok"] is False
    assert len(report["breaks"]) >= 1


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
