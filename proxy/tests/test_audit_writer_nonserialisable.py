"""
A non-JSON-serialisable field must not silently vanish the whole audit record.

Companion to ``proxy/audit/redactor.py``'s "NOT HANDLED" note:

    A non-str, non-container value (bytes, set) is not scrubbed -- but it also
    cannot be serialised, so the writer's except DROPS the whole record rather
    than leaking it. Verified: no leak, but a silent audit loss.

That note is right that nothing leaks. It is also, on its own, evidence of the
other half of "fail-open, but NEVER fail-silent": the record disappears from
every durable audit surface (the JSONL file, read_recent(), and by extension
/audit/log and the MCP arkheia_audit_log tool) with nothing but an ephemeral
``logger.error()`` line -- itself not part of the audit trail -- to say so.
Losing a HIGH-risk detection event without a trace a verifier could ever find
is precisely the forbidden half of that contract.

This file pins the writer-level half of the defect: the record must still be
present -- in some form -- after passing through the real AuditWriter and its
real async queue/loop, not a mock.

Sibling: proxy/tests/test_audit_chain_verification.py pins the corresponding
hash-chain half (a sequence number consumed by a write that never landed
leaves a hole that verify_chain() must be able to see).
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import pytest

from proxy.audit.writer import AuditWriter


def _writer(tmp_path: Path) -> AuditWriter:
    return AuditWriter(log_path=str(tmp_path / "audit.jsonl"), retention_days=365)


async def _write_all(writer: AuditWriter, records: list[dict]) -> None:
    await writer.start()
    for record in records:
        await writer.write(record)
    await writer.stop()  # drains the queue -- every enqueued write has landed (or failed) by the time this returns


def _ids(log_path: Path) -> list[str]:
    if not log_path.exists():
        return []
    lines = [json.loads(ln) for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [r.get("detection_id") for r in lines]


# ---------------------------------------------------------------------------
# RED: a non-serialisable field must not drop the whole record
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_field_name,bad_value", [
    ("payload", b"\x00\x01\x02raw-bytes-cannot-be-json-dumped"),
    ("triggered_set", {"unique_word_ratio", "entropy_spike"}),
])
async def test_non_serialisable_value_is_not_silently_lost(tmp_path, bad_field_name, bad_value):
    """
    RED: before the fix, the record carrying a non-serialisable field vanishes
    from disk entirely -- json.dumps() raises TypeError inside the writer's
    try block, the broad except swallows it, and nothing durable ever notes
    that a HIGH-risk detection event existed and was lost.
    """
    writer = _writer(tmp_path)
    await _write_all(writer, [
        {"detection_id": "det-good-before", "event": "detect", "risk_level": "LOW"},
        {
            "detection_id": "det-nonserialisable",
            "event": "detect",
            "risk_level": "HIGH",
            bad_field_name: bad_value,
        },
        {"detection_id": "det-good-after", "event": "detect", "risk_level": "LOW"},
    ])

    ids = _ids(writer.log_path)

    # --- POSITIVE CONTROL ---
    assert "det-good-before" in ids and "det-good-after" in ids, (
        f"POSITIVE CONTROL FAILED: the plain SERIALISABLE records are missing too "
        f"({ids!r}) -- this run proves nothing about the non-serialisable one specifically."
    )

    # --- THE CHECK ---
    assert "det-nonserialisable" in ids, (
        f"a HIGH-risk detection event carrying a non-serialisable {bad_field_name!r} "
        f"was silently dropped from the audit log (records on disk: {ids!r}) -- no "
        f"trace of it exists anywhere a verifier or operator could find later."
    )


async def test_non_serialisable_value_still_reaches_the_read_surface(tmp_path):
    """
    RED: read_recent() backs /audit/log and the MCP arkheia_audit_log tool --
    it must not serve a world where the record simply never existed either.
    """
    writer = _writer(tmp_path)
    await _write_all(writer, [
        {"detection_id": "det-nonserialisable-2", "event": "detect", "risk_level": "HIGH",
         "payload": b"binary-blob"},
    ])

    reader = AuditWriter(str(writer.log_path))
    served_ids = [e.get("detection_id") for e in reader.read_recent(limit=10)["events"]]

    assert "det-nonserialisable-2" in served_ids, (
        f"the non-serialisable-field record is absent from read_recent() ({served_ids!r}) -- "
        f"the read surface agrees with the loss instead of catching it."
    )


async def test_queue_full_warning_redacts_detection_id(tmp_path, caplog):
    """
    Queue saturation drops before the writer loop can sanitize/redact the record.
    The diagnostic path must not reach back to the raw caller record for an id.
    """
    writer = _writer(tmp_path)
    n = 0
    while True:
        try:
            writer._queue.put_nowait({"detection_id": f"filler-{n}"})
        except asyncio.QueueFull:
            break
        n += 1
    assert n >= 1000, f"queue saturated after only {n} records; wrong premise"

    secret_detection_id = "sk-ant-api03-" + "Qx7Az9Bw2Ck4Dm6Fn8" * 3
    caplog.set_level(logging.WARNING, logger="proxy.audit.writer")

    await writer.write({"detection_id": secret_detection_id, "event": "detect"})

    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert secret_detection_id not in logged, logged
    assert "[REDACTED:" in logged, logged


# ---------------------------------------------------------------------------
# RED: a sequence number must not be consumed by a write that never landed
#
# Distinct from the two tests above: those are closed by DEGRADING the record
# so the write always succeeds. This one forces a hard I/O failure that
# degrading a value cannot prevent, to pin the ORDERING fix on its own merits
# (self._seq / self._last_hash must only advance on an actual successful
# write) rather than relying on coercion to make the failure path unreachable.
# ---------------------------------------------------------------------------

async def test_a_failed_write_does_not_consume_a_sequence_number(tmp_path, monkeypatch):
    """
    RED: ``self._seq += 1`` (writer.py) runs before the record is known to
    have reached disk. If the write after it raises for ANY reason -- not
    just a non-serialisable value, a bare I/O failure works identically --
    the number is already spent and the NEXT successful write silently
    continues past it, leaving a hole in the persisted sequence that nothing
    in the writer itself ever reports.
    """
    writer = _writer(tmp_path)
    await writer.start()

    real_open = open
    calls = {"n": 0}

    def flaky_open(file, mode="r", *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("simulated disk failure")
        return real_open(file, mode, *args, **kwargs)

    # `open` is a builtin, not a module attribute -- raising=False lets
    # monkeypatch insert it into the module namespace, which shadows the
    # builtin lookup for `open(...)` calls inside writer.py.
    monkeypatch.setattr("proxy.audit.writer.open", flaky_open, raising=False)

    await writer.write({"detection_id": "ok-1", "event": "detect"})
    await writer.write({"detection_id": "would-fail", "event": "detect"})
    await writer.write({"detection_id": "ok-2", "event": "detect"})
    await writer.stop()

    records = [json.loads(ln) for ln in writer.log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    ids = [r["detection_id"] for r in records]
    seqs = [r["seq"] for r in records]

    assert ids == ["ok-1", "ok-2"], (
        f"POSITIVE CONTROL: expected exactly the two writes that did not hit the "
        f"simulated I/O failure, got {ids!r} -- the test is not exercising the "
        f"failure path it claims to."
    )

    # THE CHECK: no gap. Pre-fix this is [1, 3] (seq 2 was spent on the write
    # that raised and never reached disk). Post-fix it must be [1, 2].
    assert seqs == [1, 2], (
        f"sequence numbers on disk are {seqs!r} -- a write that never reached "
        f"disk consumed a chain position anyway, leaving a hole a verifier "
        f"cannot distinguish from a deleted record."
    )
