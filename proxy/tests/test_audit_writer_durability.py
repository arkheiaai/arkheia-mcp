import asyncio
import json
import logging
from unittest.mock import patch

import pytest

from proxy.audit.writer import (
    AUDIT_WRITE_ENQUEUED,
    AUDIT_WRITE_NOT_RUNNING,
    AUDIT_WRITE_QUEUE_FULL,
    AUDIT_WRITE_WRITE_FAILED,
    AuditWriter,
    _compute_hash,
)


SECRET = "sk-ant-" + "a" * 40


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.mark.asyncio
async def test_queue_full_returns_failed_receipt_and_redacts_diagnostics(tmp_path, caplog):
    writer = AuditWriter(str(tmp_path / "audit.jsonl"))
    await writer.start()
    try:
        with patch.object(writer._queue, "put_nowait", side_effect=asyncio.QueueFull()):
            with caplog.at_level(logging.WARNING, logger="proxy.audit.writer"):
                outcome = await writer.write({
                    "detection_id": SECRET,
                    "receipt_id": SECRET,
                    "risk_level": "LOW",
                })
    finally:
        await writer.stop()

    assert outcome.accepted is False
    assert outcome.receipt == AUDIT_WRITE_QUEUE_FULL
    health = writer.chain_status()
    assert health["ok"] is False
    assert health["status"] == "RECORD_DROPPED"
    assert health["dropped_records"] == 1

    rendered_logs = "\n".join(r.getMessage() for r in caplog.records)
    rendered_health = json.dumps(health, sort_keys=True)
    assert SECRET not in rendered_logs
    assert SECRET not in rendered_health
    assert "[REDACTED:" in rendered_health


@pytest.mark.asyncio
async def test_write_after_stop_is_rejected_not_left_in_an_undrained_queue(tmp_path):
    log = tmp_path / "audit.jsonl"
    writer = AuditWriter(str(log))
    await writer.start()
    await writer.stop()

    outcome = await writer.write({"detection_id": "late-record", "risk_level": "LOW"})

    assert outcome.accepted is False
    assert outcome.receipt == AUDIT_WRITE_NOT_RUNNING
    assert writer._queue.qsize() == 0
    assert not log.exists() or "late-record" not in log.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_filesystem_commit_failure_degrades_writer_health(tmp_path):
    log = tmp_path / "audit.jsonl"
    log.mkdir()
    writer = AuditWriter(str(log))
    await writer.start()
    try:
        outcome = await writer.write({"detection_id": "fs-fail", "risk_level": "HIGH"})
        await asyncio.wait_for(writer._queue.join(), timeout=5.0)
        health = writer.chain_status()
    finally:
        await writer.stop()

    assert outcome.receipt == AUDIT_WRITE_ENQUEUED
    assert health["ok"] is False
    assert health["failed_records"] >= 1
    assert health["last_failure"]["receipt"] == AUDIT_WRITE_WRITE_FAILED


@pytest.mark.asyncio
async def test_startup_recovers_chain_state_from_large_final_record(tmp_path):
    log = tmp_path / "audit.jsonl"
    prev = "0" * 64
    first = {
        "seq": 1,
        "prev_hash": prev,
        "event_type": "large-record",
        "payload": "x" * 20_000,
    }
    first["this_hash"] = _compute_hash(first, prev)
    log.write_text(json.dumps(first) + "\n", encoding="utf-8")

    writer = AuditWriter(str(log))
    await writer.start()
    try:
        assert writer.chain_status()["seq"] == 1
        outcome = await writer.write({"detection_id": "second", "risk_level": "LOW"})
    finally:
        await writer.stop()

    assert outcome.receipt == AUDIT_WRITE_ENQUEUED
    rows = _rows(log)
    assert [r["seq"] for r in rows] == [1, 2]
    assert rows[1]["prev_hash"] == rows[0]["this_hash"]
    assert AuditWriter(str(log)).verify_chain()["ok"] is True
