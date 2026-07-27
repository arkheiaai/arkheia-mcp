"""Durable decision receipts for MCP tool-gate decisions."""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proxy.audit.writer import AuditWriter

logger = logging.getLogger(__name__)

DECISION_ALLOWED = "allowed"
DECISION_DENIED = "denied"
DECISION_UNREPRESENTABLE = "unrepresentable"

STATUS_RECORDED = "recorded"
STATUS_UNRECORDED = "unrecorded"

_DECISIONS = {DECISION_ALLOWED, DECISION_DENIED, DECISION_UNREPRESENTABLE}


def new_receipt_id() -> str:
    """Return a fresh opaque id for one gate decision."""
    return uuid.uuid4().hex


def build_record(
    *,
    receipt_id: str,
    tool: str,
    decision: str,
    event_type: str,
    **fields: Any,
) -> dict[str, Any]:
    """Build one audit record for a tool-gate decision."""
    if decision not in _DECISIONS:
        raise ValueError(f"unknown tool-gate decision {decision!r}")
    return {
        "event_type": event_type,
        "receipt_id": receipt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "decision": decision,
        **fields,
    }


def read_rows(log_path: str | Path) -> list[dict[str, Any]]:
    """Read every parseable JSONL row from the receipt log."""
    path = Path(log_path)
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def find_receipt(log_path: str | Path, receipt_id: str) -> dict[str, Any] | None:
    """Return the row carrying receipt_id, or None if it did not land."""
    for row in read_rows(log_path):
        if row.get("receipt_id") == receipt_id:
            return row
    return None


async def emit(log_path: str | Path, record: dict[str, Any]) -> bool:
    """
    Write one receipt and confirm it landed. Never raises.

    AuditWriter.write() only enqueues, and its loop swallows write errors. This
    helper therefore drains through stop() and then reads back by receipt_id.
    """
    path = Path(log_path)
    receipt_id = record.get("receipt_id")
    writer = AuditWriter(str(path))
    try:
        await writer.start()
        try:
            await writer.write(record)
        finally:
            await writer.stop()
    except Exception as exc:  # pragma: no cover - defensive
        logger.error(
            "MCP receipt failed to write (%s): tool=%s decision=%s receipt_id=%s",
            exc,
            record.get("tool"),
            record.get("decision"),
            receipt_id,
            exc_info=True,
        )
        return False

    if not receipt_id or find_receipt(path, str(receipt_id)) is None:
        logger.error(
            "MCP receipt was enqueued but is not on disk: tool=%s decision=%s "
            "receipt_id=%s path=%s",
            record.get("tool"),
            record.get("decision"),
            receipt_id,
            path,
        )
        return False
    return True


def default_tool_gate_log_path() -> Path:
    """Resolve the default tool-gate receipt path."""
    raw = os.environ.get("ARKHEIA_TOOL_GATE_RECEIPT_LOG")
    return Path(raw).expanduser() if raw else Path("~/.arkheia/mcp/tool-gate-receipts.jsonl").expanduser()
