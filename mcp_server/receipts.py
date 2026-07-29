"""Durable decision receipts for MCP tool-gate decisions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proxy.audit.redactor import redact
from proxy.audit.writer import _compute_hash, _load_chain_state

logger = logging.getLogger(__name__)

DECISION_ALLOWED = "allowed"
DECISION_DENIED = "denied"
DECISION_UNREPRESENTABLE = "unrepresentable"

STATUS_RECORDED = "recorded"
STATUS_UNRECORDED = "unrecorded"

_DECISIONS = {DECISION_ALLOWED, DECISION_DENIED, DECISION_UNREPRESENTABLE}
_RECEIPT_FILE_MODE = 0o600
_LOCKS_GUARD = threading.Lock()
_PATH_LOCKS: dict[tuple[str, int], asyncio.Lock] = {}

try:  # pragma: no cover - exercised on POSIX CI, imported conditionally for Windows.
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback keeps the in-process lock.
    fcntl = None  # type: ignore[assignment]


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


def _path_lock(path: Path) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    key = (str(path.expanduser().resolve()), id(loop))
    with _LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _PATH_LOCKS[key] = lock
        return lock


@contextmanager
def _exclusive_file_lock(path: Path):
    lock_path = path.with_name(f".{path.name}.lock")
    with open(lock_path, "a", encoding="utf-8") as lock_file:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _ensure_receipt_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        os.chmod(path, _RECEIPT_FILE_MODE)
        return
    with suppress(FileExistsError):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _RECEIPT_FILE_MODE)
        os.close(fd)


def _append_record_and_confirm(path: Path, record: dict[str, Any], receipt_id: object) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_file_lock(path):
        _ensure_receipt_file(path)
        last_hash, last_seq = _load_chain_state(path)
        clean = redact(record)
        clean["seq"] = last_seq + 1
        clean["prev_hash"] = last_hash
        clean["this_hash"] = _compute_hash(clean, last_hash)

        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(clean) + "\n")
            f.flush()
            os.fsync(f.fileno())

        return bool(receipt_id) and find_receipt(path, str(receipt_id)) is not None


async def emit(log_path: str | Path, record: dict[str, Any]) -> bool:
    """
    Write one receipt and confirm it landed. Never raises.

    Tool-gate receipts are synchronous evidence for a policy decision. Each write
    therefore allocates seq/hash state inside a per-log critical section and then
    reads back by receipt_id before reporting ``recorded``.
    """
    path = Path(log_path)
    receipt_id = record.get("receipt_id")
    lock = _path_lock(path)
    try:
        async with lock:
            ok = await asyncio.to_thread(
                _append_record_and_confirm, path, record, receipt_id
            )
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

    if not ok:
        logger.error(
            "MCP receipt write was not confirmed on disk: tool=%s decision=%s "
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
