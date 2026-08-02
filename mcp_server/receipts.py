"""Durable decision receipts for MCP tool-gate decisions."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import uuid
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from proxy.audit.redactor import redact, redact_in_credential_context
from proxy.audit.writer import _compute_hash

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
_CONTEXTUAL_RECEIPT_FIELDS = frozenset(
    {"tool", "argument_keys", "argument_values", "call_site"}
)
_DEFAULT_RECEIPT_DIR = Path("~/.arkheia/mcp").expanduser()

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
    path = _validate_receipt_log_path(log_path)
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


def _path_inside(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _validate_receipt_log_path(log_path: str | Path) -> Path:
    """Return a confined absolute path for MCP tool-gate receipt logs."""
    raw = os.fspath(log_path)
    if "\0" in raw:
        raise ValueError("receipt log path contains a NUL byte")
    path = Path(log_path).expanduser()
    if not path.is_absolute():
        raise ValueError("receipt log path must be absolute")
    resolved = path.resolve(strict=False)
    if resolved.name.startswith("."):
        raise ValueError("receipt log filename must not be hidden")
    if resolved.suffix != ".jsonl":
        raise ValueError("receipt log path must end in .jsonl")
    allowed_roots = (
        _DEFAULT_RECEIPT_DIR.resolve(strict=False),
        Path(tempfile.gettempdir()).resolve(strict=False),
        Path("/private/tmp").resolve(strict=False),
    )
    if not any(_path_inside(resolved, root) for root in allowed_roots):
        raise ValueError(
            "receipt log path must be under ~/.arkheia/mcp or the OS temp directory"
        )
    return resolved


def validate_receipt_log_path(log_path: str | Path) -> Path:
    """Public wrapper for callers that need to fail before emitting."""
    return _validate_receipt_log_path(log_path)


def _load_receipt_chain_state(log_path: Path) -> tuple[str, int]:
    """Recover the last parseable receipt row without assuming rows fit in a small tail."""
    log_path = _validate_receipt_log_path(log_path)
    genesis = ("0" * 64, 0)
    if not log_path.exists():
        return genesis
    last: dict[str, Any] | None = None
    try:
        for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)
            except json.JSONDecodeError:
                continue
    except OSError as exc:
        logger.warning(
            "MCP receipt rail: could not recover chain state from %s: %s",
            log_path,
            exc,
        )
        return genesis
    if last is None:
        return genesis
    return str(last.get("this_hash") or "0" * 64), int(last.get("seq") or 0)


def _path_lock(path: Path) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    key = (str(_validate_receipt_log_path(path)), id(loop))
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


def _redact_receipt_record(record: dict[str, Any]) -> dict[str, Any]:
    clean = redact(record)
    for field in _CONTEXTUAL_RECEIPT_FIELDS:
        if field in clean:
            clean[field] = redact_in_credential_context(clean[field])
    return clean


def log_safe_value(value: Any) -> Any:
    """Return a receipt subject value safe for diagnostic logging."""
    return redact_in_credential_context(value)


def _append_record_and_confirm(path: Path, record: dict[str, Any], receipt_id: object) -> bool:
    path = _validate_receipt_log_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _exclusive_file_lock(path):
        _ensure_receipt_file(path)
        last_hash, last_seq = _load_receipt_chain_state(path)
        clean = _redact_receipt_record(record)
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
    path = _validate_receipt_log_path(log_path)
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
            log_safe_value(record.get("tool")),
            record.get("decision"),
            receipt_id,
            exc_info=True,
        )
        return False

    if not ok:
        logger.error(
            "MCP receipt write was not confirmed on disk: tool=%s decision=%s "
            "receipt_id=%s path=%s",
            log_safe_value(record.get("tool")),
            record.get("decision"),
            receipt_id,
            path,
        )
        return False
    return True


def default_tool_gate_log_path() -> Path:
    """Resolve the default tool-gate receipt path."""
    raw = os.environ.get("ARKHEIA_TOOL_GATE_RECEIPT_LOG")
    path = Path(raw).expanduser() if raw else _DEFAULT_RECEIPT_DIR / "tool-gate-receipts.jsonl"
    return _validate_receipt_log_path(path)
