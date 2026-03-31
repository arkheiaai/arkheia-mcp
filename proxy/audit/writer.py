"""
Async audit log writer.

Writes one JSONL record per detection event. Non-blocking -- uses an asyncio
queue so writes never delay the response pipeline. Target write latency < 5ms.

Security properties:
  - Secrets redacted at the boundary before any write (see redactor.py)
  - Tamper-evident hash chain: every record carries seq, prev_hash, this_hash
    so any modification or deletion is detectable by replaying the chain
  - The audit log never contains prompt or response text -- only their
    sha256 hashes are stored

Hash chain:
  Genesis prev_hash = "0" * 64 (all-zeros sentinel)
  this_hash = sha256(json.dumps(record_without_this_hash, sort_keys=True) + prev_hash)
  On startup: last record is read to recover (last_hash, last_seq)

Hook for enterprise upgrade:
  - Replace JSONL with append-only DB with row-level signing
  - Publish this_hash to an external transparency log for independent verification
  - Add Merkle tree support for efficient range proofs
"""

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

from proxy.audit.redactor import redact

logger = logging.getLogger(__name__)


def _compute_hash(record: dict, prev_hash: str) -> str:
    """
    Compute this_hash for a record.

    Hashes the JSON-serialised record (sort_keys for determinism) concatenated
    with prev_hash. The record passed in must NOT contain 'this_hash' yet.
    """
    content = json.dumps(record, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()


def _load_chain_state(log_path: Path) -> tuple[str, int]:
    """
    Read the last record to recover hash chain state on startup.

    Returns (last_hash, last_seq). Falls back to genesis state on any error.
    """
    genesis = ("0" * 64, 0)
    if not log_path.exists():
        return genesis
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return genesis
            # Read last 8 KB — sufficient for any single record
            f.seek(max(0, size - 8192))
            tail = f.read().decode("utf-8", errors="replace")

        lines = [ln.strip() for ln in tail.split("\n") if ln.strip()]
        if not lines:
            return genesis

        last = json.loads(lines[-1])
        return last.get("this_hash", "0" * 64), last.get("seq", 0)
    except Exception as e:
        logger.warning("AuditWriter: could not recover chain state: %s — starting fresh", e)
        return genesis


class AuditWriter:
    """
    Fire-and-forget JSONL audit writer with hash chain and secrets redaction.

    Usage:
        writer = AuditWriter("/var/log/arkheia/audit.jsonl")
        await writer.start()                    # call from app lifespan
        await writer.write({...})               # non-blocking, returns immediately
        await writer.stop()                     # flush and close
    """

    def __init__(self, log_path: str, retention_days: int = 365):
        self.log_path = Path(log_path)
        self.retention_days = retention_days
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        self._task: Optional[asyncio.Task] = None
        self._running = False
        # Hash chain state — recovered from log on start()
        self._last_hash: str = "0" * 64
        self._seq: int = 0

    async def start(self) -> None:
        """Start the background writer task. Call from app lifespan startup."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Recover chain state from existing log (survive restarts)
        self._last_hash, self._seq = _load_chain_state(self.log_path)
        self._running = True
        self._task = asyncio.create_task(self._writer_loop(), name="audit-writer")
        logger.info(
            "AuditWriter started: %s  chain_seq=%d  last_hash=%.16s…",
            self.log_path, self._seq, self._last_hash,
        )

    async def stop(self) -> None:
        """Flush queue and stop writer. Call from app lifespan shutdown."""
        self._running = False
        if self._task:
            try:
                await asyncio.wait_for(self._queue.join(), timeout=5.0)
            except asyncio.TimeoutError:
                logger.warning("AuditWriter: queue drain timed out, %d events lost",
                               self._queue.qsize())
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("AuditWriter stopped  final_seq=%d", self._seq)

    async def write(self, record: dict) -> None:
        """
        Enqueue a record for async write. Returns immediately.
        If queue is full, logs a warning and drops the record (never blocks).
        """
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("AuditWriter queue full — dropping detection event %s",
                           record.get("detection_id", "?"))

    async def _writer_loop(self) -> None:
        """Background loop: drain queue, redact, chain-hash, write to JSONL."""
        while self._running or not self._queue.empty():
            try:
                record = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                # 1. Redact secrets before anything touches disk
                clean = redact(record)

                # 2. Add chain fields (seq, prev_hash) — but not this_hash yet
                self._seq += 1
                clean["seq"]       = self._seq
                clean["prev_hash"] = self._last_hash

                # 3. Compute this_hash over the clean record (no this_hash yet)
                this_hash = _compute_hash(clean, self._last_hash)
                clean["this_hash"] = this_hash

                # 4. Write
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(clean) + "\n")

                # 5. Advance chain state
                self._last_hash = this_hash

            except Exception as e:
                logger.error("AuditWriter: failed to write record: %s", e)
            finally:
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Read methods (for /audit/log endpoint)
    # ------------------------------------------------------------------

    def read_recent(
        self,
        limit: int = 50,
        session_id: Optional[str] = None,
    ) -> dict:
        """
        Read recent audit events from the JSONL file.

        Returns {"events": [...], "summary": {"LOW": n, ...}}
        """
        if not self.log_path.exists():
            return {"events": [], "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}}

        limit = min(limit, 500)
        events = []

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if session_id and event.get("session_id") != session_id:
                    continue

                events.append(event)
                if len(events) >= limit:
                    break

        except Exception as e:
            logger.error("AuditWriter: failed to read log: %s", e)

        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
        for e in events:
            rl = e.get("risk_level", "UNKNOWN")
            summary[rl] = summary.get(rl, 0) + 1

        return {"events": events, "summary": summary}

    def verify_chain(self, limit: int = 1000) -> dict:
        """
        Walk the hash chain and report any breaks.

        Returns {"ok": bool, "verified": n, "breaks": [{seq, expected, got}]}

        Hook for enterprise upgrade: expose this via /admin/verify-chain endpoint
        and run it on a schedule to detect log tampering.
        """
        if not self.log_path.exists():
            return {"ok": True, "verified": 0, "breaks": []}

        breaks = []
        prev_hash = "0" * 64
        verified = 0

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        record = json.loads(raw_line)
                    except json.JSONDecodeError:
                        continue

                    stored_this  = record.pop("this_hash", None)
                    stored_prev  = record.get("prev_hash", "")

                    expected = _compute_hash(record, prev_hash)

                    if stored_this != expected or stored_prev != prev_hash:
                        breaks.append({
                            "seq":      record.get("seq"),
                            "expected": expected,
                            "got":      stored_this,
                        })

                    prev_hash = stored_this or expected
                    verified += 1
                    if verified >= limit:
                        break

        except Exception as e:
            logger.error("AuditWriter.verify_chain: %s", e)

        return {"ok": len(breaks) == 0, "verified": verified, "breaks": breaks}

    def purge_old_records(self) -> int:
        """Remove records older than retention_days. Returns count deleted."""
        if not self.log_path.exists():
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
        kept = []
        deleted = 0

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        ts_str = event.get("timestamp", "")
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts >= cutoff:
                            kept.append(line)
                        else:
                            deleted += 1
                    except Exception:
                        kept.append(line)

            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))

        except Exception as e:
            logger.error("AuditWriter: purge failed: %s", e)

        return deleted
