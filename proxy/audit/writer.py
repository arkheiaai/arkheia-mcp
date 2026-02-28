"""
Async audit log writer.

Writes one JSONL record per detection event. Non-blocking -- uses an asyncio
queue so writes never delay the response pipeline. Target write latency < 5ms.

The audit log never contains prompt or response text -- only the prompt hash
(sha256) and response_length are stored.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class AuditWriter:
    """
    Fire-and-forget JSONL audit writer.

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

    async def start(self) -> None:
        """Start the background writer task. Call from app lifespan startup."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._running = True
        self._task = asyncio.create_task(self._writer_loop(), name="audit-writer")
        logger.info("AuditWriter started: %s", self.log_path)

    async def stop(self) -> None:
        """Flush queue and stop writer. Call from app lifespan shutdown."""
        self._running = False
        if self._task:
            # Allow queue to drain
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
        logger.info("AuditWriter stopped")

    async def write(self, record: dict) -> None:
        """
        Enqueue a record for async write. Returns immediately.
        If queue is full, logs a warning and drops the record (never blocks).
        """
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            logger.warning("AuditWriter queue full -- dropping detection event %s",
                           record.get("detection_id", "?"))

    async def _writer_loop(self) -> None:
        """Background loop: drain queue and write to JSONL file."""
        while self._running or not self._queue.empty():
            try:
                record = await asyncio.wait_for(self._queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
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

        Returns {"events": [...], "summary": {"LOW": n, "MEDIUM": n, "HIGH": n, "UNKNOWN": n}}
        """
        if not self.log_path.exists():
            return {"events": [], "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}}

        limit = min(limit, 500)
        events = []

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            # Read from end (most recent first)
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
                        kept.append(line)  # keep malformed lines

            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write("\n".join(kept) + ("\n" if kept else ""))

        except Exception as e:
            logger.error("AuditWriter: purge failed: %s", e)

        return deleted
