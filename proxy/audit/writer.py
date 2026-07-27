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

    Callers within this module always pass a record that has already been
    through ``_sanitize_for_json`` (see its docstring), so this stays a
    strict ``json.dumps`` with no ``default=`` fallback: by the time a record
    reaches here it must already be fully JSON-native, and a TypeError at
    this point is a bug in the sanitiser, not an expected input shape.
    """
    content = json.dumps(record, sort_keys=True) + prev_hash
    return hashlib.sha256(content.encode()).hexdigest()


_JSON_SCALARS = (str, int, float, bool, type(None))


def _sanitize_for_json(obj):
    """
    Recursively coerce a value into something json.dumps can always serialise,
    and report whether anything had to be coerced.

    CHOSEN POSTURE — degrade, don't drop (see module docstring / the "audit
    loss" incident this closes, 2026-07-27): a field such as raw ``bytes`` or
    a ``set`` cannot be shaped by the string-anchored redactor and previously
    reached ``json.dumps`` unchanged inside ``_writer_loop``'s try block,
    which raised ``TypeError``. Because that raise happened AFTER
    ``self._seq`` had already been incremented, the whole record was dropped
    silently (no leak, but a lost audit record AND a hole in the hash chain
    a verifier could not tell apart from a deletion).

    Refusing the record outright was the other defensible option (surface
    loudly, write nothing) — rejected here because a HIGH-risk detection
    event is exactly the record you most need on disk, and refusing it is
    strictly worse than a degraded-but-present one for anyone auditing later.
    Sanitising BEFORE either hashing or writing means both operations see the
    identical, already-safe structure, and the failure mode this function
    exists to prevent has been designed out before either of those steps
    runs — not merely made survivable by wrapping them in a wider except.

    Returns (sanitised_value, changed). The caller logs once, loudly, when
    `changed` is True — coercion must never be quiet either; "degrade, don't
    drop" is not "degrade, don't tell".
    """
    if isinstance(obj, dict):
        changed = False
        out = {}
        for k, v in obj.items():
            if isinstance(k, str):
                key = k
            else:
                key, _ = _sanitize_for_json(k)
                key = str(key)
                changed = True
            value, v_changed = _sanitize_for_json(v)
            changed = changed or v_changed
            out[key] = value
        return out, changed

    if isinstance(obj, (list, tuple)):
        changed = False
        out = []
        for item in obj:
            value, v_changed = _sanitize_for_json(item)
            changed = changed or v_changed
            out.append(value)
        return out, changed

    if isinstance(obj, (set, frozenset)):
        # A set has no stable JSON shape at all -- becoming a sorted list is
        # itself the degradation, regardless of whether its elements are.
        try:
            ordered = sorted(obj, key=repr)
        except Exception:
            ordered = list(obj)
        out = [_sanitize_for_json(item)[0] for item in ordered]
        return out, True

    if isinstance(obj, _JSON_SCALARS):
        return obj, False

    if isinstance(obj, (bytes, bytearray)):
        digest = hashlib.sha256(bytes(obj)).hexdigest()[:16]
        return f"<unserialisable:bytes len={len(obj)} sha256={digest}>", True

    try:
        text = repr(obj)
    except Exception:
        text = "<repr() failed>"
    return f"<unserialisable:{type(obj).__name__} {text[:200]}>", True


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

                # 1b. Guarantee JSON-serialisability. A value the redactor
                #     passes through unchanged (bytes, set, ...) would
                #     otherwise reach json.dumps() below and raise -- see
                #     _sanitize_for_json's docstring for why this is a
                #     "degrade, don't drop" coercion rather than a refusal.
                clean, degraded = _sanitize_for_json(clean)
                if degraded:
                    logger.warning(
                        "AuditWriter: record %s contained non-JSON-serialisable "
                        "field(s) — writing a degraded-but-present form instead "
                        "of dropping it",
                        record.get("detection_id", "?"),
                    )

                # 2. Compute the NEXT chain position without committing to it
                #    yet. seq/last_hash are only written into self._seq /
                #    self._last_hash after the disk write below actually
                #    succeeds (step 5) — a write that never lands must never
                #    consume a sequence number, or the persisted chain gets a
                #    hole a verifier cannot tell apart from a deleted record.
                next_seq = self._seq + 1
                clean["seq"]       = next_seq
                clean["prev_hash"] = self._last_hash

                # 3. Compute this_hash over the clean record (no this_hash yet)
                this_hash = _compute_hash(clean, self._last_hash)
                clean["this_hash"] = this_hash

                # 4. Write
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(clean) + "\n")

                # 5. Only now commit chain state — the write above is the
                #    last thing that can fail before this point.
                self._seq = next_seq
                self._last_hash = this_hash

            except Exception as e:
                logger.error(
                    "AuditWriter: failed to write record %s — sequence NOT "
                    "advanced (chain state unchanged, no gap created): %s",
                    record.get("detection_id", "?"), e,
                )
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
        Walk the hash chain and report any breaks or sequence gaps.

        Returns {"ok": bool, "verified": n, "breaks": [{seq, expected, got}],
        "gaps": [{after_seq, expected_seq, got_seq}], "error": str|None}

        "ok" is only True for a chain that was actually walked without incident
        (including the legitimate case of a log that does not exist yet -- a
        fresh deployment has nothing to verify, and that is not evidence of
        tampering). It is deliberately NOT just `len(breaks) == 0`: an absent
        log, a genuinely empty one, a log whose every line failed to parse, and
        a walk that raised before checking anything all leave `breaks` empty
        too, but only the first two are "nothing to check" -- the latter two are
        content that COULD NOT be verified, which is evidence of a problem, not
        an intact chain, and must not read the same as one (Codex adversarial
        review, 2026-07-27; sibling of the integrity.py empty-manifest defect).

        `gaps` is a SEPARATE signal from `breaks`, added 2026-07-27 alongside
        the writer-loop fix that stopped `self._seq` from being consumed by a
        write that never landed on disk. A dropped write leaves every hash
        LINK between the records that DID make it to disk fully intact --
        prev_hash of the record after the hole really does equal this_hash of
        the record before it, because `self._last_hash` was only ever advanced
        on writes that succeeded. So a seq gap (1, 2, 4 -- 3 missing) produces
        zero hash breaks and, before this method tracked seq continuity, read
        exactly like a genuinely intact chain. `ok` folds both signals: a
        chain with no hash breaks but a seq gap is not "ok" either -- it is
        evidence that something existed and is not on disk, which a verifier
        must not be unable to tell apart from a chain where nothing is missing.

        Hook for enterprise upgrade: expose this via /admin/verify-chain endpoint
        and run it on a schedule to detect log tampering.
        """
        if not self.log_path.exists():
            return {"ok": True, "verified": 0, "breaks": [], "gaps": [], "error": None}

        breaks = []
        gaps = []
        prev_hash = "0" * 64
        expected_seq: Optional[int] = None
        verified = 0
        total_lines = 0
        unparseable = 0
        error: Optional[str] = None

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    total_lines += 1
                    try:
                        record = json.loads(raw_line)
                    except json.JSONDecodeError:
                        unparseable += 1
                        continue

                    stored_this  = record.pop("this_hash", None)
                    stored_prev  = record.get("prev_hash", "")
                    seq          = record.get("seq")

                    expected = _compute_hash(record, prev_hash)

                    if stored_this != expected or stored_prev != prev_hash:
                        breaks.append({
                            "seq":      seq,
                            "expected": expected,
                            "got":      stored_this,
                        })

                    # Sequence continuity: independent of the hash-link check
                    # above, and catches what it structurally cannot -- a
                    # record whose write never happened at all leaves no line
                    # to hash-compare against, only a hole in `seq`.
                    if isinstance(seq, int):
                        if expected_seq is not None and seq != expected_seq:
                            gaps.append({
                                "after_seq":    expected_seq - 1,
                                "expected_seq": expected_seq,
                                "got_seq":      seq,
                            })
                        expected_seq = seq + 1
                    else:
                        # No usable seq on this record -- stop asserting
                        # continuity until we see a real one again rather
                        # than compare against a stale expectation.
                        expected_seq = None

                    prev_hash = stored_this or expected
                    verified += 1
                    if verified >= limit:
                        break

        except Exception as e:
            logger.error("AuditWriter.verify_chain: %s", e)
            error = str(e)

        if error is not None:
            # The walk did not complete -- we cannot claim anything about the
            # chain's integrity, so this must not be reported as ok=True.
            return {"ok": False, "verified": verified, "breaks": breaks, "gaps": gaps, "error": error}

        if total_lines > 0 and verified == 0:
            # The log has content, but every line failed to parse. That is
            # evidence of corruption, not "nothing to verify" -- do not let
            # `len(breaks) == 0` (true only because nothing was ever checked)
            # read as ok=True.
            return {
                "ok": False,
                "verified": 0,
                "breaks": breaks,
                "gaps": gaps,
                "error": f"{unparseable} log line(s) present but none parseable "
                         f"-- cannot verify chain integrity",
            }

        return {
            "ok": len(breaks) == 0 and len(gaps) == 0,
            "verified": verified,
            "breaks": breaks,
            "gaps": gaps,
            "error": None,
        }

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
