"""
Async audit log writer.

Writes one JSONL record per detection event. Non-blocking -- uses an asyncio
queue so writes never delay the response pipeline. Target write latency < 5ms.

Security properties:
  - Secrets redacted at the boundary before any write (see redactor.py).
    ORDER MATTERS: the record is sanitised into JSON-native, all-string
    shapes (_sanitize_for_json) BEFORE redact() ever sees it, never after.
    A set or an arbitrary object is invisible to the redactor (not a
    container it descends into, not a string it can scan) -- sanitizing
    such a value turns it INTO a new string, and a string created after
    redaction reaches disk unscrubbed. Regression found in review
    (2026-07-27): the first version of the non-serialisable-value fix ran
    redact() first and shipped exactly this leak.
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
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import NamedTuple, Optional

from proxy.audit.redactor import redact

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

# A chain hash is EXACTLY what hashlib.sha256().hexdigest() emits: 64 lowercase
# hex characters. Anchored, so no prefix/suffix smuggling. Anything else read
# back from disk is not a hash with an unusual value -- it is corrupt state.
_HASH_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# How often the degraded-chain signal is re-emitted while the writer keeps
# working. See AuditWriter._note_degraded_chain: a corrupted chain must stay
# visible in the log stream, not be one boot line that scrolls away.
_DEGRADED_REPEAT_EVERY = 50


def _is_valid_chain_hash(value: object) -> bool:
    """True only for a well-formed sha256 hexdigest (or the genesis sentinel)."""
    return isinstance(value, str) and _HASH_RE.match(value) is not None


def _is_valid_seq(value: object) -> bool:
    """
    True only for a non-negative Python int.

    ``isinstance(True, int)`` is True, so ``bool`` is excluded explicitly --
    otherwise ``{"seq": true}`` on disk is adopted as sequence number 1.
    """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class ChainState(NamedTuple):
    """
    Chain head recovered from disk, plus whether recovering it was clean.

    ``ok=False`` means the log tail contained something that is not valid chain
    state. ``last_hash``/``last_seq`` are ALWAYS well-formed regardless -- the
    whole point of this type is that a caller can never be handed a poisoned
    value to adopt.
    """
    last_hash: str
    last_seq: int
    ok: bool = True
    detail: Optional[str] = None


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

    MUST run BEFORE redact(), never after. This function's whole job is
    turning shapes the redactor cannot see (a ``set``, an arbitrary object)
    into new strings it CAN see. If those new strings are produced after
    redact() has already run, they are never scanned at all, and any secret
    they carried reaches disk verbatim — a regression that shipped in the
    same PR that introduced this function (2026-07-27), caught in review.
    The caller (``_writer_loop``) always sanitises first, then redacts the
    result.
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


_TAIL_BYTES = 8192


def _load_chain_state(log_path: Path) -> ChainState:
    """
    Read the log tail to recover hash chain state on startup.

    THE LOG IS UNTRUSTED INPUT. Whatever process wrote it, whatever else has
    touched the file since, this function is parsing attacker-controlled bytes
    and handing the result straight into the writer's most privileged state.
    It previously ended::

        last = json.loads(lines[-1])
        return last.get("this_hash", "0" * 64), last.get("seq", 0)

    ``.get(key, default)`` defends only against a MISSING key. A key that is
    PRESENT with a hostile value is adopted verbatim, at whatever type it
    happened to parse as. One appended line carrying ``"this_hash": null``
    therefore recovered ``_last_hash = None``, and every subsequent write hit
    ``_compute_hash(clean, None)`` -> ``TypeError`` -> the record was dropped by
    ``_writer_loop``'s except. ``self._last_hash`` is only reassigned after a
    write SUCCEEDS, so the poisoned value never healed: the audit log stopped
    recording for the entire remaining life of the process, silently, while the
    service reported healthy. That is the exact silent audit loss this module's
    other fixes exist to close, reintroduced through the load path and made
    permanent. It is also a one-append denial of auditing. (Codex adversarial
    review of PR #37, 2026-07-27.)

    So: every field adopted from disk is now VALIDATED, not merely defaulted.
      * ``this_hash`` -> must satisfy ``_is_valid_chain_hash`` (str, 64 chars,
        lowercase hex). Not null, not an int, not 63 chars, not uppercase.
      * ``seq``       -> must satisfy ``_is_valid_seq`` (non-negative int, and
        NOT a bool, which ``isinstance(x, int)`` alone would let through).
    The two returned values are well-formed by construction, so no caller can
    be handed a value that poisons the writer.

    RECOVERY, not reset. Falling back to genesis whenever anything is wrong
    would be its own defect: a restart would silently restart the chain at
    seq 1 and prev_hash 0*64, overwriting the sequence space of records already
    on disk. Instead the tail is walked BACKWARDS for the most recent record
    that carries a well-formed ``this_hash``, and the sequence number adopted
    is the HIGHEST valid ``seq`` seen in the tail, so a number already used on
    disk is never handed out again. Only if the tail yields nothing usable at
    all does this fall back to genesis -- and that case reports ``ok=False``.

    Returns a ChainState. ``ok=False`` + ``detail`` is the load-path half of
    "fail-open, but NEVER fail-silent": the writer still starts and still
    writes (see AuditWriter.start), but it starts KNOWING its chain is corrupt
    and says so on every operator surface for as long as it runs.
    """
    genesis = ChainState(GENESIS_HASH, 0, True, None)
    if not log_path.exists():
        return genesis
    try:
        with open(log_path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return genesis
            # Read last 8 KB — sufficient for any single record
            partial = size > _TAIL_BYTES
            f.seek(max(0, size - _TAIL_BYTES))
            tail = f.read().decode("utf-8", errors="replace")

        lines = [ln.strip() for ln in tail.split("\n") if ln.strip()]
        if partial and lines:
            # The window almost certainly begins mid-record. That is normal for
            # a large log, not corruption, so it must not be reported as such.
            lines = lines[1:]
        if not lines:
            return ChainState(
                GENESIS_HASH, 0, False,
                f"the last {_TAIL_BYTES} bytes of the log contain no complete "
                f"record — chain state could not be recovered",
            )

        problems: list[str] = []
        adopted_hash: Optional[str] = None
        highest_seq: Optional[int] = None

        # Newest line first: the first well-formed this_hash we meet is the
        # most recent usable chain head.
        for back, line in enumerate(reversed(lines), start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                problems.append(f"line -{back} is not valid JSON")
                continue
            if not isinstance(record, dict):
                # A bare array or string parses fine and has no .get at all.
                problems.append(
                    f"line -{back} is a JSON {type(record).__name__}, not an object"
                )
                continue

            this_hash = record.get("this_hash")
            if _is_valid_chain_hash(this_hash):
                if adopted_hash is None:
                    adopted_hash = this_hash
            else:
                problems.append(
                    f"line -{back} this_hash is {type(this_hash).__name__} "
                    f"{this_hash!r:.48} — not a 64-char lowercase hex digest"
                )

            seq = record.get("seq")
            if _is_valid_seq(seq):
                if highest_seq is None or seq > highest_seq:
                    highest_seq = seq
            else:
                problems.append(
                    f"line -{back} seq is {type(seq).__name__} {seq!r:.32} "
                    f"— not a non-negative int"
                )

        if adopted_hash is None:
            return ChainState(
                GENESIS_HASH,
                highest_seq if highest_seq is not None else 0,
                False,
                "no record in the log tail carries a well-formed this_hash; "
                "continuing from the genesis sentinel: " + "; ".join(problems[:3]),
            )

        return ChainState(
            adopted_hash,
            highest_seq if highest_seq is not None else 0,
            not problems,
            "; ".join(problems[:3]) if problems else None,
        )
    except Exception as e:
        # Cannot read the file at all. Genesis is the only state available --
        # and this is emphatically NOT a clean recovery.
        logger.warning("AuditWriter: could not recover chain state: %s", e)
        return ChainState(
            GENESIS_HASH, 0, False,
            f"chain state could not be read from {log_path}: {type(e).__name__}: {e}",
        )


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
        self._last_hash: str = GENESIS_HASH
        self._seq: int = 0
        # Chain health. Not a boot-time log line: a live, queryable state that
        # every operator surface reads for as long as the process runs.
        self._chain_ok: bool = True
        self._chain_status: str = "OK"
        self._chain_detail: Optional[str] = None
        self._chain_detected_at: Optional[str] = None
        self._degraded_since_signal: int = 0
        self._write_failures: int = 0
        self._degraded_writes: int = 0

    # ------------------------------------------------------------------
    # Chain health — the "never fail-silent" surface
    # ------------------------------------------------------------------

    def chain_status(self) -> dict:
        """
        Live audit-chain health, safe to call at any time.

        Published on ``/admin/health`` (via ``app.state.audit_chain``) so a
        corrupted chain is VISIBLE to an operator continuously, not only in a
        startup log line that has long since scrolled away by the time anyone
        looks. ``ok=False`` here is the reason ``/admin/health`` reports a
        top-level status of "degraded" rather than "ok".
        """
        return {
            "ok": self._chain_ok,
            "status": self._chain_status,
            "detail": self._chain_detail,
            "detected_at": self._chain_detected_at,
            "seq": self._seq,
            "write_failures": self._write_failures,
            "degraded_writes": self._degraded_writes,
            "startup_blocked": False,
        }

    def mark_chain_degraded(self, status: str, detail: str) -> None:
        """
        Record that the chain is not trustworthy, and log it loudly ONCE here.

        Idempotent in spirit: the first cause is kept as ``detected_at`` and
        later causes are appended to the detail, so a second finding never
        erases the first. ``_note_degraded_chain`` then keeps re-emitting the
        signal from the writer loop for as long as the state persists.
        """
        first = self._chain_ok
        self._chain_ok = False
        self._chain_status = status
        if first:
            self._chain_detail = detail
            self._chain_detected_at = datetime.now(timezone.utc).isoformat()
        elif detail and detail not in (self._chain_detail or ""):
            self._chain_detail = f"{self._chain_detail}; {detail}"
        logger.error(
            "AuditWriter: audit hash chain is %s — %s. The service continues "
            "(an audit self-check must never be a one-append denial of the "
            "whole proxy) but this chain is NOT trustworthy and is published "
            "on /admin/health until it is repaired.",
            status, detail,
        )

    def _note_degraded_chain(self) -> None:
        """
        Re-emit the degraded signal periodically while the writer keeps working.

        The failure mode this exists to prevent: one WARNING at boot, then a
        service that looks entirely normal in the log stream forever after. A
        corrupted audit chain must keep saying so.
        """
        if self._chain_ok:
            return
        self._degraded_since_signal += 1
        if self._degraded_since_signal % _DEGRADED_REPEAT_EVERY == 1:
            logger.warning(
                "AuditWriter: still writing onto a DEGRADED audit hash chain "
                "(%s, detected %s): %s — %d record(s) written since detection, "
                "%d write failure(s), %d degraded record(s)",
                self._chain_status, self._chain_detected_at, self._chain_detail,
                self._degraded_since_signal, self._write_failures,
                self._degraded_writes,
            )

    async def start(self) -> None:
        """Start the background writer task. Call from app lifespan startup."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Recover chain state from existing log (survive restarts). Every field
        # adopted here is validated inside _load_chain_state -- self._last_hash
        # is a well-formed digest and self._seq a non-negative int by
        # construction, so a hostile log line can no longer poison the writer.
        state = _load_chain_state(self.log_path)
        self._last_hash, self._seq = state.last_hash, state.last_seq
        self._running = True
        self._task = asyncio.create_task(self._writer_loop(), name="audit-writer")
        if not state.ok:
            self.mark_chain_degraded("CORRUPT_CHAIN_STATE", state.detail or "unknown")
        logger.info(
            "AuditWriter started: %s  chain_seq=%d  last_hash=%.16s…  chain=%s",
            self.log_path, self._seq, self._last_hash, self._chain_status,
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
                # 1. Guarantee JSON-serialisability FIRST -- before the
                #    redactor ever sees the record. A `set` is not a
                #    container the redactor descends into, and an arbitrary
                #    object is not a string it can scan, so both pass through
                #    `redact()` completely untouched. `_sanitize_for_json`
                #    turns EXACTLY those two shapes into new strings (a
                #    sorted list of the set's raw elements; a bounded
                #    `repr()` of the object) -- and a string that is created
                #    AFTER redaction reaches disk having never been scrubbed.
                #    Concretely: redact({SECRET}) returns {SECRET} unchanged
                #    (a set, not a string); only sanitizing it into
                #    ['sk-ant-...'] makes the secret redactable at all, so
                #    sanitizing must happen before redact() runs, not after.
                #    (Regression found in review, 2026-07-27: sanitize-after-
                #    redact shipped a leak in this same PR.)
                clean, degraded = _sanitize_for_json(record)
                if degraded:
                    logger.warning(
                        "AuditWriter: record %s contained non-JSON-serialisable "
                        "field(s) — writing a degraded-but-present form instead "
                        "of dropping it",
                        record.get("detection_id", "?"),
                    )

                # 2. Redact secrets before anything touches disk. Runs on the
                #    now fully JSON-native (all-string-shaped) record, so
                #    every string it needs to scan -- including ones that did
                #    not exist before step 1 -- is actually visible to it.
                clean = redact(clean)

                # 3. Compute the NEXT chain position without committing to it
                #    yet. seq/last_hash are only written into self._seq /
                #    self._last_hash after the disk write below actually
                #    succeeds (step 6) — a write that never lands must never
                #    consume a sequence number, or the persisted chain gets a
                #    hole a verifier cannot tell apart from a deleted record.
                #    Belt and braces on the chain head: _load_chain_state can
                #    no longer hand out a malformed one, but this is the single
                #    value whose corruption costs every future record, so it is
                #    checked at the point of use rather than trusted to have
                #    stayed well-formed. Repairing to the genesis sentinel keeps
                #    writes flowing; the break stays visible via chain_status()
                #    and verify_chain().
                if not _is_valid_chain_hash(self._last_hash):
                    self.mark_chain_degraded(
                        "CORRUPT_CHAIN_HEAD",
                        f"in-memory chain head was {type(self._last_hash).__name__} "
                        f"{self._last_hash!r:.48}; reset to the genesis sentinel so "
                        f"records keep being recorded",
                    )
                    self._last_hash = GENESIS_HASH
                if not _is_valid_seq(self._seq):
                    self.mark_chain_degraded(
                        "CORRUPT_CHAIN_SEQ",
                        f"in-memory seq was {type(self._seq).__name__} "
                        f"{self._seq!r:.32}; reset to 0",
                    )
                    self._seq = 0

                next_seq = self._seq + 1
                clean["seq"]       = next_seq
                clean["prev_hash"] = self._last_hash

                # 4. Compute this_hash over the FINAL, fully sanitised and
                #    redacted record (no this_hash yet) -- this must be the
                #    exact same object that step 5 writes to disk, or
                #    verify_chain()'s recomputation on read-back will not
                #    match what was actually persisted.
                #
                #    DEGRADE, DON'T DROP (same posture as _sanitize_for_json).
                #    If hashing or serialising this record raises anyway, the
                #    old code let the exception fall to the outer except and
                #    the record disappeared with nothing but an ephemeral log
                #    line -- the very silent audit loss this module exists to
                #    prevent. Instead we fall back to a minimal, provably
                #    JSON-native stand-in that RECORDS THAT THE EVENT HAPPENED
                #    and why its body could not be written. A degraded record
                #    on disk is recoverable evidence; a dropped one is not.
                try:
                    payload = clean
                    this_hash = _compute_hash(payload, self._last_hash)
                except Exception as hash_exc:
                    self._degraded_writes += 1
                    self.mark_chain_degraded(
                        "DEGRADED_RECORD",
                        f"record {record.get('detection_id', '?')} could not be "
                        f"hashed or serialised ({type(hash_exc).__name__}: "
                        f"{hash_exc}); a placeholder was written in its place",
                    )
                    payload = {
                        "seq": next_seq,
                        "prev_hash": self._last_hash,
                        "detection_id": str(record.get("detection_id", "?"))[:200],
                        "risk_level": "UNKNOWN",
                        "audit_record_degraded": True,
                        "degraded_reason": f"{type(hash_exc).__name__}: {hash_exc}"[:500],
                    }
                    this_hash = _compute_hash(payload, self._last_hash)

                payload["this_hash"] = this_hash
                # The bytes written are exactly the bytes hashed plus this_hash:
                # verify_chain() pops this_hash back off and recomputes over the
                # remainder, so the two must describe the identical structure.
                line = json.dumps(payload)

                # 5. Write
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")

                # 6. Only now commit chain state — the write above is the
                #    last thing that can fail before this point.
                self._seq = next_seq
                self._last_hash = this_hash

            except Exception as e:
                # Nothing reached disk. The record is lost, so the ONE thing
                # that must not also be lost is the fact that it was lost:
                # counted on chain_status() (and therefore /admin/health), and
                # the chain is marked degraded so no surface reports healthy.
                self._write_failures += 1
                self.mark_chain_degraded(
                    "WRITE_FAILED",
                    f"record {record.get('detection_id', '?')} could not be "
                    f"written ({type(e).__name__}: {e}) — sequence NOT advanced "
                    f"(chain state unchanged, no gap created)",
                )
            finally:
                self._note_degraded_chain()
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

        # `risk_level` comes straight off an untrusted log line, and this loop
        # sits OUTSIDE the try above. An unhashable value (`[]`, `{}`) made
        # `summary[rl]` raise TypeError out of the whole method, so one appended
        # line took down /audit/log and the MCP arkheia_audit_log tool with it.
        # Same class as the load path: parsed JSON trusted by type.
        summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
        for e in events:
            rl = e.get("risk_level", "UNKNOWN") if isinstance(e, dict) else "UNKNOWN"
            if not isinstance(rl, str):
                rl = "UNKNOWN"
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

                    if not isinstance(record, dict):
                        # A bare JSON array/string/number parses fine and has
                        # no fields to check. Count it as unverifiable content,
                        # not as a verified record.
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
                    # _is_valid_seq, not isinstance(seq, int): `"seq": true`
                    # is an int to isinstance() and would be treated as 1.
                    if _is_valid_seq(seq):
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

                    # The link carried forward must itself be a well-formed
                    # hash. `stored_this or expected` adopted whatever type
                    # this_hash happened to have: a non-empty non-str (e.g.
                    # `123`) became the next prev_hash and made _compute_hash
                    # raise on the NEXT record, aborting the walk and leaving
                    # every later record unverified. A tampered value must be
                    # reported (it already is, just above) and the walk must
                    # keep going, not stop looking.
                    prev_hash = stored_this if _is_valid_chain_hash(stored_this) else expected
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
