"""
Receipt probe — drive the REAL audit rail and read the artifact back off disk.

WHY THIS EXISTS
---------------
The `receipted` axis asks a specific question: *the flow makes a decision — does
that decision leave a durable record, written on the production path, that can be
read back and tied to the decision it describes?*

Three ways a "receipt test" fails to answer it, all seen in this repo:

1. **It drives a helper, not the writer.** Asserting on the dict that
   ``_audit_record()`` returns proves what the endpoint *hands* the audit layer.
   It proves nothing about what reaches disk — the writer redacts, chains and
   serialises after that point, and can drop the record entirely
   (``AuditWriter._writer_loop`` swallows every exception, and ``write()`` drops
   silently on a full queue). A recording stub cannot observe any of that.

2. **It reads back *a* record, not *this* record.** A test that writes one record
   and then asserts something about "the record on disk" passes even when the id
   the caller was handed has nothing to do with the row that landed. The guard is
   to look the row up **by the surfaced id** and to prove that a *fabricated* id
   finds nothing — otherwise the lookup is decorative.

3. **It asserts permissively.** ``assert record is not None`` passes for any
   garbage. Every assertion here pins a positively-computed expected value, and
   every absence assertion is paired with a positive control proving the probe was
   looking at the right bytes at all.

This module is deliberately NOT named ``test_*`` so pytest does not collect it;
it is imported by the receipt test modules.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from proxy.audit.writer import AuditWriter, _compute_hash


class ReceiptProbe:
    """
    A live ``AuditWriter`` plus read-back helpers.

    Usage::

        probe = ReceiptProbe(tmp_path / "audit.jsonl")
        await probe.start()
        await probe.write({"detection_id": "...", ...})
        await probe.stop()
        row = probe.require("...")

    ``write()`` drains the writer's queue before returning, so by the time it
    returns the record has been through the production ``_writer_loop`` — redact,
    chain, serialise, append — exactly as it would in the running proxy. Nothing
    here reimplements that path.
    """

    def __init__(self, log_path: Path, retention_days: int = 365):
        self.log_path = Path(log_path)
        self.writer = AuditWriter(str(self.log_path), retention_days=retention_days)

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> "ReceiptProbe":
        await self.writer.start()
        return self

    async def stop(self) -> None:
        await self.writer.stop()

    async def write(self, record: dict) -> None:
        """Enqueue via the production API and wait until the loop has drained it."""
        await self.writer.write(record)
        await asyncio.wait_for(self.writer._queue.join(), timeout=5.0)

    # -- read-back ---------------------------------------------------------

    def raw_bytes(self) -> bytes:
        """The exact bytes on disk. Nothing parses or normalises them first."""
        if not self.log_path.exists():
            return b""
        return self.log_path.read_bytes()

    def rows(self) -> list[dict]:
        """Every record on disk, parsed, in write order."""
        out: list[dict] = []
        for line in self.raw_bytes().decode("utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out

    def find(self, detection_id: str) -> Optional[dict]:
        """
        Locate the row for a surfaced ``detection_id``.

        Returns None when no row carries that id — this is the half that makes the
        vacuity guard possible. A probe that returned "the only row" regardless of
        the id would make every read-back assertion pass by accident.
        """
        matches = [r for r in self.rows() if r.get("detection_id") == detection_id]
        if not matches:
            return None
        assert len(matches) == 1, (
            f"{len(matches)} rows carry detection_id={detection_id!r}; a receipt id "
            f"that is not unique cannot tie a record to its decision"
        )
        return matches[0]

    def require(self, detection_id: str) -> dict:
        """``find()`` but fails loudly, naming what WAS on disk."""
        row = self.find(detection_id)
        if row is None:
            present = [r.get("detection_id") for r in self.rows()]
            raise AssertionError(
                f"no audit row for detection_id={detection_id!r}. "
                f"{len(present)} row(s) on disk carrying ids: {present!r}. "
                f"The decision produced no record, or the record is not tied to "
                f"the id the caller was handed."
            )
        return row

    # -- chain -------------------------------------------------------------

    def verify_chain(self) -> dict:
        return self.writer.verify_chain()

    def recompute_this_hash(self, row: dict) -> str:
        """
        Recompute a row's ``this_hash`` from the row AS IT SITS ON DISK.

        This is what ties a receipt to the tamper-evident chain: the chain hash is
        computed over the record *after* redaction, so if the on-disk (redacted)
        form reproduces the stored hash, the redacted form is what was committed —
        not a plaintext record scrubbed afterwards.
        """
        body = {k: v for k, v in row.items() if k != "this_hash"}
        return _compute_hash(body, row["prev_hash"])


def contains(haystack: bytes, needle: Any) -> bool:
    """Substring test against the raw on-disk bytes, not a parsed view."""
    return str(needle).encode("utf-8") in haystack
