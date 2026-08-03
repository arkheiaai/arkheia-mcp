"""
Receipt probe — drive the REAL audit rail and read the artifact back off disk.

THE ONE PROBE. Three near-identical copies of this discipline existed across the
receipted-axis branches, differing only in which field carries the surfaced id:

  * ``proxy/tests/_receipt_probe.py``            — ``detection_id``  (PR #18)
  * ``registry_server/tests/_auth_receipt_probe.py`` — ``receipt_id``  (registry auth)
  * ``MemoryReceiptProbe`` inside
    ``mcp_server/tests/test_memory_receipts.py``     — ``receipt_id``  (memory KG)

They are collapsed here, with the id field parameterised. Every proof property any
copy had is kept — see PROOF PROPERTIES below; nothing was dropped. Adoption for a
flow whose id field is ``receipt_id`` is one argument::

    probe = ReceiptProbe(path, id_field="receipt_id")

WHY THIS EXISTS
---------------
The `receipted` axis asks a specific question: *the flow makes a decision — does
that decision leave a durable record, written on the production path, that can be
read back and tied to the decision it describes?*

Three ways a "receipt test" fails to answer it, all seen in this repo:

1. **It drives a helper, not the writer.** Asserting on the dict that
   ``_audit_record()`` / ``build_record()`` returns proves what the flow *hands*
   the audit layer. It proves nothing about what reaches disk — the writer
   redacts, chains and serialises after that point, and can drop the record
   entirely (``AuditWriter._writer_loop`` swallows every exception, and
   ``write()`` reports but still drops on a full queue). A recording stub cannot
   observe any of that.

2. **It reads back *a* record, not *this* record.** A test that writes one record
   and then asserts something about "the record on disk" passes even when the id
   the caller was handed has nothing to do with the row that landed. The guard is
   to look the row up **by the surfaced id** and to prove that a *fabricated* id
   finds nothing — otherwise the lookup is decorative.

3. **It asserts permissively.** ``assert record is not None`` passes for any
   garbage. Every assertion in the suites that use this probe pins a positively
   computed expected value, and every absence assertion is paired with a positive
   control proving the probe was looking at the right bytes at all.

PROOF PROPERTIES — the union of what the three copies collectively had
----------------------------------------------------------------------
P1. **Drives the real writer.** ``start()``/``write()``/``stop()`` hold a live
    ``AuditWriter`` and drain its queue, so a record has been through the
    production ``_writer_loop`` before any assertion runs. (From the proxy copy.)
P2. **Read-only mode over a file the production code wrote.** A flow that
    constructs its own writer (registry auth, memory KG) points the probe at the
    path and never calls ``start()``. The writer is constructed lazily, so this
    mode has no side effects at all. (From the registry / memory copies.)
P3. **Look-up BY THE SURFACED ID**, in a parameterised field, so a row can be
    tied to the decision the caller was told about.
P4. **A fabricated id finds nothing** — ``find()`` returns ``None`` rather than
    "the only row", which is what lets a suite pair an absence assertion with a
    positive control.
P5. **An id that is not unique is an error**, not a silently-picked first match.
P6. **``require()`` fails loudly, naming what WAS on disk**, so a red run says
    which ids landed instead of "assert row is not None".
P7. **Raw bytes, unparsed** — ``raw_bytes()`` / ``contains()`` for "this text is
    NOT in the evidence file", asserted on bytes rather than a parsed view.
P8. **Recompute the chain hash from the row AS IT SITS ON DISK.**
P9. **Delegate to the production chain verifier** — ``verify_chain()``.

This module is deliberately NOT named ``test_*`` so pytest does not collect it;
it is imported by the receipt test modules. Its own contract is tested by
``proxy/tests/test_receipt_probe_contract.py``.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Optional

from proxy.audit.writer import AuditWriter, _compute_hash

#: The id field the proxy's own detection records carry. Other flows pass their own.
DEFAULT_ID_FIELD = "detection_id"


class ReceiptProbe:
    """
    Read-back over the receipt file the production path actually writes to,
    optionally driving a live ``AuditWriter`` itself.

    Writer-owned mode (the proxy's own audit rail)::

        probe = ReceiptProbe(tmp_path / "audit.jsonl")
        await probe.start()
        await probe.write({"detection_id": "...", ...})
        await probe.stop()
        row = probe.require("...")

    ``write()`` drains the writer's queue before returning, so by the time it
    returns the record has been through the production ``_writer_loop`` — redact,
    chain, serialise, append — exactly as it would in the running proxy. Nothing
    here reimplements that path.

    Read-only mode (a flow that constructs its own writer per emit)::

        probe = ReceiptProbe(log_path, id_field="receipt_id")
        result = await store_entity(...)          # the REAL tool writes the file
        row = probe.require(result["receipt_id"])

    In read-only mode the ``AuditWriter`` is never constructed unless
    ``verify_chain()`` or a lifecycle method asks for it, so pointing a probe at a
    path costs nothing and creates nothing.
    """

    def __init__(
        self,
        log_path: Path,
        retention_days: int = 365,
        *,
        id_field: str = DEFAULT_ID_FIELD,
    ):
        self.log_path = Path(log_path)
        self.id_field = id_field
        self.retention_days = retention_days
        self._writer: Optional[AuditWriter] = None

    # -- lifecycle ---------------------------------------------------------

    @property
    def writer(self) -> AuditWriter:
        """
        The live writer, constructed on first use.

        Lazy so that read-only mode (P2) has no side effects: a probe that merely
        reads a file the flow under test wrote must not itself instantiate queues
        or touch the filesystem.
        """
        if self._writer is None:
            self._writer = AuditWriter(
                str(self.log_path), retention_days=self.retention_days
            )
        return self._writer

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

    def find(self, receipt_id: str) -> Optional[dict]:
        """
        Locate the row for an id the caller was handed, in ``self.id_field``.

        Returns None when no row carries that id — this is the half that makes the
        vacuity guard possible. A probe that returned "the only row" regardless of
        the id would make every read-back assertion pass by accident.
        """
        matches = [r for r in self.rows() if r.get(self.id_field) == receipt_id]
        if not matches:
            return None
        assert len(matches) == 1, (
            f"{len(matches)} rows carry {self.id_field}={receipt_id!r}; a receipt id "
            f"that is not unique cannot tie a record to the decision it describes"
        )
        return matches[0]

    def require(self, receipt_id: str) -> dict:
        """``find()`` but fails loudly, naming what WAS on disk."""
        row = self.find(receipt_id)
        if row is None:
            present = [r.get(self.id_field) for r in self.rows()]
            raise AssertionError(
                f"no audit row for {self.id_field}={receipt_id!r}. "
                f"{len(present)} row(s) on disk carrying ids: {present!r}. "
                f"Either the decision produced no record, or the record is not "
                f"tied to the id the caller was handed."
            )
        return row

    # -- chain -------------------------------------------------------------

    def verify_chain(self) -> dict:
        """Delegate to the production chain verifier — not a reimplementation."""
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


def assert_decision_identity(
    row: dict, *, branch: str, expect_source: Optional[str] = None
) -> None:
    """
    Every governance row on the rail carries the identity of the decision it
    describes — asserted on the row AS READ BACK OFF DISK.

    Why this is its own helper rather than three lines in each test: a
    hash-chained row with no ``decision_id``, no ``decided_at`` and
    ``receipt_deferred_ms: null`` is a record that LOOKS like evidence and is
    not one — worse than no row, because it counts. Codex reproduced exactly
    that on the production key-load branches of ``proxy/main.py`` (PR #34) while
    the covering tests asserted only row existence, ``outcome`` and count, and
    therefore could not see it.

    Every assertion below pins a positively computed value. ``receipt_deferred_ms``
    in particular is checked against the difference between the two timestamps in
    the same row, so a hard-coded zero cannot satisfy it.
    """
    import uuid as _uuid
    from datetime import datetime

    decision_id = row.get("decision_id")
    assert decision_id, (
        f"{branch}: the row on disk carries no decision_id "
        f"({decision_id!r}). A hash-chained row that cannot be tied to the "
        f"decision it describes is not a receipt. Fields present on the row: "
        # NAMES, never values. Every field on a decision record is built from
        # arguments whose lineage includes key material, so a diagnostic that
        # dumps the row is one careless future field away from printing it —
        # the same reasoning that produced _label()/_uuid_label() after CodeQL
        # flagged this module. The shape is what a red run needs anyway.
        f"{sorted(row)}"
    )
    assert str(_uuid.UUID(hex=str(decision_id))) == str(decision_id), (
        f"{branch}: decision_id {decision_id!r} is not a canonical UUID"
    )

    decided_at = row.get("decided_at")
    assert decided_at, (
        f"{branch}: the row on disk carries no decided_at ({decided_at!r}). "
        f"Without it nothing states WHEN the decision was taken, and the "
        f"deferral this flow exists to disclose cannot be computed at all"
    )
    decided = datetime.fromisoformat(str(decided_at))
    assert decided.tzinfo is not None, (
        f"{branch}: decided_at {decided_at!r} carries no timezone"
    )

    enqueued_at = row.get("receipt_enqueued_at")
    assert enqueued_at, f"{branch}: the row carries no receipt_enqueued_at"
    enqueued = datetime.fromisoformat(str(enqueued_at))

    deferred = row.get("receipt_deferred_ms")
    assert isinstance(deferred, (int, float)) and not isinstance(deferred, bool), (
        f"{branch}: receipt_deferred_ms is {deferred!r}, not a number. The "
        f"deferral-as-a-field mechanism reports null exactly when the record "
        f"never had a decided_at to defer from — a null here means the branch "
        f"never reached the mechanism"
    )
    assert deferred >= 0, f"{branch}: receipt_deferred_ms is negative ({deferred})"

    expected = round((enqueued - decided).total_seconds() * 1000.0, 3)
    assert abs(deferred - expected) < 1.0, (
        f"{branch}: receipt_deferred_ms={deferred} does not describe the gap "
        f"between decided_at and receipt_enqueued_at in the same row "
        f"({expected}). A constant would satisfy 'is a number'; it must not "
        f"satisfy this"
    )

    source = row.get("decided_at_source")
    assert source in ("journalled_at_decision", "stamped_at_emit"), (
        f"{branch}: decided_at_source is {source!r}. A reader must be able to "
        f"tell a decided_at recorded AT the decision from one stamped when the "
        f"record reached the rail; an unlabelled timestamp claims the first "
        f"while possibly being the second"
    )
    if expect_source is not None:
        assert source == expect_source, (
            f"{branch}: decided_at_source is {source!r}, expected "
            f"{expect_source!r}. A record journalled at the decision and one "
            f"stamped when it reached the rail describe different facts, and a "
            f"row that reports the wrong one is telling a reader the deferral "
            f"was something it was not"
        )
