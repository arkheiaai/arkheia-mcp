"""
Receipt probe for registry auth decisions — drive the REAL rail, read the
artifact back off disk.

Discipline borrowed wholesale from ``proxy/tests/_receipt_probe.py`` (PR #18),
restated here for a different id field (``receipt_id``, not ``detection_id``)
and, more importantly, so this suite does not import from another open PR's
branch. FOLLOW-UP, not fixed here: once #18 lands, the two should collapse into
one generic probe parameterised by id field. Naming it rather than quietly
duplicating it.

The three ways a "receipt test" fails to answer the receipted question, all
observed in this repo, and how this probe closes each:

1. **It drives a helper, not the writer.** Asserting on the dict
   ``build_record()`` returns proves what the auth path HANDS the audit layer.
   It proves nothing about what reaches disk: ``AuditWriter._writer_loop``
   redacts, chains and serialises after that point, and can drop the record
   entirely (it swallows every exception, and ``write()`` reports but still
   drops on a full queue). A recording stub cannot observe any of that. So this probe
   holds a live ``AuditWriter`` and reads the FILE.

2. **It reads back *a* record, not *this* record.** A test that writes one
   record and asserts something about "the record on disk" passes even when
   the id the caller was handed has nothing to do with the row that landed.
   So: look the row up BY THE SURFACED ID (the ``X-Arkheia-Receipt`` header the
   caller actually received), and prove a fabricated id finds nothing.

3. **It asserts permissively.** ``assert row is not None`` passes for any
   garbage. Every assertion pins a positively-computed expected value, and
   every absence assertion is paired with a positive control proving the probe
   was looking at the right bytes at all.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


class AuthReceiptProbe:
    """Read-back over the receipt file the running server actually writes to."""

    def __init__(self, log_path: Path):
        self.log_path = Path(log_path)

    # -- raw ---------------------------------------------------------------

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

    # -- read-back by SURFACED id -----------------------------------------

    def find(self, receipt_id: str) -> Optional[dict]:
        """
        Locate the row for a receipt id the caller was handed.

        Returns None when no row carries that id — the half that makes the
        vacuity guard possible. A probe that returned "the only row"
        regardless of the id would make every read-back assertion pass by
        accident.
        """
        matches = [r for r in self.rows() if r.get("receipt_id") == receipt_id]
        if not matches:
            return None
        assert len(matches) == 1, (
            f"{len(matches)} rows carry receipt_id={receipt_id!r}; an id that is not "
            f"unique cannot tie a record to the decision it describes"
        )
        return matches[0]

    def require(self, receipt_id: str) -> dict:
        """``find()`` but fails loudly, naming what WAS on disk."""
        row = self.find(receipt_id)
        if row is None:
            present = [r.get("receipt_id") for r in self.rows()]
            raise AssertionError(
                f"no receipt row for receipt_id={receipt_id!r}. {len(present)} row(s) on "
                f"disk carrying ids: {present!r}. Either the decision produced no record, "
                f"or the record is not tied to the id the caller was handed."
            )
        return row

    # -- chain -------------------------------------------------------------

    def recompute_this_hash(self, row: dict) -> str:
        """
        Recompute a row's ``this_hash`` from the row AS IT SITS ON DISK.

        This is what ties a receipt to the tamper-evident chain: the hash is
        computed over the record AFTER redaction, so if the on-disk form
        reproduces the stored hash, the redacted form is what was committed —
        not a plaintext record scrubbed afterwards.
        """
        from proxy.audit.writer import _compute_hash

        body = {k: v for k, v in row.items() if k != "this_hash"}
        return _compute_hash(body, row["prev_hash"])
