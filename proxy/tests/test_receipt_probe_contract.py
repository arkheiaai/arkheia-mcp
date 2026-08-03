"""
The collapsed ``ReceiptProbe`` still has every proof property its three copies had.

WHY THIS SUITE EXISTS
---------------------
Three near-identical probes were collapsed into one (see
``proxy/tests/_receipt_probe.py``). A collapse is exactly the operation that
silently drops a guarantee: the merged helper keeps working for the loudest
caller while a property only the quietest copy had disappears, and no test
notices because the property lived in the helper, not in any suite's assertions.

So the helper's own contract is pinned here, property by property, in BOTH modes
(writer-owned and read-only) and for BOTH id fields (``detection_id``, the
proxy's; ``receipt_id``, the registry-auth and memory-KG flows'). If a future
"cleanup" removes lazy construction, hard-codes the id field, makes ``find()``
return the only row, or drops the chain recomputation, one of these goes red.

Every absence assertion below is paired with a positive control, because
"nothing found" and "looked in the wrong place" are the same result.
"""

import json
import uuid

import pytest

from proxy.audit.writer import AuditWriter
from proxy.tests._receipt_probe import DEFAULT_ID_FIELD, ReceiptProbe, contains

# The same construction discipline as the redaction suite: no credential-shaped
# literal in the source, but an exact match for a redactor pattern at runtime.
_SECRET = "sk-" + "ant-" + ("A9fK2mQ7xR4tL8vN3wB6yC1zD5eG0hJ" * 2)
MARKER = "probe-contract-positive-control-4c11"


def _record(id_value: str, id_field: str = DEFAULT_ID_FIELD, **extra) -> dict:
    rec = {
        id_field: id_value,
        "timestamp": "2026-07-26T00:00:00+00:00",
        "session_id": MARKER,
        "source": "probe-contract",
        "error": None,
    }
    rec.update(extra)
    return rec


# ---------------------------------------------------------------------------
# P1 — writer-owned mode drives the REAL writer, not a file append
# ---------------------------------------------------------------------------

async def test_a_written_record_went_through_the_production_writer_loop(tmp_path):
    """
    The distinguishing evidence that the production loop ran — rather than the
    probe appending JSON itself — is that the record arrives REDACTED and
    CHAINED. A helper that wrote the dict straight to the file would land the
    credential verbatim and carry no seq/prev_hash/this_hash.
    """
    probe = ReceiptProbe(tmp_path / "audit.jsonl")
    await probe.start()
    try:
        det_id = str(uuid.uuid4())
        await probe.write(_record(det_id, error=f"upstream rejected {_SECRET}"))
    finally:
        await probe.stop()

    raw = probe.raw_bytes()
    assert contains(raw, MARKER), (
        "positive control absent — the probe is reading the wrong bytes, so the "
        "absence assertion below would prove nothing"
    )
    assert not contains(raw, _SECRET), "the writer's redaction did not run"

    row = probe.require(det_id)
    assert row["seq"] == 1
    assert row["prev_hash"] == "0" * 64
    assert row["this_hash"] == probe.recompute_this_hash(row)


# ---------------------------------------------------------------------------
# P2 — read-only mode: no writer is constructed, nothing is created
# ---------------------------------------------------------------------------

def test_pointing_a_probe_at_a_path_constructs_no_writer_and_creates_nothing(tmp_path):
    """
    The registry-auth and memory-KG flows construct their OWN writer per emit and
    hand the probe a path. If the probe eagerly built an ``AuditWriter``, a suite
    that merely inspects a path would allocate a queue and (on ``start``) create
    directories — a probe with side effects can change the thing it observes.
    """
    path = tmp_path / "nested" / "receipts.jsonl"
    probe = ReceiptProbe(path, id_field="receipt_id")

    assert probe._writer is None
    assert not path.exists()
    assert not path.parent.exists()

    # And an absent file reads as empty rather than raising.
    assert probe.raw_bytes() == b""
    assert probe.rows() == []
    assert probe.find("anything") is None

    # POSITIVE CONTROL: the writer is still reachable when something asks for it.
    assert probe.writer is not None
    assert probe._writer is not None


async def test_read_only_mode_reads_back_a_file_another_writer_produced(tmp_path):
    """The mode the memory-KG and registry-auth suites actually use."""
    path = tmp_path / "receipts.jsonl"
    writer = AuditWriter(str(path))
    await writer.start()
    try:
        rid = str(uuid.uuid4())
        await writer.write(_record(rid, "receipt_id", decision="recorded"))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path, id_field="receipt_id")
    assert probe._writer is None, "read-back must not need a writer of its own"
    row = probe.require(rid)
    assert row["decision"] == "recorded"
    assert row["this_hash"] == probe.recompute_this_hash(row)


# ---------------------------------------------------------------------------
# P3 — the id field is genuinely parameterised, not defaulted-and-ignored
# ---------------------------------------------------------------------------

async def test_the_id_field_is_the_field_that_is_searched(tmp_path):
    """
    The single reason the three copies existed. A collapse that kept looking in
    ``detection_id`` while accepting an ``id_field`` argument would pass every
    proxy test and silently stop finding registry / memory rows.

    Both fields are present on the SAME row with DIFFERENT values, so a probe
    reading the wrong one resolves the wrong id — and the pairing means neither
    half can pass by the row simply being absent.
    """
    path = tmp_path / "audit.jsonl"
    det_id, rid = str(uuid.uuid4()), str(uuid.uuid4())

    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(det_id, DEFAULT_ID_FIELD, receipt_id=rid))
    finally:
        await writer.stop()

    by_detection = ReceiptProbe(path)
    by_receipt = ReceiptProbe(path, id_field="receipt_id")

    assert by_detection.id_field == DEFAULT_ID_FIELD == "detection_id"
    assert by_detection.find(det_id) is not None
    assert by_detection.find(rid) is None

    assert by_receipt.find(rid) is not None
    assert by_receipt.find(det_id) is None


# ---------------------------------------------------------------------------
# P4 — a fabricated id finds nothing, paired with a positive control
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("id_field", ["detection_id", "receipt_id"])
async def test_a_fabricated_id_finds_nothing_while_the_real_one_resolves(tmp_path, id_field):
    path = tmp_path / f"{id_field}.jsonl"
    real = str(uuid.uuid4())

    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(real, id_field))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path, id_field=id_field)
    assert probe.find(real) is not None, "positive control: the real id must resolve"
    assert probe.find("0" * 32) is None
    assert probe.find(real[:-1] + ("0" if real[-1] != "0" else "1")) is None


# ---------------------------------------------------------------------------
# P5 — a non-unique id is an error, not a silently-picked first match
# ---------------------------------------------------------------------------

async def test_two_rows_carrying_one_id_fail_rather_than_resolve(tmp_path):
    """
    An id that maps to two rows cannot tie a record to a decision. Returning the
    first would make the ambiguity invisible exactly when it matters.
    """
    path = tmp_path / "audit.jsonl"
    dup = str(uuid.uuid4())

    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(dup))
        await writer.write(_record(dup))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path)
    with pytest.raises(AssertionError, match="not unique"):
        probe.find(dup)


# ---------------------------------------------------------------------------
# P6 — require() fails loudly, naming what WAS on disk
# ---------------------------------------------------------------------------

async def test_a_missing_row_names_the_ids_that_did_land(tmp_path):
    """
    ``assert row is not None`` tells a reader nothing. The failure has to name the
    ids present, because the common cause is a record written under a DIFFERENT
    id than the caller was handed — invisible from a bare truthiness failure.
    """
    path = tmp_path / "audit.jsonl"
    landed = str(uuid.uuid4())

    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(landed))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path)
    with pytest.raises(AssertionError) as exc:
        probe.require("absent-id")

    message = str(exc.value)
    assert "absent-id" in message
    assert landed in message, "the failure must name what DID land, not just what did not"
    assert "detection_id" in message, "the failure must name the field it searched"


# ---------------------------------------------------------------------------
# P7 — raw bytes, unparsed
# ---------------------------------------------------------------------------

async def test_raw_bytes_are_the_bytes_on_disk(tmp_path):
    """
    "The secret is not in the evidence file" is only true if asserted on bytes. A
    parsed view would miss a credential embedded in a key, a nested string, or a
    field the parser drops.
    """
    path = tmp_path / "audit.jsonl"
    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(str(uuid.uuid4())))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path)
    assert probe.raw_bytes() == path.read_bytes()
    assert contains(probe.raw_bytes(), MARKER)
    assert not contains(probe.raw_bytes(), "a-string-that-was-never-written")


# ---------------------------------------------------------------------------
# P8 — the chain hash is recomputed from the row as it sits on disk
# ---------------------------------------------------------------------------

async def test_the_recomputation_detects_an_edited_row(tmp_path):
    """
    POSITIVE CONTROL for every ``this_hash == recompute_this_hash(row)`` assertion
    in the receipt suites: a recomputation that could not disagree would satisfy
    all of them. Rewrite a field on disk and require the recomputation to differ.
    """
    path = tmp_path / "audit.jsonl"
    det_id = str(uuid.uuid4())

    writer = AuditWriter(str(path))
    await writer.start()
    try:
        await writer.write(_record(det_id))
    finally:
        await writer.stop()

    probe = ReceiptProbe(path)
    row = probe.require(det_id)
    assert row["this_hash"] == probe.recompute_this_hash(row)

    tampered = dict(row)
    tampered["source"] = "somewhere-else"
    path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")

    after = probe.require(det_id)
    assert after["this_hash"] != probe.recompute_this_hash(after)


# ---------------------------------------------------------------------------
# P9 — verify_chain() delegates to the production verifier and can fail
# ---------------------------------------------------------------------------

async def test_chain_verification_delegates_and_can_go_false(tmp_path):
    path = tmp_path / "audit.jsonl"
    probe = ReceiptProbe(path)
    await probe.start()
    try:
        for _ in range(3):
            await probe.write(_record(str(uuid.uuid4())))
    finally:
        await probe.stop()

    assert probe.verify_chain()["ok"] is True

    rows = probe.rows()
    rows[1]["source"] = "forged"
    path.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )

    assert probe.verify_chain()["ok"] is False
