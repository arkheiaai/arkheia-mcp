"""
RECEIPTED — Binary integrity verification, D2: the RUNTIME verdict.

Phase 1: what decision are we demanding a record of?
----------------------------------------------------
``proxy/license/integrity.py`` makes two decisions, and they need separating
because only one of them was ever evidenced.

**D1, build time** — *"these hashes are the trusted state of this artifact"*.
Its durable record is ``integrity_manifest.json``, shipped inside the release and
read back by ``verify_integrity``. That record is proved end-to-end in
``proxy/tests/test_integrity_manifest_receipt.py``; it is not re-proved here.

**D2, runtime** — *"the binaries on this host, right now, do / do not match those
hashes"*. This is the decision an auditor, a customer or an incident responder
actually asks about, and before this change it left **nothing**. Verified against
the pre-fix code, not inferred:

* the pass path produced ``logger.info("Integrity check passed: %d modules
  verified")`` — a log line, not an artefact, gone with the process;
* the tamper path raised ``TamperDetected`` and wrote **zero** new files (asserted
  by diffing the directory before and after the raise);
* and no production code called ``verify_integrity`` at all — ``grep`` across
  every branch found callers only in ``tests/``, while the module docstring said
  "At startup, verifies…". A mechanism nothing invokes cannot be receipted,
  so the wiring is part of the fix and ``test_the_proxy_actually_runs_this_at_
  startup`` drives the real lifespan to prove it.

For a tamper-evidence mechanism specifically, an unrecorded verdict is close to
worthless: the mechanism exists to let someone *afterwards* establish what state
the binaries were in, and a verdict that evaporates with the process cannot do
that. So this is emphatically not an ``n/a``.

Phase 2: what proving it requires
---------------------------------
* **The estate's rail, not a new one.** The receipt goes onto the existing
  tamper-evident audit log via the production ``AuditWriter``, and the tests drive
  it through ``ReceiptProbe`` — the same instrument PR #16/#18 use — so the record
  is redacted, chained and serialised by the real writer loop.
* **The record must say WHAT, WHEN and AGAINST WHICH expected digest.** Every
  assertion below recomputes the expected value independently from the file bytes
  in the test. A receipt that merely says "ok" would pass a weaker test and prove
  nothing; ``manifest_sha256`` is asserted too, because "verified" against an
  attacker-supplied manifest and "verified" against the shipped one must not be
  the same record.
* **Both outcomes.** A receipt only on the happy path is the failure shape this
  sweep exists to catch, so the tamper verdict is required to be on disk *before*
  the raise lands.
* **Vacuity guards.** A fabricated receipt id must find nothing, or every
  read-back assertion is decorative.
* **Absence of a guarantee is not a guarantee.** The rail is lossy by design
  (``write()`` drops on a full queue, ``_writer_loop`` swallows write errors), so
  ``_emit_receipt`` confirms by read-back and ``ReceiptNotDurable`` is proved to
  fire — and proved NOT to suppress a tamper halt.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from pathlib import Path

import pytest

from proxy.audit.writer import AuditWriter
from proxy.license.integrity import (
    INTEGRITY_EVENT_TYPE,
    VERDICT_TAMPERED,
    VERDICT_UNVERIFIABLE,
    VERDICT_VERIFIED,
    ReceiptNotDurable,
    TamperDetected,
    build_integrity_record,
    generate_manifest,
    runtime_module_dirs,
    verify_and_receipt,
    verify_integrity,
)
from proxy.tests._receipt_probe import ReceiptProbe

MODULE_A = "features.cpython-312-x86_64-linux-gnu.so"
MODULE_B = "profile_router.cpython-312-x86_64-linux-gnu.so"


def _sha(data: bytes) -> str:
    """Digest computed in the TEST, from bytes the test controls."""
    return hashlib.sha256(data).hexdigest()


def _release_dir(tmp_path: Path, **modules: bytes) -> Path:
    """A directory of compiled artifacts plus the manifest that certifies them."""
    d = tmp_path / "release"
    d.mkdir(exist_ok=True)
    for name, payload in modules.items():
        (d / name.replace("__", ".")).write_bytes(payload)
    generate_manifest(d, d / "integrity_manifest.json")
    return d


async def _probe(tmp_path: Path) -> ReceiptProbe:
    probe = ReceiptProbe(tmp_path / "audit.jsonl")
    await probe.start()
    return probe


# ---------------------------------------------------------------------------
# The verified verdict — and what the record has to contain to be evidence
# ---------------------------------------------------------------------------


async def test_a_verified_run_records_what_it_verified_against_which_digests(tmp_path):
    """
    The pass path leaves a record naming every module, its expected digest and the
    digest actually observed — each recomputed here from the real file bytes.

    ``assert verdict == "verified"`` alone would be satisfied by a record that
    certifies nothing, which is exactly the D1 defect one layer down.
    """
    payload_a = b"compiled feature extractor v1"
    payload_b = b"compiled profile router v1"
    d = _release_dir(tmp_path, **{MODULE_A: payload_a, MODULE_B: payload_b})
    manifest_bytes = (d / "integrity_manifest.json").read_bytes()

    probe = await _probe(tmp_path)
    try:
        record = await verify_and_receipt(d, probe.writer)
    finally:
        await probe.stop()

    row = probe.require(record["receipt_id"])          # read back BY ID, off disk

    assert row["event_type"] == INTEGRITY_EVENT_TYPE
    assert row["verdict"] == VERDICT_VERIFIED
    assert row["reason"] == "all_modules_matched"
    assert row["risk_level"] == "LOW"
    assert row["module_dir"] == str(d.resolve())

    # WHICH expected-digest set. A record that omits this cannot distinguish a
    # pass against the shipped manifest from a pass against a swapped one.
    assert row["manifest_sha256"] == _sha(manifest_bytes)

    # WHAT, per module — no aggregate stands in for the units (floor inv. 9(a)).
    assert row["modules_expected"] == 2
    assert row["modules_matched"] == 2
    assert row["modules_not_matched"] == []
    by_name = {m["name"]: m for m in row["modules"]}
    assert set(by_name) == {MODULE_A, MODULE_B}
    for name, payload in ((MODULE_A, payload_a), (MODULE_B, payload_b)):
        assert by_name[name]["expected_sha256"] == _sha(payload)
        assert by_name[name]["actual_sha256"] == _sha(payload)
        assert by_name[name]["result"] == "match"

    # WHEN — parseable, not a free-text stamp.
    from datetime import datetime

    datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))


async def test_a_fabricated_receipt_id_finds_nothing(tmp_path):
    """
    Vacuity guard for every read-back above: the lookup must discriminate.

    Includes a one-character mutation of the real id, because a lookup that
    returned "the only row" would pass a random-UUID probe by luck.
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"payload"})
    probe = await _probe(tmp_path)
    try:
        record = await verify_and_receipt(d, probe.writer)
    finally:
        await probe.stop()

    real = record["receipt_id"]
    assert probe.find(real) is not None                       # positive control
    assert probe.find(str(uuid.uuid4())) is None
    mutated = real[:-1] + ("0" if real[-1] != "0" else "1")
    assert probe.find(mutated) is None


async def test_the_receipt_is_sealed_into_the_tamper_evident_chain(tmp_path):
    """
    An integrity receipt that could be edited afterwards would be a poor witness.
    Recompute ``this_hash`` from the row AS IT SITS ON DISK, and walk the chain.
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"payload"})
    probe = await _probe(tmp_path)
    try:
        record = await verify_and_receipt(d, probe.writer)
    finally:
        await probe.stop()

    row = probe.require(record["receipt_id"])
    assert row["this_hash"] == probe.recompute_this_hash(row)
    assert probe.verify_chain() == {"ok": True, "verified": 1, "breaks": []}


# ---------------------------------------------------------------------------
# The adverse verdict — the one that actually matters
# ---------------------------------------------------------------------------


async def test_a_tamper_finding_is_on_disk_before_it_raises(tmp_path):
    """
    The POSITIVE finding is the whole point of a tamper check, and pre-fix it was
    the outcome with the least evidence: an exception message and nothing written.

    Requires the record to exist after the raise, to be classified HIGH, and to
    carry both digests — what was expected and what was actually found — so the
    finding can be investigated from the record alone.
    """
    original = b"compiled feature extractor v1"
    d = _release_dir(tmp_path, **{MODULE_A: original})
    malicious = b"compiled feature extractor v1 + backdoor"
    (d / MODULE_A).write_bytes(malicious)

    probe = await _probe(tmp_path)
    try:
        with pytest.raises(TamperDetected, match="Modified module"):
            await verify_and_receipt(d, probe.writer)
    finally:
        await probe.stop()

    rows = [r for r in probe.rows() if r.get("event_type") == INTEGRITY_EVENT_TYPE]
    assert len(rows) == 1, "the tamper verdict produced no record"
    row = rows[0]

    assert row["verdict"] == VERDICT_TAMPERED
    assert row["reason"] == "module_mismatch"
    assert row["risk_level"] == "HIGH"
    assert row["modules_not_matched"] == [MODULE_A]
    assert row["modules_matched"] == 0
    entry = row["modules"][0]
    assert entry["result"] == "modified"
    assert entry["expected_sha256"] == _sha(original)
    assert entry["actual_sha256"] == _sha(malicious)
    # And it is retrievable by the id, like any other receipt.
    assert probe.require(row["receipt_id"])["verdict"] == VERDICT_TAMPERED


async def test_one_bad_module_does_not_hide_behind_the_others(tmp_path):
    """
    Floor invariant 9(a): "1 of 2 verified" passes every non-zero assertion while
    one unit went unexamined, so the unit is NAMED.

    Pre-fix, ``verify_integrity`` raised on the FIRST bad entry, so the record
    (had there been one) could never have listed what else was wrong.
    """
    good = b"clean router"
    d = _release_dir(tmp_path, **{MODULE_A: b"orig", MODULE_B: good})
    (d / MODULE_A).write_bytes(b"tampered")
    (d / MODULE_B).unlink()          # a second, different failure mode

    record = build_integrity_record(d)
    assert record["verdict"] == VERDICT_TAMPERED
    assert record["modules_expected"] == 2
    assert record["modules_matched"] == 0
    assert sorted(record["modules_not_matched"]) == sorted([MODULE_A, MODULE_B])
    assert "Modified module" in record["detail"]
    assert "Missing module" in record["detail"]

    results = {m["name"]: m["result"] for m in record["modules"]}
    assert results == {MODULE_A: "modified", MODULE_B: "missing"}


# ---------------------------------------------------------------------------
# The bypass: a manifest that certifies nothing
# ---------------------------------------------------------------------------


def test_an_emptied_manifest_is_not_a_pass(tmp_path):
    """
    CLOSURE TEST — red against the pre-fix code, confirmed by running it there.

    The verifier reads its expectations out of a file that sits next to the very
    artifacts it is protecting. Pre-fix, an attacker who modified the binary and
    then truncated the manifest to ``{}`` got:

        Integrity check passed: 0 modules verified   ->  True

    Zero entries iterated cleanly and the function returned success, so the whole
    mechanism was defeated by editing one file. "0 modules verified" is
    not-observed, and not-observed must never fall into the pass bucket
    (floor inv. 9(d)).
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"original"})
    (d / MODULE_A).write_bytes(b"MALICIOUS")
    (d / "integrity_manifest.json").write_text("{}")

    record = build_integrity_record(d)
    assert record["verdict"] == VERDICT_TAMPERED
    assert record["reason"] == "manifest_certifies_nothing"
    assert record["modules_expected"] == 0

    with pytest.raises(TamperDetected, match="lists no modules"):
        verify_integrity(d)


def test_an_unparseable_manifest_is_a_finding_not_a_pass(tmp_path):
    d = _release_dir(tmp_path, **{MODULE_A: b"original"})
    (d / "integrity_manifest.json").write_text("{not json")

    record = build_integrity_record(d)
    assert record["verdict"] == VERDICT_TAMPERED
    assert record["reason"] == "manifest_unparseable"
    # The bytes that failed to parse are still pinned by their digest.
    assert record["manifest_sha256"] == _sha(b"{not json")


# ---------------------------------------------------------------------------
# The fail-open path: dev mode is recorded, not silent
# ---------------------------------------------------------------------------


async def test_dev_mode_is_receipted_as_unverifiable_never_as_verified(tmp_path):
    """
    No manifest -> nothing was verified. The call still returns True (a source
    checkout has no binaries to check and must boot), but the record says
    ``unverifiable``, so a host that never verified anything cannot later be
    read as one that verified successfully. The fail-open is now evidenced.
    """
    d = tmp_path / "source_checkout"
    d.mkdir()

    probe = await _probe(tmp_path)
    try:
        record = await verify_and_receipt(d, probe.writer)
    finally:
        await probe.stop()

    row = probe.require(record["receipt_id"])
    assert row["verdict"] == VERDICT_UNVERIFIABLE
    assert row["verdict"] != VERDICT_VERIFIED
    assert row["reason"] == "no_manifest"
    assert row["manifest_present"] is False
    assert row["risk_level"] == "UNKNOWN"
    assert row["modules"] == []

    assert verify_integrity(d) is True          # behaviour preserved


# ---------------------------------------------------------------------------
# The rail is lossy — so the receipt is confirmed, and its failure is loud
# ---------------------------------------------------------------------------


async def test_a_receipt_that_does_not_land_is_raised_not_logged(tmp_path):
    """
    ``AuditWriter.write()`` returns immediately and drops silently on a full
    queue; ``_writer_loop`` swallows every write exception. So "we called write()"
    is not "the verdict is recorded", and the difference must be observable.

    Driven with a writer that was never started: nothing drains the queue, so the
    flush times out and the emit refuses to claim success.
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"payload"})
    never_started = AuditWriter(str(tmp_path / "unwritten.jsonl"))

    with pytest.raises(ReceiptNotDurable):
        await verify_and_receipt(d, never_started, timeout=0.2)

    assert not (tmp_path / "unwritten.jsonl").exists()


async def test_a_receipt_failure_never_suppresses_the_tamper_halt(tmp_path):
    """
    The evidence channel failing must not become a way to survive a tamper
    finding. With BOTH broken — tampered binaries and an undeliverable receipt —
    ``TamperDetected`` is what reaches the caller, and the receipt failure is
    chained onto it rather than discarded.
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"original"})
    (d / MODULE_A).write_bytes(b"MALICIOUS")
    never_started = AuditWriter(str(tmp_path / "unwritten.jsonl"))

    with pytest.raises(TamperDetected) as excinfo:
        await verify_and_receipt(d, never_started, timeout=0.2)

    assert isinstance(excinfo.value.__cause__, ReceiptNotDurable)


async def test_the_landed_check_is_not_vacuous(tmp_path):
    """
    Positive control for the test above: the same writer, started, DOES satisfy
    the read-back — so ``ReceiptNotDurable`` fires on the failure, not on
    everything.
    """
    d = _release_dir(tmp_path, **{MODULE_A: b"payload"})
    writer = AuditWriter(str(tmp_path / "written.jsonl"))
    await writer.start()
    try:
        record = await verify_and_receipt(d, writer, timeout=5.0)
    finally:
        await writer.stop()

    assert record["verdict"] == VERDICT_VERIFIED
    assert (tmp_path / "written.jsonl").exists()


async def test_flush_surfaces_a_stalled_queue_instead_of_swallowing_it(tmp_path):
    """``AuditWriter.flush`` must raise, not return, when the queue does not drain."""
    writer = AuditWriter(str(tmp_path / "stalled.jsonl"))
    await writer.write({"detection_id": "never-drained"})
    with pytest.raises(asyncio.TimeoutError):
        await writer.flush(timeout=0.2)


# ---------------------------------------------------------------------------
# A receipt mechanism nothing calls is not "receipted"
# ---------------------------------------------------------------------------


def test_the_runtime_verifies_the_directories_the_build_compiles(tmp_path):
    """
    ``runtime_module_dirs()`` must track the directories of
    ``COMPILED_MODULES`` — the modules the build actually hashes. If the build
    starts compiling a third package and this list is not updated, that package
    ships unverified and the receipt reports a clean run over the other two.
    """
    from scripts.build_release import COMPILED_MODULES

    build_dirs = {Path(m).parent.name for m in COMPILED_MODULES}
    runtime_dirs = {d.name for d in runtime_module_dirs()}
    assert build_dirs <= runtime_dirs, (
        f"the build compiles modules in {sorted(build_dirs - runtime_dirs)} which "
        f"startup verification never looks at, so their integrity verdict would "
        f"never be produced or receipted"
    )


async def test_the_proxy_actually_runs_this_at_startup(tmp_path, monkeypatch):
    """
    THE ONE THAT MAKES THE REST MEAN ANYTHING.

    ``proxy/license/integrity.py`` has claimed "At startup, verifies…" since it
    was written, and ``grep`` across every branch of this repo found no caller
    outside ``tests/`` — the check did not run in any deployed process, so no
    runtime verdict existed to be receipted.

    This drives the REAL FastAPI lifespan (``app.router.lifespan_context``), not a
    stub, and requires an integrity receipt for every compiled module directory to
    be on disk in the configured audit log afterwards. Red before the wiring
    landed: the file contained detection records only, and no integrity event.
    """
    from proxy.config import settings

    audit_log = tmp_path / "startup-audit.jsonl"
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    monkeypatch.setattr(settings.audit, "log_path", str(audit_log))
    monkeypatch.setattr(settings.detection, "profile_dir", str(profiles_dir))
    monkeypatch.setattr(settings.registry, "pull_on_startup", False)
    monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)
    monkeypatch.delenv("ARKHEIA_REQUIRE_LICENSE", raising=False)

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    async with app.router.lifespan_context(app):
        pass

    rows = [
        json.loads(line)
        for line in audit_log.read_text().splitlines()
        if line.strip()
    ]
    integrity_rows = [r for r in rows if r.get("event_type") == INTEGRITY_EVENT_TYPE]

    expected_dirs = {str(d.resolve()) for d in runtime_module_dirs()}
    assert expected_dirs, "no compiled module directories resolved"
    assert {r["module_dir"] for r in integrity_rows} == expected_dirs, (
        "startup did not produce an integrity receipt for every compiled module "
        f"directory; got {[r.get('module_dir') for r in integrity_rows]}"
    )
    for row in integrity_rows:
        # A source checkout has no manifests, so `unverifiable` is the honest
        # verdict here — and it is on the record, which is the point.
        assert row["verdict"] in (VERDICT_VERIFIED, VERDICT_UNVERIFIABLE)
        assert row["receipt_id"]
