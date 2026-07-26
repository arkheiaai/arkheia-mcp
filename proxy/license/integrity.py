"""
Binary integrity verification.

At startup, verifies that compiled detection modules (.so/.pyd) have not been
tampered with by checking SHA-256 hashes against build-time signed values.

The hash manifest is generated during CI build and embedded in the package.

THE RUNTIME VERDICT IS A RECEIPT, NOT A LOG LINE
------------------------------------------------
Integrity verification makes two governed decisions. The first is at BUILD time
("these hashes are the trusted state of this artifact") and its durable record is
``integrity_manifest.json``, shipped inside the release — see
``scripts/build_release.step_generate_manifest``.

The second is the RUNTIME verdict, and it is the one a customer, an auditor or an
incident responder actually asks about: *did this process, on this host, at this
time, verify these binaries against those expected digests — and what did it
find?* Before this module was reworked that verdict left **nothing**: a
``logger.info`` on the pass path and an in-memory exception on the tamper path,
neither of which survives the process. A tamper-evidence mechanism whose verdict
is not recorded cannot evidence its own result, which is most of what it is for.

So every call to :func:`verify_and_receipt` emits one record onto the proxy's
existing tamper-evident audit rail (``proxy/audit/writer.py``: redacted, hash-
chained, append-only JSONL) carrying WHAT was verified (each module, with the
expected digest AND the digest actually observed), WHEN, and against WHICH
expected-digest set (``manifest_sha256`` — a digest of the manifest file itself,
so a swapped manifest is visible in the record rather than invisible behind it).

THREE HONEST BUCKETS
--------------------
Per DONE.md floor invariant 9(d) — *an outcome that produced no observation must
not be counted as a success* — the verdict is one of:

``verified``      a manifest exists, lists at least one module, and every listed
                  module's bytes hash to the recorded digest.
``tampered``      a concrete adverse finding: a module modified or missing, a
                  manifest that will not parse, or a manifest that exists yet
                  certifies zero modules (see below).
``unverifiable``  no manifest at all — the dev-mode fail-open. It still returns
                  True, because a source checkout has no binaries to verify, but
                  it is NEVER reported as ``verified``. The fail-open is now on
                  the record instead of being silent.

WHY AN EMPTY MANIFEST IS A TAMPER FINDING, NOT A PASS
-----------------------------------------------------
``verify_integrity`` previously treated a manifest that EXISTS as a manifest to
check, iterated its entries, and returned True — so a manifest containing ``{}``
produced *"Integrity check passed: 0 modules verified"* and a True. That is not a
missing check, it is a **bypass**: an attacker who modifies ``features.so`` and
then truncates ``integrity_manifest.json`` to ``{}`` defeats the whole mechanism,
because the file the verifier reads its expectations from is the file it is
supposed to be protecting against. Verified empirically against the pre-fix code:
modified binary + emptied manifest returned True.

An existing manifest that certifies nothing is therefore indistinguishable from
an emptied one, and is treated as ``tampered``. A *missing* manifest is a
different statement ("this is a source checkout") and stays ``unverifiable``.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

MANIFEST_FILE = "integrity_manifest.json"

#: Audit event type for the runtime verdict. One type, one meaning.
INTEGRITY_EVENT_TYPE = "license.integrity_verification"

VERDICT_VERIFIED = "verified"
VERDICT_TAMPERED = "tampered"
VERDICT_UNVERIFIABLE = "unverifiable"

#: verdict -> the audit rail's risk_level, so an integrity failure lands in the
#: same HIGH bucket the detection stream uses and is picked up by
#: ``AuditWriter.read_recent``'s summary and any surface that alerts on it.
_RISK_LEVEL = {
    VERDICT_VERIFIED: "LOW",
    VERDICT_TAMPERED: "HIGH",
    VERDICT_UNVERIFIABLE: "UNKNOWN",
}

#: Package subdirectories whose compiled artifacts are verified at startup.
#: Mirrors the directories of ``setup_cython.COMPILED_MODULES`` /
#: ``scripts.build_release.COMPILED_MODULES`` (proxy/detection, proxy/router).
RUNTIME_MODULE_SUBDIRS = ("detection", "router")


class TamperDetected(RuntimeError):
    """Raised when a compiled module fails integrity verification."""


class ReceiptNotDurable(RuntimeError):
    """
    The integrity verdict was produced but its record did not reach disk.

    Raised rather than logged because the audit rail is deliberately lossy for
    the detection stream — ``AuditWriter.write`` drops silently when its queue is
    full and ``_writer_loop`` swallows every write exception — and a verdict that
    is only "probably recorded" is not evidence. Never suppresses a
    :class:`TamperDetected`; see :func:`verify_and_receipt`.
    """


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_manifest(module_dir: Path, output_path: Optional[Path] = None) -> dict:
    """
    Generate integrity manifest for all .so/.pyd files in module_dir.
    Called at build time by scripts/build_release.py.
    """
    manifest = {}
    for ext in ("*.so", "*.pyd"):
        for f in module_dir.glob(ext):
            manifest[f.name] = _sha256_file(f)

    if output_path:
        output_path.write_text(json.dumps(manifest, indent=2))
        logger.info("Integrity manifest written: %d modules", len(manifest))

    return manifest


def runtime_module_dirs(package_root: Optional[Path] = None) -> list[Path]:
    """The directories whose compiled artifacts are verified at proxy startup."""
    root = package_root or Path(__file__).resolve().parent.parent
    return [root / name for name in RUNTIME_MODULE_SUBDIRS if (root / name).is_dir()]


def build_integrity_record(
    module_dir: Path,
    *,
    receipt_id: Optional[str] = None,
) -> dict[str, Any]:
    """
    Evaluate ``module_dir`` and return the verdict record. Never raises.

    This is the whole decision, expressed as data: the record IS the evidence,
    and :func:`verify_integrity` / :func:`verify_and_receipt` are thin policy on
    top of it. Separating them is what makes the tamper path receiptable — the
    old code raised from inside the loop, so the finding existed only as an
    exception message and there was no artifact to write down.

    Every module is evaluated, not just up to the first failure: per DONE.md
    floor invariant 9(a) the units that did not verify are NAMED, and
    ``modules_matched`` of ``modules_expected`` is reported so "1 of 2 verified"
    cannot pass as clean.
    """
    module_dir = Path(module_dir)
    manifest_path = module_dir / MANIFEST_FILE
    receipt_id = receipt_id or str(uuid.uuid4())

    record: dict[str, Any] = {
        "event_type": INTEGRITY_EVENT_TYPE,
        # The audit rail keys read-back off `detection_id`; carrying the receipt
        # id under both names means an integrity receipt is retrievable by the
        # same lookup as every other record on the rail.
        "detection_id": receipt_id,
        "receipt_id": receipt_id,
        "timestamp": _now_iso(),
        "module_dir": str(module_dir.resolve()),
        "manifest_path": str(manifest_path.resolve()),
        "manifest_present": manifest_path.exists(),
        "manifest_sha256": None,
        "modules_expected": 0,
        "modules_matched": 0,
        "modules_not_matched": [],
        "modules": [],
    }

    def _finish(verdict: str, reason: str, detail: str) -> dict[str, Any]:
        record["verdict"] = verdict
        record["reason"] = reason
        record["detail"] = detail
        record["risk_level"] = _RISK_LEVEL[verdict]
        return record

    if not manifest_path.exists():
        return _finish(
            VERDICT_UNVERIFIABLE,
            "no_manifest",
            f"No integrity manifest in {module_dir} — nothing was verified "
            f"(source checkout / dev mode).",
        )

    # The digest of the expectations themselves. Without this the record cannot
    # distinguish "verified against the shipped manifest" from "verified against
    # a manifest an attacker supplied", which is the difference that matters.
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as exc:
        return _finish(
            VERDICT_TAMPERED,
            "manifest_unreadable",
            f"Corrupt integrity manifest: {exc}",
        )
    record["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()

    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        return _finish(
            VERDICT_TAMPERED,
            "manifest_unparseable",
            f"Corrupt integrity manifest: {exc}",
        )

    if not isinstance(manifest, dict) or not manifest:
        # See module docstring: an existing manifest certifying nothing is the
        # bypass, not a neutral state.
        return _finish(
            VERDICT_TAMPERED,
            "manifest_certifies_nothing",
            f"Integrity manifest {manifest_path} exists but lists no modules, so "
            f"a pass would certify nothing. This is indistinguishable from a "
            f"manifest emptied to defeat the check.",
        )

    record["modules_expected"] = len(manifest)
    findings: list[str] = []

    for module_name, expected_hash in sorted(manifest.items()):
        module_path = module_dir / module_name
        entry: dict[str, Any] = {
            "name": module_name,
            "expected_sha256": expected_hash,
            "actual_sha256": None,
        }
        if not module_path.exists():
            entry["result"] = "missing"
            findings.append(f"Missing module: {module_name}")
        else:
            actual_hash = _sha256_file(module_path)
            entry["actual_sha256"] = actual_hash
            if actual_hash == expected_hash:
                entry["result"] = "match"
                record["modules_matched"] += 1
            else:
                entry["result"] = "modified"
                findings.append(
                    f"Modified module: {module_name} "
                    f"(expected {str(expected_hash)[:12]}..., got {actual_hash[:12]}...)"
                )
        if entry["result"] != "match":
            record["modules_not_matched"].append(module_name)
        record["modules"].append(entry)

    if findings:
        return _finish(VERDICT_TAMPERED, "module_mismatch", "; ".join(findings))

    return _finish(
        VERDICT_VERIFIED,
        "all_modules_matched",
        f"{record['modules_matched']} of {record['modules_expected']} modules "
        f"matched their recorded digests.",
    )


def _log_record(record: dict[str, Any]) -> None:
    """Log the verdict at a level that matches it. Not the evidence — the receipt is."""
    if record["verdict"] == VERDICT_TAMPERED:
        logger.error("Integrity check FAILED (%s): %s", record["reason"], record["detail"])
    elif record["verdict"] == VERDICT_UNVERIFIABLE:
        logger.warning("Integrity NOT verified (%s): %s", record["reason"], record["detail"])
    else:
        logger.info(
            "Integrity check passed: %d modules verified", record["modules_matched"]
        )


def verify_integrity(module_dir: Path) -> bool:
    """
    Verify compiled modules against the integrity manifest.

    Returns True if all checks pass or no manifest exists (dev mode).
    Raises TamperDetected if any module has been modified, if the manifest will
    not parse, or if the manifest exists but certifies nothing.

    Leaves NO durable record — use :func:`verify_and_receipt` on any path where
    the verdict has to be evidenced afterwards (which is every runtime path).
    """
    record = build_integrity_record(module_dir)
    _log_record(record)
    if record["verdict"] == VERDICT_TAMPERED:
        raise TamperDetected(record["detail"])
    return True


def _receipt_landed(log_path: Path, receipt_id: str) -> bool:
    """Is a record carrying ``receipt_id`` actually on disk?"""
    if not log_path.exists():
        return False
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if row.get("receipt_id") == receipt_id:
                    return True
    except OSError:
        return False
    return False


async def _emit_receipt(record: dict[str, Any], audit_writer: Any, timeout: float) -> None:
    """
    Put the verdict on the audit rail and CONFIRM it landed.

    The confirmation is not ceremony. ``AuditWriter.write`` returns immediately
    and drops the record without raising when its queue is full, and
    ``_writer_loop`` catches every exception around the actual file write. Both
    are correct for the detection stream — an audit write must never delay or
    fail a response — and both are wrong for a verdict whose entire purpose is to
    be producible later. So: enqueue through the production API, drain, and read
    the record back off disk by its own id.
    """
    await audit_writer.write(dict(record))
    try:
        await audit_writer.flush(timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ReceiptNotDurable(
            f"integrity receipt {record['receipt_id']} was not drained within "
            f"{timeout}s (verdict={record['verdict']})"
        ) from exc

    if not _receipt_landed(Path(audit_writer.log_path), record["receipt_id"]):
        raise ReceiptNotDurable(
            f"integrity receipt {record['receipt_id']} (verdict="
            f"{record['verdict']}) is not present in {audit_writer.log_path} "
            f"after draining — the verdict was reached but not recorded"
        )


async def verify_and_receipt(
    module_dir: Path,
    audit_writer: Any,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Verify ``module_dir`` and leave a durable, attributable record of the verdict.

    Returns the record on ``verified`` / ``unverifiable``.

    Raises :class:`TamperDetected` on an adverse finding — **after** the receipt
    has been attempted, so the finding is recorded before it halts anything.

    Raises :class:`ReceiptNotDurable` when the record did not reach disk, EXCEPT
    when the verdict is ``tampered``: there, the tamper raise wins. A failure of
    the evidence channel must never suppress the halt it was meant to witness
    (the receipt failure is logged CRITICAL and chained onto the TamperDetected
    so it is not lost either).
    """
    record = build_integrity_record(module_dir)
    _log_record(record)

    receipt_failure: Optional[ReceiptNotDurable] = None
    try:
        await _emit_receipt(record, audit_writer, timeout)
    except ReceiptNotDurable as exc:
        receipt_failure = exc
        logger.critical("Integrity verdict could not be receipted: %s", exc)

    if record["verdict"] == VERDICT_TAMPERED:
        raise TamperDetected(record["detail"]) from receipt_failure

    if receipt_failure is not None:
        raise receipt_failure

    return record
