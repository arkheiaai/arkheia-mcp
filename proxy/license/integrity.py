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

``verified``      a manifest exists, lists at least one module, every listed
                  module's bytes hash to the recorded digest, and no compiled
                  artifact is present that the manifest does not mention.
``tampered``      a concrete adverse finding: a module modified, missing or
                  unreadable; a manifest that will not parse, is not an object,
                  certifies zero modules, carries an entry that points outside
                  the directory, or is absent while compiled artifacts are
                  present; or a compiled artifact with no manifest entry.
``unverifiable``  no manifest AND no compiled artifacts — the dev-mode fail-open.
                  It still returns True, because a source checkout has no binaries
                  to verify, but it is NEVER reported as ``verified``. The
                  fail-open is now on the record instead of being silent.

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
an emptied one, and is treated as ``tampered``.

WHY A *MISSING* MANIFEST DEPENDS ON WHAT IS SITTING NEXT TO IT
-------------------------------------------------------------
Closing the emptied manifest taught an attacker which file to *delete* instead of
truncate, and deleting took a different branch: no manifest -> ``unverifiable``
-> the halt rule did not fire -> tampered binaries ran. Reproduced against the
pre-fix code by a second vendor and again here (a ``.so`` present, the manifest
removed, ``verify_integrity`` returned True).

The fix is NOT "make ``unverifiable`` halt". ``unverifiable`` is the
**not-observed** bucket (see below); halting on it would turn absence of evidence
into an adverse finding, collapse the three buckets into two, and — because the
proxy deploys as a source checkout with nothing compiled — refuse to boot
production on every start.

A missing manifest is two different facts, and the discriminator is whether
there was anything to verify at all:

* **no compiled artifacts + no manifest** — a source checkout. Nothing to verify
  and nothing claiming there was. ``unverifiable``; boots.
* **compiled artifacts + no manifest** — the file that was supposed to describe
  binaries that ARE present has been removed. That is not an absence of evidence,
  it is the affirmative observation that the expectations are gone. ``tampered``;
  halts.

In one sentence: **the manifest's absence is only benign when the thing it was
supposed to describe is also absent.**

The same reasoning generalises past the file's presence. A manifest is a
whitelist by enumeration, so a compiled artifact it does not mention was
previously invisible — list module A, tamper module B, and the verdict was
``verified``, ``1 of 1``. Truncating the manifest to drop one entry was the same
bypass wearing a valid-JSON hat. Any compiled artifact present with no expectation
recorded for it is now a finding (``unlisted_compiled_artifact``).

Every state ``integrity_manifest.json`` can be in is enumerated with its ruling
in ``proxy/tests/test_integrity_manifest_states.py``.
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

#: What counts as a compiled artifact. CANONICAL — ``generate_manifest`` globs
#: this to decide what a manifest CONTAINS and :func:`compiled_artifacts` globs it
#: to decide whether a missing manifest is benign, so the two cannot disagree.
#: ``scripts/build_release.py`` imports it rather than keeping a mirror; a mirror
#: that drifts low would make an artifact the build records invisible to the
#: runtime check, which is the missing-manifest bypass with extra steps.
COMPILED_ARTIFACT_GLOBS = ("*.so", "*.pyd")

#: verdict -> the audit rail's risk_level, so an integrity failure lands in the
#: same HIGH bucket the detection stream uses and is picked up by
#: ``AuditWriter.read_recent``'s summary and any surface that alerts on it.
#: Read through :func:`_risk_level_for`, never subscripted directly — an
#: unmapped verdict must be treated as high risk, not raise a KeyError from
#: inside the function that is supposed to produce the finding.
_RISK_LEVEL = {
    VERDICT_VERIFIED: "LOW",
    VERDICT_TAMPERED: "HIGH",
    VERDICT_UNVERIFIABLE: "UNKNOWN",
}

#: The ONLY verdicts that permit the process to continue. Everything else halts,
#: INCLUDING a verdict added after this line was written.
#:
#: This inversion is the structural half of the P1 fix. The halt rule used to be
#: ``if verdict == VERDICT_TAMPERED: raise`` — an enumerated deny-list — so every
#: state that was not spelled out defaulted to "boot anyway". That is fail-OPEN in
#: a control whose entire job is to refuse, and it is exactly how ``unverifiable``
#: came to be a bypass: nobody decided it should not halt, it simply was not
#: mentioned. With an allow-list, a new verdict halts until someone deliberately
#: exempts it, and ``tests/test_integrity_halt_floor.py`` fails on any declared
#: verdict that has not been classified either way.
NON_HALTING_VERDICTS = frozenset({VERDICT_VERIFIED, VERDICT_UNVERIFIABLE})


def _risk_level_for(verdict: str) -> str:
    """Risk level for a verdict; an unknown verdict is HIGH, never a KeyError."""
    return _RISK_LEVEL.get(verdict, "HIGH")


def should_halt(record: dict[str, Any]) -> bool:
    """
    Does this verdict refuse to let the process continue?

    Fail-closed by default: anything not explicitly exempted halts.

    Both :func:`verify_integrity` and :func:`verify_and_receipt` route through
    here rather than each testing the verdict themselves. The rule was previously
    written out twice, and only ``verify_and_receipt`` runs in production — so a
    fix applied to the copy a test happens to drive would leave the deployed path
    unchanged. One rule, one place, pinned by
    ``tests/test_integrity_halt_floor.py``.
    """
    return record.get("verdict") not in NON_HALTING_VERDICTS


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


def compiled_artifacts(module_dir: Path) -> list[Path]:
    """
    Every compiled artifact present in ``module_dir``, sorted by name.

    Load-bearing for the missing-manifest ruling: this is what decides whether
    "no manifest" means *source checkout* (benign) or *the expectations for these
    binaries were removed* (adverse). It deliberately shares
    :data:`COMPILED_ARTIFACT_GLOBS` with :func:`generate_manifest` — if the
    detector saw fewer files than the generator records, an artifact could be
    present, unrecorded and unnoticed.

    Symlinks are included (they are still artifacts the interpreter can import)
    but directories are not: a directory named ``x.so`` is not a module and
    hashing it would raise.
    """
    module_dir = Path(module_dir)
    found: dict[str, Path] = {}
    for pattern in COMPILED_ARTIFACT_GLOBS:
        for path in module_dir.glob(pattern):
            if path.is_dir():
                continue
            found[path.name] = path
    return [found[name] for name in sorted(found)]


def generate_manifest(module_dir: Path, output_path: Optional[Path] = None) -> dict:
    """
    Generate integrity manifest for all .so/.pyd files in module_dir.
    Called at build time by scripts/build_release.py.
    """
    manifest = {}
    for f in compiled_artifacts(module_dir):
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

    present = [p.name for p in compiled_artifacts(module_dir)]

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
        # Recorded, not refused. Expectations reached through a symlink still have
        # to match the artifacts' bytes, so this grants an attacker nothing they
        # do not already have — but a reader of the receipt must be able to see
        # that the expectations did not come from inside the package.
        "manifest_is_symlink": manifest_path.is_symlink(),
        "manifest_sha256": None,
        # WHAT WAS ON DISK. Without this the record cannot distinguish "no
        # manifest because nothing is compiled" from "no manifest because someone
        # deleted it", which is the whole P1.
        "compiled_artifacts_present": present,
        "unlisted_artifacts": [],
        "modules_expected": 0,
        "modules_matched": 0,
        "modules_not_matched": [],
        "modules": [],
    }

    def _finish(verdict: str, reason: str, detail: str) -> dict[str, Any]:
        record["verdict"] = verdict
        record["reason"] = reason
        record["detail"] = detail
        record["risk_level"] = _risk_level_for(verdict)
        return record

    if not manifest_path.exists():
        if present:
            # THE P1. Compiled artifacts with no expectations recorded for them
            # is an adverse finding, not a missing observation: something removed
            # the file that was supposed to describe these binaries. Naming the
            # artifacts and the remedy is required — an operator who hit this by
            # running an in-place Cython build must be told what to run, not left
            # to read the source (Gate-9 legibility).
            record["unlisted_artifacts"] = list(present)
            return _finish(
                VERDICT_TAMPERED,
                "manifest_missing_for_compiled_artifacts",
                f"{len(present)} compiled artifact(s) in {module_dir} have no "
                f"integrity manifest describing them: {', '.join(present)}. "
                f"A manifest was expected beside them and is absent, so their "
                f"digests cannot be checked against anything — this is "
                f"indistinguishable from a manifest deleted to defeat the check. "
                f"If these were built in place, regenerate the manifest with "
                f"scripts/build_release.py (step 3) so the artifacts on disk are "
                f"recorded; do not remove this check.",
            )
        return _finish(
            VERDICT_UNVERIFIABLE,
            "no_manifest",
            f"No integrity manifest in {module_dir} and no compiled artifacts "
            f"({' / '.join(COMPILED_ARTIFACT_GLOBS)}) present — nothing was "
            f"verified because there is nothing to verify (source checkout / "
            f"dev mode).",
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

    if not isinstance(manifest, dict):
        # ``[]``, ``"x"``, ``null``, ``3`` all parse. They certify nothing too,
        # but for a different reason, and the reason is what an operator acts on.
        return _finish(
            VERDICT_TAMPERED,
            "manifest_not_an_object",
            f"Integrity manifest {manifest_path} parsed as {type(manifest).__name__}, "
            f"not a JSON object of name -> digest, so no expectation can be read "
            f"from it. Regenerate it with scripts/build_release.py (step 3).",
        )

    if not manifest:
        # See module docstring: an existing manifest certifying nothing is the
        # bypass, not a neutral state.
        return _finish(
            VERDICT_TAMPERED,
            "manifest_certifies_nothing",
            f"Integrity manifest {manifest_path} exists but lists no modules, so "
            f"a pass would certify nothing. This is indistinguishable from a "
            f"manifest emptied to defeat the check.",
        )

    # A manifest entry is a NAME inside this directory, and it is read out of the
    # very file being verified. ``module_dir / "../x"`` walks out of the tree and
    # ``module_dir / "/etc/hosts"`` discards the base entirely, so an unchecked
    # key lets the artifact steer the verifier at files it does not own — the
    # verifier-owned-parameters principle, applied to the join.
    invalid = [
        name
        for name in sorted(manifest)
        if not isinstance(name, str)
        or not name
        or Path(name).is_absolute()
        or Path(name).name != name
    ]
    if invalid:
        return _finish(
            VERDICT_TAMPERED,
            "manifest_invalid_entry",
            f"Integrity manifest {manifest_path} contains {len(invalid)} entry "
            f"name(s) that are not plain filenames inside {module_dir}: "
            f"{', '.join(map(repr, invalid))}. A manifest may only describe "
            f"artifacts in its own directory; an entry that escapes it would "
            f"point the verifier at a file the release does not own.",
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
            try:
                actual_hash = _sha256_file(module_path)
            except OSError as exc:
                # Pre-fix this escaped as a bare PermissionError out of a
                # function documented as never raising, so NO verdict and
                # therefore NO RECEIPT was produced — the one outcome a
                # tamper-evidence mechanism must not have. Unreadable is
                # not-observed, and not-observed is never a pass
                # (DONE.md floor invariant 9(d)).
                entry["result"] = "unreadable"
                findings.append(f"Unreadable module: {module_name} ({exc.strerror or exc})")
            else:
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

    # A manifest is a whitelist by enumeration, so anything it does not mention
    # used to be invisible: list A, tamper B, get `verified` over "1 of 1". Every
    # compiled artifact on disk must have an expectation recorded for it, or the
    # count in the receipt is measuring the wrong population.
    unlisted = [name for name in present if name not in manifest]
    if unlisted:
        record["unlisted_artifacts"] = unlisted
        return _finish(
            VERDICT_TAMPERED,
            "unlisted_compiled_artifact",
            f"{len(unlisted)} compiled artifact(s) in {module_dir} have no entry "
            f"in {MANIFEST_FILE}: {', '.join(unlisted)}. The manifest's "
            f"{len(manifest)} listed module(s) all matched, so a pass here would "
            f"report `verified` while these went unchecked. An artifact added "
            f"after the manifest was generated, or an entry removed from it, "
            f"produces exactly this state.",
        )

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

    Returns True only for a verdict in :data:`NON_HALTING_VERDICTS` — ``verified``
    (everything present is recorded and matches) or ``unverifiable`` (nothing
    compiled and no manifest: a source checkout, which must boot).

    Raises :class:`TamperDetected` for every other verdict. The rule is an
    allow-list on purpose; see :data:`NON_HALTING_VERDICTS`.

    Leaves NO durable record — use :func:`verify_and_receipt` on any path where
    the verdict has to be evidenced afterwards (which is every runtime path).
    """
    record = build_integrity_record(module_dir)
    _log_record(record)
    if should_halt(record):
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

    if should_halt(record):
        raise TamperDetected(record["detail"]) from receipt_failure

    if receipt_failure is not None:
        raise receipt_failure

    return record
