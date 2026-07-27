"""
Binary integrity verification.

At startup, verifies that compiled detection modules (.so/.pyd) have not been
tampered with by checking SHA-256 hashes against build-time signed values.

The hash manifest is generated during CI build and embedded in the package.

------------------------------------------------------------------------------
Two states this module used to collapse (Codex finding 4, 2026-07-26)
------------------------------------------------------------------------------
``verify_integrity()`` returned ``True`` both when every module verified AND when
there was no manifest at all. Those are not the same state:

  * NO MANIFEST / unreadable artifact  -> **absence of evidence**. A source
    checkout has nothing to verify against. Fail open: log it, keep running, and
    make the unverified state visible.
  * HASH MISMATCH / missing listed module / corrupt manifest -> **evidence**. A
    positive tamper finding. Do NOT start. A tampered detection engine that
    reports LOW is worse than no detection at all, because it is trusted.

Collapsing them into one ``bool`` made it impossible for a caller to tell them
apart, and ``proxy/main.py`` duly caught everything and continued — so the
observable outcome of a tampered engine was "error log plus service ready".
``verify_integrity()`` now returns an :class:`IntegrityReport` naming the state,
and still RAISES :class:`TamperDetected` on a positive finding, so a caller cannot
treat a tamper as a pass by accident.

RULING (adopted 2026-07-26): a corrupt/unparseable manifest counts as a POSITIVE
finding, not as absence. The manifest ships inside the artifact; if it exists and
cannot be read, either the integrity record itself was altered or the artifact is
damaged, and either way the engine cannot be trusted. The cost of this ruling is
named rather than hidden: a bad build that emits a malformed manifest will refuse
to start instead of starting unverified.

RULING (adopted 2026-07-27, Codex adversarial review): the same applies to an
EMPTY manifest -- one that parses fine but lists zero modules. The 2026-07-26 fix
above named "no manifest" vs "verified" as distinct states, but left a third
collapse in place: ``for module_name, expected_hash in manifest.items()`` over an
empty dict never executes, so the function fell through to VERIFIED with
``modules_checked=0``. Zero modules checked is not the same as zero modules
tampered. An empty manifest is treated exactly like a corrupt one: EVIDENCE, not
absence, so it raises TamperDetected rather than reading as a pass.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import NamedTuple, Optional

logger = logging.getLogger(__name__)

MANIFEST_FILE = "integrity_manifest.json"


class TamperDetected(RuntimeError):
    """Raised on a POSITIVE integrity finding. Must NOT be treated as fail-open."""


class IntegrityStatus:
    """The distinct outcomes of an integrity check. Never collapse these."""

    #: every module listed in the manifest matched its build-time hash.
    VERIFIED = "VERIFIED"
    #: no manifest present — nothing to verify against (source checkout).
    UNVERIFIED_NO_MANIFEST = "UNVERIFIED_NO_MANIFEST"
    #: a manifest exists but the check could not be completed (e.g. an unreadable
    #: module file). Absence of evidence, like UNVERIFIED_NO_MANIFEST.
    UNVERIFIABLE = "UNVERIFIABLE"
    #: a positive tamper finding. Evidence. Reported by raising TamperDetected.
    TAMPERED = "TAMPERED"

    #: the states in which the modules are NOT known to be intact.
    NOT_VERIFIED = (UNVERIFIED_NO_MANIFEST, UNVERIFIABLE, TAMPERED)


class IntegrityReport(NamedTuple):
    status: str
    module_dir: str
    modules_checked: int
    detail: str

    @property
    def verified(self) -> bool:
        return self.status == IntegrityStatus.VERIFIED


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


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


def verify_integrity(module_dir: Path) -> IntegrityReport:
    """
    Verify compiled modules in ``module_dir`` against its integrity manifest.

    Returns an :class:`IntegrityReport`. ``VERIFIED`` and
    ``UNVERIFIED_NO_MANIFEST`` are DIFFERENT states and are deliberately no longer
    both spelled ``True`` — see the module docstring.

    Raises:
        TamperDetected: on a POSITIVE finding — a modified module, a module listed
            in the manifest but missing from disk, or a manifest that exists and
            cannot be parsed. Callers must not swallow this alongside ordinary
            errors: it is evidence, not an absence of evidence.
    """
    module_dir = Path(module_dir)
    manifest_path = module_dir / MANIFEST_FILE
    if not manifest_path.exists():
        logger.debug("No integrity manifest in %s — nothing to verify", module_dir)
        return IntegrityReport(
            IntegrityStatus.UNVERIFIED_NO_MANIFEST,
            str(module_dir),
            0,
            f"no {MANIFEST_FILE} in {module_dir}: nothing to verify against. This "
            f"is absence of evidence, NOT an integrity pass.",
        )

    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read integrity manifest: %s", exc)
        raise TamperDetected(f"Corrupt integrity manifest: {exc}") from exc

    if not manifest:
        # An EMPTY manifest is not the same state as NO manifest. Absence (handled
        # above) means "not built with integrity checking at all" -- there is no
        # claim being made, so it is fail-open. An empty manifest means the
        # opposite: MANIFEST_FILE exists, so this directory is asserting it is a
        # checked build artifact, and that assertion lists zero modules. Left
        # unguarded, `for module_name, expected_hash in manifest.items()` never
        # executes and falls through to the VERIFIED return below with
        # modules_checked=0 -- the classic `all([]) is True` vacuous pass: iterate
        # nothing, conclude success. Per this module's own ruling on corrupt
        # manifests, an empty one ships inside the artifact too, and either the
        # build emitted a truncated manifest or one was tampered down to nothing.
        # Either way it is EVIDENCE, not absence, and must refuse to start exactly
        # like a corrupt or mismatched manifest -- never read as verified.
        raise TamperDetected(
            f"Empty integrity manifest: {manifest_path} exists but lists zero "
            f"modules. A manifest with nothing in it verifies nothing."
        )

    for module_name, expected_hash in manifest.items():
        module_path = module_dir / module_name
        if not module_path.exists():
            raise TamperDetected(f"Missing module: {module_name}")
        try:
            actual_hash = _sha256_file(module_path)
        except OSError as exc:
            # The manifest parsed and the file is present, but we could not read
            # it. Not evidence of tampering — report it as unverifiable.
            return IntegrityReport(
                IntegrityStatus.UNVERIFIABLE,
                str(module_dir),
                0,
                f"could not read {module_name} to hash it: {exc}",
            )
        if actual_hash != expected_hash:
            raise TamperDetected(
                f"Modified module: {module_name} "
                f"(expected {expected_hash[:12]}..., got {actual_hash[:12]}...)"
            )

    logger.info("Integrity check passed: %d modules verified", len(manifest))
    return IntegrityReport(
        IntegrityStatus.VERIFIED,
        str(module_dir),
        len(manifest),
        f"{len(manifest)} module(s) verified against {MANIFEST_FILE}",
    )


def _scan_root() -> Path:
    """
    Tree searched for integrity manifests: the installed ``proxy`` package.

    A function, not a constant, so a test can redirect the scan instead of writing
    probe files into the package it is verifying.
    """
    return Path(__file__).resolve().parents[1]


def manifest_dirs(root: Optional[Path] = None) -> list[Path]:
    """
    Directories under ``root`` that carry an integrity manifest.

    Discovered by looking for the manifest itself rather than by duplicating
    ``scripts/build_release.py``'s COMPILED_MODULES list, which would drift
    silently when the build's module list changes.
    """
    base = Path(root) if root is not None else _scan_root()
    return sorted({p.parent for p in base.rglob(MANIFEST_FILE)})


def verify_all(root: Optional[Path] = None) -> list[IntegrityReport]:
    """
    Verify every compiled-module directory under ``root``.

    Returns one report per directory, or a single ``UNVERIFIED_NO_MANIFEST`` report
    if there is no manifest anywhere. Raises :class:`TamperDetected` on the first
    positive finding — the caller is expected to refuse to start.
    """
    base = Path(root) if root is not None else _scan_root()
    dirs = manifest_dirs(base)
    if not dirs:
        return [
            IntegrityReport(
                IntegrityStatus.UNVERIFIED_NO_MANIFEST,
                str(base),
                0,
                f"no {MANIFEST_FILE} anywhere under {base}: running from source, so "
                f"there are no compiled modules to verify. Expected for a source "
                f"deployment, and NOT an integrity pass.",
            )
        ]
    return [verify_integrity(d) for d in dirs]
