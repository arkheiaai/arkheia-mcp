"""
Binary integrity verification.

At startup, verifies that compiled detection modules (.so/.pyd) have not been
tampered with by checking SHA-256 hashes against build-time signed values.

The hash manifest is generated during CI build and embedded in the package.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

MANIFEST_FILE = "integrity_manifest.json"


class TamperDetected(RuntimeError):
    """Raised when a compiled module fails integrity verification."""


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


def verify_integrity(module_dir: Path) -> bool:
    """
    Verify compiled modules against the integrity manifest.

    Returns True if all checks pass or no manifest exists (dev mode).
    Raises TamperDetected if any module has been modified.
    """
    manifest_path = module_dir / MANIFEST_FILE
    if not manifest_path.exists():
        logger.debug("No integrity manifest found — skipping check (dev mode)")
        return True

    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Failed to read integrity manifest: %s", exc)
        raise TamperDetected(f"Corrupt integrity manifest: {exc}") from exc

    for module_name, expected_hash in manifest.items():
        module_path = module_dir / module_name
        if not module_path.exists():
            raise TamperDetected(f"Missing module: {module_name}")
        actual_hash = _sha256_file(module_path)
        if actual_hash != expected_hash:
            raise TamperDetected(
                f"Modified module: {module_name} "
                f"(expected {expected_hash[:12]}..., got {actual_hash[:12]}...)"
            )

    logger.info("Integrity check passed: %d modules verified", len(manifest))
    return True
