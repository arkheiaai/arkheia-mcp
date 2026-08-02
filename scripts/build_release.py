#!/usr/bin/env python3
"""Orchestrate the Arkheia release build pipeline."""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import subprocess
import sys
from pathlib import Path
from typing import Sequence

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from proxy.crypto.profile_crypto import decrypt_profile, encrypt_profile
from proxy.license.integrity import generate_manifest
try:
    from setup_cython import COMPILED_MODULES
except ImportError:
    COMPILED_MODULES = [
        "proxy/detection/features.py",
        "proxy/detection/engine.py",
        "proxy/router/profile_router.py",
    ]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the Arkheia release artifacts")
    parser.add_argument(
        "--profile-key",
        default=None,
        help="Base64-encoded 32-byte profile master key. Defaults to ARKHEIA_PROFILE_MASTER_KEY.",
    )
    parser.add_argument(
        "--skip-compile",
        action="store_true",
        help="Skip the Cython build step and use existing compiled binaries.",
    )
    return parser.parse_args(argv)


def resolve_profile_key(profile_key: str | None) -> bytes:
    key_b64 = profile_key or os.environ.get("ARKHEIA_PROFILE_MASTER_KEY")
    if not key_b64:
        raise ValueError("Profile key missing. Pass --profile-key or set ARKHEIA_PROFILE_MASTER_KEY.")

    try:
        master_key = base64.b64decode(key_b64)
    except binascii.Error as exc:
        raise ValueError("Profile key must be valid base64.") from exc

    if len(master_key) != 32:
        raise ValueError(f"Profile key must decode to 32 bytes, got {len(master_key)}.")

    return master_key


def step_cython_compile(repo_root: Path = REPO_ROOT) -> None:
    print("\n=== Step 1: Cython compile ===")
    subprocess.run(
        [sys.executable, "setup_cython.py", "build_ext", "--inplace"],
        check=True,
        cwd=repo_root,
    )
    print("  Cython compilation complete.")


def step_encrypt_profiles(master_key: bytes, profile_dir: Path) -> int:
    print("\n=== Step 2: Encrypt profiles ===")

    if not profile_dir.exists():
        raise FileNotFoundError(f"Profile directory not found: {profile_dir}")

    encrypted_count = 0
    for yaml_file in sorted(profile_dir.glob("*.yaml")):
        if yaml_file.name == "schema.yaml":
            continue

        profile_name = yaml_file.stem
        plaintext = yaml_file.read_bytes()
        encrypted = encrypt_profile(plaintext, master_key, profile_name)
        enc_path = profile_dir / f"{profile_name}.yaml.enc"
        enc_path.write_bytes(encrypted)

        # Prove the ciphertext is RECOVERABLE before destroying the only plaintext copy.
        # Without this, a broken or mis-keyed encrypt_profile writes undecryptable bytes, this
        # step reports success, and the source YAML is deleted -- unrecoverable data loss that
        # every existing assertion passes straight through, because they only check that the
        # plaintext is gone and a .enc exists. Read back from DISK rather than trusting the
        # in-memory buffer, so a truncated or partial write is caught too.
        try:
            recovered = decrypt_profile(enc_path.read_bytes(), master_key, profile_name)
        except Exception as exc:  # noqa: BLE001 - any failure here must stop the build
            raise RuntimeError(
                f"Refusing to delete {yaml_file.name}: the ciphertext written to "
                f"{enc_path.name} could not be decrypted ({exc!r}). The plaintext has been "
                f"left in place."
            ) from exc
        if recovered != plaintext:
            raise RuntimeError(
                f"Refusing to delete {yaml_file.name}: {enc_path.name} decrypts to "
                f"{len(recovered)} bytes but the source is {len(plaintext)} bytes. The "
                f"plaintext has been left in place."
            )

        yaml_file.unlink()
        encrypted_count += 1
        print(f"  Encrypted: {yaml_file.name} -> {enc_path.name} (round-trip verified)")

    if encrypted_count == 0:
        # A zero count previously printed "Profiles encrypted: 0" and returned success, so a
        # release could ship with nothing encrypted and nothing to say so.
        raise RuntimeError(
            f"Refusing to continue: no profiles were encrypted. Searched {profile_dir} for "
            f"'*.yaml' (excluding schema.yaml) and found no candidates."
        )

    print(f"  Profiles encrypted: {encrypted_count} (all round-trip verified)")
    return encrypted_count


#: What ``proxy.license.integrity.generate_manifest`` globs for. Named here so the
#: refusal below can tell an operator what was actually searched for, rather than
#: reporting an unexplained zero.
COMPILED_ARTIFACT_GLOBS = ("*.so", "*.pyd")


class EmptyManifest(ValueError):
    """A manifest that lists no modules. See ``step_generate_manifest``."""


def step_generate_manifest(module_dir: Path, output_path: Path | None = None) -> dict[str, str]:
    """
    Write the integrity manifest for ``module_dir`` — the durable record of the
    build-time decision *"these hashes are the trusted state of this artifact"*.

    REFUSES TO WRITE AN EMPTY MANIFEST.
    ------------------------------------
    ``generate_manifest`` globs ``*.so``/``*.pyd``. When a directory contains
    none — ``--skip-compile`` on a source checkout, or a Cython step that
    produced nothing — it returned ``{}`` and this function wrote it out, printed
    ``Manifest written: … (0 modules)``, and the build carried on to exit 0.

    That empty file is not a neutral placeholder, it is a FALSE RECEIPT.
    Historically, ``proxy/license/integrity.verify_integrity`` treated a manifest
    that exists as a manifest to check, iterated its zero entries, logged
    *"Integrity check passed: 0 modules verified"* and returned success. Current
    ``master`` now rejects that at runtime, but a release build still must not
    ship an artifact whose integrity record certifies zero modules.

    Worse still, the build did not stop: step 4 then DELETED the compiled Python
    sources listed in ``COMPILED_MODULES``, so a no-binaries build destroyed the
    originals and still printed "Release build complete".

    So: compute the manifest, and if it lists nothing, delete the file that was
    just written and abort. Raising here (step 3) aborts before step 4 removes
    any source. Per DONE.md floor invariant 9(a) the refusal NAMES THE UNITS —
    the directory and the globs that found nothing — instead of reporting an
    aggregate zero.
    """
    print(f"\n=== Step 3: Generate integrity manifest ({module_dir}) ===")
    manifest_path = output_path or module_dir / "integrity_manifest.json"
    manifest = generate_manifest(module_dir, manifest_path)

    if not manifest:
        # Remove the false receipt. Leaving it behind is the defect itself: a
        # release build must not ship a manifest that records zero modules.
        if manifest_path.exists():
            manifest_path.unlink()
        raise EmptyManifest(
            f"refusing to write an empty integrity manifest for {module_dir}: "
            f"no {' / '.join(COMPILED_ARTIFACT_GLOBS)} found there, so the "
            f"manifest would certify ZERO modules. Current verify_integrity() "
            f"treats that as tamper evidence, and the release build must stop "
            f"before sources are removed. Run the Cython compile step (drop "
            f"--skip-compile) or remove {module_dir} from COMPILED_MODULES; "
            f"do not rely on startup integrity checks to reject a bad release."
        )

    print(f"  Manifest written: {manifest_path} ({len(manifest)} modules)")
    for name in sorted(manifest):
        print(f"    - {name}")
    return manifest


def compiled_module_dirs(repo_root: Path = REPO_ROOT) -> list[Path]:
    seen: list[Path] = []
    for module_path in COMPILED_MODULES:
        module_dir = (repo_root / module_path).parent
        if module_dir not in seen:
            seen.append(module_dir)
    return seen


class UnrecordedModule(ValueError):
    """A module in COMPILED_MODULES that no manifest entry covers."""


def check_every_module_is_recorded(
    manifests: dict[str, dict[str, str]],
    repo_root: Path = REPO_ROOT,
) -> None:
    """
    Require a manifest entry for EVERY module in ``COMPILED_MODULES``.

    A non-empty manifest is not enough, because the manifest is generated
    per-DIRECTORY while ``COMPILED_MODULES`` is a list of FILES. All three
    default entries live in two directories, so one compiled artifact makes its
    whole directory's manifest non-empty — and a module whose Cython build
    silently produced nothing is then invisible: it is absent from the manifest,
    ``verify_integrity`` never looks for it, and step 4 deletes its source
    anyway. The build ships a partially-verified artifact and reports success.

    This is DONE.md floor invariant 9(a): "39 of 44 scored" passes every
    non-zero assertion while five units go unexamined, so the five must be
    NAMED. The per-directory count is the aggregate; the per-module check below
    is the unit.

    Matching is by stem, because the build tool decides the suffix:
    ``proxy/detection/features.py`` is satisfied by ``features.so``,
    ``features.pyd`` or ``features.cpython-312-darwin.so``.
    """
    recorded_stems: dict[Path, set[str]] = {}
    for manifest_path, manifest in manifests.items():
        directory = Path(manifest_path).parent
        recorded_stems.setdefault(directory, set()).update(
            name.split(".", 1)[0] for name in manifest
        )

    missing: list[str] = []
    for module_path in COMPILED_MODULES:
        source = repo_root / module_path
        if source.stem not in recorded_stems.get(source.parent, set()):
            missing.append(module_path)

    if missing:
        raise UnrecordedModule(
            f"{len(missing)} of {len(COMPILED_MODULES)} modules have no compiled "
            f"artifact in any integrity manifest: {', '.join(missing)}. Their "
            f"sources would be deleted by step 4 while nothing verifies them. "
            f"A per-directory manifest count hides this — one sibling that did "
            f"compile makes the directory look covered."
        )

    print(
        f"\n=== Step 3b: Integrity coverage ===\n"
        f"  {len(COMPILED_MODULES)} of {len(COMPILED_MODULES)} modules recorded."
    )


def step_remove_source(repo_root: Path = REPO_ROOT) -> list[Path]:
    print("\n=== Step 4: Remove compiled Python sources ===")
    removed: list[Path] = []

    for module_path in COMPILED_MODULES:
        source_path = repo_root / module_path
        if source_path.exists():
            source_path.unlink()
            removed.append(source_path)
            print(f"  Removed: {source_path.relative_to(repo_root)}")

    if not removed:
        print("  No source files removed.")

    return removed


def print_summary(
    *,
    compiled: bool,
    encrypted_count: int,
    manifests: dict[str, dict[str, str]],
    removed: list[Path],
    repo_root: Path = REPO_ROOT,
) -> None:
    print("\n=== Release build complete ===")
    print(f"  Compile step run : {compiled}")
    print(f"  Profiles encrypted: {encrypted_count}")
    print(f"  Manifest files   : {len(manifests)}")
    for manifest_path, manifest in manifests.items():
        try:
            relative_path = Path(manifest_path).relative_to(repo_root)
        except ValueError:
            relative_path = Path(manifest_path)
        print(f"    - {relative_path} ({len(manifest)} modules)")
    print(f"  Sources removed  : {len(removed)}")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        master_key = resolve_profile_key(args.profile_key)
        if not args.skip_compile:
            step_cython_compile(REPO_ROOT)

        encrypted_count = step_encrypt_profiles(master_key, REPO_ROOT / "profiles")

        manifests: dict[str, dict[str, str]] = {}
        for module_dir in compiled_module_dirs(REPO_ROOT):
            manifest_path = module_dir / "integrity_manifest.json"
            manifests[str(manifest_path)] = step_generate_manifest(module_dir, manifest_path)

        # Before anything is deleted: every module must be covered by a record.
        check_every_module_is_recorded(manifests, REPO_ROOT)

        removed = step_remove_source(REPO_ROOT)
        print_summary(
            compiled=not args.skip_compile,
            encrypted_count=encrypted_count,
            manifests=manifests,
            removed=removed,
            repo_root=REPO_ROOT,
        )
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
