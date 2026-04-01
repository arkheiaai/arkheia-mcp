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

from proxy.crypto.profile_crypto import encrypt_profile
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
        yaml_file.unlink()
        encrypted_count += 1
        print(f"  Encrypted: {yaml_file.name} -> {enc_path.name}")

    print(f"  Profiles encrypted: {encrypted_count}")
    return encrypted_count


def step_generate_manifest(module_dir: Path, output_path: Path | None = None) -> dict[str, str]:
    print(f"\n=== Step 3: Generate integrity manifest ({module_dir}) ===")
    manifest_path = output_path or module_dir / "integrity_manifest.json"
    manifest = generate_manifest(module_dir, manifest_path)
    print(f"  Manifest written: {manifest_path} ({len(manifest)} modules)")
    return manifest


def compiled_module_dirs(repo_root: Path = REPO_ROOT) -> list[Path]:
    seen: list[Path] = []
    for module_path in COMPILED_MODULES:
        module_dir = (repo_root / module_path).parent
        if module_dir not in seen:
            seen.append(module_dir)
    return seen


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
