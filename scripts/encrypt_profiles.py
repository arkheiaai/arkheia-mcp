#!/usr/bin/env python3
"""
Build-time tool: encrypt all YAML profiles into .yaml.enc files.

Usage:
    ARKHEIA_PROFILE_MASTER_KEY=<base64-master-key> python scripts/encrypt_profiles.py
    python scripts/encrypt_profiles.py --key-file /run/secrets/profile-master-key

The master key should be a 32-byte key, base64-encoded.
To generate one:  python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

This script runs in CI — never on customer machines.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
from pathlib import Path
from typing import Sequence

# Add parent to path so we can import proxy modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxy.crypto.profile_crypto import encrypt_profile


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt YAML profiles for distribution")
    parser.add_argument("--key", dest="key_cli", default=None, help=argparse.SUPPRESS)
    parser.add_argument(
        "--key-file",
        default=None,
        help=(
            "Path to a file containing the base64-encoded 32-byte profile "
            "master key. Defaults to ARKHEIA_PROFILE_MASTER_KEY."
        ),
    )
    parser.add_argument("--profile-dir", default="profiles", help="Source directory with .yaml files")
    parser.add_argument("--output-dir", default=None, help="Output directory (defaults to profile-dir)")
    parser.add_argument("--keep-plaintext", action="store_true", help="Don't delete .yaml originals")
    return parser.parse_args(argv)


def _read_key_file(key_file: str) -> str:
    return Path(key_file).read_text(encoding="utf-8").strip()


def resolve_master_key(key_cli: str | None = None, key_file: str | None = None) -> bytes:
    if key_cli:
        raise ValueError(
            "Refusing profile master key on the command line. Use "
            "ARKHEIA_PROFILE_MASTER_KEY or --key-file instead."
        )

    key_b64 = (
        _read_key_file(key_file)
        if key_file
        else os.environ.get("ARKHEIA_PROFILE_MASTER_KEY")
    )
    if not key_b64:
        raise ValueError(
            "Profile key missing. Set ARKHEIA_PROFILE_MASTER_KEY or pass --key-file."
        )

    try:
        master_key = base64.b64decode(key_b64)
    except binascii.Error as exc:
        raise ValueError("Profile key must be valid base64.") from exc
    if len(master_key) != 32:
        raise ValueError(f"Profile key must decode to 32 bytes, got {len(master_key)}.")
    return master_key


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        master_key = resolve_master_key(args.key_cli, args.key_file)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    profile_dir = Path(args.profile_dir)
    output_dir = Path(args.output_dir) if args.output_dir else profile_dir

    if not profile_dir.exists():
        print(f"ERROR: Profile directory not found: {profile_dir}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = {}
    encrypted_count = 0

    for yaml_file in sorted(profile_dir.glob("*.yaml")):
        if yaml_file.name == "schema.yaml":
            continue

        profile_name = yaml_file.stem  # e.g. "gpt-4o" from "gpt-4o.yaml"
        plaintext = yaml_file.read_bytes()
        encrypted = encrypt_profile(plaintext, master_key, profile_name)

        enc_path = output_dir / f"{profile_name}.yaml.enc"
        enc_path.write_bytes(encrypted)

        manifest[profile_name] = {
            "file": enc_path.name,
            "plaintext_size": len(plaintext),
            "encrypted_size": len(encrypted),
        }
        encrypted_count += 1
        print(f"  Encrypted: {yaml_file.name} -> {enc_path.name} ({len(encrypted)} bytes)")

        if not args.keep_plaintext:
            yaml_file.unlink()
            print(f"  Removed:   {yaml_file.name}")

    # Write manifest (not encrypted — just profile names and versions)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"\nDone: {encrypted_count} profiles encrypted, manifest at {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
