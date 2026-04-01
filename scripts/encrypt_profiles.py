#!/usr/bin/env python3
"""
Build-time tool: encrypt all YAML profiles into .yaml.enc files.

Usage:
    python scripts/encrypt_profiles.py --key <base64-master-key> [--profile-dir profiles/] [--output-dir profiles/]

The master key should be a 32-byte key, base64-encoded.
To generate one:  python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

This script runs in CI — never on customer machines.
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

# Add parent to path so we can import proxy modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from proxy.crypto.profile_crypto import encrypt_profile


def main():
    parser = argparse.ArgumentParser(description="Encrypt YAML profiles for distribution")
    parser.add_argument("--key", required=True, help="Base64-encoded 32-byte master key")
    parser.add_argument("--profile-dir", default="profiles", help="Source directory with .yaml files")
    parser.add_argument("--output-dir", default=None, help="Output directory (defaults to profile-dir)")
    parser.add_argument("--keep-plaintext", action="store_true", help="Don't delete .yaml originals")
    args = parser.parse_args()

    master_key = base64.b64decode(args.key)
    if len(master_key) != 32:
        print(f"ERROR: Key must be 32 bytes, got {len(master_key)}", file=sys.stderr)
        sys.exit(1)

    profile_dir = Path(args.profile_dir)
    output_dir = Path(args.output_dir) if args.output_dir else profile_dir

    if not profile_dir.exists():
        print(f"ERROR: Profile directory not found: {profile_dir}", file=sys.stderr)
        sys.exit(1)

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


if __name__ == "__main__":
    main()
