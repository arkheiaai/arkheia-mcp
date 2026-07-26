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

from proxy.crypto.profile_crypto import decrypt_profile, encrypt_profile


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

    candidates = [
        f for f in sorted(profile_dir.glob("*.yaml")) if f.name != "schema.yaml"
    ]

    # DONE.md floor invariant 9: a step that reports a count must fail when the
    # count is zero. Before 2026-07-26 this loop over an empty directory printed
    # "Done: 0 profiles encrypted" and exited 0 — a release that encrypted NOTHING
    # reported success, exactly as `generate_manifest` over a directory with no
    # `.so` wrote `{}` and then logged "Integrity check passed: 0 modules verified".
    if not candidates:
        print(
            f"ERROR: No profiles to encrypt in {profile_dir} (0 *.yaml files, "
            "excluding schema.yaml). Refusing to report a successful release "
            "build that encrypted nothing.",
            file=sys.stderr,
        )
        sys.exit(2)

    for yaml_file in candidates:
        profile_name = yaml_file.stem  # e.g. "gpt-4o" from "gpt-4o.yaml"
        plaintext = yaml_file.read_bytes()
        encrypted = encrypt_profile(plaintext, master_key, profile_name)

        enc_path = output_dir / f"{profile_name}.yaml.enc"
        enc_path.write_bytes(encrypted)

        # Verify the round trip BEFORE deleting the only plaintext copy. This step
        # is destructive and was previously unverified: it wrote the .enc, unlinked
        # the source, and never once proved the bytes it had just written could be
        # read back. A short write, a wrong-but-well-formed key, or any future
        # framing change would have destroyed the profile corpus irrecoverably,
        # and the symptom would not appear until a customer's proxy started up.
        readback = enc_path.read_bytes()
        recovered = decrypt_profile(readback, master_key, profile_name)
        if recovered != plaintext:
            print(
                f"ERROR: round-trip verification FAILED for {yaml_file.name} — "
                f"the encrypted file does not decrypt back to the source. "
                f"Plaintext NOT deleted. Aborting.",
                file=sys.stderr,
            )
            sys.exit(3)

        manifest[profile_name] = {
            "file": enc_path.name,
            "plaintext_size": len(plaintext),
            "encrypted_size": len(encrypted),
        }
        encrypted_count += 1
        print(
            f"  Encrypted: {yaml_file.name} -> {enc_path.name} "
            f"({len(encrypted)} bytes, round-trip verified)"
        )

        if not args.keep_plaintext:
            yaml_file.unlink()
            print(f"  Removed:   {yaml_file.name}")

    # Write manifest (not encrypted — just profile names and versions)
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    if encrypted_count != len(candidates):  # pragma: no cover - defensive
        missing = sorted({f.stem for f in candidates} - set(manifest))
        print(
            f"ERROR: {encrypted_count} of {len(candidates)} profiles encrypted. "
            f"NOT encrypted: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(4)

    print(f"\nDone: {encrypted_count} profiles encrypted, manifest at {manifest_path}")


if __name__ == "__main__":
    main()
