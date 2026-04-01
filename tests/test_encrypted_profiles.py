"""
test_encrypted_profiles.py — Profile encryption round-trip tests.

Verifies:
  - Encrypt/decrypt round-trip produces identical YAML
  - Wrong key fails decryption (InvalidTag)
  - Tampered ciphertext fails decryption
  - ProfileRouter loads .yaml.enc files when key is provided
  - ProfileRouter warns when .yaml.enc files exist but no key
  - Dynamic key loader cache save/load round-trip
"""
from __future__ import annotations

import base64
import secrets
import tempfile
from pathlib import Path

import pytest
import yaml

from proxy.crypto.profile_crypto import (
    decrypt_profile,
    derive_key,
    encrypt_profile,
    DynamicKeyLoader,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def sample_profile() -> dict:
    return {
        "model": "gpt-4o",
        "version": "1.0",
        "thresholds": {"cohens_d": 0.35, "confidence": 0.85},
        "features": {
            "truth_mean": 0.72,
            "fab_mean": 0.31,
            "sentence_length_ratio": 1.12,
        },
    }


@pytest.fixture
def profile_yaml(sample_profile) -> bytes:
    return yaml.dump(sample_profile).encode("utf-8")


# ---------------------------------------------------------------------------
# Encrypt/Decrypt Round-Trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_round_trip(master_key, profile_yaml):
    """Encrypt then decrypt should produce identical plaintext."""
    encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
    decrypted = decrypt_profile(encrypted, master_key, "gpt-4o")
    assert decrypted == profile_yaml


def test_decrypt_with_wrong_key(master_key, profile_yaml):
    """Decryption with wrong key should raise InvalidTag."""
    from cryptography.exceptions import InvalidTag

    encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
    wrong_key = secrets.token_bytes(32)
    with pytest.raises(InvalidTag):
        decrypt_profile(encrypted, wrong_key, "gpt-4o")


def test_decrypt_with_wrong_profile_name(master_key, profile_yaml):
    """Decryption with wrong profile name (AAD mismatch) should raise InvalidTag."""
    from cryptography.exceptions import InvalidTag

    encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
    with pytest.raises(InvalidTag):
        decrypt_profile(encrypted, master_key, "claude-sonnet-4-6")


def test_tampered_ciphertext(master_key, profile_yaml):
    """Flipping a byte in ciphertext should fail decryption."""
    from cryptography.exceptions import InvalidTag

    encrypted = bytearray(encrypt_profile(profile_yaml, master_key, "gpt-4o"))
    # Flip a byte in the ciphertext (after the 12-byte nonce)
    encrypted[20] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_profile(bytes(encrypted), master_key, "gpt-4o")


def test_too_short_data(master_key):
    """Data shorter than nonce + tag should raise ValueError."""
    with pytest.raises(ValueError, match="too short"):
        decrypt_profile(b"short", master_key, "test")


def test_derive_key_deterministic(master_key):
    """Same inputs should produce same derived key."""
    k1 = derive_key(master_key, "gpt-4o")
    k2 = derive_key(master_key, "gpt-4o")
    assert k1 == k2
    assert len(k1) == 32


def test_derive_key_different_profiles(master_key):
    """Different profile names should produce different keys."""
    k1 = derive_key(master_key, "gpt-4o")
    k2 = derive_key(master_key, "claude-sonnet-4-6")
    assert k1 != k2


# ---------------------------------------------------------------------------
# ProfileRouter with Encrypted Profiles
# ---------------------------------------------------------------------------

def test_profile_router_loads_encrypted(master_key, sample_profile, profile_yaml):
    """ProfileRouter should load .yaml.enc files when decryption key is set."""
    from proxy.router.profile_router import ProfileRouter

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write encrypted profile
        encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
        (Path(tmpdir) / "gpt-4o.yaml.enc").write_bytes(encrypted)

        router = ProfileRouter(tmpdir, decryption_key=master_key)
        assert router.loaded_count == 1
        profile = router.get("gpt-4o")
        assert profile is not None
        assert profile["model"] == "gpt-4o"
        assert profile["thresholds"]["cohens_d"] == 0.35


def test_profile_router_warns_no_key(master_key, profile_yaml, caplog):
    """ProfileRouter should warn when encrypted profiles exist but no key."""
    import logging
    from proxy.router.profile_router import ProfileRouter

    with tempfile.TemporaryDirectory() as tmpdir:
        encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
        (Path(tmpdir) / "gpt-4o.yaml.enc").write_bytes(encrypted)

        with caplog.at_level(logging.WARNING):
            router = ProfileRouter(tmpdir)  # No decryption key
            assert router.loaded_count == 0

        assert any("no decryption key" in r.message.lower() for r in caplog.records)


def test_profile_router_mixed_plaintext_and_encrypted(master_key, sample_profile, profile_yaml):
    """ProfileRouter should load both .yaml and .yaml.enc files."""
    from proxy.router.profile_router import ProfileRouter

    with tempfile.TemporaryDirectory() as tmpdir:
        # Write plaintext profile
        claude_profile = {**sample_profile, "model": "claude-sonnet-4-6"}
        (Path(tmpdir) / "claude-sonnet-4-6.yaml").write_text(yaml.dump(claude_profile))

        # Write encrypted profile
        encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
        (Path(tmpdir) / "gpt-4o.yaml.enc").write_bytes(encrypted)

        router = ProfileRouter(tmpdir, decryption_key=master_key)
        assert router.loaded_count == 2
        assert router.get("gpt-4o") is not None
        assert router.get("claude-sonnet-4-6") is not None


def test_profile_router_set_decryption_key(master_key, profile_yaml):
    """set_decryption_key should reload encrypted profiles."""
    from proxy.router.profile_router import ProfileRouter

    with tempfile.TemporaryDirectory() as tmpdir:
        encrypted = encrypt_profile(profile_yaml, master_key, "gpt-4o")
        (Path(tmpdir) / "gpt-4o.yaml.enc").write_bytes(encrypted)

        # Start without key
        router = ProfileRouter(tmpdir)
        assert router.loaded_count == 0

        # Set key — should reload and find the encrypted profile
        router.set_decryption_key(master_key)
        assert router.loaded_count == 1
        assert router.get("gpt-4o") is not None


# ---------------------------------------------------------------------------
# Dynamic Key Loader Cache
# ---------------------------------------------------------------------------

def test_key_loader_cache_round_trip():
    """Save and load from local cache should return same key."""
    key = secrets.token_bytes(32)
    loader = DynamicKeyLoader("http://localhost:8098", "ak_live_test")

    loader._save_cache(key)
    loaded = loader._load_cache()
    assert loaded == key

    # Cleanup
    if loader.CACHE_FILE.exists():
        loader.CACHE_FILE.unlink()


def test_key_loader_no_cache():
    """Load from missing cache should return None."""
    loader = DynamicKeyLoader("http://localhost:8098", "ak_live_test")
    # Ensure no cache file
    if loader.CACHE_FILE.exists():
        loader.CACHE_FILE.unlink()
    assert loader._load_cache() is None


# ---------------------------------------------------------------------------
# Integrity Module
# ---------------------------------------------------------------------------

def test_integrity_no_manifest():
    """No manifest file should pass (dev mode)."""
    from proxy.license.integrity import verify_integrity

    with tempfile.TemporaryDirectory() as tmpdir:
        assert verify_integrity(Path(tmpdir)) is True


def test_integrity_valid_manifest():
    """Valid manifest should pass verification."""
    from proxy.license.integrity import generate_manifest, verify_integrity

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        # Create a fake .so file
        (p / "features.cpython-312.so").write_bytes(b"fake compiled module content")
        generate_manifest(p, p / "integrity_manifest.json")
        assert verify_integrity(p) is True


def test_integrity_tampered_module():
    """Tampered module should raise TamperDetected."""
    from proxy.license.integrity import generate_manifest, verify_integrity, TamperDetected

    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir)
        mod = p / "features.cpython-312.so"
        mod.write_bytes(b"original content")
        generate_manifest(p, p / "integrity_manifest.json")

        # Tamper with the module
        mod.write_bytes(b"tampered content")
        with pytest.raises(TamperDetected, match="Modified module"):
            verify_integrity(p)
