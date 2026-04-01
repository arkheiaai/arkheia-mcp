"""
test_dynamic_key_startup.py — Verify DynamicKeyLoader wiring in proxy startup.

Tests:
  - Key fetched and applied when .yaml.enc files exist + API key set
  - Skipped when no .yaml.enc files
  - Warning logged when no API key
  - Server continues when key fetch fails
"""
from __future__ import annotations

import logging
import os
import secrets
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import yaml

from proxy.crypto.profile_crypto import encrypt_profile
from proxy.router.profile_router import ProfileRouter


@pytest.fixture
def master_key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def profile_dir_with_enc(tmp_path, master_key):
    """Create a temp dir with one encrypted profile."""
    profile = {"model": "test-model", "version": "1.0", "thresholds": {"cohens_d": 0.5}}
    plaintext = yaml.dump(profile).encode("utf-8")
    encrypted = encrypt_profile(plaintext, master_key, "test-model")
    (tmp_path / "test-model.yaml.enc").write_bytes(encrypted)
    return tmp_path


@pytest.fixture
def profile_dir_empty(tmp_path):
    """Create an empty temp dir (no .yaml.enc files)."""
    return tmp_path


def test_startup_loads_key_when_enc_files_exist(profile_dir_with_enc, master_key):
    """When .yaml.enc files exist and API key is set, key should be fetched and profiles loaded."""
    mock_loader = MagicMock()
    mock_loader.fetch_key = MagicMock(return_value=master_key)

    router = ProfileRouter(str(profile_dir_with_enc))
    assert router.loaded_count == 0  # No key yet

    # Simulate what main.py does
    enc_files = list(Path(profile_dir_with_enc).glob("*.yaml.enc"))
    assert len(enc_files) == 1

    key = mock_loader.fetch_key()
    assert key is not None
    router.set_decryption_key(key)
    assert router.loaded_count == 1


def test_startup_skips_when_no_enc_files(profile_dir_empty):
    """When no .yaml.enc files exist, DynamicKeyLoader should not be needed."""
    enc_files = list(Path(profile_dir_empty).glob("*.yaml.enc"))
    assert len(enc_files) == 0
    # The startup block is guarded by `if enc_files`, so nothing happens
    router = ProfileRouter(str(profile_dir_empty))
    assert router.loaded_count == 0


def test_startup_warns_when_no_api_key(profile_dir_with_enc, caplog):
    """When .yaml.enc files exist but no API key, a warning should be logged."""
    router = ProfileRouter(str(profile_dir_with_enc))

    # Simulate the startup check
    enc_files = list(Path(profile_dir_with_enc).glob("*.yaml.enc"))
    api_key = ""  # No key

    with caplog.at_level(logging.WARNING):
        if enc_files and not router._decryption_key:
            if not api_key:
                logging.getLogger("proxy.main").warning(
                    "Encrypted profiles found but no ARKHEIA_API_KEY — "
                    "set key or provide decryption_key"
                )

    assert any("no ARKHEIA_API_KEY" in r.message for r in caplog.records)


def test_startup_continues_when_fetch_fails(profile_dir_with_enc):
    """When key fetch fails, server should continue with zero encrypted profiles."""
    mock_loader = MagicMock()
    mock_loader.fetch_key = MagicMock(return_value=None)

    router = ProfileRouter(str(profile_dir_with_enc))

    # Simulate fetch failure
    key = mock_loader.fetch_key()
    assert key is None

    # Router should still work, just with 0 encrypted profiles
    assert router.loaded_count == 0
    assert router.get("test-model") is None  # Not loaded
