from __future__ import annotations

import importlib.util
import json
import secrets
import shutil
import uuid
from pathlib import Path

import pytest

from proxy.crypto.profile_crypto import decrypt_profile

HAS_SETUPTOOLS = importlib.util.find_spec("setuptools") is not None

if HAS_SETUPTOOLS:
    import setup_cython
else:
    setup_cython = None

from scripts import build_release

HAS_CYTHON = importlib.util.find_spec("Cython") is not None
TEMP_ROOT = Path(__file__).resolve().parent.parent / ".tmp_test_build_pipeline"


def make_case_dir(case_name: str) -> Path:
    TEMP_ROOT.mkdir(exist_ok=True)
    case_dir = TEMP_ROOT / f"{case_name}_{uuid.uuid4().hex}"
    case_dir.mkdir()
    return case_dir


@pytest.mark.skipif(not HAS_SETUPTOOLS, reason="setuptools not installed")
def test_setup_cython_has_modules():
    assert setup_cython.COMPILED_MODULES == [
        "proxy/detection/features.py",
        "proxy/detection/engine.py",
        "proxy/router/profile_router.py",
    ]


def test_build_release_encrypt_step():
    case_dir = make_case_dir("encrypt")
    try:
        profiles_dir = case_dir / "profiles"
        profiles_dir.mkdir()
        (profiles_dir / "gpt-4o.yaml").write_text("model: gpt-4o\nthresholds:\n  cohens_d: 0.35\n")
        (profiles_dir / "schema.yaml").write_text("type: object\n")

        source_bytes = (profiles_dir / "gpt-4o.yaml").read_bytes()
        master_key = secrets.token_bytes(32)
        encrypted_count = build_release.step_encrypt_profiles(master_key, profiles_dir)

        assert encrypted_count == 1
        assert not (profiles_dir / "gpt-4o.yaml").exists()
        assert (profiles_dir / "gpt-4o.yaml.enc").exists()
        assert (profiles_dir / "schema.yaml").exists()

        # The plaintext is now GONE, so the only thing that makes deleting it safe is that the
        # ciphertext decrypts back to it. Assert that, not merely that the .enc file exists.
        recovered = decrypt_profile(
            (profiles_dir / "gpt-4o.yaml.enc").read_bytes(), master_key, "gpt-4o"
        )
        assert recovered == source_bytes
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_encrypt_step_refuses_to_delete_unrecoverable_plaintext(monkeypatch):
    """The release path must not destroy the source when the ciphertext cannot be recovered.

    Before the round-trip guard, a broken encrypt_profile wrote undecryptable bytes, the step
    printed success and returned 1, and gpt-4o.yaml was deleted -- unrecoverable loss that every
    other assertion in this file passed straight through.
    """
    case_dir = make_case_dir("encrypt-unrecoverable")
    try:
        profiles_dir = case_dir / "profiles"
        profiles_dir.mkdir()
        (profiles_dir / "gpt-4o.yaml").write_text("model: gpt-4o\n")

        monkeypatch.setattr(
            build_release, "encrypt_profile",
            lambda plaintext, master_key, profile_name: b"not-a-valid-aes-gcm-profile",
        )
        with pytest.raises(RuntimeError, match="Refusing to delete"):
            build_release.step_encrypt_profiles(secrets.token_bytes(32), profiles_dir)

        assert (profiles_dir / "gpt-4o.yaml").exists(), "source plaintext must survive a failed encrypt"
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_encrypt_step_refuses_a_zero_profile_release():
    """Zero encrypted profiles previously printed 'Profiles encrypted: 0' and returned success."""
    case_dir = make_case_dir("encrypt-empty")
    try:
        profiles_dir = case_dir / "profiles"
        profiles_dir.mkdir()
        (profiles_dir / "schema.yaml").write_text("type: object\n")
        with pytest.raises(RuntimeError, match="no profiles were encrypted"):
            build_release.step_encrypt_profiles(secrets.token_bytes(32), profiles_dir)
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_manifest_step():
    case_dir = make_case_dir("manifest")
    try:
        module_dir = case_dir / "compiled"
        module_dir.mkdir()
        fake_module = module_dir / "features.cpython-313-x86_64-linux-gnu.so"
        fake_module.write_bytes(b"compiled-bytes")
        manifest_path = module_dir / "integrity_manifest.json"

        manifest = build_release.step_generate_manifest(module_dir, manifest_path)

        assert manifest_path.exists()
        manifest_json = json.loads(manifest_path.read_text())
        assert manifest == manifest_json
        assert fake_module.name in manifest_json
        assert len(manifest_json[fake_module.name]) == 64
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


@pytest.mark.skipif(not HAS_SETUPTOOLS or not HAS_CYTHON, reason="setuptools or Cython not installed")
def test_setup_cython_exposes_build_hook():
    assert callable(setup_cython.build_extensions)
