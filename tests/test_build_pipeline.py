from __future__ import annotations

import importlib.util
import base64
import json
import secrets
import shutil
import uuid
from pathlib import Path

import pytest

HAS_SETUPTOOLS = importlib.util.find_spec("setuptools") is not None

if HAS_SETUPTOOLS:
    import setup_cython
else:
    setup_cython = None

from scripts import build_release
from scripts import encrypt_profiles

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

        encrypted_count = build_release.step_encrypt_profiles(secrets.token_bytes(32), profiles_dir)

        assert encrypted_count == 1
        assert not (profiles_dir / "gpt-4o.yaml").exists()
        assert (profiles_dir / "gpt-4o.yaml.enc").exists()
        assert (profiles_dir / "schema.yaml").exists()
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_rejects_command_line_profile_key_without_echo():
    secret = base64.b64encode(secrets.token_bytes(32)).decode()
    with pytest.raises(ValueError) as exc:
        build_release.resolve_profile_key(profile_key_cli=secret)

    message = str(exc.value)
    assert "command line" in message
    assert secret not in message


def test_build_release_main_rejects_command_line_profile_key_without_echo(capsys):
    secret = base64.b64encode(secrets.token_bytes(32)).decode()

    rc = build_release.main(["--profile-key", secret, "--skip-compile"])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "command line" in captured.err
    assert secret not in rendered
    assert "Traceback" not in rendered


def test_build_release_fails_closed_without_profile_key(monkeypatch):
    monkeypatch.delenv("ARKHEIA_PROFILE_MASTER_KEY", raising=False)

    with pytest.raises(ValueError) as exc:
        build_release.resolve_profile_key()

    assert "Profile key missing" in str(exc.value)


def test_build_release_main_fails_closed_without_profile_key(monkeypatch, capsys):
    monkeypatch.delenv("ARKHEIA_PROFILE_MASTER_KEY", raising=False)

    rc = build_release.main(["--skip-compile"])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "Profile key missing" in captured.err
    assert "Traceback" not in rendered


def test_build_release_reads_profile_key_file(tmp_path):
    raw = secrets.token_bytes(32)
    key_file = tmp_path / "profile-key"
    key_file.write_text(base64.b64encode(raw).decode(), encoding="utf-8")

    assert build_release.resolve_profile_key(profile_key_file=str(key_file)) == raw


def test_build_release_missing_profile_key_file_is_clean_error(tmp_path, capsys):
    missing = tmp_path / "missing-profile-key"

    rc = build_release.main(["--skip-compile", "--profile-key-file", str(missing)])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "ERROR: Could not read profile key file." in captured.err
    assert "Traceback" not in rendered
    assert str(missing) not in rendered


def test_encrypt_profiles_rejects_command_line_key_without_echo():
    secret = base64.b64encode(secrets.token_bytes(32)).decode()
    with pytest.raises(ValueError) as exc:
        encrypt_profiles.resolve_master_key(key_cli=secret)

    message = str(exc.value)
    assert "command line" in message
    assert secret not in message


def test_encrypt_profiles_main_rejects_command_line_key_without_echo(tmp_path, capsys):
    secret = base64.b64encode(secrets.token_bytes(32)).decode()
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    (profiles_dir / "gpt-4o.yaml").write_text("model: gpt-4o\n", encoding="utf-8")

    rc = encrypt_profiles.main(["--key", secret, "--profile-dir", str(profiles_dir)])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "command line" in captured.err
    assert secret not in rendered
    assert "Traceback" not in rendered
    assert (profiles_dir / "gpt-4o.yaml").exists()
    assert not (profiles_dir / "gpt-4o.yaml.enc").exists()


def test_encrypt_profiles_fails_closed_without_profile_key(monkeypatch):
    monkeypatch.delenv("ARKHEIA_PROFILE_MASTER_KEY", raising=False)

    with pytest.raises(ValueError) as exc:
        encrypt_profiles.resolve_master_key()

    assert "Profile key missing" in str(exc.value)


def test_encrypt_profiles_main_fails_closed_without_profile_key(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("ARKHEIA_PROFILE_MASTER_KEY", raising=False)
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    (profiles_dir / "gpt-4o.yaml").write_text("model: gpt-4o\n", encoding="utf-8")

    rc = encrypt_profiles.main(["--profile-dir", str(profiles_dir)])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "Profile key missing" in captured.err
    assert "Traceback" not in rendered
    assert (profiles_dir / "gpt-4o.yaml").exists()
    assert not (profiles_dir / "gpt-4o.yaml.enc").exists()


def test_encrypt_profiles_reads_profile_key_file(tmp_path):
    raw = secrets.token_bytes(32)
    key_file = tmp_path / "profile-key"
    key_file.write_text(base64.b64encode(raw).decode(), encoding="utf-8")

    assert encrypt_profiles.resolve_master_key(key_file=str(key_file)) == raw


def test_encrypt_profiles_missing_key_file_is_clean_error(tmp_path, capsys):
    missing = tmp_path / "missing-profile-key"

    rc = encrypt_profiles.main(["--key-file", str(missing)])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert rc == 1
    assert "ERROR: Could not read profile key file." in captured.err
    assert "Traceback" not in rendered
    assert str(missing) not in rendered


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
