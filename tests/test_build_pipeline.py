from __future__ import annotations

import base64
import importlib.util
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

HAS_CYTHON = importlib.util.find_spec("Cython") is not None
TEMP_ROOT = Path(__file__).resolve().parent.parent / ".tmp_test_build_pipeline"


def make_case_dir(case_name: str) -> Path:
    TEMP_ROOT.mkdir(exist_ok=True)
    case_dir = TEMP_ROOT / f"{case_name}_{uuid.uuid4().hex}"
    case_dir.mkdir()
    return case_dir


def release_key() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def seed_release_profiles(repo_root: Path) -> None:
    profiles_dir = repo_root / "profiles"
    profiles_dir.mkdir()
    (profiles_dir / "gpt-4o.yaml").write_text(
        "model: gpt-4o\nthresholds:\n  cohens_d: 0.35\n",
        encoding="utf-8",
    )
    (profiles_dir / "schema.yaml").write_text("type: object\n", encoding="utf-8")


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


def test_build_release_refuses_empty_compiled_module_configuration(monkeypatch, capsys):
    """
    Hard-empty release floor: a build whose configured compiled-module population
    is empty must fail before it can print a successful release summary.
    """
    case_dir = make_case_dir("empty_compiled_modules")
    try:
        seed_release_profiles(case_dir)
        monkeypatch.setattr(build_release, "REPO_ROOT", case_dir)
        monkeypatch.setattr(build_release, "COMPILED_MODULES", [])

        rc = build_release.main(["--skip-compile", "--profile-key", release_key()])

        captured = capsys.readouterr()
        assert rc == 1
        assert "No compiled modules configured" in captured.err
        assert "Release build complete" not in captured.out
        assert (case_dir / "profiles" / "gpt-4o.yaml").exists(), (
            "the build mutated profiles before refusing the empty compiled-module "
            "population"
        )
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_refuses_manifest_dirs_with_zero_compiled_artifacts(
    monkeypatch, capsys
):
    """
    Soft-empty release floor: COMPILED_MODULES can be non-empty while the compiled
    artifact population is still empty, for example when --skip-compile is used
    against a clean source checkout. That must not produce an empty manifest and
    report success.
    """
    case_dir = make_case_dir("zero_compiled_artifacts")
    try:
        seed_release_profiles(case_dir)
        source_path = case_dir / "proxy" / "detection" / "features.py"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("VALUE = 1\n", encoding="utf-8")
        monkeypatch.setattr(build_release, "REPO_ROOT", case_dir)
        monkeypatch.setattr(build_release, "COMPILED_MODULES", [
            "proxy/detection/features.py",
        ])

        rc = build_release.main(["--skip-compile", "--profile-key", release_key()])

        captured = capsys.readouterr()
        assert rc == 1
        assert "No compiled artifacts found" in captured.err
        assert "Release build complete" not in captured.out
        assert not (source_path.parent / "integrity_manifest.json").exists()
        assert source_path.exists(), (
            "the build removed source before proving there was a compiled artifact "
            "to manifest"
        )
        assert (case_dir / "profiles" / "gpt-4o.yaml").exists(), (
            "the build encrypted profiles before refusing the empty compiled "
            "artifact population"
        )
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


@pytest.mark.skipif(not HAS_SETUPTOOLS or not HAS_CYTHON, reason="setuptools or Cython not installed")
def test_setup_cython_exposes_build_hook():
    assert callable(setup_cython.build_extensions)
