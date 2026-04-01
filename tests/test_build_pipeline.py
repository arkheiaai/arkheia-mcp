from __future__ import annotations

import importlib.util
import json
import secrets
import shutil
import uuid
from pathlib import Path

import pytest

import setup_cython
from scripts import build_release

HAS_CYTHON = importlib.util.find_spec("Cython") is not None
TEMP_ROOT = Path(__file__).resolve().parent.parent / ".tmp_test_build_pipeline"


def make_case_dir(case_name: str) -> Path:
    TEMP_ROOT.mkdir(exist_ok=True)
    case_dir = TEMP_ROOT / f"{case_name}_{uuid.uuid4().hex}"
    case_dir.mkdir()
    return case_dir


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


@pytest.mark.skipif(not HAS_CYTHON, reason="Cython is not installed")
def test_setup_cython_exposes_build_hook():
    assert callable(setup_cython.build_extensions)
