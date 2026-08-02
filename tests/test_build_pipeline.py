from __future__ import annotations

import hashlib
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
from proxy.license.integrity import (
    MANIFEST_FILE,
    IntegrityStatus,
    TamperDetected,
    generate_manifest,
    verify_integrity,
)

HAS_CYTHON = importlib.util.find_spec("Cython") is not None
TEMP_ROOT = Path(__file__).resolve().parent.parent / ".tmp_test_build_pipeline"
PROFILE_KEY = "A" * 43 + "="


def make_case_dir(case_name: str) -> Path:
    TEMP_ROOT.mkdir(exist_ok=True)
    case_dir = TEMP_ROOT / f"{case_name}_{uuid.uuid4().hex}"
    case_dir.mkdir()
    return case_dir


def _fake_binary(directory: Path, name: str, payload: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(payload)
    return path


def _release_repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "profiles").mkdir(parents=True)
    (root / "profiles" / "demo.yaml").write_text("model: demo\nversion: '1.0'\n")
    pkg = root / "proxy" / "detection"
    pkg.mkdir(parents=True)
    (pkg / "features.py").write_text("# real source, must survive failed builds\n")
    (pkg / "engine.py").write_text("# real source, must survive failed builds\n")
    return root


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


def test_build_release_manifest_step(capsys):
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
        assert fake_module.name in capsys.readouterr().out
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)


def test_build_release_manifest_is_consumed_by_integrity_report(tmp_path):
    module_dir = tmp_path / "detection"
    features = _fake_binary(
        module_dir,
        "features.cpython-312-darwin.so",
        b"\x7fELF" + b"features-bytes" * 8,
    )
    engine = _fake_binary(
        module_dir,
        "engine.cpython-312-darwin.so",
        b"\x7fELF" + b"engine-bytes" * 8,
    )
    (module_dir / "notes.txt").write_text("not a compiled module")

    returned = build_release.step_generate_manifest(module_dir)
    manifest_path = module_dir / MANIFEST_FILE
    on_disk = json.loads(manifest_path.read_text())

    assert on_disk == returned
    assert set(on_disk) == {features.name, engine.name}
    assert "notes.txt" not in on_disk
    for name, recorded in on_disk.items():
        assert recorded == hashlib.sha256((module_dir / name).read_bytes()).hexdigest()

    report = verify_integrity(module_dir)
    assert report.status == IntegrityStatus.VERIFIED
    assert report.verified is True
    assert report.modules_checked == 2

    manifest = json.loads(manifest_path.read_text())
    fabricated = f"{uuid.uuid4().hex}.so"
    manifest[fabricated] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(TamperDetected, match=fabricated):
        verify_integrity(module_dir)

    manifest.pop(fabricated)
    manifest[engine.name] = "f" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(TamperDetected, match=engine.name):
        verify_integrity(module_dir)

    manifest[engine.name] = hashlib.sha256(engine.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    assert verify_integrity(module_dir).status == IntegrityStatus.VERIFIED

    engine.write_bytes(b"\x7fELF" + b"tampered" * 8)
    with pytest.raises(TamperDetected, match=engine.name):
        verify_integrity(module_dir)


def test_empty_manifest_is_runtime_tamper_not_verified(tmp_path):
    empty_dir = tmp_path / "no_binaries"
    empty_dir.mkdir()

    manifest = generate_manifest(empty_dir, empty_dir / MANIFEST_FILE)
    assert manifest == {}

    with pytest.raises(TamperDetected, match="[Ee]mpty"):
        verify_integrity(empty_dir)


def test_step_3_refuses_to_ship_a_manifest_that_certifies_nothing(tmp_path):
    empty_dir = tmp_path / "no_binaries"
    empty_dir.mkdir()

    with pytest.raises(build_release.EmptyManifest) as exc:
        build_release.step_generate_manifest(empty_dir)

    message = str(exc.value)
    assert str(empty_dir) in message
    for glob in build_release.COMPILED_ARTIFACT_GLOBS:
        assert glob in message
    assert "verify_integrity()" in message
    assert not (empty_dir / MANIFEST_FILE).exists()

    good = tmp_path / "has_binaries"
    _fake_binary(good, "features.so", b"\x7fELFsome-real-bytes")
    assert build_release.step_generate_manifest(good) != {}
    assert (good / MANIFEST_FILE).exists()


def test_build_with_no_binaries_aborts_before_deleting_sources(tmp_path, monkeypatch, capsys):
    root = _release_repo(tmp_path)
    sources = [
        root / "proxy" / "detection" / "features.py",
        root / "proxy" / "detection" / "engine.py",
    ]

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    rc = build_release.main(["--skip-compile", "--profile-key", PROFILE_KEY])
    out = capsys.readouterr()

    assert rc == 1
    assert "Release build complete" not in out.out
    assert "ERROR:" in out.err
    for source in sources:
        assert source.exists()
    assert not list(root.rglob(MANIFEST_FILE))


def test_partly_compiled_build_names_modules_no_record_covers(
    tmp_path, monkeypatch, capsys
):
    root = _release_repo(tmp_path)
    pkg = root / "proxy" / "detection"
    _fake_binary(pkg, "features.cpython-312-darwin.so", b"\x7fELF" + b"x" * 64)

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    rc = build_release.main(["--skip-compile", "--profile-key", PROFILE_KEY])
    out = capsys.readouterr()

    assert rc == 1
    assert "proxy/detection/engine.py" in out.err
    assert "proxy/detection/features.py" not in out.err
    assert (pkg / "engine.py").exists()
    assert (pkg / "features.py").exists()


def test_complete_compiled_build_records_every_module_then_removes_sources(
    tmp_path, monkeypatch, capsys
):
    root = _release_repo(tmp_path)
    pkg = root / "proxy" / "detection"
    _fake_binary(pkg, "features.cpython-312-darwin.so", b"\x7fELF" + b"x" * 64)
    _fake_binary(pkg, "engine.cpython-312-darwin.so", b"\x7fELF" + b"y" * 64)

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    rc = build_release.main(["--skip-compile", "--profile-key", PROFILE_KEY])
    out = capsys.readouterr()

    assert rc == 0, out.err
    assert "Release build complete" in out.out
    assert "2 of 2 modules recorded" in out.out

    manifest = json.loads((pkg / MANIFEST_FILE).read_text())
    assert sorted(manifest) == [
        "engine.cpython-312-darwin.so",
        "features.cpython-312-darwin.so",
    ]
    for name, recorded in manifest.items():
        assert recorded == hashlib.sha256((pkg / name).read_bytes()).hexdigest()

    assert not (pkg / "features.py").exists()
    assert not (pkg / "engine.py").exists()


@pytest.mark.skipif(not HAS_SETUPTOOLS or not HAS_CYTHON, reason="setuptools or Cython not installed")
def test_setup_cython_exposes_build_hook():
    assert callable(setup_cython.build_extensions)
