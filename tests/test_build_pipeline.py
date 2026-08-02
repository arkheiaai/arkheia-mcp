from __future__ import annotations

import hashlib
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

    # The key goes through ARKHEIA_PROFILE_MASTER_KEY, not argv. This branch makes
    # `--profile-key` a HARD REFUSAL -- a master key on the command line is visible in `ps`
    # output to every user on the box -- so passing it that way makes main() return 1 at
    # step 0 and this test never reaches the manifest behaviour it exists to pin. The subject
    # here is what the manifest RECORDS; argv was only ever the plumbing.
    monkeypatch.setenv("ARKHEIA_PROFILE_MASTER_KEY", PROFILE_KEY)
    rc = build_release.main(["--skip-compile"])
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

    # The key goes through ARKHEIA_PROFILE_MASTER_KEY, not argv. This branch makes
    # `--profile-key` a HARD REFUSAL -- a master key on the command line is visible in `ps`
    # output to every user on the box -- so passing it that way makes main() return 1 at
    # step 0 and this test never reaches the manifest behaviour it exists to pin. The subject
    # here is what the manifest RECORDS; argv was only ever the plumbing.
    monkeypatch.setenv("ARKHEIA_PROFILE_MASTER_KEY", PROFILE_KEY)
    rc = build_release.main(["--skip-compile"])
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

    # The key goes through ARKHEIA_PROFILE_MASTER_KEY, not argv. This branch makes
    # `--profile-key` a HARD REFUSAL -- a master key on the command line is visible in `ps`
    # output to every user on the box -- so passing it that way makes main() return 1 at
    # step 0 and this test never reaches the manifest behaviour it exists to pin. The subject
    # here is what the manifest RECORDS; argv was only ever the plumbing.
    monkeypatch.setenv("ARKHEIA_PROFILE_MASTER_KEY", PROFILE_KEY)
    rc = build_release.main(["--skip-compile"])
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
