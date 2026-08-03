"""
Startup binary-integrity: fail open on source checkouts, fail closed on evidence.

This file used to assert the retired ``IntegrityReport`` API. PR #29 splits the
API differently:

* ``build_integrity_record()`` names the state and the measured population.
* ``verify_integrity()`` is policy: returns ``True`` for non-halting states and
  raises ``TamperDetected`` for every halting state.
* ``proxy.main`` drives ``verify_and_receipt()`` so the runtime verdict is
  written before startup is allowed or refused.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from proxy.license import integrity as integrity_mod
from proxy.license.integrity import (
    MANIFEST_FILE,
    VERDICT_TAMPERED,
    VERDICT_UNVERIFIABLE,
    VERDICT_VERIFIED,
    TamperDetected,
    build_integrity_record,
    generate_manifest,
    verify_integrity,
)

MODULE_NAME = "_probe_features.cpython-312.so"
ORIGINAL_BYTES = b"pretend this is a compiled detection module"


def _write_verified_module(root: Path) -> Path:
    mod_dir = root / "detection"
    mod_dir.mkdir(parents=True, exist_ok=True)
    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES)
    generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    return mod_dir


def _audit_rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.fixture
def app_env(monkeypatch, tmp_path):
    """
    Redirect every absolute production path touched by the real lifespan.

    The profile directory must exist or startup raises before the integrity
    block, which would make refusal tests pass for the wrong reason.
    """
    from proxy.config import settings

    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    audit_log = tmp_path / "audit.jsonl"

    monkeypatch.setattr(settings.detection, "profile_dir", str(profiles_dir))
    monkeypatch.setattr(settings.audit, "log_path", str(audit_log))
    monkeypatch.setattr(settings.registry, "pull_on_startup", False)
    monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)
    monkeypatch.setenv(
        "JWT_SECRET",
        "ci-test-secret-not-for-production-use-minimum-32chars!!",
    )
    monkeypatch.delenv("ARKHEIA_REQUIRE_LICENSE", raising=False)
    return audit_log


def test_verify_integrity_distinguishes_verified_from_no_manifest(tmp_path):
    """The source-checkout and verified states both boot, but record differently."""
    empty = tmp_path / "source_checkout"
    empty.mkdir()

    absent = build_integrity_record(empty)
    assert absent["verdict"] == VERDICT_UNVERIFIABLE
    assert absent["modules_expected"] == 0
    assert absent["compiled_artifacts_present"] == []
    assert verify_integrity(empty) is True

    mod_dir = _write_verified_module(tmp_path / "pkg")
    ok = build_integrity_record(mod_dir)
    assert ok["verdict"] == VERDICT_VERIFIED
    assert ok["modules_expected"] == 1
    assert ok["modules_matched"] == 1
    assert verify_integrity(mod_dir) is True

    assert ok["verdict"] != absent["verdict"]


def test_verify_integrity_raises_on_empty_manifest(tmp_path):
    mod_dir = tmp_path / "detection"
    mod_dir.mkdir()
    (mod_dir / MANIFEST_FILE).write_text("{}")

    record = build_integrity_record(mod_dir)
    assert record["verdict"] == VERDICT_TAMPERED
    assert record["reason"] == "manifest_certifies_nothing"
    with pytest.raises(TamperDetected, match="lists no modules"):
        verify_integrity(mod_dir)


def test_verify_integrity_raises_when_the_glob_finds_nothing_to_manifest(tmp_path):
    mod_dir = tmp_path / "detection"
    mod_dir.mkdir()
    manifest = generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    assert manifest == {}, "test setup: expected the glob to match zero files"

    with pytest.raises(TamperDetected, match="lists no modules"):
        verify_integrity(mod_dir)


def test_empty_manifest_is_not_the_same_state_as_no_manifest(tmp_path):
    absent_dir = tmp_path / "detection"
    absent_dir.mkdir()
    assert build_integrity_record(absent_dir)["verdict"] == VERDICT_UNVERIFIABLE
    assert verify_integrity(absent_dir) is True

    (absent_dir / MANIFEST_FILE).write_text("{}")
    assert build_integrity_record(absent_dir)["verdict"] == VERDICT_TAMPERED
    with pytest.raises(TamperDetected):
        verify_integrity(absent_dir)


def test_verify_integrity_raises_on_each_positive_finding(tmp_path):
    mod_dir = _write_verified_module(tmp_path / "pkg")

    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES + b"\x00tampered")
    with pytest.raises(TamperDetected, match="Modified module"):
        verify_integrity(mod_dir)

    (mod_dir / MODULE_NAME).unlink()
    with pytest.raises(TamperDetected, match="Missing module"):
        verify_integrity(mod_dir)

    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES)
    (mod_dir / MANIFEST_FILE).write_text("{ not json")
    with pytest.raises(TamperDetected, match="Corrupt integrity manifest"):
        verify_integrity(mod_dir)

    generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    assert build_integrity_record(mod_dir)["verdict"] == VERDICT_VERIFIED
    assert verify_integrity(mod_dir) is True


@pytest.mark.asyncio
async def test_startup_refuses_to_start_on_a_byte_modified_module(
    tmp_path, monkeypatch, app_env
):
    mod_dir = _write_verified_module(tmp_path / "pkg")
    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES.replace(b"pretend", b"PRETEND"))
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    with pytest.raises(TamperDetected, match="Modified module"):
        async with app.router.lifespan_context(app):
            pass

    rows = [
        row
        for row in _audit_rows(app_env)
        if row.get("event_type") == "license.integrity_verification"
    ]
    assert len(rows) == 1
    assert rows[0]["verdict"] == VERDICT_TAMPERED
    assert rows[0]["risk_level"] == "HIGH"


@pytest.mark.asyncio
async def test_startup_refuses_on_a_corrupt_manifest(tmp_path, monkeypatch, app_env):
    mod_dir = _write_verified_module(tmp_path / "pkg")
    (mod_dir / MANIFEST_FILE).write_text("{{{ not json at all")
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    with pytest.raises(TamperDetected, match="Corrupt integrity manifest"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.asyncio
async def test_startup_refuses_when_a_manifest_module_is_missing(
    tmp_path, monkeypatch, app_env
):
    mod_dir = _write_verified_module(tmp_path / "pkg")
    (mod_dir / MODULE_NAME).unlink()
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    with pytest.raises(TamperDetected, match="Missing module"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.asyncio
async def test_startup_refuses_on_an_empty_manifest(tmp_path, monkeypatch, app_env):
    mod_dir = tmp_path / "detection"
    mod_dir.mkdir()
    (mod_dir / MANIFEST_FILE).write_text("{}")
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    with pytest.raises(TamperDetected, match="lists no modules"):
        async with app.router.lifespan_context(app):
            pass


@pytest.mark.asyncio
async def test_startup_continues_with_no_manifest_and_publishes_unverified(
    tmp_path, monkeypatch, app_env
):
    source = tmp_path / "source"
    source.mkdir()
    (source / "engine.py").write_text("# not compiled\n")
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [source])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    async with app.router.lifespan_context(app):
        state = app.state.integrity
        assert state["status"] == VERDICT_UNVERIFIABLE
        assert state["verified"] is False
        assert state["startup_blocked"] is False

    rows = [
        row
        for row in _audit_rows(app_env)
        if row.get("event_type") == "license.integrity_verification"
    ]
    assert [row["verdict"] for row in rows] == [VERDICT_UNVERIFIABLE]


@pytest.mark.asyncio
async def test_startup_reports_verified_when_the_manifest_matches(
    tmp_path, monkeypatch, app_env
):
    mod_dir = _write_verified_module(tmp_path / "pkg")
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    import proxy.main as proxy_main

    app = proxy_main.create_app()
    async with app.router.lifespan_context(app):
        state = app.state.integrity
        assert state["status"] == VERDICT_VERIFIED
        assert state["verified"] is True
        assert state["modules_checked"] == 1
        assert state["directories"] == [str(mod_dir.resolve())]


@pytest.mark.asyncio
async def test_tamper_and_absence_produce_different_startup_outcomes(
    tmp_path, monkeypatch, app_env
):
    source = tmp_path / "source"
    source.mkdir()
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [source])

    import proxy.main as proxy_main

    absent_app = proxy_main.create_app()
    async with absent_app.router.lifespan_context(absent_app):
        absent_status = absent_app.state.integrity["status"]
    assert absent_status == VERDICT_UNVERIFIABLE

    mod_dir = _write_verified_module(tmp_path / "pkg")
    (mod_dir / MODULE_NAME).write_bytes(b"different bytes entirely")
    monkeypatch.setattr(integrity_mod, "runtime_module_dirs", lambda: [mod_dir])

    tampered_app = proxy_main.create_app()
    with pytest.raises(TamperDetected):
        async with tampered_app.router.lifespan_context(tampered_app):
            pass

    manifest = json.loads((mod_dir / MANIFEST_FILE).read_text())
    assert MODULE_NAME in manifest and len(manifest[MODULE_NAME]) == 64
