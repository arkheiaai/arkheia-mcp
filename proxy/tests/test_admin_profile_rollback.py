from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from fastapi import FastAPI

from proxy import auth
from proxy.audit.decision_journal import (
    DECIDED_AT_AT_EMIT,
    EVENT_PROFILE_ROLLBACK,
    PROFILE_ROLLBACK_APPLIED,
    PROFILE_ROLLBACK_BACKUP_VALIDATION_FAILED,
    PROFILE_ROLLBACK_LIVE_VALIDATION_FAILED,
    PROFILE_ROLLBACK_MODEL_MISMATCH,
    PROFILE_ROLLBACK_RELOAD_FAILED,
    RECEIPT_ENQUEUED,
)
from proxy.endpoints.admin import router as admin_router
from proxy.tests._receipt_probe import ReceiptProbe, assert_decision_identity

JWT_SECRET = "admin-rollback-test-secret-32-characters-minimum"
ADMIN_EMAIL = "admin@example.com"
ATTACKER_EMAIL = "attacker@evil.example"


def _profile(model_id: str = "gpt-4o", version: str = "1.0") -> bytes:
    return (
        f'model: "{model_id}"\n'
        f'version: "{version}"\n'
        "detection:\n"
        "  features: {}\n"
    ).encode("utf-8")


def _invalid_profile() -> bytes:
    return b'model: "gpt-4o"\nversion: "broken"\ndetection: []\n'


async def _drain(probe: ReceiptProbe) -> None:
    await asyncio.wait_for(probe.writer._queue.join(), timeout=5.0)


@pytest.fixture(autouse=True)
def real_admin_auth(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", JWT_SECRET)
    monkeypatch.setattr(auth, "_jwt_secret", None)
    monkeypatch.setattr(auth, "EMAIL_WHITELIST", {ADMIN_EMAIL})
    yield
    monkeypatch.setattr(auth, "_jwt_secret", None)


def _build_app(tmp_path, audit_writer):
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()

    app = FastAPI()
    app.include_router(admin_router)

    profile_router = SimpleNamespace(reload=AsyncMock())
    app.state.settings = SimpleNamespace(
        detection=SimpleNamespace(profile_dir=str(profile_dir))
    )
    app.state.profile_router = profile_router
    app.state.audit_writer = audit_writer
    return app, profile_dir, profile_router


def _auth_headers(email: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth.create_jwt(email)}"}


async def _post(app: FastAPI, path: str, email: str | None = ADMIN_EMAIL):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        headers = _auth_headers(email) if email is not None else None
        return await client.post(path, headers=headers)


def _row_for_response(probe: ReceiptProbe, body: dict) -> dict:
    assert body["receipt_status"] == RECEIPT_ENQUEUED
    return probe.require(body["decision_id"])


@pytest.mark.asyncio
async def test_admin_profile_rollback_requires_admin_auth(tmp_path):
    app = FastAPI()
    app.include_router(admin_router)
    resp = await _post(app, "/admin/profiles/gpt-4o/rollback", email=None)

    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"


@pytest.mark.asyncio
async def test_admin_profile_rollback_rejects_unwhitelisted_signed_jwt_without_mutating(
    tmp_path,
):
    app, profile_dir, profile_router = _build_app(tmp_path, audit_writer=None)
    live = _profile("gpt-4o", "2.0")
    backup = _profile("gpt-4o", "1.0")
    live_path = profile_dir / "gpt-4o.yaml"
    live_path.write_bytes(live)
    (profile_dir / "gpt-4o.yaml.bak").write_bytes(backup)

    resp = await _post(
        app,
        "/admin/profiles/gpt-4o/rollback",
        email=ATTACKER_EMAIL,
    )

    assert resp.status_code == 403
    assert resp.json()["detail"] == "Admin access required"
    assert live_path.read_bytes() == live
    profile_router.reload.assert_not_awaited()


@pytest.mark.asyncio
async def test_successful_admin_profile_rollback_validates_reloads_and_receipts(tmp_path):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        app, profile_dir, profile_router = _build_app(tmp_path, probe.writer)
        live = _profile("zai-org/GLM-5.2", "2.0")
        backup = _profile("zai-org/GLM-5.2", "1.0")
        live_path = profile_dir / "together-glm-5.2.yaml"
        live_path.write_bytes(live)
        (profile_dir / "together-glm-5.2.yaml.bak").write_bytes(backup)

        resp = await _post(app, "/admin/profiles/together-glm-5.2/rollback")
        await _drain(probe)
    finally:
        await probe.stop()

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ok"
    assert body["live_version"] == "2.0"
    assert body["backup_version"] == "1.0"
    assert live_path.read_bytes() == backup
    profile_router.reload.assert_awaited_once()

    row = _row_for_response(probe, body)
    assert row["event_type"] == EVENT_PROFILE_ROLLBACK
    assert row["source"] == "admin_profile_rollback"
    assert row["outcome"] == PROFILE_ROLLBACK_APPLIED
    assert row["model_id"] == "together-glm-5.2"
    assert row["admin_email"] == ADMIN_EMAIL
    assert row["live_model_id"] == "zai-org/GLM-5.2"
    assert row["backup_model_id"] == "zai-org/GLM-5.2"
    assert row["live_version"] == "2.0"
    assert row["backup_version"] == "1.0"
    assert_decision_identity(
        row, branch="admin profile rollback", expect_source=DECIDED_AT_AT_EMIT
    )
    chain = probe.verify_chain()
    assert chain["ok"] is True
    assert chain["verified"] == 1


@pytest.mark.asyncio
async def test_invalid_backup_is_not_applied_and_is_receipted(tmp_path):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        app, profile_dir, profile_router = _build_app(tmp_path, probe.writer)
        live = _profile("gpt-4o", "2.0")
        live_path = profile_dir / "gpt-4o.yaml"
        live_path.write_bytes(live)
        (profile_dir / "gpt-4o.yaml.bak").write_bytes(_invalid_profile())

        resp = await _post(app, "/admin/profiles/gpt-4o/rollback")
        await _drain(probe)
    finally:
        await probe.stop()

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["status"] == "error"
    assert live_path.read_bytes() == live
    profile_router.reload.assert_not_awaited()

    row = _row_for_response(probe, body)
    assert row["outcome"] == PROFILE_ROLLBACK_BACKUP_VALIDATION_FAILED
    assert row["live_model_id"] == "gpt-4o"
    assert row["live_version"] == "2.0"
    assert row["backup_model_id"] is None
    assert row["error_type"] == "ValueError"


@pytest.mark.asyncio
async def test_invalid_live_profile_is_not_overwritten_by_rollback(tmp_path):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        app, profile_dir, profile_router = _build_app(tmp_path, probe.writer)
        live_path = profile_dir / "gpt-4o.yaml"
        live_path.write_bytes(_invalid_profile())
        (profile_dir / "gpt-4o.yaml.bak").write_bytes(_profile("gpt-4o", "1.0"))

        resp = await _post(app, "/admin/profiles/gpt-4o/rollback")
        await _drain(probe)
    finally:
        await probe.stop()

    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert body["status"] == "error"
    assert live_path.read_bytes() == _invalid_profile()
    profile_router.reload.assert_not_awaited()

    row = _row_for_response(probe, body)
    assert row["outcome"] == PROFILE_ROLLBACK_LIVE_VALIDATION_FAILED
    assert row["error_type"] == "ValueError"


@pytest.mark.asyncio
async def test_model_mismatch_between_live_and_backup_is_refused(tmp_path):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        app, profile_dir, profile_router = _build_app(tmp_path, probe.writer)
        live = _profile("gpt-4o", "2.0")
        live_path = profile_dir / "gpt-4o.yaml"
        live_path.write_bytes(live)
        (profile_dir / "gpt-4o.yaml.bak").write_bytes(_profile("claude-sonnet-4", "1.0"))

        resp = await _post(app, "/admin/profiles/gpt-4o/rollback")
        await _drain(probe)
    finally:
        await probe.stop()

    assert resp.status_code == 409, resp.text
    body = resp.json()
    assert live_path.read_bytes() == live
    profile_router.reload.assert_not_awaited()

    row = _row_for_response(probe, body)
    assert row["outcome"] == PROFILE_ROLLBACK_MODEL_MISMATCH
    assert row["live_model_id"] == "gpt-4o"
    assert row["backup_model_id"] == "claude-sonnet-4"


@pytest.mark.asyncio
async def test_reload_failure_restores_live_profile_and_receipts_failure(tmp_path):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        app, profile_dir, profile_router = _build_app(tmp_path, probe.writer)
        profile_router.reload.side_effect = [RuntimeError("reload exploded"), None]
        live = _profile("gpt-4o", "2.0")
        backup = _profile("gpt-4o", "1.0")
        live_path = profile_dir / "gpt-4o.yaml"
        live_path.write_bytes(live)
        (profile_dir / "gpt-4o.yaml.bak").write_bytes(backup)

        resp = await _post(app, "/admin/profiles/gpt-4o/rollback")
        await _drain(probe)
    finally:
        await probe.stop()

    assert resp.status_code == 500, resp.text
    body = resp.json()
    assert body["status"] == "error"
    assert live_path.read_bytes() == live
    assert profile_router.reload.await_count == 2

    row = _row_for_response(probe, body)
    assert row["outcome"] == PROFILE_ROLLBACK_RELOAD_FAILED
    assert row["live_version"] == "2.0"
    assert row["backup_version"] == "1.0"
    assert row["error_type"] == "RuntimeError"
