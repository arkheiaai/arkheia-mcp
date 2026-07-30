"""Auth floors for admin, OAuth, and audit-read surfaces.

These tests are intentionally black-box at the FastAPI router boundary. They
prove the advertised operator surfaces cannot be reached without a valid
session, and that OAuth login only mints that session after state and whitelist
checks pass.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import proxy.auth as auth
import proxy.endpoints.auth_routes as auth_routes
from proxy.auth import COOKIE_NAME, CSRF_COOKIE_NAME, create_jwt
from proxy.endpoints.admin import router as admin_router
from proxy.endpoints.audit import router as audit_router
from proxy.endpoints.auth_routes import router as auth_router


class _Audit:
    def __init__(self):
        self.calls = []

    def read_recent(self, *, limit, session_id):
        self.calls.append({"limit": limit, "session_id": session_id})
        return {
            "events": [{"detection_id": "det-1", "risk_level": "LOW"}],
            "summary": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        }


class _RegistryClient:
    def __init__(self):
        self.calls = []
        self.last_pull = None

    async def pull(self):
        self.calls.append("pull")
        return None


HEALTHY_AUDIT_CHAIN = {
    "ok": True,
    "status": "OK",
    "detail": None,
    "startup_blocked": False,
}


@pytest.fixture(autouse=True)
def auth_floor_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "admin-audit-auth-floor-secret-32chars!!")
    monkeypatch.setattr(auth, "_jwt_secret", None)
    monkeypatch.setattr(auth, "EMAIL_WHITELIST", {"reviewer@example.com"})


@pytest.fixture
def client():
    app = FastAPI()
    app.include_router(auth_router)
    app.include_router(admin_router)
    app.include_router(audit_router)
    app.state.audit_writer = _Audit()
    app.state.audit_chain = dict(HEALTHY_AUDIT_CHAIN)
    app.state.registry_client = _RegistryClient()
    return TestClient(app, raise_server_exceptions=False), app


def _bearer(email: str = "reviewer@example.com") -> dict[str, str]:
    return {"Authorization": f"Bearer {create_jwt(email)}"}


def _dependency_calls(route: APIRoute) -> set[object]:
    return {dependency.call for dependency in route.dependant.dependencies}


def test_admin_json_routes_declare_require_auth_dependency():
    missing = [
        route.path
        for route in admin_router.routes
        if isinstance(route, APIRoute)
        and route.path != "/admin/ui"
        and auth.require_auth not in _dependency_calls(route)
    ]

    assert missing == []


def test_audit_log_route_declares_require_auth_dependency():
    routes = [
        route
        for route in audit_router.routes
        if isinstance(route, APIRoute) and route.path == "/audit/log"
    ]

    assert len(routes) == 1
    assert auth.require_auth in _dependency_calls(routes[0])


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/admin/health"),
        ("get", "/admin/profiles"),
        ("post", "/admin/registry/pull"),
        ("post", "/admin/profiles/gpt-4o/rollback"),
    ],
)
def test_admin_json_endpoints_require_authentication(client, method, path):
    test_client, app = client

    response = getattr(test_client, method)(path)

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
    assert app.state.registry_client.calls == []


def test_admin_json_endpoints_reject_invalid_bearer(client):
    test_client, _ = client

    response = test_client.get(
        "/admin/health",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired session"


def test_admin_json_endpoint_accepts_valid_jwt(client):
    test_client, _ = client

    response = test_client.get("/admin/health", headers=_bearer())

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_admin_ui_redirects_without_valid_session_cookie(client):
    test_client, _ = client

    missing = test_client.get("/admin/ui", follow_redirects=False)
    invalid = test_client.get(
        "/admin/ui",
        headers={"Cookie": f"{COOKIE_NAME}=not-a-valid-jwt"},
        follow_redirects=False,
    )

    assert missing.status_code == 302
    assert missing.headers["location"] == "/auth/google"
    assert invalid.status_code == 302
    assert invalid.headers["location"] == "/auth/google"


def test_admin_ui_accepts_valid_session_cookie(client):
    test_client, _ = client
    token = create_jwt("reviewer@example.com")

    response = test_client.get(
        "/admin/ui",
        headers={"Cookie": f"{COOKIE_NAME}={token}"},
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert "Arkheia Enterprise Proxy" in response.text


def test_auth_google_issues_oauth_state_cookie_matching_redirect(client):
    test_client, _ = client

    response = test_client.get("/auth/google", follow_redirects=False)

    assert response.status_code in {302, 307}
    parsed = urlparse(response.headers["location"])
    state = parse_qs(parsed.query)["state"][0]
    assert state
    assert response.cookies[CSRF_COOKIE_NAME] == state


def test_oauth_callback_rejects_missing_or_mismatched_state_before_exchange(
    client,
    monkeypatch,
):
    test_client, _ = client

    async def _exchange_tripwire(code):  # pragma: no cover - must not be called
        raise AssertionError("OAuth code exchange ran before state validation")

    monkeypatch.setattr(auth_routes, "exchange_google_code", _exchange_tripwire)

    no_cookie = test_client.get(
        "/auth/callback?code=code-1&state=state-1",
        follow_redirects=False,
    )
    mismatch = test_client.get(
        "/auth/callback?code=code-1&state=state-1",
        headers={"Cookie": f"{CSRF_COOKIE_NAME}=state-2"},
        follow_redirects=False,
    )

    assert no_cookie.status_code == 400
    assert "Invalid session state" in no_cookie.text
    assert mismatch.status_code == 400
    assert "Invalid session state" in mismatch.text


def test_oauth_callback_rejects_non_whitelisted_email_without_session_cookie(
    client,
    monkeypatch,
):
    test_client, _ = client

    async def _exchange_google_code(code):
        return {"email": "intruder@example.com"}

    monkeypatch.setattr(auth_routes, "exchange_google_code", _exchange_google_code)

    response = test_client.get(
        "/auth/callback?code=code-1&state=state-1",
        headers={"Cookie": f"{CSRF_COOKIE_NAME}=state-1"},
        follow_redirects=False,
    )

    assert response.status_code == 403
    assert "intruder@example.com" not in response.text
    assert COOKIE_NAME not in response.headers.get("set-cookie", "")


def test_oauth_callback_mints_session_only_after_state_and_whitelist_pass(
    client,
    monkeypatch,
):
    test_client, _ = client

    async def _exchange_google_code(code):
        return {"email": "reviewer@example.com"}

    monkeypatch.setattr(auth_routes, "exchange_google_code", _exchange_google_code)

    response = test_client.get(
        "/auth/callback?code=code-1&state=state-1",
        headers={"Cookie": f"{CSRF_COOKIE_NAME}=state-1"},
        follow_redirects=False,
    )

    set_cookie = response.headers.get("set-cookie", "")
    assert response.status_code == 302
    assert response.headers["location"] == "/admin/ui"
    assert COOKIE_NAME in set_cookie
    assert CSRF_COOKIE_NAME in set_cookie


def test_audit_log_requires_authentication(client):
    test_client, app = client

    response = test_client.get("/audit/log")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
    assert app.state.audit_writer.calls == []


def test_audit_log_rejects_invalid_bearer(client):
    test_client, app = client

    response = test_client.get(
        "/audit/log",
        headers={"Authorization": "Bearer not-a-valid-jwt"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired session"
    assert app.state.audit_writer.calls == []


def test_audit_log_authenticated_read_reaches_audit_writer(client):
    test_client, app = client

    response = test_client.get(
        "/audit/log?limit=7&session_id=session-1",
        headers=_bearer(),
    )

    assert response.status_code == 200
    assert response.json()["events"] == [
        {"detection_id": "det-1", "risk_level": "LOW"}
    ]
    assert app.state.audit_writer.calls == [{"limit": 7, "session_id": "session-1"}]
