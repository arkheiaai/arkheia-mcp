"""B336 High2: verified Google identities and legacy-session revocation.

Gate1 packet19bb5f25. Real exchange, JWT and ASGI consumer boundaries; no
provider traffic. Signature validation is independent of the new claim guard.
"""
import time

import httpx
import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy import auth
from proxy.endpoints import auth_routes
from proxy.endpoints.admin import router as admin_router
from proxy.endpoints.audit import router as audit_router

_ABSENT = object()
_IDENTITY = "allowed@example.test"
_REJECTED = [False, None, 0, 1, "true", "", [], {}, _ABSENT]
_IDS = ["false", "null", "zero", "one", "text", "empty", "array", "object", "absent"]
_PROTECTED = [
    ("GET", "/admin/health"),
    ("POST", "/admin/registry/pull"),
    ("POST", "/admin/profiles/model/rollback"),
    ("POST", "/admin/profiles/vendor/model/rollback"),
    ("GET", "/admin/profiles"),
    ("GET", "/audit/log"),
]


@pytest.fixture
def session_env(monkeypatch):
    material = "local-fixture-" + "m" * 40
    monkeypatch.setenv("JWT_SECRET", material)
    monkeypatch.setattr(auth, "_jwt_secret", None)
    monkeypatch.setattr(auth, "EMAIL_WHITELIST", {_IDENTITY})
    return material


@pytest.fixture
def client(session_env):
    app = FastAPI()
    app.include_router(auth_routes.router)
    app.include_router(admin_router)
    app.include_router(audit_router)
    with TestClient(app, base_url="https://admin.example.test", raise_server_exceptions=False) as result:
        yield result


def _google(monkeypatch, value):
    requests = []
    mints = []
    original = auth_routes.create_jwt

    def transport(request):
        requests.append((request.method, str(request.url)))
        if str(request.url) == auth.GOOGLE_TOKEN_URL:
            assert request.method == "POST"
            return httpx.Response(200, json={"access_token": "local-" + "g" * 20})
        assert str(request.url) == auth.GOOGLE_USERINFO_URL
        body = {"email": _IDENTITY, "name": "Fixture", "id": "local-user"}
        if value is not _ABSENT:
            body["verified_email"] = value
        return httpx.Response(200, json=body)

    def factory(**kwargs):
        return httpx.AsyncClient(transport=httpx.MockTransport(transport), **kwargs)

    def mint(*args, **kwargs):
        mints.append((args, kwargs))
        return original(*args, **kwargs)

    monkeypatch.setattr(auth, "egress_async_client", factory)
    monkeypatch.setattr(auth_routes, "create_jwt", mint)
    return requests, mints


def _callback(client):
    return client.get(
        "/auth/callback?code=local-code&state=local-state",
        headers={"Cookie": f"{auth.CSRF_COOKIE_NAME}=local-state"},
        follow_redirects=False,
    )


@pytest.mark.parametrize("value", _REJECTED, ids=_IDS)
def test_real_google_exchange_refuses_non_true_verification(client, monkeypatch, value):
    requests, mints = _google(monkeypatch, value)
    response = _callback(client)
    assert requests == [("POST", auth.GOOGLE_TOKEN_URL), ("GET", auth.GOOGLE_USERINFO_URL)]
    assert response.status_code == 403
    assert mints == []
    assert auth.COOKIE_NAME not in response.headers.get("set-cookie", "")
    assert _IDENTITY not in response.text


def test_real_verified_exchange_cookie_reaches_landing_and_json(client, monkeypatch):
    _, mints = _google(monkeypatch, True)
    response = _callback(client)
    assert response.status_code == 302
    assert len(mints) == 1
    assert response.headers["location"] == "/admin/ui"
    assert client.get(response.headers["location"]).status_code == 200
    assert client.get("/admin/profiles").status_code == 200
    cookie = response.headers.get("set-cookie", "")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=lax" in cookie


def test_session_factory_does_not_infer_verified_identity(session_env):
    with pytest.raises(ValueError):
        auth.create_jwt(_IDENTITY)


@pytest.mark.parametrize("value", _REJECTED[:-1], ids=_IDS[:-1])
def test_session_factory_refuses_non_true_flag(session_env, value):
    # A new signature can be absent on baseline; only the default/no-arg and
    # real-callback assertion failures count as the original defect's RED proof.
    try:
        auth.create_jwt(_IDENTITY, verified_email=value)
    except Exception as exc:
        assert isinstance(exc, ValueError)
    else:
        pytest.fail("unverified identity minted a session")


def _signed(material, marker=_ABSENT):
    now = int(time.time())
    payload = {"sub": _IDENTITY, "iat": now, "exp": now + 300}
    if marker is not _ABSENT:
        payload["email_verified"] = marker
    value = jwt.encode(payload, material, algorithm=auth.JWT_ALGORITHM)
    assert jwt.decode(value, material, algorithms=[auth.JWT_ALGORITHM])["sub"] == _IDENTITY
    return value


@pytest.mark.parametrize("value", _REJECTED, ids=_IDS)
def test_verifier_refuses_validly_signed_non_verified_claim(session_env, value):
    assert auth.verify_jwt(_signed(session_env, value)) is None


@pytest.mark.parametrize("method,path", _PROTECTED)
@pytest.mark.parametrize("channel", ["cookie", "bearer"])
def test_actual_json_consumers_refuse_legacy_sessions(client, session_env, method, path, channel):
    value = _signed(session_env)
    header = ({"Cookie": f"{auth.COOKIE_NAME}={value}"} if channel == "cookie"
              else {"Authorization": f"Bearer {value}"})
    assert client.request(method, path, headers=header, follow_redirects=False).status_code == 401


def test_direct_admin_ui_consumer_redirects_legacy_session(client, session_env):
    response = client.get(
        "/admin/ui", headers={"Cookie": f"{auth.COOKIE_NAME}={_signed(session_env)}"},
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["location"] == "/auth/google"


def test_real_new_verified_factory_token_authenticates_bearer(client, session_env):
    value = auth.create_jwt(_IDENTITY, verified_email=True)
    assert jwt.decode(value, session_env, algorithms=[auth.JWT_ALGORITHM])["email_verified"] is True
    assert client.get("/admin/profiles", headers={"Authorization": f"Bearer {value}"}).status_code == 200
