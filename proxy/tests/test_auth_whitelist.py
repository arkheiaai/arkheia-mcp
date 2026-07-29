from __future__ import annotations

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from proxy import auth


def _bearer_request(token: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/audit/log",
            "headers": [(b"authorization", f"Bearer {token}".encode("ascii"))],
            "query_string": b"",
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


@pytest.mark.asyncio
async def test_require_auth_rechecks_current_email_whitelist(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 64)
    monkeypatch.setattr(auth, "_jwt_secret", None)
    monkeypatch.setattr(auth, "EMAIL_WHITELIST", {"current@example.com"})

    token = auth.create_jwt("offboarded@example.com")

    with pytest.raises(HTTPException) as exc:
        await auth.require_auth(_bearer_request(token))

    assert exc.value.status_code == 401
    assert exc.value.detail == "Session no longer authorized"


@pytest.mark.asyncio
async def test_require_auth_accepts_still_whitelisted_jwt(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 64)
    monkeypatch.setattr(auth, "_jwt_secret", None)
    monkeypatch.setattr(auth, "EMAIL_WHITELIST", {"current@example.com"})

    token = auth.create_jwt("current@example.com")

    assert await auth.require_auth(_bearer_request(token)) == "current@example.com"
