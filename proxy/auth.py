"""Google OAuth 2.0 + JWT session management for Arkheia Enterprise Proxy.

Flow:
1. GET /auth/google  → redirect to Google consent screen
2. GET /auth/callback → exchange code, verify email whitelist, set JWT cookie
3. GET /auth/logout   → clear session cookie

JWT tokens are stored in httponly, secure, samesite=lax cookies.
"""

from __future__ import annotations

import logging
import os
import secrets
import sys
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, Request, Response, status

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration (loaded from env)
# ---------------------------------------------------------------------------

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8098/auth/callback")

# SECURITY: No fallback secret - validated lazily so tests can import this
# module without the env var, but the app still fails on first real use.
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(64))"
_jwt_secret: str | None = None


def _get_jwt_secret() -> str:
    """Return the validated JWT_SECRET, caching after first successful read."""
    global _jwt_secret
    if _jwt_secret is not None:
        return _jwt_secret

    raw = os.getenv("JWT_SECRET")
    if not raw:
        raise RuntimeError(
            "JWT_SECRET environment variable is not set.\n"
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\"\n"
            "Then set it via: nssm set ArkheiaEnterpriseProxy AppEnvironmentExtra JWT_SECRET=<value>"
        )
    if len(raw) < 32:
        raise RuntimeError(
            f"JWT_SECRET must be at least 32 characters long (current: {len(raw)}).\n"
            "Generate a proper secret with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )
    _jwt_secret = raw
    return _jwt_secret


JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = int(os.getenv("JWT_EXPIRY_SECONDS", "86400"))  # 24 hours

COOKIE_NAME = "arkheia_enterprise_session"
CSRF_COOKIE_NAME = "arkheia_oauth_state"

_default_whitelist = "david@arkheia.ai"
EMAIL_WHITELIST: set[str] = {
    e.strip().lower()
    for e in os.getenv("EMAIL_WHITELIST", _default_whitelist).split(",")
    if e.strip()
}

# Google endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # nosec B105
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_jwt(email: str) -> str:
    """Create a signed JWT for the given email address."""
    payload = {
        "sub": email,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, _get_jwt_secret(), algorithm=JWT_ALGORITHM)


def verify_jwt(token: str) -> str | None:
    """Verify a JWT and return the email (sub) or None if invalid/expired."""
    try:
        payload = jwt.decode(token, _get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        return payload.get("sub")
    except jwt.ExpiredSignatureError:
        logger.debug("JWT expired")
        return None
    except jwt.InvalidTokenError as exc:
        logger.debug("JWT invalid: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Google OAuth helpers
# ---------------------------------------------------------------------------

def get_google_auth_url(state: str = "") -> str:
    """Build the Google OAuth consent-screen redirect URL."""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    if state:
        params["state"] = state
    query = httpx.QueryParams(params)
    return f"{GOOGLE_AUTH_URL}?{query}"


async def exchange_google_code(code: str) -> dict[str, Any]:
    """Exchange an authorization code for user info.

    Returns dict with 'email', 'name', 'picture' keys on success,
    or raises HTTPException on failure.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Exchange code for tokens
        token_resp = await client.post(
            GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
            },
        )
        if token_resp.status_code != 200:
            logger.error("Google token exchange failed: %s", token_resp.text)
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to exchange Google authorization code",
            )
        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="No access token in Google response",
            )

        # Fetch user profile
        userinfo_resp = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if userinfo_resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Failed to fetch Google user info",
            )
        return userinfo_resp.json()


def is_email_whitelisted(email: str) -> bool:
    """Check whether *email* is in the configured whitelist."""
    return email.lower().strip() in EMAIL_WHITELIST


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _is_cookie_secure() -> bool:
    """Cookie secure flag — defaults to True (safe default for production).
    Set COOKIE_SECURE=false explicitly for local development only."""
    return os.getenv("COOKIE_SECURE", "true").lower() != "false"


def set_auth_cookie(response: Response, token: str) -> None:
    """Set the JWT session cookie on a response."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=_is_cookie_secure(),
        max_age=JWT_EXPIRY_SECONDS,
        path="/",
    )


def clear_auth_cookie(response: Response) -> None:
    """Delete the JWT session cookie."""
    response.delete_cookie(key=COOKIE_NAME, path="/")


# ---------------------------------------------------------------------------
# OAuth CSRF state helpers
# ---------------------------------------------------------------------------

def generate_oauth_state() -> str:
    """Generate a cryptographic random state token for OAuth CSRF protection."""
    return secrets.token_urlsafe(32)


def set_oauth_state_cookie(response: Response, state: str) -> None:
    """Set a short-lived cookie containing the OAuth state parameter."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=state,
        httponly=True,
        samesite="lax",
        secure=_is_cookie_secure(),
        max_age=600,  # 10 minutes — enough for the OAuth flow
        path="/auth",
    )


def clear_oauth_state_cookie(response: Response) -> None:
    """Clear the OAuth state cookie after validation."""
    response.delete_cookie(key=CSRF_COOKIE_NAME, path="/auth")


# ---------------------------------------------------------------------------
# FastAPI dependency — require authentication (JSON API endpoints → 401)
# ---------------------------------------------------------------------------

async def require_auth(request: Request) -> str:
    """FastAPI dependency that enforces authentication.

    Checks the session cookie first, then the Authorization header.
    Returns the authenticated email address.
    Raises 401 if not authenticated.
    """
    # 1. Cookie
    token = request.cookies.get(COOKIE_NAME)

    # 2. Authorization header fallback
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    email = verify_jwt(token)
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    return email
