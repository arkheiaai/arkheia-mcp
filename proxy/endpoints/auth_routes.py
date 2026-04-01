"""Google OAuth 2.0 routes for the Enterprise Proxy admin UI.

Security:
  - OAuth state parameter for CSRF protection
  - No PII (email addresses) in error responses
  - Secure cookie defaults
"""

import logging

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, HTMLResponse

from proxy.auth import (
    get_google_auth_url,
    exchange_google_code,
    is_email_whitelisted,
    create_jwt,
    set_auth_cookie,
    clear_auth_cookie,
    generate_oauth_state,
    set_oauth_state_cookie,
    clear_oauth_state_cookie,
    COOKIE_NAME,
    CSRF_COOKIE_NAME,
    verify_jwt,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/auth/google")
async def auth_google():
    """Redirect to Google OAuth consent screen with CSRF state."""
    state = generate_oauth_state()
    url = get_google_auth_url(state=state)
    redirect = RedirectResponse(url=url)
    set_oauth_state_cookie(redirect, state)
    return redirect


@router.get("/auth/callback")
async def auth_callback(
    request: Request,
    response: Response,
    code: str = "",
    state: str = "",
    error: str = "",
):
    """Handle Google OAuth callback, set session cookie, redirect to admin UI."""
    if error or not code:
        return HTMLResponse(
            "<h1>Auth failed</h1><p>Access denied or cancelled.</p>",
            status_code=400,
        )

    # Validate OAuth state parameter (CSRF protection)
    expected_state = request.cookies.get(CSRF_COOKIE_NAME, "")
    if not state or not expected_state or state != expected_state:
        logger.warning("OAuth state mismatch — possible CSRF attempt")
        return HTMLResponse(
            "<h1>Auth failed</h1><p>Invalid session state. Please try again.</p>",
            status_code=400,
        )

    user = await exchange_google_code(code)
    email = user.get("email", "")
    if not is_email_whitelisted(email):
        # Do NOT include the email in the response — prevents enumeration
        logger.warning("Unauthorised login attempt from email not in whitelist")
        return HTMLResponse(
            "<h1>Access denied</h1><p>This account is not authorised. "
            "Contact your administrator.</p>",
            status_code=403,
        )
    token = create_jwt(email)
    redirect = RedirectResponse(url="/admin/ui", status_code=302)
    set_auth_cookie(redirect, token)
    clear_oauth_state_cookie(redirect)
    return redirect


@router.get("/auth/logout")
async def auth_logout():
    """Clear session cookie and redirect to login."""
    redirect = RedirectResponse(url="/auth/google", status_code=302)
    clear_auth_cookie(redirect)
    return redirect
