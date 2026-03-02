"""Google OAuth 2.0 routes for the Enterprise Proxy admin UI."""

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse, HTMLResponse

from proxy.auth import (
    get_google_auth_url,
    exchange_google_code,
    is_email_whitelisted,
    create_jwt,
    set_auth_cookie,
    clear_auth_cookie,
    COOKIE_NAME,
    verify_jwt,
)

router = APIRouter()


@router.get("/auth/google")
async def auth_google():
    """Redirect to Google OAuth consent screen."""
    url = get_google_auth_url()
    return RedirectResponse(url=url)


@router.get("/auth/callback")
async def auth_callback(
    request: Request,
    response: Response,
    code: str = "",
    error: str = "",
):
    """Handle Google OAuth callback, set session cookie, redirect to admin UI."""
    if error or not code:
        return HTMLResponse(
            "<h1>Auth failed</h1><p>Access denied or cancelled.</p>",
            status_code=400,
        )
    user = await exchange_google_code(code)
    email = user.get("email", "")
    if not is_email_whitelisted(email):
        return HTMLResponse(
            f"<h1>Access denied</h1><p>{email} is not authorised.</p>",
            status_code=403,
        )
    token = create_jwt(email)
    redirect = RedirectResponse(url="/admin/ui", status_code=302)
    set_auth_cookie(redirect, token)
    return redirect


@router.get("/auth/logout")
async def auth_logout():
    """Clear session cookie and redirect to login."""
    redirect = RedirectResponse(url="/auth/google", status_code=302)
    clear_auth_cookie(redirect)
    return redirect
