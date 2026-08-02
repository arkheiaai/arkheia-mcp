"""
Arkheia Registry Server

Serves detection profiles to enterprise proxy instances.

Endpoints:
  GET /                           -- service info (no auth)
  GET /health                     -- health check (no auth)
  GET /profiles                   -- list available profiles (auth required)
  GET /profiles/download?model_id= -- download profile YAML (auth required); the
                                     ADVERTISED shape, id in the query so the URL
                                     is percent-decode-invariant
  GET /profiles/{model_id}/download -- legacy alias, id in the path (auth required)

Config (env vars):
  ARKHEIA_REGISTRY_PROFILE_DIR   -- profiles directory (default: ../profiles relative to this file)
  ARKHEIA_REGISTRY_BASE_URL      -- base URL for download_url construction (default: http://localhost:8200)
  ARKHEIA_REGISTRY_PORT          -- port to listen on (default: 8200)
  ARKHEIA_REGISTRY_KEYS          -- comma-separated valid API keys (required for protected endpoints)
  ARKHEIA_REGISTRY_AUDIT_LOG     -- auth-decision receipt log (default: ./registry_audit.jsonl)
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import Response

from registry_server import receipts
from registry_server.auth import require_auth
from registry_server.storage import ProfileStorage


def _get_profile_dir() -> str:
    default = str(Path(__file__).parent.parent / "profiles")
    return os.environ.get("ARKHEIA_REGISTRY_PROFILE_DIR", default)


def _get_base_url() -> str:
    return os.environ.get("ARKHEIA_REGISTRY_BASE_URL", "http://localhost:8200")


@asynccontextmanager
async def lifespan(app: FastAPI):
    profile_dir = _get_profile_dir()
    base_url = _get_base_url()
    app.state.storage = ProfileStorage(profile_dir=profile_dir, base_url=base_url)
    # Auth-decision receipts. Started here so the writer's background drain
    # task lives for the app's lifetime and is flushed on shutdown. If this
    # raised, the server would not boot -- deliberate: a registry that cannot
    # record who it let in should be fixed, not run silently. It does not
    # raise in practice (AuditWriter.start only mkdirs and spawns a task), and
    # a per-request write failure is fail-open by design (see receipts.emit).
    await receipts.start()
    try:
        yield
    finally:
        await receipts.stop()


app = FastAPI(
    title="Arkheia Registry Server",
    description="Serves detection profiles to enterprise proxy instances.",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/")
async def root():
    """Service info."""
    return {
        "service": "arkheia-registry",
        "version": "1.0.0",
        "description": "Arkheia detection profile registry",
        "endpoints": {
            "health": "/health",
            "profiles": "/profiles",
            "download": "/profiles/download?model_id={model_id}",
            "download_legacy": "/profiles/{model_id}/download",
        },
    }


@app.get("/health")
async def health():
    """Health check -- no auth required."""
    storage: ProfileStorage = app.state.storage
    profiles = storage.list_profiles()
    return {
        "status": "ok",
        "profiles_available": len(profiles),
    }


@app.get("/profiles")
async def list_profiles(
    since: Optional[str] = Query(
        default=None,
        description="ISO8601 datetime -- only return profiles updated after this time",
    ),
    api_key: str = Depends(require_auth),
):
    """List available profiles. Supports incremental pulls via `since` parameter."""
    storage: ProfileStorage = app.state.storage

    since_dt: Optional[datetime] = None
    if since is not None:
        try:
            since_dt = datetime.fromisoformat(since)
            # Ensure timezone-aware
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid `since` datetime format: {since!r}. Use ISO8601.",
            )

    profiles = storage.list_profiles(since=since_dt)
    return {"profiles": profiles, "count": len(profiles)}


def _serve_profile(model_id: str) -> Response:
    """Resolve ``model_id`` through storage containment and serve the bytes, or
    404. The SINGLE resolution chokepoint for both download routes below —
    ``get_profile_bytes`` applies the syntactic pre-filter + realpath containment,
    so neither route can read outside the profiles root."""
    storage: ProfileStorage = app.state.storage
    content = storage.get_profile_bytes(model_id)
    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile not found: {model_id}",
        )
    return Response(content=content, media_type="application/yaml")


@app.get("/profiles/download")
async def download_profile_by_query(
    model_id: str = Query(
        ...,
        description="Registry model id, percent-escaped into the query string.",
    ),
    api_key: str = Depends(require_auth),
):
    """ADVERTISED download route: the id travels in the QUERY, not the path.

    ``list_profiles()`` advertises this shape because a query string is decoded
    EXACTLY ONCE by every layer in the stack, whereas a path is decoded once by
    uvicorn but TWICE by starlette's TestClient (and by path-normalising reverse
    proxies) — which 404'd the advertised URL for any id containing a literal
    percent escape (``model%23`` -> ``model#``), Codex #13 LOW. Keeping the id out
    of the path makes the advertised URL decode-invariant: there is no escape in
    its path for anyone to decode.

    Declared BEFORE the ``{model_id:path}`` route: ``/profiles/download`` cannot
    match that pattern (it needs a segment before ``/download``), but the explicit
    ordering keeps that independent of regex subtleties.

    Same containment as the legacy route — ``get_profile_bytes`` rejects ``..``/
    NUL/backslash ids and any resolved path escaping the profiles root, so
    ``?model_id=../../etc/passwd`` is a 404 with no read out-of-root.
    """
    return _serve_profile(model_id)


@app.get("/profiles/{model_id:path}/download")
async def download_profile(
    model_id: str,
    api_key: str = Depends(require_auth),
):
    """LEGACY/alias download route: the id in the path.

    Retained (and still exercised) because it resolves every id wherever the path
    is decoded exactly once — slash ids included — but it is NO LONGER what
    ``list_profiles()`` advertises: a path segment cannot carry an id containing a
    literal ``%`` robustly (see ``download_profile_by_query``).

    Original note, still true:

    Uses the ``:path`` converter so a registry id that legitimately contains a
    ``/`` (HF ``deepseek-ai/DeepSeek-V3.1``) matches — the single-segment
    ``{model_id}`` route 404'd the advertised download_url for those 6 ids. The
    ``:path`` surface is safe ONLY because ``get_profile_bytes`` applies the
    syntactic pre-filter + realpath containment: Starlette decodes ``%2f``/``%2e``
    before this handler, so a traversal like ``..%2f..%2fx`` arrives as
    ``../../x`` and is rejected there (contains ``..``) — 404, no read
    out-of-root. Containment is the backstop; the route just stops mis-404ing
    legitimate slash ids.
    """
    return _serve_profile(model_id)
