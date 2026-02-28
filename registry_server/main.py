"""
Arkheia Registry Server

Serves detection profiles to enterprise proxy instances.

Endpoints:
  GET /                           -- service info (no auth)
  GET /health                     -- health check (no auth)
  GET /profiles                   -- list available profiles (auth required)
  GET /profiles/{model_id}/download -- download profile YAML (auth required)

Config (env vars):
  ARKHEIA_REGISTRY_PROFILE_DIR   -- profiles directory (default: ../profiles relative to this file)
  ARKHEIA_REGISTRY_BASE_URL      -- base URL for download_url construction (default: http://localhost:8200)
  ARKHEIA_REGISTRY_PORT          -- port to listen on (default: 8200)
  ARKHEIA_REGISTRY_KEYS          -- comma-separated valid API keys (required for protected endpoints)
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import Response

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
    yield


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
            "download": "/profiles/{model_id}/download",
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


@app.get("/profiles/{model_id}/download")
async def download_profile(
    model_id: str,
    api_key: str = Depends(require_auth),
):
    """Download raw YAML bytes for the given model_id."""
    storage: ProfileStorage = app.state.storage
    content = storage.get_profile_bytes(model_id)
    if content is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Profile not found: {model_id}",
        )
    return Response(content=content, media_type="application/yaml")
