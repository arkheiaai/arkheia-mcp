"""
Admin endpoints.

These are not authenticated in Phase 1 -- deploy behind network controls
(firewall, VPN) in production. Authentication layer is Phase 2.
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Request

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")


@router.get("/health")
async def health(request: Request):
    """
    Health check. Returns loaded profile count and last registry pull timestamp.
    """
    profile_router = getattr(request.app.state, "profile_router", None)
    registry_client = getattr(request.app.state, "registry_client", None)

    profiles_loaded = profile_router.loaded_count if profile_router else 0
    profile_ids = profile_router.profile_ids if profile_router else []
    last_pull = (
        registry_client.last_pull.isoformat()
        if registry_client and registry_client.last_pull
        else None
    )

    return {
        "status": "ok",
        "profiles_loaded": profiles_loaded,
        "profile_ids": profile_ids,
        "last_registry_pull": last_pull,
    }


@router.post("/registry/pull")
async def manual_registry_pull(request: Request):
    """Trigger a manual profile registry pull."""
    registry_client = getattr(request.app.state, "registry_client", None)
    if registry_client is None:
        return {"status": "error", "detail": "registry_client not configured"}

    try:
        await registry_client.pull()
        return {"status": "ok", "message": "Registry pull completed"}
    except Exception as e:
        logger.error("Manual registry pull failed: %s", e)
        return {"status": "error", "detail": str(e)}


@router.post("/profiles/{model_id}/rollback")
async def rollback_profile(model_id: str, request: Request):
    """
    Roll back a profile to its previous version (.bak file).

    The registry client keeps a .bak of the previous version after each update.
    Rollback replaces the current YAML with the .bak and reloads the router.
    """
    settings = getattr(request.app.state, "settings", None)
    profile_router = getattr(request.app.state, "profile_router", None)

    if settings is None or profile_router is None:
        return {"status": "error", "detail": "server not fully initialized"}

    profile_dir = settings.detection.profile_dir
    path = Path(profile_dir) / f"{model_id}.yaml"
    bak = Path(str(path) + ".bak")

    if not bak.exists():
        return {"status": "error", "detail": f"no backup available for {model_id}"}

    try:
        path.write_bytes(bak.read_bytes())
        await profile_router.reload()
        return {"status": "ok", "message": f"Rolled back {model_id} from backup"}
    except Exception as e:
        logger.error("Rollback failed for %s: %s", model_id, e)
        return {"status": "error", "detail": str(e)}


@router.get("/profiles")
async def list_profiles(request: Request):
    """List all loaded profiles with their versions."""
    profile_router = getattr(request.app.state, "profile_router", None)
    if profile_router is None:
        return {"profiles": []}

    profiles = []
    for model_id, data in profile_router._profiles.items():
        version = str(
            data.get("version")
            or data.get("metadata", {}).get("version", "unknown")
        )
        profiles.append({"model_id": model_id, "version": version})

    return {"profiles": profiles, "count": len(profiles)}
