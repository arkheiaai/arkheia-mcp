"""
API key authentication for the Arkheia Registry Server.

Keys are stored in OS environment only -- never in files.

ARKHEIA_REGISTRY_KEYS: comma-separated list of valid API keys
  e.g. ARKHEIA_REGISTRY_KEYS=ak_live_abc123,ak_live_def456

Key format: ak_live_{random_hex_32} or ak_test_{random_hex_32}

Utility: python -c "from registry_server.auth import generate_key; print(generate_key())"
"""

import os
import secrets
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)

def _load_valid_keys() -> set[str]:
    raw = os.environ.get("ARKHEIA_REGISTRY_KEYS", "")
    return {k.strip() for k in raw.split(",") if k.strip()}

def generate_key(prefix: str = "ak_live") -> str:
    """Generate a new API key. Run this to provision customer keys."""
    return f"{prefix}_{secrets.token_hex(16)}"

async def require_auth(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    """FastAPI dependency. Returns the validated API key on success."""
    valid_keys = _load_valid_keys()

    # If no keys configured: reject all (server not provisioned)
    if not valid_keys:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registry not provisioned -- ARKHEIA_REGISTRY_KEYS not set",
        )

    if credentials is None or credentials.credentials not in valid_keys:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
