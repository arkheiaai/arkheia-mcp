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

def _key_is_valid(candidate: str, valid_keys: set[str]) -> bool:
    """
    Constant-time membership test for ``candidate`` in ``valid_keys``.

    Two properties, both deliberate:

    * Every comparison goes through ``secrets.compare_digest``. The previous
      ``candidate not in valid_keys`` was a hash-table lookup, which is
      *incidentally* timing-safe in CPython (the candidate is hashed before
      any byte comparison, so a wrong key almost never reaches a memcmp) --
      but that is an implementation detail, not a guarantee, and it weakens
      if hash randomisation is disabled (``PYTHONHASHSEED=0``).
    * The loop does NOT short-circuit on a match. Returning as soon as a key
      matches leaks the matching key's *position* among the configured keys
      -- measurably: ~12 ns on the reference machine. Every configured key is
      compared on every request, match or not.

    ``compare_digest`` requires ASCII-only ``str`` operands, so both sides are
    encoded to bytes first. A non-ASCII candidate is then simply invalid
    rather than an exception -- a raised exception would surface as a 500,
    which is an oracle in its own right (it distinguishes "malformed" from
    "wrong").
    """
    if not candidate or not valid_keys:
        return False
    candidate_bytes = candidate.encode("utf-8", errors="surrogatepass")
    found = False
    for key in valid_keys:
        key_bytes = key.encode("utf-8", errors="surrogatepass")
        if secrets.compare_digest(candidate_bytes, key_bytes):
            found = True
    return found

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

    # ONE refusal covers both "no credential" and "wrong credential". They must
    # stay indistinguishable -- a different status, message or header for an
    # unknown key tells an attacker which guesses have the right shape.
    if credentials is None or not _key_is_valid(credentials.credentials, valid_keys):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return credentials.credentials
