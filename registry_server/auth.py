"""
API key authentication for the Arkheia Registry Server.

Keys are stored in OS environment only -- never in files.

ARKHEIA_REGISTRY_KEYS: comma-separated list of valid API keys
  e.g. ARKHEIA_REGISTRY_KEYS=ak_live_abc123,ak_live_def456

Key format: ak_live_{random_hex_32} or ak_test_{random_hex_32}

Utility: python -c "from registry_server.auth import generate_key; print(generate_key())"
"""

import logging
import os
import secrets
from typing import Optional

from fastapi import HTTPException, Request, Response, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from registry_server import receipts

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
    request: Request,
    response: Response,
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    """
    FastAPI dependency. Returns the validated API key on success.

    Every one of the three outcomes -- accepted, rejected, unprovisioned --
    leaves a durable receipt (see ``registry_server.receipts``) and carries its
    receipt id back to the caller in ``X-Arkheia-Receipt``. The receipt is
    written on the way OUT of the decision, never as a precondition of it: a
    receipt that cannot be written must not turn a refusal into an acceptance,
    and must not turn one into a 500 either.
    """
    valid_keys = _load_valid_keys()
    presented: Optional[str] = credentials.credentials if credentials is not None else None
    receipt_id = receipts.new_receipt_id()

    async def _record(decision: str, outcome_status: int) -> None:
        """
        Emit the receipt for this decision. Swallows EVERYTHING.

        ``receipts.emit`` already guards the write, so this looks redundant --
        it is not. The standing ruling is that a receipt failure must never
        block the halt, and "the halt" here is the refusal. If any part of the
        receipt path raises (record construction, a future emit
        implementation, a monkeypatched rail in a test), the exception would
        propagate out of the dependency and FastAPI would turn a 401 into a
        500. A 500 is not a refusal: it is an unhandled error that tells the
        caller something different, is retried differently, and pages someone.
        Caught by test_a_failing_receipt_writer_does_not_turn_a_refusal_into_
        an_acceptance, which found exactly this hole in the first version.
        """
        try:
            await receipts.emit(receipts.build_record(
                receipt_id=receipt_id,
                decision=decision,
                outcome_status=outcome_status,
                method=request.method,
                path=request.url.path,
                client_ip=request.client.host if request.client else None,
                credential=presented,
                keys_configured=len(valid_keys),
            ))
        except Exception:
            logging.getLogger(__name__).error(
                "Registry auth receipt path RAISED for decision=%s receipt_id=%s "
                "-- decision stands, but it is UNRECORDED",
                decision, receipt_id, exc_info=True,
            )

    # If no keys configured: reject all (server not provisioned)
    if not valid_keys:
        await _record(receipts.DECISION_UNPROVISIONED, status.HTTP_503_SERVICE_UNAVAILABLE)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Registry not provisioned -- ARKHEIA_REGISTRY_KEYS not set",
            headers={receipts.RECEIPT_HEADER: receipt_id},
        )

    # ONE refusal covers both "no credential" and "wrong credential". They must
    # stay indistinguishable -- a different status, message or header for an
    # unknown key tells an attacker which guesses have the right shape. The
    # receipt id is the only per-request-varying part, and it is a fresh uuid4
    # derived from nothing about the credential.
    if credentials is None or not _key_is_valid(presented, valid_keys):
        await _record(receipts.DECISION_REJECTED, status.HTTP_401_UNAUTHORIZED)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={
                "WWW-Authenticate": "Bearer",
                receipts.RECEIPT_HEADER: receipt_id,
            },
        )

    await _record(receipts.DECISION_ACCEPTED, status.HTTP_200_OK)
    response.headers[receipts.RECEIPT_HEADER] = receipt_id
    return credentials.credentials
