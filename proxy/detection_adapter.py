"""
Push detection events to the Arkheia Governance Detection Adapter.

THE RECEIVER IS REAL AND ITS CONTRACT IS NOT NEGOTIABLE
-------------------------------------------------------
The other end of this push is a live Rust service in `arkheia-synesis`:
`services/detection-adapter/src/{handlers,hmac_auth,normalise}.rs`, documented in
`contracts-detection.md`. This module is the ONLY producer of the
`X-Arkheia-Key-Id / -Timestamp / -Signature` header set in the estate, and that
service is its ONLY consumer. So there is exactly one contract, and it is theirs.

It has three hard requirements, each of which independently rejects a request:

1. **Signing string** (`hmac_auth.rs::verify`)::

       HMAC-SHA256(secret, "POST\\n" + path + "\\n" + timestamp + "\\n" + sha256_hex(body))

   Anything else is `401 INVALID_SIGNATURE`.

2. **Key id** -- `X-Arkheia-Key-Id` must equal the receiver's configured
   `DETECTION_ADAPTER_HMAC_KEY_ID` **exactly**; checked BEFORE the signature, so a
   mismatch is `401 UNKNOWN_KEY_ID` regardless of how well the body is signed.

3. **Body schema** -- `normalise.rs::ProxyEvent`. Ten required fields, `event_id`
   and `invocation.invocation_id` must parse as UUIDs, `tenant` is an OBJECT.
   Anything else is `400 VALIDATION_ERROR`.

Before 2026-07-26 this module satisfied NONE of them: it signed
``f"{timestamp}.{body}"`` and posted a flat six-key body missing nine of the ten
required fields. Every push this module has ever made would have been rejected --
and the rejection was logged at ``logger.debug``, i.e. invisible. That is the same
defect that kept the proxy's Synesis ingest rail dark for twenty days behind a
swallowed ``400 MISSING_EVENT_ID``.

FAIL-OPEN, BUT NEVER FAIL-SILENT
--------------------------------
Fail-open is correct here: a governance report must never crash the detection
pipeline it reports on. `push_event` therefore never raises. But a governance
record that does not land is a governance record that does not exist, so every
non-2xx and every transport failure is logged at **ERROR** with the stable marker
``GOVERNANCE_PUSH_FAILED``, and -- when an audit writer is supplied -- leaves a
durable, hash-chained receipt of the outcome. Silence is never "delivered".

NO UNSIGNED FALLBACK
--------------------
If the URL or the HMAC secret is absent, nothing is sent. There is no unsigned
path, no derived key, no on-disk key cache: the secret comes from
``DETECTION_ADAPTER_HMAC_SECRET`` and nowhere else. An unconfigured deployment is
silent-but-safe, and `push_event` reports ``skipped_unconfigured`` so the caller
can tell "not configured" from "delivered".

Config (env vars, read at CALL time -- not frozen at import):
  DETECTION_ADAPTER_URL          - e.g. http://detection-adapter:7070
  DETECTION_ADAPTER_HMAC_SECRET  - shared secret for HMAC-SHA256 signing
  DETECTION_ADAPTER_KEY_ID       - key identifier; MUST match the receiver's
                                   DETECTION_ADAPTER_HMAC_KEY_ID (default: mcp-v1)
"""
import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

# The receiver mounts exactly this path and signs over exactly this literal
# (handlers.rs::receive_proxy_event passes "/v1/events/proxy" to hmac_auth::verify).
ADAPTER_PATH = "/v1/events/proxy"

# ProxyEvent envelope constants (normalise.rs requires the keys; it ignores the
# values -- the endpoint hardcodes SourceProduct::ApiProxy. We still send the
# truthful product name so the wire record is not a lie.)
SCHEMA_VERSION = "1.0"
SOURCE_PRODUCT = "mcp_server"
SOURCE_VERSION = "1.3.0"

# Stable log marker. Grep-able, and pinned by tests/test_detection_adapter_push.py
# so a future edit cannot quietly drop the failure to debug level again.
FAILURE_MARKER = "GOVERNANCE_PUSH_FAILED"

# Namespace for deriving a UUID from a non-UUID detection id. Deterministic, so
# the same detection always maps to the same governance event_id.
_DETECTION_ID_NS = uuid.UUID("6b8f1e2a-0c3d-4f5e-9a7b-1d2c3e4f5a6b")

_VALID_RISK = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


class PushOutcome:
    """
    What actually happened to a governance push.

    Returned (never raised) so a caller can distinguish the four states that a
    ``-> None`` signature collapses into one: not configured, delivered, rejected
    by the receiver, and never reached the receiver.
    """

    SKIPPED = "skipped_unconfigured"
    DELIVERED = "delivered"
    REJECTED = "rejected"       # receiver answered, with a non-2xx
    FAILED = "failed"           # never got an answer (network, timeout, ...)

    def __init__(
        self,
        status: str,
        http_status: Optional[int] = None,
        error: Optional[str] = None,
        event_id: Optional[str] = None,
    ):
        self.status = status
        self.http_status = http_status
        self.error = error
        self.event_id = event_id

    @property
    def delivered(self) -> bool:
        return self.status == self.DELIVERED

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"PushOutcome(status={self.status!r}, http_status={self.http_status!r}, "
            f"error={self.error!r}, event_id={self.event_id!r})"
        )


def _as_uuid_str(value: Any) -> str:
    """
    Coerce an id to a UUID string.

    `normalise.rs` types `event_id` and `invocation_id` as `Uuid`; serde rejects
    the whole body if either fails to parse. The detection engine is not required
    to hand us a UUID, so a non-UUID id is mapped deterministically (UUIDv5)
    rather than being allowed to 400 the push.
    """
    if isinstance(value, uuid.UUID):
        return str(value)
    text = str(value or "")
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError, TypeError):
        if not text:
            return str(uuid.uuid4())
        return str(uuid.uuid5(_DETECTION_ID_NS, text))


def _classification(risk_level: str) -> str:
    """
    Map our risk band onto `normalise.rs::parse_classification`.

    The receiver has no UNKNOWN band: `parse_risk` maps every unrecognised string
    to `FabricationRisk::Low`, and `parse_classification` maps every unrecognised
    string to `Authentic`. So an evidence-limited UNKNOWN detection, pushed
    naively, arrives at the governance plane as a CONFIDENT CLEAN LOW -- exactly
    the "couldn't assess must never read as all-clear" failure. We cannot add a
    band to their enum from here, but we can refuse to claim AUTHENTIC: anything
    that is not a clean LOW is reported as UNCERTAIN or FABRICATED.
    """
    band = (risk_level or "").upper()
    if band == "LOW":
        return "AUTHENTIC"
    if band in ("HIGH", "CRITICAL"):
        return "FABRICATED"
    # MEDIUM, UNKNOWN, and anything unrecognised.
    return "UNCERTAIN"


def build_proxy_event(
    tenant_id: str,
    source_id: str,
    event_type: str,
    payload: dict[str, Any],
    risk_level: str = "LOW",
    *,
    emitted_at: Optional[str] = None,
) -> dict:
    """
    Build a body that satisfies `normalise.rs::ProxyEvent`.

    Every one of the ten required fields is present, `tenant` is an object, and
    both id fields are UUIDs. Everything we carry that their schema has no home
    for goes in `context`, which they type as free-form `serde_json::Value`.
    """
    payload = payload or {}
    detection_id = payload.get("detection_id")
    event_id = _as_uuid_str(detection_id)
    now = emitted_at or datetime.now(timezone.utc).isoformat()
    band = (risk_level or "").upper()

    context = {k: v for k, v in payload.items() if k not in ("detection_id", "confidence")}
    context["event_type"] = event_type
    context["source_id"] = source_id
    context["detection_id"] = detection_id
    # The band as WE saw it, before their enum flattens anything unrecognised to
    # Low. This is the only place an UNKNOWN survives the hop.
    context["risk_level_raw"] = risk_level

    return {
        "schema_version": SCHEMA_VERSION,
        "source_product": SOURCE_PRODUCT,
        "source_version": SOURCE_VERSION,
        "event_id": event_id,
        "emitted_at": now,
        "tenant": {
            "tenant_id": tenant_id,
            "proxy_deployment_id": None,
        },
        "invocation": {
            # One mcp /detect/verify call IS one invocation, and the detection id
            # identifies it 1:1, so reusing it keeps the governance plane's
            # source_event_id and invocation_id correlated to the same decision.
            "invocation_id": event_id,
            "intercepted_at": now,
            "workflow_id": None,
            "caller_id": None,
            "caller_type": None,
        },
        "model": {
            "model_id": payload.get("model_id") or source_id,
            "provider": None,
            "model_version": None,
            "endpoint": None,
        },
        "detection": {
            "fabrication_risk": band if band in _VALID_RISK else "UNKNOWN",
            "confidence": float(payload.get("confidence") or 0.0),
            "method": "combined",
            "surface_version": payload.get("profile_version"),
            "surface_deviation": None,
            "classification": _classification(band),
        },
        "context": context,
    }


def _sign_headers(body: bytes, secret: str, key_id: str, timestamp: Optional[str] = None) -> dict:
    """
    Build the signing headers the receiver verifies.

    Signing string, verbatim from `arkheia-synesis/services/detection-adapter/
    src/hmac_auth.rs::verify`::

        format!("POST\\n{}\\n{}\\n{}", path, headers.timestamp, body_hash)

    where `body_hash = hex(sha256(body))` over the RAW BYTES POSTed. The signature
    is computed over the bytes that are actually sent -- never over a re-serialised
    copy -- so any modification of the body in flight invalidates it.
    """
    ts = timestamp if timestamp is not None else str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    signing_string = f"POST\n{ADAPTER_PATH}\n{ts}\n{body_hash}"
    sig = _hmac.new(secret.encode(), signing_string.encode(), hashlib.sha256).hexdigest()
    return {
        "X-Arkheia-Key-Id": key_id,
        "X-Arkheia-Timestamp": ts,
        "X-Arkheia-Signature": sig,
        "Content-Type": "application/json",
    }


async def _receipt(audit, record: dict) -> None:
    """Write a push-outcome receipt. Best-effort, but never silent on failure."""
    if audit is None:
        return
    try:
        await audit.write(record)
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "%s could not receipt governance push event_id=%s: %s",
            FAILURE_MARKER, record.get("detection_id"), exc,
        )


async def push_event(
    tenant_id: str,
    source_id: str,
    event_type: str,
    payload: dict[str, Any],
    risk_level: str = "LOW",
    audit: Any = None,
) -> PushOutcome:
    """
    Push a detection event to the governance adapter.

    Fails open -- never raises -- but never fails silently: a rejected or
    undelivered push is logged at ERROR and receipted. Returns a `PushOutcome` so
    "not configured", "delivered", "rejected" and "never arrived" are
    distinguishable.
    """
    url = os.getenv("DETECTION_ADAPTER_URL", "")
    secret = os.getenv("DETECTION_ADAPTER_HMAC_SECRET", "")
    key_id = os.getenv("DETECTION_ADAPTER_KEY_ID", "mcp-v1")

    # No URL or no secret => send NOTHING. There is deliberately no unsigned
    # fallback: an unauthenticated governance record is worse than no record.
    if not url or not secret:
        return PushOutcome(PushOutcome.SKIPPED)

    body_dict = build_proxy_event(tenant_id, source_id, event_type, payload, risk_level)
    event_id = body_dict["event_id"]
    body = json.dumps(body_dict).encode()
    headers = _sign_headers(body, secret, key_id)

    def _record(outcome: PushOutcome) -> dict:
        return {
            # Unique per ATTEMPT. `detection_id` correlates the receipt to the
            # decision, but it is not unique: a retried push for the same
            # detection would otherwise write two records no reader could tell
            # apart. The attempt is the thing being receipted here.
            "push_id": str(uuid.uuid4()),
            "detection_id": event_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "governance_push",
            "event_type": "governance_detection_push",
            "adapter_url": url,
            "key_id": key_id,
            "signed": True,
            "delivery_status": outcome.status,
            "http_status": outcome.http_status,
            "error": outcome.error,
            "risk_level": risk_level,
            "model_id": body_dict["model"]["model_id"],
        }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{url}{ADAPTER_PATH}",
                content=body,
                headers=headers,
            )
    except Exception as exc:  # noqa: BLE001
        outcome = PushOutcome(
            PushOutcome.FAILED, error=f"{type(exc).__name__}: {exc}", event_id=event_id
        )
        # A governance record that never left the box. Visible, or the rail is dark.
        logger.error(
            "%s transport error posting event_id=%s to %s: %s",
            FAILURE_MARKER, event_id, url, outcome.error,
        )
        await _receipt(audit, _record(outcome))
        return outcome

    if resp.status_code >= 400:
        outcome = PushOutcome(
            PushOutcome.REJECTED,
            http_status=resp.status_code,
            error=resp.text[:200],
            event_id=event_id,
        )
        # THE defect this module shipped with: a 401/400 here used to be a
        # logger.debug. A governance push the receiver refused is a governance
        # record that does not exist, so it is an ERROR, not a debug crumb.
        logger.error(
            "%s adapter rejected event_id=%s with HTTP %s: %s",
            FAILURE_MARKER, event_id, resp.status_code, outcome.error,
        )
        await _receipt(audit, _record(outcome))
        return outcome

    outcome = PushOutcome(
        PushOutcome.DELIVERED, http_status=resp.status_code, event_id=event_id
    )
    await _receipt(audit, _record(outcome))
    return outcome


def _log_task_result(task: "asyncio.Task") -> None:
    """A fire-and-forget task whose exception nobody retrieves is a silent rail."""
    try:
        exc = task.exception()
    except asyncio.CancelledError:  # pragma: no cover - shutdown race
        logger.error("%s push task cancelled before completion", FAILURE_MARKER)
        return
    if exc is not None:
        logger.error("%s push task raised: %r", FAILURE_MARKER, exc)


def schedule_push(
    tenant_id: str,
    source_id: str,
    event_type: str,
    payload: dict[str, Any],
    risk_level: str = "LOW",
    audit: Any = None,
):
    """
    Dispatch a push without blocking the caller.

    Uses `get_running_loop()`, not the deprecated `get_event_loop()`: on Python
    3.12 the latter warns outside a loop and on 3.14 it RAISES, which the old
    broad `except` swallowed at debug level -- so on a modern interpreter this
    function silently did nothing at all when called from sync code.
    """
    coro = push_event(tenant_id, source_id, event_type, payload, risk_level, audit)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        task = loop.create_task(coro)
        task.add_done_callback(_log_task_result)
        return task

    try:
        return asyncio.run(coro)
    except Exception as exc:  # noqa: BLE001
        coro.close()
        logger.error("%s schedule_push could not dispatch: %r", FAILURE_MARKER, exc)
        return None
