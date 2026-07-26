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

THE ADDRESS IS PART OF THE CONTRACT TOO
---------------------------------------
The signing string and the body schema are computed here and cannot drift without
a code change. The ADDRESS is different: an operator types it into a deployment,
so it is the one term of the contract that a human can get wrong at any time.

This module composed its target as ``f"{url}{ADAPTER_PATH}"``. With
``DETECTION_ADAPTER_URL=http://adapter:7070/`` -- a trailing slash, the commonest
way anyone writes a base URL -- that POSTs to ``//v1/events/proxy``. `httpx` does
not fold the empty segment, and the receiver's axum router is built with no
`NormalizePathLayer`, so the request is a **404 with an empty body**: no reason
text, on a fire-and-forget path, with a perfect signature over a request that
never arrived. One character reverts the rail to dark and nothing above notices.

So the base URL is normalised and VALIDATED in one place (`normalise_base_url` /
`adapter_target`), a value that cannot address the receiver is refused at STARTUP
(`validate_config_or_raise`) rather than discovered one lost push at a time, and
every failure log names the target that was actually attempted -- because a 404
with an empty body says nothing at all without it.

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
import urllib.parse
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

# The only schemes that can carry an HMAC-signed POST to the receiver. Anything
# else -- a bare hostname, a path, `ftp://` -- cannot be dialled, so it is a
# configuration fault rather than a delivery failure and is reported as one.
_ALLOWED_SCHEMES = ("http", "https")

# Env var names, named once so error text can point the operator at the setting
# to change instead of at a stack frame.
ENV_URL = "DETECTION_ADAPTER_URL"
ENV_SECRET = "DETECTION_ADAPTER_HMAC_SECRET"
ENV_KEY_ID = "DETECTION_ADAPTER_KEY_ID"


class AdapterConfigError(ValueError):
    """
    `DETECTION_ADAPTER_URL` cannot address the receiver.

    Distinct from every delivery failure on purpose: no retry, no backoff and no
    amount of waiting will fix it, and it is not "unconfigured" either -- someone
    set the value and got it wrong. Its own type, so its own outcome and its own
    message.
    """


def normalise_base_url(raw: Optional[str]) -> str:
    """
    Turn whatever an operator wrote into a base URL that composes cleanly.

    Returns "" for an absent value -- absent is a THIRD answer, distinct from both
    valid and malformed, because a deployment that never enabled this rail must
    stay silent while a deployment that mistyped the address must not.

    Handles, deliberately, the ways this value actually arrives in the wild:
      * a trailing slash (or several) -- the defect that motivated this function;
      * surrounding whitespace, which survives `.env` files, YAML block scalars
        and copy-paste out of a dashboard, and which `httpx` would percent-encode
        into the HOST rather than reject;
      * a sub-path mount (`https://gw/adapter`), which is PRESERVED -- a gateway
        in front of the receiver is a legitimate topology, and the receiver still
        verifies over its own mounted `ADAPTER_PATH`, so the signature is
        unaffected by any prefix a gateway strips.

    Raises `AdapterConfigError`, naming the setting and the offending value, for
    anything that cannot be dialled. Refusing here is what lets the caller fail
    at startup instead of at push time.
    """
    text = (raw or "").strip()
    if not text:
        return ""

    parts = urllib.parse.urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES or not parts.netloc:
        raise AdapterConfigError(
            f"{ENV_URL}={text!r} is not a usable base URL: expected "
            f"scheme://host[:port][/prefix] with scheme one of "
            f"{'/'.join(_ALLOWED_SCHEMES)}"
        )
    if parts.query or parts.fragment:
        raise AdapterConfigError(
            f"{ENV_URL}={text!r} is not a usable base URL: a query string or "
            f"fragment cannot survive having {ADAPTER_PATH} appended to it"
        )

    # rstrip, not replace: only the JOIN is ambiguous. A `//` inside an operator's
    # deliberate sub-path prefix is theirs to keep -- we are not rewriting their
    # gateway's routing, only refusing to introduce an empty segment ourselves.
    return urllib.parse.urlunsplit((scheme, parts.netloc, parts.path.rstrip("/"), "", ""))


def adapter_target(raw: Optional[str]) -> str:
    """
    The one place a base URL and `ADAPTER_PATH` are joined.

    Every send goes through here, so the misroute has exactly one place to live
    and exactly one place to be tested. Returns "" when unconfigured.
    """
    base = normalise_base_url(raw)
    return f"{base}{ADAPTER_PATH}" if base else ""


def _config() -> tuple[str, str, str]:
    """
    Read the whole config surface, once, at CALL time (never frozen at import).

    One reader so the startup guard and the send path cannot disagree about what
    is configured -- and so the signing secret has exactly one source in this
    module, which `tests/test_governance_push_floor.py` pins structurally.
    """
    return (
        os.getenv("DETECTION_ADAPTER_URL", ""),
        os.getenv("DETECTION_ADAPTER_HMAC_SECRET", ""),
        os.getenv("DETECTION_ADAPTER_KEY_ID", "mcp-v1"),
    )


def validate_config_or_raise() -> None:
    """
    Startup guard. Call from application boot, BEFORE any traffic.

    Discovering an undialable address at push time loses every push until someone
    reads the logs, and the value cannot become valid later -- so the honest
    moment to refuse is boot, where an operator is watching and the fix is one
    env var. Raises `RuntimeError` (the pattern `proxy/main.py` already uses for
    `JWT_SECRET` and missing config) rather than `AdapterConfigError`, so a boot
    failure reads as a boot failure.

    Demo/local parity (DONE.md Gate 2): this fires ONLY on a value someone
    actually set and got wrong. With the rail unconfigured -- which is what
    `.env.example` and `docker-compose.yaml` ship -- it returns silently. A guard
    that bricked a clean local boot would be switched off within a day, and then
    there would be no guard.

    A half-configured rail (one of URL/secret, not both) is WARNED, not fatal:
    nothing unsigned is ever sent so the state is safe, but `push_event` would
    report it as `skipped_unconfigured` -- the same answer it gives a deployment
    that never wanted the rail. Someone who set one of the two plainly wanted it,
    so the ambiguity is resolved out loud at boot.
    """
    url, secret, _key_id = _config()
    url_set, secret_set = bool(url.strip()), bool(secret)

    if not url_set and not secret_set:
        return

    if url_set:
        try:
            normalise_base_url(url)
        except AdapterConfigError as exc:
            raise RuntimeError(f"Cannot start: {exc}") from None

    if url_set != secret_set:
        missing = ENV_SECRET if url_set else ENV_URL
        logger.warning(
            "Governance detection push is HALF-CONFIGURED: %s is missing, so no "
            "event will be pushed (nothing unsigned is ever sent). Set %s to arm "
            "the rail, or clear both to disable it deliberately.",
            missing, missing,
        )


class PushOutcome:
    """
    What actually happened to a governance push.

    Returned (never raised) so a caller can distinguish the five states that a
    ``-> None`` signature collapses into one: not configured, misconfigured,
    delivered, rejected by the receiver, and never reached the receiver.

    `MISCONFIGURED` is deliberately NOT folded into `SKIPPED`. `SKIPPED` means
    "nobody asked for this rail" and is silent by design; filing an operator's
    typo under that heading is precisely how a rail goes dark while reporting
    itself healthy. The honest buckets are observed-good, observed-bad, and
    not-observed -- and a value that was never sent belongs in the third with a
    reason attached, never in the first.
    """

    SKIPPED = "skipped_unconfigured"
    MISCONFIGURED = "misconfigured"  # a value was set and cannot address anything
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

    Fails open -- never raises -- but never fails silently: a rejected,
    misconfigured or undelivered push is logged at ERROR and receipted. Returns a
    `PushOutcome` so "not configured", "misconfigured", "delivered", "rejected"
    and "never arrived" are distinguishable.
    """
    url, secret, key_id = _config()

    # No URL or no secret => send NOTHING. There is deliberately no unsigned
    # fallback: an unauthenticated governance record is worse than no record.
    # `.strip()` so a whitespace-only value reads as absent rather than as a
    # malformed address someone needs to be shouted at about.
    if not url.strip() or not secret:
        return PushOutcome(PushOutcome.SKIPPED)

    body_dict = build_proxy_event(tenant_id, source_id, event_type, payload, risk_level)
    event_id = body_dict["event_id"]

    def _record(outcome: PushOutcome, target: str) -> dict:
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
            # The TARGET, not the raw base URL. A misroute's only question is
            # "what address did this attempt actually use?", and a receipt holding
            # the un-composed base cannot answer it.
            "adapter_url": target,
            "key_id": key_id,
            "signed": True,
            "delivery_status": outcome.status,
            "http_status": outcome.http_status,
            "error": outcome.error,
            "risk_level": risk_level,
            "model_id": body_dict["model"]["model_id"],
        }

    # Belt to the startup guard's braces. `validate_config_or_raise` should have
    # caught this at boot, but this module is imported by callers that have no
    # boot sequence (the MCP server, scripts, tests), and env vars are read at
    # call time and can change under a running process. Fail-open applies: report,
    # never raise into the governed decision.
    try:
        target = adapter_target(url)
    except AdapterConfigError as exc:
        outcome = PushOutcome(
            PushOutcome.MISCONFIGURED, error=str(exc), event_id=event_id
        )
        logger.error(
            "%s nothing sent for event_id=%s: %s", FAILURE_MARKER, event_id, exc,
        )
        await _receipt(audit, _record(outcome, ""))
        return outcome

    body = json.dumps(body_dict).encode()
    headers = _sign_headers(body, secret, key_id)

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                target,
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
            FAILURE_MARKER, event_id, target, outcome.error,
        )
        await _receipt(audit, _record(outcome, target))
        return outcome

    if resp.status_code >= 400:
        outcome = PushOutcome(
            PushOutcome.REJECTED,
            http_status=resp.status_code,
            error=resp.text[:200],
            event_id=event_id,
        )
        # A 404/405 is the ROUTE-MISS signature, and it is the hardest rejection
        # to diagnose because axum answers an unmatched path with an EMPTY BODY --
        # `resp.text` carries nothing, so without the target and a named cause the
        # log line says only "something, somewhere, returned 404". It is also the
        # one rejection class that is a CONFIGURATION fault rather than a
        # credential or receiver fault, so it names the setting to change.
        if resp.status_code in (404, 405):
            hint = (
                f" -- that address is not mounted on the receiver, which serves "
                f"exactly {ADAPTER_PATH!r}; this is a configuration fault, check "
                f"{ENV_URL}"
            )
        else:
            hint = ""
        # THE defect this module shipped with: a 401/400 here used to be a
        # logger.debug. A governance push the receiver refused is a governance
        # record that does not exist, so it is an ERROR, not a debug crumb.
        # ONE log call, one sentence derived from one verdict: where the verdict,
        # the receipt and the wording an operator reads are separate decisions,
        # they eventually disagree (DONE.md floor entry 9).
        logger.error(
            "%s adapter rejected event_id=%s with HTTP %s posting to %s: %s%s",
            FAILURE_MARKER, event_id, resp.status_code, target, outcome.error, hint,
        )
        await _receipt(audit, _record(outcome, target))
        return outcome

    outcome = PushOutcome(
        PushOutcome.DELIVERED, http_status=resp.status_code, event_id=event_id
    )
    await _receipt(audit, _record(outcome, target))
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
