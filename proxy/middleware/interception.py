"""
Arkheia Enterprise Proxy -- AI Interception Middleware.

Intercepts requests to /v1/* paths, runs fabrication detection on the
upstream response, and takes action based on risk level and configuration.

All other paths (including /detect/verify, /admin/*, /audit/*) bypass
this middleware completely.

DESTINATION IS CONFIG-DERIVED — WHICH IS WHY THE POST-CONDITION EXISTS
----------------------------------------------------------------------
The sibling passthrough flow forwards to one of four module-level constants, so
its destination cannot move by construction. This module builds its destination
from ``settings.detection.upstream_url`` and the caller's own path. The prefix
test that decides a request is interceptable (``path.startswith("/v1/")``) is
therefore NOT the same statement as "the request we send stays under /v1/":
``scope["path"]`` arrives percent-decoded and with dot segments intact (uvicorn
does not remove them; every HTTP *client* does, which is why a client-driven
test cannot see this), and httpx removes them when it builds the URL. So
``/v1/../admin/keys`` passed the prefix test and left as ``/admin/keys`` with
the caller's Authorization attached.

``_resolve_upstream`` is the single place a destination is produced, and
``_confine`` is a post-condition on its OUTPUT — verifier-owned expectations
derived from the configured base, never from the request. Every refusal is
decided BEFORE any client is constructed and before any credential is attached.

RESPONSE FRAMING
----------------
``content-encoding`` and ``content-length`` are dropped together. httpx
advertises ``accept-encoding: gzip`` and transparently decodes, so an upstream
``content-length`` describes the compressed body while the bytes we serve are
the decoded ones; relaying one without the other serves an empty body under a
non-zero length (measured on the sibling flow, PR #31).

FAIL-OPEN NEVER FABRICATES
--------------------------
Detection is fail-open by contract: it degrades, it never blocks. The recovery
path used to re-enter ``call_next``, which serves the proxy's OWN local routes —
so a detector crash returned content the model never produced, at HTTP 200. For
a fabrication-detection product that is the worst available failure mode. The
response is now obtained once and relayed unchanged if scoring fails.

THE BLOCK IS AUTHORISED BY ``gate_action``, NOT BY POLICY INTENT
---------------------------------------------------------------
``proxy/endpoints/detect.py`` documents two non-interchangeable signals and
states the rule in terms: *"a consumer MUST hard-block ONLY when gate_action ==
'block'"*. ``gate_action`` is the profile-EARNED gate — "block" only where the
profile declares it AND carries non-null precision + f1 within the false-positive
ceiling (``features.py::resolve_gate_action``); everything else is "advise".
``high_risk_action`` is the customer's POLICY INTENT and authorises nothing.

This middleware is the ONLY place in the product that blocks transport, and it
used to key entirely off ``high_risk_action`` — the one enforcing site enforcing
on the one signal the codebase says must not be enforced on. Both are now
required: policy asks, the gate authorises. Anything that is not exactly the
token ``"block"`` — absent, empty, mis-cased, novel — fails closed to advise.

BEHAVIOUR CHANGE: a deployment configured ``high_risk_action: block`` against a
profile that has not earned the gate now WARNS. The verdict, the receipt and the
headers all still fire; the answer is delivered. Both signals are surfaced
(``X-Arkheia-Gate-Action`` / ``X-Arkheia-Policy-Action``) and recorded, so a
downgraded block is legible rather than silent.

THE RECEIPT STATUS IS DERIVED, NEVER ASSERTED
---------------------------------------------
``_emit`` returns silently when no audit writer is configured and swallows a
write that raises — both deliberate (the halt must not depend on the record
landing). The block and refusal bodies nonetheless hard-coded
``"receipt": "enqueued"``, so a response asserted an evidence trail that did not
exist. ``_emit`` now RETURNS what happened and the payload carries that value.

FORWARD HEADERS ARE AN ALLOW-LIST
---------------------------------
A deny-list forwards every header nobody thought of, and the failure is silent
and permissive: ``cookie``, ``x-forwarded-for`` and ``x-arkheia-internal`` all
reached the configured upstream on an ordinary accepted call. The forward leg
now names what a provider API needs and drops everything else, so an unknown
header — including one that does not exist yet — is not forwarded.
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Verifier-owned constants
# ---------------------------------------------------------------------------

#: The prefix that makes a request interceptable, and the prefix the forwarded
#: request must still be under once resolved. One constant, both roles — they
#: cannot drift apart.
INTERCEPT_PREFIX = "/v1/"

#: RFC 9110 §7.6.1 connection-specific header fields. A proxy relays none of
#: them in either direction: they address the hop, not the endpoint.
HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})

#: Headers whose meaning is destroyed by silently picking one of several
#: occurrences. ``{k: v for ...}`` kept the LAST, so ``Authorization: LEGIT``
#: followed by ``Authorization: ATTACKER`` authenticated as ATTACKER while the
#: caller and every log believed otherwise. Fail closed instead of choosing.
SINGLE_VALUED_CREDENTIAL_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
})

#: THE FORWARD LEG IS AN ALLOW-LIST, NOT A DENY-LIST.
#:
#: A deny-list of forbidden headers forwards anything nobody thought of, and the
#: failure is silent and in the permissive direction — the same shape as the
#: enumerated deny-list that let ``unverifiable`` skip a halt on a sibling flow.
#: This names what a provider API genuinely needs; everything else is dropped,
#: including headers that do not exist yet.
#:
#: What is deliberately EXCLUDED, and why (report any of these that a real
#: upstream turns out to need — the answer is to add it here with a reason, not
#: to go back to a deny-list):
#:   cookie                        a bearer credential for a DIFFERENT origin
#:   x-forwarded-*, forwarded,
#:   x-real-ip                     caller network topology; provider APIs ignore
#:                                 them and they are an internal-estate leak
#:   x-arkheia-*                   proxy-domain signalling; ours, not the
#:                                 upstream's, and one of them is internal-only
#:   user-agent, referer, origin   caller fingerprinting; httpx supplies its own
#:                                 user-agent
#:   accept-encoding               httpx negotiates and transparently DECODES;
#:                                 relaying the caller's breaks the framing
#:                                 invariant this module holds on the way back
#:   x-stainless-*                 provider-SDK client telemetry, not required
#:   cache/conditional headers     (if-none-match, range, …) meaningless for a
#:                                 completion POST and a cache-poisoning surface
#:   host, content-length          FRAMING WE OWN. ``host`` is set by httpx from
#:                                 the resolved URL — httpx honours an explicit
#:                                 one while still connecting to the URL's
#:                                 authority, so relaying the caller's addresses
#:                                 the provider to somewhere else.
#:                                 ``content-length`` is recomputed from the body
#:                                 we actually send; two framing headers are a
#:                                 smuggling primitive even when they agree.
#:                                 (These had their own deny-set before; the
#:                                 allow-list subsumes it — they are simply not
#:                                 forwardable, so there is one decision site.)
#:   hop-by-hop (RFC 9110 §7.6.1)  addressed to this hop, never the endpoint.
#:                                 Also subsumed; ``HOP_BY_HOP_HEADERS`` remains
#:                                 the deny-set for the RESPONSE leg, where a
#:                                 relay-everything default is correct.
FORWARDABLE_HEADERS = frozenset({
    # Credentials the provider authenticates with.
    "authorization",          # OpenAI and most providers
    "x-api-key",              # Anthropic
    "api-key",                # Azure OpenAI
    # Provider-required API negotiation.
    "anthropic-version",      # REQUIRED by the Anthropic messages API
    "anthropic-beta",
    "openai-organization",
    "openai-project",
    "openai-beta",
    # Payload and response negotiation.
    "content-type",
    "accept",                 # incl. text/event-stream for streaming
    # Safe request semantics the caller owns.
    "idempotency-key",
})

#: Response headers we own. ``content-encoding`` and ``content-length`` are a
#: pair: httpx already decoded the body, so both describe bytes that no longer
#: exist.
RESPONSE_OWNED_HEADERS = frozenset({"content-length", "content-encoding"})

#: Only these may be a forwarding destination. ``file://`` and ``gopher://``
#: are not transport misconfigurations, they are exfiltration primitives.
ALLOWED_UPSTREAM_SCHEMES = frozenset({"http", "https"})

#: Percent-encodings and characters whose only purpose in a provider API path
#: is to survive OUR normalisation and be decoded into a separator by the
#: origin. Checked on the raw path; ``_confine`` cannot see them because httpx
#: leaves them encoded.
UNSAFE_PATH_MARKERS = ("%2f", "%5c", "%2e", "\\", "\x00")

#: The complete set of reasons this flow refuses. A refusal outside this set
#: means a decision path landed without being classified.
DENY_CODES = {
    "path_escapes_prefix": (
        "the resolved upstream path left the {prefix} prefix that authorised "
        "interception",
        "send the provider path directly, without '..' segments or encoded "
        "separators",
    ),
    "unsafe_path_encoding": (
        "the request path carries an encoded separator or a backslash",
        "send the provider path with literal '/' separators only",
    ),
    "duplicate_credential_header": (
        "more than one {header} header was sent; which credential applies is "
        "ambiguous",
        "send exactly one {header} header",
    ),
    "upstream_scheme_not_allowed": (
        "the configured upstream is not an http(s) endpoint",
        "set detection.upstream_url to an http:// or https:// origin",
    ),
    "upstream_unreachable": (
        "the configured upstream did not answer",
        "retry, or check that detection.upstream_url is reachable from the proxy",
    ),
}

#: Every action this flow may record. Mirrors the vocabulary of
#: ``proxy/endpoints/detect.py`` so ``/audit/log`` reads as one stream.
ACTION_TAKEN_VALUES = frozenset({
    "block", "warn", "pass", "refused", "unavailable", "error",
})

#: The ONE token that authorises a hard block, per
#: ``proxy/detection/features.py::resolve_gate_action``. Compared exactly:
#: absent, empty, mis-cased or novel values all fail closed to advisory, because
#: that is the direction an unvalidated profile arrives from.
GATE_ACTION_BLOCK = "block"

#: What the caller is told about the evidence trail, DERIVED from what happened
#: at the emission site — never asserted. ``enqueued`` is deliberately weaker
#: than ``recorded``: ``AuditWriter.write()`` hands the record to a queue that a
#: background loop drains, and that loop swallows its own I/O errors, so the
#: most this flow can honestly support is that the rail accepted it.
#:
#: KNOWN GAP, pinned by a test rather than papered over: ``write()`` also
#: swallows its own ``QueueFull`` and drops the record, so a saturated rail still
#: reports ``enqueued``. Closing that needs ``AuditWriter.write()`` to report its
#: own outcome — a change to a rail co-owned with another branch.
RECEIPT_ENQUEUED = "enqueued"
RECEIPT_NO_WRITER = "no_audit_writer"
RECEIPT_WRITE_FAILED = "write_failed"
RECEIPT_STATUSES = frozenset({
    RECEIPT_ENQUEUED, RECEIPT_NO_WRITER, RECEIPT_WRITE_FAILED,
})


class InterceptionRefusal(Exception):
    """A refusal decided before any credential leaves the process."""

    def __init__(self, deny_code: str, **fmt: str):
        if deny_code not in DENY_CODES:
            raise AssertionError(f"unclassified deny code {deny_code!r}")
        reason, remedy = DENY_CODES[deny_code]
        self.deny_code = deny_code
        self.reason = reason.format(**fmt)
        self.remedy = remedy.format(**fmt)
        super().__init__(f"{deny_code}: {self.reason}")


# ---------------------------------------------------------------------------
# Body extraction helpers (module-level, not methods)
# ---------------------------------------------------------------------------

def _extract_model_id(body: bytes) -> str:
    """Parse JSON body and return the model field. Returns 'unknown' on any error."""
    try:
        body_json = json.loads(body)
        return body_json.get("model", "unknown")
    except Exception:
        return "unknown"


def _extract_prompt(body: bytes) -> str:
    """
    Parse JSON body and extract the prompt text.

    If a 'messages' key exists, join all content fields from messages where
    role == 'user'. Otherwise return the top-level 'prompt' field.
    Returns '' on any error.
    """
    try:
        body_json = json.loads(body)
        if "messages" in body_json:
            parts = []
            for msg in body_json["messages"]:
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        # Handle content blocks (e.g. OpenAI vision format)
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                parts.append(block.get("text", ""))
            return " ".join(parts)
        return body_json.get("prompt", "")
    except Exception:
        return ""


def _json_object(body: bytes) -> Optional[dict[str, Any]]:
    try:
        body_json = json.loads(body)
    except Exception:
        return None
    return body_json if isinstance(body_json, dict) else None


def _output_tokens_from_usage(usage: Optional[dict[str, Any]]) -> Any:
    if not isinstance(usage, dict):
        return None
    for key in (
        "output_tokens",
        "completion_tokens",
        "candidatesTokenCount",
        "eval_count",
        "response_tokens",
    ):
        if key in usage:
            return usage[key]
    return None


def _extract_output_tokens(body: bytes) -> Any:
    body_json = _json_object(body)
    if body_json is None:
        return None
    usage = body_json.get("usage")
    if not isinstance(usage, dict):
        usage = body_json.get("usageMetadata")
    return _output_tokens_from_usage(usage if isinstance(usage, dict) else None)


# ---------------------------------------------------------------------------
# Destination resolution — the ONLY place a target URL is produced
# ---------------------------------------------------------------------------

def _check_raw_path(path: str) -> None:
    """
    Pre-condition on the path as the application received it.

    Independent of ``_confine``, not redundant with it: httpx leaves ``%2f`` /
    ``%5c`` / ``%2e`` percent-encoded, so a resolved-URL post-condition sees a
    confined path while a lenient origin decodes the escape and escapes anyway.
    Backslash is the same trick without an encoding.
    """
    lowered = path.lower()
    for marker in UNSAFE_PATH_MARKERS:
        if marker in lowered:
            raise InterceptionRefusal("unsafe_path_encoding")


def _resolve_upstream(upstream_url: str, path: str, query: str) -> httpx.URL:
    """
    Build the destination, then prove it stayed where it was supposed to.

    ``base`` is the verifier's expectation and comes from configuration only;
    nothing in the request may contribute to scheme, host or port.
    """
    base = httpx.URL(upstream_url.rstrip("/") or upstream_url)
    if base.scheme not in ALLOWED_UPSTREAM_SCHEMES:
        raise InterceptionRefusal("upstream_scheme_not_allowed")

    target = httpx.URL(upstream_url.rstrip("/") + path)
    if query:
        target = target.copy_with(query=query.encode("ascii", "ignore"))
    _confine(target, base)
    return target


def _confine(target: httpx.URL, base: httpx.URL) -> None:
    """
    Post-condition on the RESOLVED destination.

    Every expectation is taken from ``base`` (configuration), never from the
    artifact being checked. A caller can influence only the path, so the
    authority is asserted rather than assumed, and the path is required to be
    under the same prefix that authorised interception in the first place.
    """
    if target.scheme != base.scheme:
        raise InterceptionRefusal("path_escapes_prefix", prefix=INTERCEPT_PREFIX)
    if target.host != base.host:
        raise InterceptionRefusal("path_escapes_prefix", prefix=INTERCEPT_PREFIX)
    if target.port != base.port:
        raise InterceptionRefusal("path_escapes_prefix", prefix=INTERCEPT_PREFIX)
    if target.userinfo != base.userinfo:
        raise InterceptionRefusal("path_escapes_prefix", prefix=INTERCEPT_PREFIX)
    expected_prefix = base.path.rstrip("/") + INTERCEPT_PREFIX
    if not target.path.startswith(expected_prefix):
        raise InterceptionRefusal("path_escapes_prefix", prefix=INTERCEPT_PREFIX)


# ---------------------------------------------------------------------------
# Header handling
# ---------------------------------------------------------------------------

def _nominated_hop_headers(headers: Headers) -> set[str]:
    """``Connection: x-internal-token`` nominates that field as hop-by-hop."""
    nominated: set[str] = set()
    for value in headers.getlist("connection"):
        for token in value.split(","):
            token = token.strip().lower()
            if token:
                nominated.add(token)
    return nominated


def _forward_headers(headers: Headers) -> list[tuple[str, str]]:
    """
    The request headers to relay, as a LIST so legitimate repeats survive.

    ALLOW-LIST, not deny-list. A header is forwarded only if it is named in
    ``FORWARDABLE_HEADERS``; anything else — known-bad, unknown, or invented
    tomorrow — is dropped. A deny-list gets the default wrong in the permissive
    direction, and that is how ``cookie`` / ``x-forwarded-for`` /
    ``x-arkheia-internal`` reached the upstream on an ordinary accepted call.

    Ordering is load-bearing and pinned by a test:

    * The duplicate-credential refusal runs over EVERY occurrence, before any
      filtering, so it cannot be made unreachable by the allow-list. Refusing
      rather than resolving is the point: choosing one silently is the smuggling
      primitive, whichever end you choose from.
    * ``Connection``-nomination is honoured even for an allow-listed field.
      ``Connection: accept`` makes ``accept`` hop-by-hop for this hop, and
      membership of the allow-list must not defeat the nomination.
    """
    nominated = _nominated_hop_headers(headers)
    seen_credentials: dict[str, int] = {}
    out: list[tuple[str, str]] = []
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in SINGLE_VALUED_CREDENTIAL_HEADERS:
            seen_credentials[lowered] = seen_credentials.get(lowered, 0) + 1
            if seen_credentials[lowered] > 1:
                raise InterceptionRefusal(
                    "duplicate_credential_header", header=lowered
                )
        if lowered not in FORWARDABLE_HEADERS:
            continue
        if lowered in nominated:
            continue
        out.append((name, value))
    return out


def _relay_headers(upstream_headers) -> list[tuple[str, str]]:
    """Response headers to pass back, minus everything we own or already used."""
    nominated: set[str] = set()
    for value in upstream_headers.get_list("connection"):
        for token in value.split(","):
            token = token.strip().lower()
            if token:
                nominated.add(token)
    out: list[tuple[str, str]] = []
    for name, value in upstream_headers.multi_items():
        lowered = name.lower()
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        if lowered in RESPONSE_OWNED_HEADERS:
            continue
        if lowered in nominated:
            continue
        out.append((name, value))
    return out


# ---------------------------------------------------------------------------
# Response construction
# ---------------------------------------------------------------------------

def _build_response(
    body: bytes,
    status_code: int,
    relayed: list[tuple[str, str]],
    arkheia: dict,
) -> Response:
    """
    A response carrying the upstream's own status and headers plus the Arkheia
    signal fields. Duplicates (``set-cookie``) survive because the raw header
    list is extended rather than a mapping written.
    """
    response = Response(content=body, status_code=status_code)
    extra = [(k.lower().encode("latin-1"), v.encode("latin-1"))
             for k, v in relayed
             if k.lower() not in RESPONSE_OWNED_HEADERS]
    extra += [(k.encode("latin-1"), str(v).encode("latin-1"))
              for k, v in arkheia.items() if v is not None]
    response.raw_headers = list(response.raw_headers) + extra
    return response


def _signal_headers(risk_level: str, action: Optional[str] = None,
                    detection_id: Optional[str] = None,
                    gate_action: Optional[str] = None,
                    policy_action: Optional[str] = None) -> dict:
    """
    Header-only signalling. The body is never mutated: prepending a banner to a
    JSON completion produces bytes no parser accepts, and
    ``proxy/endpoints/detect.py::_signal`` already rules against the pattern by
    name ("we never prepend to the body (that pattern in interception.py
    corrupts responses and 400-loops sessions)").

    Three decision fields, and they are NOT interchangeable:

      X-Arkheia-Action        what this proxy DID (block / warn / pass /
                              refused / unavailable / error). Mirrors
                              ``action_taken`` on the evidence row.
      X-Arkheia-Gate-Action   the AUTHORITATIVE profile-earned gate, verbatim
                              from the detector. A hard block requires this to
                              be exactly "block".
      X-Arkheia-Policy-Action the customer's configured INTENT
                              (``high_risk_action``). Records what policy
                              wanted, which authorises nothing.

    Surfacing all three is what makes a DOWNGRADED block legible: policy=block,
    gate=advise, action=warn says, without touching the body, that the operator
    asked for a block and the profile had not earned one. ``None`` values are
    dropped by ``_build_response``, so a path with no verdict emits no field.
    """
    return {
        "X-Arkheia-Risk": risk_level,
        "X-Arkheia-Action": action,
        "X-Arkheia-Detection-Id": detection_id,
        "X-Arkheia-Gate-Action": gate_action,
        "X-Arkheia-Policy-Action": policy_action,
    }


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _audit_record(
    detection_id: str,
    risk_level: str,
    action_taken: str,
    path: str,
    method: str,
    prompt: str,
    response_body: bytes,
    model_id: str = "unknown",
    profile_version: str = "none",
    confidence: float = 0.0,
    features_triggered: Optional[list] = None,
    deny_code: Optional[str] = None,
    reason: Optional[str] = None,
    error: Optional[str] = None,
    gate_action: Optional[str] = None,
    policy_action: Optional[str] = None,
) -> dict:
    """
    The evidence row. Shaped to match ``proxy/endpoints/detect.py::_audit_record``
    so ``/audit/log`` reads as one stream, plus the transport facts an
    investigator needs (which surface, which method) that a scoring-only record
    does not carry.

    Text never goes in — only hashes. The rail redacts on top of that.
    """
    if action_taken not in ACTION_TAKEN_VALUES:
        raise AssertionError(f"unclassified action_taken {action_taken!r}")
    return {
        "detection_id": detection_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": None,
        "model_id": model_id,
        "profile_version": profile_version,
        "risk_level": risk_level,
        "confidence": confidence,
        "features_triggered": features_triggered or [],
        "prompt_hash": hashlib.sha256(prompt.encode("utf-8", "replace")).hexdigest(),
        "response_hash": hashlib.sha256(response_body).hexdigest(),
        "response_length": len(response_body),
        "action_taken": action_taken,
        # WHAT WAS AUTHORISED vs WHAT WAS ASKED FOR. Without both, a block that
        # was downgraded because the profile had not earned the gate is
        # indistinguishable on the row from an ordinary warn — and the operator
        # whose configured block stopped firing has no way to find out why.
        "gate_action": gate_action,
        "policy_action": policy_action,
        "source": "interception",
        "path": path,
        "method": method,
        "deny_code": deny_code,
        "reason": reason,
        "error": error,
    }


async def _emit(request: Request, record: dict) -> str:
    """
    Fire-and-forget enqueue that REPORTS WHAT HAPPENED.

    Never raises: a receipt failure must not turn a block into a served answer
    (kill-switch-receipt ruling — the halt does not depend on the record
    landing). But it must not be silent about it either. The caller-facing
    ``receipt`` field is this return value, so the response can never claim an
    evidence trail that does not exist:

      ``enqueued``        the rail accepted the record
      ``no_audit_writer`` no rail is configured — nothing was enqueued anywhere
      ``write_failed``    the rail raised; nothing landed

    The three are distinguished HERE, at the one place that can observe the
    difference. A literal at the response-construction site cannot, which is the
    entire defect this replaces.
    """
    audit = getattr(request.app.state, "audit_writer", None)
    if audit is None:
        logger.warning(
            "Interception decision not receipted: no audit writer configured "
            "(decision unaffected; the caller is told '%s')", RECEIPT_NO_WRITER,
        )
        return RECEIPT_NO_WRITER
    try:
        await audit.write(record)
    except Exception as exc:
        logger.error("Interception audit write failed (decision unaffected): %s", exc)
        return RECEIPT_WRITE_FAILED
    return RECEIPT_ENQUEUED


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AIInterceptionMiddleware(BaseHTTPMiddleware):
    """
    Intercepts /v1/* requests, detects fabrication risk in the AI response,
    and optionally blocks or warns based on configured action.
    """

    async def dispatch(self, request: Request, call_next):
        # Only activate for /v1/ paths
        if not request.url.path.startswith(INTERCEPT_PREFIX):
            return await call_next(request)

        body = await request.body()
        model_id = _extract_model_id(body)
        prompt = _extract_prompt(body)

        # -- obtain the response -------------------------------------------
        try:
            response_body, status_code, relayed = await self._obtain(
                request, call_next, body
            )
        except InterceptionRefusal as refusal:
            return await self._refuse(request, refusal, prompt)
        except Exception as exc:
            logger.exception("Interception could not obtain a response: %s", exc)
            return await self._refuse(
                request, InterceptionRefusal("upstream_unreachable"), prompt,
                status_code=502,
            )

        # -- score it ------------------------------------------------------
        engine = getattr(request.app.state, "engine", None)
        if engine is None:
            return _build_response(
                response_body, status_code, relayed,
                _signal_headers("UNAVAILABLE", "unavailable"),
            )

        try:
            metadata = {}
            output_tokens = _extract_output_tokens(response_body)
            if output_tokens is not None:
                metadata["output_tokens"] = output_tokens
            result = await engine.verify(
                prompt,
                response_body.decode("utf-8", errors="replace"),
                model_id,
                **metadata,
            )
        except Exception as exc:
            # Fail-open: deliver the answer we already hold, unchanged. Never
            # re-enter call_next — that serves the proxy's own local routes.
            logger.exception("Detection failed; passing response through: %s", exc)
            return _build_response(
                response_body, status_code, relayed,
                _signal_headers("ERROR", "error"),
            )

        # -- act on the verdict --------------------------------------------
        # TWO signals, and they are not interchangeable. `policy` is what the
        # customer configured and authorises nothing; `gate_action` is the
        # profile-EARNED authorisation. A hard block needs both.
        settings = getattr(request.app.state, "settings", None)
        detection_cfg = getattr(settings, "detection", None) if settings else None
        if result.risk_level == "HIGH":
            policy = getattr(detection_cfg, "high_risk_action", "warn") if detection_cfg else "warn"
        else:
            policy = "pass"

        gate_action = getattr(result, "gate_action", None)
        gate_authorises_block = gate_action == GATE_ACTION_BLOCK

        if result.risk_level == "HIGH" and policy == "block" and gate_authorises_block:
            receipt = await _emit(request, _audit_record(
                detection_id=result.detection_id,
                risk_level="HIGH",
                action_taken="block",
                path=request.url.path,
                method=request.method,
                prompt=prompt,
                response_body=response_body,
                model_id=result.model_id,
                profile_version=result.profile_version,
                confidence=result.confidence,
                features_triggered=list(result.features_triggered or []),
                gate_action=gate_action,
                policy_action=policy,
            ))
            payload = {
                "error": "arkheia_blocked",
                "risk_level": "HIGH",
                "detection_id": result.detection_id,
                "reason": (
                    "the model response scored HIGH fabrication risk, this "
                    "proxy is configured to block HIGH-risk responses, and the "
                    "model profile has earned the hard-block gate"
                ),
                "remedy": (
                    "re-run the request, narrow the prompt to material the "
                    "model can ground, or ask an operator to review detection "
                    f"id {result.detection_id} in the audit log"
                ),
                "receipt": receipt,
            }
            return _build_response(
                json.dumps(payload).encode("utf-8"), 200,
                [("content-type", "application/json")],
                _signal_headers("HIGH", "block", result.detection_id,
                                gate_action=gate_action, policy_action=policy),
            )

        if result.risk_level == "HIGH" and policy in ("block", "warn"):
            # Either the customer asked to warn, or they asked to block and the
            # gate did not authorise it. Both deliver the answer; the difference
            # is legible from `policy_action` on the headers and on the record,
            # so a downgraded block is never silent.
            await _emit(request, _audit_record(
                detection_id=result.detection_id,
                risk_level="HIGH",
                action_taken="warn",
                path=request.url.path,
                method=request.method,
                prompt=prompt,
                response_body=response_body,
                model_id=result.model_id,
                profile_version=result.profile_version,
                confidence=result.confidence,
                features_triggered=list(result.features_triggered or []),
                gate_action=gate_action,
                policy_action=policy,
            ))
            return _build_response(
                response_body, status_code, relayed,
                _signal_headers("HIGH", "warn", result.detection_id,
                                gate_action=gate_action, policy_action=policy),
            )

        return _build_response(
            response_body, status_code, relayed,
            _signal_headers(result.risk_level, policy, result.detection_id,
                            gate_action=gate_action, policy_action=policy),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _obtain(self, request: Request, call_next, body: bytes):
        """
        Return ``(body, status_code, relayed_headers)`` for the request.

        In forward mode every refusal is raised BEFORE an ``httpx.AsyncClient``
        exists, so no credential can be attached to a destination the gate has
        not approved.
        """
        upstream_url = None
        app_settings = getattr(request.app.state, "settings", None)
        if app_settings is not None:
            detection = getattr(app_settings, "detection", None)
            if detection is not None:
                upstream_url = getattr(detection, "upstream_url", None)
        if not upstream_url:
            upstream_url = None

        if upstream_url is None:
            inner_response = await call_next(request)
            chunks = []
            async for chunk in inner_response.body_iterator:
                chunks.append(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
            relayed = [(k, v) for k, v in inner_response.headers.items()
                       if k.lower() not in RESPONSE_OWNED_HEADERS
                       and k.lower() not in HOP_BY_HOP_HEADERS]
            return b"".join(chunks), inner_response.status_code, relayed

        _check_raw_path(request.url.path)
        target_url = _resolve_upstream(
            upstream_url, request.url.path, request.url.query
        )
        forward_headers = _forward_headers(request.headers)

        async with httpx.AsyncClient(follow_redirects=False) as client:
            upstream_response = await client.request(
                method=request.method,
                url=target_url,
                content=body,
                headers=forward_headers,
            )
        return (
            upstream_response.content,
            upstream_response.status_code,
            _relay_headers(upstream_response.headers),
        )

    async def _refuse(self, request: Request, refusal: InterceptionRefusal,
                      prompt: str, status_code: int = 400) -> Response:
        detection_id = str(uuid.uuid4())
        receipt = await _emit(request, _audit_record(
            detection_id=detection_id,
            risk_level="REFUSED",
            action_taken="refused",
            path=request.url.path,
            method=request.method,
            prompt=prompt,
            response_body=b"",
            deny_code=refusal.deny_code,
            reason=refusal.reason,
        ))
        payload = {
            "error": "arkheia_refused",
            "deny_code": refusal.deny_code,
            "reason": refusal.reason,
            "remedy": refusal.remedy,
            "detection_id": detection_id,
            "receipt": receipt,
        }
        return _build_response(
            json.dumps(payload).encode("utf-8"), status_code,
            [("content-type", "application/json")],
            _signal_headers("REFUSED", "refused", detection_id),
        )
