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
"""

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

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

#: Framing and negotiation headers we own rather than relay. ``host`` is set by
#: httpx from the resolved URL; ``content-length`` is recomputed from the body
#: we actually send.
REQUEST_OWNED_HEADERS = frozenset({"host", "content-length"})

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

    Refuses rather than resolves a duplicated credential header: choosing one
    silently is the smuggling primitive, whichever end you choose from.
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
        if lowered in HOP_BY_HOP_HEADERS:
            continue
        if lowered in REQUEST_OWNED_HEADERS:
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
                    detection_id: Optional[str] = None) -> dict:
    """
    Header-only signalling. The body is never mutated: prepending a banner to a
    JSON completion produces bytes no parser accepts, and
    ``proxy/endpoints/detect.py::_signal`` already rules against the pattern by
    name ("we never prepend to the body (that pattern in interception.py
    corrupts responses and 400-loops sessions)").
    """
    return {
        "X-Arkheia-Risk": risk_level,
        "X-Arkheia-Action": action,
        "X-Arkheia-Detection-Id": detection_id,
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
        "source": "interception",
        "path": path,
        "method": method,
        "deny_code": deny_code,
        "reason": reason,
        "error": error,
    }


async def _emit(request: Request, record: dict) -> None:
    """
    Fire-and-forget enqueue. Never raises: a receipt failure must not turn a
    block into a served answer (kill-switch-receipt ruling — the halt does not
    depend on the record landing).
    """
    audit = getattr(request.app.state, "audit_writer", None)
    if audit is None:
        return
    try:
        await audit.write(record)
    except Exception as exc:                                # pragma: no cover
        logger.error("Interception audit write failed (decision unaffected): %s", exc)


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
            result = await engine.verify(
                prompt,
                response_body.decode("utf-8", errors="replace"),
                model_id,
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
        settings = getattr(request.app.state, "settings", None)
        detection_cfg = getattr(settings, "detection", None) if settings else None
        if result.risk_level == "HIGH":
            action = getattr(detection_cfg, "high_risk_action", "warn") if detection_cfg else "warn"
        else:
            action = "pass"

        if result.risk_level == "HIGH" and action == "block":
            await _emit(request, _audit_record(
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
            ))
            payload = {
                "error": "arkheia_blocked",
                "risk_level": "HIGH",
                "detection_id": result.detection_id,
                "reason": (
                    "the model response scored HIGH fabrication risk and this "
                    "proxy is configured to block HIGH-risk responses"
                ),
                "remedy": (
                    "re-run the request, narrow the prompt to material the "
                    "model can ground, or ask an operator to review detection "
                    f"id {result.detection_id} in the audit log"
                ),
                "receipt": "enqueued",
            }
            return _build_response(
                json.dumps(payload).encode("utf-8"), 200,
                [("content-type", "application/json")],
                _signal_headers("HIGH", "block", result.detection_id),
            )

        if result.risk_level == "HIGH" and action == "warn":
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
            ))
            return _build_response(
                response_body, status_code, relayed,
                _signal_headers("HIGH", "warn", result.detection_id),
            )

        return _build_response(
            response_body, status_code, relayed,
            _signal_headers(result.risk_level, action, result.detection_id),
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
        await _emit(request, _audit_record(
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
            "receipt": "enqueued",
        }
        return _build_response(
            json.dumps(payload).encode("utf-8"), status_code,
            [("content-type", "application/json")],
            _signal_headers("REFUSED", "refused", detection_id),
        )
