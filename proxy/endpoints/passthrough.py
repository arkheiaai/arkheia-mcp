"""
Arkheia Enterprise Proxy -- Passthrough endpoints for CLI routing.

These endpoints allow the Grok, Gemini, Together, and Anthropic CLIs to route
their traffic through Arkheia detection without any code changes to the CLIs --
only a config change to point their base URL at localhost:8098.

Routes:
  POST /proxy/grok/v1/{path}  -- forward to https://api.x.ai/v1/{path}
  POST /proxy/together/v1/{path} -- forward to https://api.together.xyz/v1/{path}
  ANY  /v1beta/{path}         -- forward to https://generativelanguage.googleapis.com/v1beta/{path}
  POST /v1/{path}             -- forward to https://api.anthropic.com/v1/{path}

All endpoints:
  1. Decide whether the request may be forwarded AT ALL (see "Forwarding gate")
  2. Forward the request to the upstream provider (safe headers only)
  3. Extract response text for detection
  4. Run Arkheia detection
  5. Return the provider response with X-Arkheia-Risk header
  6. Write to audit log (same record format as /detect/verify)

Fail-open: if DETECTION fails for any reason, the provider response is returned
unchanged with X-Arkheia-Risk: ERROR. The pipeline is never blocked by detection.
Fail-CLOSED: the forwarding gate is a grant path, not a safety path -- a request
that cannot be shown to resolve to a known provider endpoint is refused.

Forwarding gate (SSRF containment)
----------------------------------
This module dispatches caller-supplied paths against a small set of *constant*
upstream base URLs while forwarding the caller's provider credentials. Two
independent controls stand between the caller and the URL that leaves:

  1. A per-provider path allowlist (``Provider.path_re``), fully anchored with
     ``\\A``/``\\Z`` so a trailing newline cannot satisfy it, plus explicit
     rejection of dot-segments, backslashes, percent-encoded separators and
     control characters.

  2. A POST-CONDITION on the resolved URL (``_resolve_upstream``). After the URL
     is built it is re-parsed and normalised, and its scheme, host, port and path
     prefix are compared against **verifier-owned constants** taken from the
     provider table -- never from the request. This is what makes a future
     weakening of the regex non-exploitable: the request is refused even if the
     allowlist lets it through.

Both controls run BEFORE any credential is attached and before any HTTP client
is constructed; a refused request produces zero upstream traffic.

Redirects are NOT followed (``follow_redirects=False``, passed explicitly): a
provider 3xx is relayed to the caller rather than fetched by us, so a redirect
to a link-local or internal address is never dereferenced with our network
position.

Security:
  - Only allowlisted headers are forwarded upstream (no cookie/internal header leak)
  - Duplicate credential headers are refused rather than silently last-wins
  - The full RFC 9110 hop-by-hop set (plus content-length) is stripped from the
    relayed response
  - Error details are never exposed to clients
  - Every refusal is receipted to the audit rail with a deny code
"""

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

logger = logging.getLogger(__name__)

router = APIRouter()

GROK_UPSTREAM       = "https://api.x.ai/v1"
GEMINI_UPSTREAM     = "https://generativelanguage.googleapis.com/v1beta"
TOGETHER_UPSTREAM   = "https://api.together.xyz/v1"
ANTHROPIC_UPSTREAM  = "https://api.anthropic.com"

# ---------------------------------------------------------------------------
# Security: header allowlist for upstream forwarding
# ---------------------------------------------------------------------------
# Only these headers are forwarded to upstream providers. This prevents
# leaking internal cookies, auth tokens for other services, or proxy headers.
_FORWARDED_HEADERS = {
    "authorization",       # provider API key (Bearer token)
    "content-type",
    "accept",
    "user-agent",
    "x-request-id",
    "x-stainless-arch",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
    "x-api-key",           # Anthropic auth header
    "anthropic-version",   # required by Anthropic API
    "anthropic-beta",      # optional Anthropic feature flags
}

#: Headers that carry a caller credential. More than one occurrence of any of
#: these is refused: silently picking one (a dict comprehension picks the LAST)
#: means the credential this proxy authenticates with can differ from the one a
#: downstream or upstream inspector attributes the call to.
_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key"})

# ---------------------------------------------------------------------------
# Security: hop-by-hop response headers
# ---------------------------------------------------------------------------
# RFC 9110 s7.6.1 connection-specific header fields, which a proxy MUST NOT
# forward, plus content-length.
#
# content-length is load-bearing, not tidiness. httpx transparently decodes
# `content-encoding: gzip`, so the body handed to us is the DECOMPRESSED body
# while the upstream content-length describes the COMPRESSED one. Relaying that
# header alongside a decoded body is an HTTP framing desync: uvicorn raises
# "Response content longer than Content-Length" and the caller receives a
# zero-byte body under a non-zero content-length. Every gzip-compressed provider
# response hit this. Starlette recomputes the header when it is absent.
_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "content-encoding",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
})

# ---------------------------------------------------------------------------
# Security: path validation for SSRF mitigation
# ---------------------------------------------------------------------------
# Anchored with \A/\Z, never ^/$: in Python `$` also matches immediately before
# a trailing newline, so `^chat/completions$` accepts "chat/completions\n".
#
# No unbounded `.*` inside a path: `.` matches `/`, so an `audio/.*` arm accepted
# "audio/../../admin/keys", which resolved to https://api.x.ai/admin/keys — the
# allowlist's entire purpose defeated by a prefix. The audio arm now enumerates
# the three real OpenAI-compatible audio routes.
_OPENAI_PATH_RE = re.compile(
    r"\A(chat/completions|completions|embeddings|models|images/generations"
    r"|audio/(speech|transcriptions|translations)|moderations)\Z"
)
_GEMINI_PATH_RE = re.compile(
    r"\Amodels(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?\Z"
)
#: Matched against the *sub*-path (``messages`` / ``models``), not ``v1/...``.
_ANTHROPIC_PATH_RE = re.compile(
    r"\A(messages|models)\Z"
)

#: Characters that may never appear in a forwarded path segment, whatever the
#: allowlist says. Checked before the allowlist so the deny code is specific.
_TRAVERSAL_MARKERS = ("..", "\\", "%2e", "%2E", "%2f", "%2F", "%5c", "%5C")


# ---------------------------------------------------------------------------
# Deny taxonomy — a closed set. A refusal that is not one of these is a bug.
# ---------------------------------------------------------------------------

DENY_PATH_NOT_ALLOWLISTED   = "path_not_allowlisted"
DENY_PATH_TRAVERSAL         = "path_traversal"
DENY_PATH_ILLEGAL_CHARACTER = "path_illegal_character"
DENY_UPSTREAM_TARGET_ESCAPED = "upstream_target_escaped"
DENY_DUPLICATE_CREDENTIAL   = "duplicate_credential_header"

#: deny code -> (operator-facing reason, what would clear it)
DENY_TAXONOMY: dict[str, tuple[str, str]] = {
    DENY_PATH_NOT_ALLOWLISTED: (
        "The requested path is not one of this provider's allowlisted API paths.",
        "Call one of the allowlisted paths listed in `allowed`.",
    ),
    DENY_PATH_TRAVERSAL: (
        "The requested path contains a dot-segment, a backslash, or a "
        "percent-encoded path separator.",
        "Send the provider API path literally, with no '..', '\\' or %2e/%2f/%5c "
        "escapes.",
    ),
    DENY_PATH_ILLEGAL_CHARACTER: (
        "The requested path contains a control character.",
        "Remove control characters (including CR/LF) from the request path.",
    ),
    DENY_UPSTREAM_TARGET_ESCAPED: (
        "The path resolved to a URL outside this provider's API surface. The "
        "request was refused before any credential was attached.",
        "Call one of the allowlisted paths listed in `allowed`.",
    ),
    DENY_DUPLICATE_CREDENTIAL: (
        "The request carried more than one credential header, so the credential "
        "this proxy would forward is ambiguous.",
        "Send exactly one Authorization header and/or one X-Api-Key header.",
    ),
}


# ---------------------------------------------------------------------------
# Provider table — the verifier-owned constants
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Provider:
    """
    One upstream provider.

    Everything the forwarding gate compares against lives here, and nothing here
    is derived from a request. ``expected_scheme`` / ``expected_host`` /
    ``expected_port`` / ``base_path`` are parsed from ``base`` once, at import.
    """
    name: str
    base: str
    path_re: re.Pattern
    allowed: tuple[str, ...]

    @property
    def _split(self):
        return urlsplit(self.base)

    @property
    def expected_scheme(self) -> str:
        return self._split.scheme

    @property
    def expected_host(self) -> str:
        return self._split.hostname or ""

    @property
    def expected_port(self) -> Optional[int]:
        return self._split.port

    @property
    def base_path(self) -> str:
        return self._split.path.rstrip("/")


_OPENAI_ALLOWED = (
    "chat/completions", "completions", "embeddings", "models",
    "images/generations", "audio/speech", "audio/transcriptions",
    "audio/translations", "moderations",
)

GROK = Provider("grok", GROK_UPSTREAM, _OPENAI_PATH_RE, _OPENAI_ALLOWED)
TOGETHER = Provider("together", TOGETHER_UPSTREAM, _OPENAI_PATH_RE, _OPENAI_ALLOWED)
GEMINI = Provider(
    "gemini", GEMINI_UPSTREAM, _GEMINI_PATH_RE,
    ("models", "models/{model}", "models/{model}:{action}"),
)
ANTHROPIC = Provider(
    "anthropic", ANTHROPIC_UPSTREAM + "/v1", _ANTHROPIC_PATH_RE,
    ("messages", "models"),
)

PROVIDERS: tuple[Provider, ...] = (GROK, TOGETHER, GEMINI, ANTHROPIC)


# ---------------------------------------------------------------------------
# Forwarding gate
# ---------------------------------------------------------------------------

def _duplicate_credential_headers(request: Request) -> list[str]:
    """Credential header names that appear more than once on the request."""
    seen: dict[str, int] = {}
    for raw_key, _ in request.headers.raw:
        key = raw_key.decode("latin-1").lower()
        if key in _CREDENTIAL_HEADERS:
            seen[key] = seen.get(key, 0) + 1
    return sorted(k for k, n in seen.items() if n > 1)


def _screen_path(provider: Provider, path: str) -> Optional[str]:
    """
    Return a deny code, or None if ``path`` passes the allowlist screen.

    Order matters only for which code is reported; every arm refuses.
    """
    if any(ch for ch in path if ord(ch) < 0x20 or ord(ch) == 0x7F):
        return DENY_PATH_ILLEGAL_CHARACTER
    if any(marker in path for marker in _TRAVERSAL_MARKERS):
        return DENY_PATH_TRAVERSAL
    if any(segment in (".", "..") for segment in path.split("/")):
        return DENY_PATH_TRAVERSAL
    if not provider.path_re.fullmatch(path):
        return DENY_PATH_NOT_ALLOWLISTED
    return None


def _resolve_upstream(provider: Provider, path: str) -> tuple[Optional[str], Optional[str]]:
    """
    Build the upstream URL and prove it still points at ``provider``.

    Returns ``(url, None)`` or ``(None, deny_code)``.

    The post-condition is the control that survives a weakened allowlist. It
    re-parses the *built* URL — the same normalisation httpx will apply, dot
    segments removed — and compares scheme/host/port/path-prefix against the
    provider's own constants. Nothing in the comparison comes from the request.
    """
    candidate = f"{provider.base}/{path}"
    try:
        parsed = httpx.URL(candidate)
    except Exception:
        # An unparsable URL is a refusal, never a forward.
        return None, DENY_PATH_ILLEGAL_CHARACTER

    if parsed.scheme != provider.expected_scheme:
        return None, DENY_UPSTREAM_TARGET_ESCAPED
    if parsed.host != provider.expected_host:
        return None, DENY_UPSTREAM_TARGET_ESCAPED
    if parsed.port != provider.expected_port:
        return None, DENY_UPSTREAM_TARGET_ESCAPED
    if parsed.query or parsed.fragment:
        # The caller's query string is forwarded separately and explicitly; a
        # query or fragment smuggled through the PATH is not a provider path.
        return None, DENY_UPSTREAM_TARGET_ESCAPED

    base_path = provider.base_path
    resolved_path = parsed.path

    # httpx DECODES percent escapes into ``.path`` but does not remove dot
    # segments from them: "%2e%2e/%2e%2e" arrives here as "/v1/../..", which
    # satisfies a naive prefix check and is then normalised by the ORIGIN into
    # an escape. The prefix test alone is therefore not a containment proof.
    # Found by writing this module's own defence-in-depth test.
    if "\\" in resolved_path:
        return None, DENY_UPSTREAM_TARGET_ESCAPED
    if any(segment in (".", "..") for segment in resolved_path.split("/")):
        return None, DENY_UPSTREAM_TARGET_ESCAPED

    if not (resolved_path == base_path or resolved_path.startswith(base_path + "/")):
        return None, DENY_UPSTREAM_TARGET_ESCAPED

    return candidate, None


def _gate(request: Request, provider: Provider, path: str) -> tuple[Optional[str], Optional[str]]:
    """
    The whole forwarding decision. Returns ``(upstream_url, deny_code)``.

    Runs before any HTTP client exists and before any header is copied, so a
    refusal cannot leak a credential to the attempted destination.
    """
    dups = _duplicate_credential_headers(request)
    if dups:
        return None, DENY_DUPLICATE_CREDENTIAL

    deny = _screen_path(provider, path)
    if deny:
        return None, deny

    return _resolve_upstream(provider, path)


# ---------------------------------------------------------------------------
# Refusal receipt — a blocked request must be investigable
# ---------------------------------------------------------------------------

#: risk_level carried by a refusal row. Distinct from every detection verdict so
#: a refusal can never be miscounted as a screened LOW.
REFUSAL_RISK_LEVEL = "REFUSED"

#: Cap on the attempted path stored in the receipt. The path is investigation
#: evidence, so it is recorded rather than hashed away; the writer's redactor
#: strips known secret patterns before anything reaches disk, and the untruncated
#: value is pinned by attempted_path_sha256.
_MAX_RECORDED_PATH = 512


async def _receipt_refusal(
    request: Request,
    provider: Provider,
    deny_code: str,
    attempted_path: str,
) -> tuple[str, str]:
    """
    Write a durable, attributable record of a REFUSAL.

    Returns ``(receipt_id, receipt_status)`` where status is ``"recorded"`` or
    ``"unrecorded"``. Never raises: a receipt failure must not turn a deny into
    an allow, and must not turn a 400 into a 500. It is, however, never silent —
    an unrecorded refusal is logged at ERROR and reported to the caller.
    """
    receipt_id = str(uuid.uuid4())
    audit = getattr(request.app.state, "audit_writer", None)

    if audit is None:
        logger.error(
            "passthrough refusal NOT RECEIPTED (no audit writer): "
            "provider=%s deny_code=%s receipt_id=%s",
            provider.name, deny_code, receipt_id,
        )
        return receipt_id, "unrecorded"

    record = {
        "detection_id": receipt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": None,
        "model_id": None,
        "profile_version": None,
        "risk_level": REFUSAL_RISK_LEVEL,
        "confidence": None,
        "features_triggered": [],
        "prompt_hash": None,
        "response_hash": None,
        "response_length": 0,
        "action_taken": "refuse",
        "source": "passthrough",
        "error": None,
        # -- refusal-specific evidence -----------------------------------
        "event_type": "passthrough.forward_refused",
        "provider": provider.name,
        "deny_code": deny_code,
        "attempted_path": attempted_path[:_MAX_RECORDED_PATH],
        "attempted_path_sha256": hashlib.sha256(attempted_path.encode()).hexdigest(),
        "attempted_method": request.method,
        # Header/query KEY NAMES only — never values.
        "request_header_names": sorted({k.lower() for k in request.headers.keys()}),
        "query_param_names": sorted(set(request.query_params.keys())),
        "client_host": request.client.host if request.client else None,
    }

    try:
        await audit.write(record)
    except Exception as e:
        logger.error(
            "passthrough refusal NOT RECEIPTED (audit write failed: %s): "
            "provider=%s deny_code=%s receipt_id=%s",
            e, provider.name, deny_code, receipt_id,
        )
        return receipt_id, "unrecorded"

    logger.warning(
        "passthrough refused: provider=%s deny_code=%s receipt_id=%s",
        provider.name, deny_code, receipt_id,
    )
    return receipt_id, "recorded"


async def _refuse(
    request: Request,
    provider: Provider,
    deny_code: str,
    attempted_path: str,
) -> Response:
    """
    Build the 400 for a refused forward.

    Every NO carries its evidence and a path to YES: the deny code, the reason,
    what would clear it, the allowlist, and the receipt id to quote.
    """
    receipt_id, receipt_status = await _receipt_refusal(
        request, provider, deny_code, attempted_path
    )
    reason, remedy = DENY_TAXONOMY[deny_code]

    body: dict = {
        # Unchanged wire contract for the pre-existing path denies.
        "error": (
            "invalid_credential_header"
            if deny_code == DENY_DUPLICATE_CREDENTIAL
            else "invalid_path"
        ),
        "deny_code": deny_code,
        "reason": reason,
        "remedy": remedy,
        "receipt_id": receipt_id,
        "receipt_status": receipt_status,
    }
    if deny_code != DENY_DUPLICATE_CREDENTIAL:
        body["allowed"] = list(provider.allowed)

    return Response(
        content=json.dumps(body).encode(),
        status_code=400,
        media_type="application/json",
        headers={"X-Arkheia-Risk": REFUSAL_RISK_LEVEL},
    )


# ---------------------------------------------------------------------------
# Response text extractors
# ---------------------------------------------------------------------------

def _extract_openai_text(body: bytes) -> Optional[str]:
    """Extract assistant message text from an OpenAI-format chat completion."""
    try:
        data = json.loads(body)
        return data["choices"][0]["message"]["content"]
    except Exception:
        return None


def _extract_gemini_text(body: bytes) -> Optional[str]:
    """Extract response text from a Gemini generateContent response."""
    try:
        data = json.loads(body)
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Prompt extractors
# ---------------------------------------------------------------------------

def _extract_openai_prompt(body: bytes) -> str:
    try:
        data = json.loads(body)
        parts = []
        for msg in data.get("messages", []):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
        return " ".join(parts)
    except Exception:
        return ""


def _extract_gemini_prompt(body: bytes) -> str:
    try:
        data = json.loads(body)
        # Gemini format: contents[].parts[].text where role == "user"
        parts = []
        for content in data.get("contents", []):
            if content.get("role", "user") in ("user", ""):
                for part in content.get("parts", []):
                    if "text" in part:
                        parts.append(part["text"])
        return " ".join(parts)
    except Exception:
        return ""


def _extract_grok_model(body: bytes) -> str:
    try:
        return json.loads(body).get("model", "unknown")
    except Exception:
        return "unknown"


def _extract_anthropic_text(body: bytes) -> Optional[str]:
    """Extract assistant text from an Anthropic messages response."""
    try:
        data = json.loads(body)
        for block in data.get("content", []):
            if block.get("type") == "text":
                return block["text"]
        return None
    except Exception:
        return None


def _extract_anthropic_model(body: bytes) -> str:
    try:
        return json.loads(body).get("model", "unknown")
    except Exception:
        return "unknown"


def _extract_gemini_model(path: str) -> str:
    """
    Extract model name from Gemini path.
    e.g. 'models/gemini-2.5-flash:generateContent' -> 'gemini-2.5-flash'
    """
    try:
        # path looks like 'models/gemini-2.5-flash:generateContent?key=...'
        segment = path.split("/")[-1].split(":")[0]
        return segment if segment else "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Shared detection + audit helper
# ---------------------------------------------------------------------------

async def _detect_and_audit(
    request: Request,
    prompt: str,
    response_text: str,
    model_id: str,
) -> str:
    """
    Run detection and write audit record. Returns risk_level string.
    Never raises -- returns 'ERROR' on any failure.
    """
    engine = getattr(request.app.state, "engine", None)
    audit = getattr(request.app.state, "audit_writer", None)

    if engine is None or not response_text:
        return "UNKNOWN"

    try:
        result = await engine.verify(prompt, response_text, model_id)
        risk_level = result.risk_level

        if audit:
            record = {
                "detection_id": result.detection_id,
                "timestamp": result.timestamp,
                "session_id": None,
                "model_id": result.model_id,
                "profile_version": result.profile_version,
                "risk_level": risk_level,
                "confidence": result.confidence,
                "features_triggered": result.features_triggered,
                "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
                "response_hash": hashlib.sha256(response_text.encode()).hexdigest(),
                "response_length": len(response_text),
                "action_taken": "pass",
                "source": "passthrough",
                "error": result.error,
            }
            try:
                await audit.write(record)
            except Exception as e:
                logger.error("Audit write failed in passthrough: %s", e)

        return risk_level

    except Exception as e:
        logger.error("Detection failed in passthrough (model=%s): %s", model_id, e)
        return "ERROR"


# ---------------------------------------------------------------------------
# Shared forwarding helper
# ---------------------------------------------------------------------------

def _filter_response_headers(upstream_headers) -> dict:
    """
    Strip connection-specific headers from the relayed response.

    Also honours ``Connection: <token>`` — RFC 9110 lets an origin nominate
    additional headers as connection-specific, and a proxy that ignores the
    nomination relays exactly the headers the origin asked it not to.
    """
    skip = set(_HOP_BY_HOP_HEADERS)
    connection_value = upstream_headers.get("connection")
    if connection_value:
        for token in connection_value.split(","):
            token = token.strip().lower()
            if token and token not in ("close", "keep-alive"):
                skip.add(token)
    return {
        k: v for k, v in upstream_headers.items()
        if k.lower() not in skip
    }


async def _forward(
    request: Request,
    upstream_url: str,
) -> tuple[bytes, int, dict]:
    """
    Forward the request to upstream_url. Returns (body, status_code, headers).
    Raises on network error.

    Security:
      - only allowlisted headers are forwarded (see _FORWARDED_HEADERS)
      - follow_redirects is False, EXPLICITLY: a provider 3xx is relayed to the
        caller, never dereferenced by us. Relying on the library default would
        make an SSRF control a property of a dependency's release notes.
      - connection-specific response headers are stripped (see
        _filter_response_headers)
    """
    body = await request.body()

    # Only forward safe, allowlisted headers — never cookies, internal tokens, etc.
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() in _FORWARDED_HEADERS
    }

    async with httpx.AsyncClient(timeout=60.0, follow_redirects=False) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=forward_headers,
            params=dict(request.query_params),
        )

    response_headers = _filter_response_headers(upstream_response.headers)

    return upstream_response.content, upstream_response.status_code, response_headers


# ---------------------------------------------------------------------------
# Grok passthrough  --  /proxy/grok/v1/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/proxy/grok/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def grok_passthrough(path: str, request: Request):
    """
    Forward Grok CLI requests to api.x.ai with Arkheia detection.

    Configure Grok CLI:
        baseURL: "http://localhost:8098/proxy/grok/v1"
    """
    upstream_url, deny_code = _gate(request, GROK, path)
    if deny_code:
        return await _refuse(request, GROK, deny_code, path)

    logger.debug("grok_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("grok_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    # Only screen successful responses with extractable text
    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_openai_text(response_body)
        if response_text:
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("grok_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Together AI passthrough  --  /proxy/together/v1/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/proxy/together/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def together_passthrough(path: str, request: Request):
    """
    Forward Together AI requests to api.together.xyz with Arkheia detection.

    Configure Together AI client:
        base_url = "http://localhost:8098/proxy/together/v1"
    """
    upstream_url, deny_code = _gate(request, TOGETHER, path)
    if deny_code:
        return await _refuse(request, TOGETHER, deny_code, path)

    logger.debug("together_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("together_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_openai_text(response_body)
        if response_text:
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)  # same field: "model"
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("together_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Gemini passthrough  --  /v1beta/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/v1beta/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def gemini_passthrough(path: str, request: Request):
    """
    Forward Gemini CLI requests to generativelanguage.googleapis.com with detection.

    Configure Gemini CLI:
        GEMINI_API_BASE_URL=http://localhost:8098
        GOOGLE_GENERATIVE_AI_BASE_URL=http://localhost:8098
    """
    upstream_url, deny_code = _gate(request, GEMINI, path)
    if deny_code:
        return await _refuse(request, GEMINI, deny_code, path)

    logger.debug("gemini_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("gemini_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_gemini_text(response_body)
        if response_text:
            prompt = _extract_gemini_prompt(request_body)
            model_id = _extract_gemini_model(path)
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("gemini_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Anthropic passthrough  --  /v1/messages, /v1/models
# ---------------------------------------------------------------------------

@router.api_route(
    "/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def anthropic_passthrough(path: str, request: Request):
    """
    Forward Anthropic SDK requests to api.anthropic.com with Arkheia detection.

    Configure Anthropic SDK / Claude Code CLI:
        ANTHROPIC_BASE_URL=http://localhost:8098
    """
    upstream_url, deny_code = _gate(request, ANTHROPIC, path)
    if deny_code:
        return await _refuse(request, ANTHROPIC, deny_code, path)

    logger.debug("anthropic_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("anthropic_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_anthropic_text(response_body)
        if response_text:
            prompt = _extract_openai_prompt(request_body)  # Anthropic uses same messages[] format
            model_id = _extract_anthropic_model(response_body)
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("anthropic_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )
