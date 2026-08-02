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

Credential boundary (cross-provider disclosure containment)
-----------------------------------------------------------
The credential forwarded to a provider is the one THAT provider uses, and only
that one. The mapping is per destination (``Provider.credential_headers`` /
``credential_query_params``), not one allowlist shared by all four: a shared
list cannot express "this key belongs to that vendor", and the previous one --
holding both ``authorization`` and ``x-api-key`` -- delivered BOTH to whichever
single destination the route resolved to. A caller routing Anthropic and xAI
traffic through this proxy had their Anthropic key handed to xAI on the ACCEPTED
path, in a request they authorised for something else.

A credential the destination does not use is REFUSED, not quietly dropped
(``foreign_credential``): a secret arriving at the wrong vendor's route is a
caller mistake worth telling them about, and silence would leave them believing
a key they can see in their own config is reaching a provider it never reaches.
The same rule closes the query string, where a Google ``?key=`` addressed to the
Grok route used to leave for api.x.ai.

How MANY credentials may be addressed to a destination is a second, separate
question, and it is counted PER DESTINATION over every channel at once (see
``CREDENTIAL_CHANNELS``) — never per header name, and never per channel. A rule
that counts headers is blind to a header ⇄ query-parameter interaction in
exactly the way a rule that counted one header name was blind to two: Gemini
accepts ``authorization``, ``x-goog-api-key`` and ``?key=``, so a bearer plus a
``?key=`` was two credentials the header count read as one, and both left for
Google. More than one credential for one destination is REFUSED
(``multiple_credentials``); more than one permitted credential FORM is fine, and
any single one of them still forwards.

Security:
  - Only allowlisted headers are forwarded upstream (no cookie/internal header leak)
  - Credentials are attached per destination; a foreign credential is refused
  - More than one credential for one destination is refused, counted across
    headers and query parameters together, rather than silently last-wins
  - The full RFC 9110 hop-by-hop set (plus content-length) is stripped from the
    relayed response
  - Error details are never exposed to clients
  - Every refusal is receipted to the audit rail with a deny code
"""

import dataclasses
import hashlib
import json
import logging
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

from arkheia_common.egress import egress_async_client

logger = logging.getLogger(__name__)

router = APIRouter()

GROK_UPSTREAM       = "https://api.x.ai/v1"
GEMINI_UPSTREAM     = "https://generativelanguage.googleapis.com/v1beta"
TOGETHER_UPSTREAM   = "https://api.together.xyz/v1"
ANTHROPIC_UPSTREAM  = "https://api.anthropic.com"

# ---------------------------------------------------------------------------
# Security: header allowlist for upstream forwarding
# ---------------------------------------------------------------------------
# Forwarded to EVERY destination. Nothing in this set carries a caller secret,
# and that is the invariant — enforced statically by the floor tier, because it
# is the property whose loss produced a cross-vendor credential disclosure.
#
# A GLOBAL allowlist cannot express "this key belongs to that vendor". The
# previous one held BOTH `authorization` and `x-api-key` and was applied to all
# four providers, so a caller carrying both — the ordinary shape for a client
# configured for two vendors, or a gateway that attaches every credential it
# holds — had both delivered to whichever single destination the route resolved
# to. Credentials are therefore attached PER DESTINATION, from
# `Provider.credential_headers`, and never from here.
_SAFE_TRANSPORT_HEADERS = frozenset({
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
})

#: Every header name that can carry a caller credential to ANY provider — the
#: vocabulary the screen recognises, not the set any one destination accepts.
#: It must be a superset of every provider's `credential_headers`; that is what
#: makes a credential FOREIGN to a destination detectable at all. A header
#: absent from this vocabulary is invisible to the screen, so an addition to a
#: provider's set without an addition here would be a silent hole (the floor
#: tier fails the build on exactly that).
_CREDENTIAL_HEADERS = frozenset({
    "authorization",     # OpenAI-compatible bearer (xAI, Together), Anthropic
                         # OAuth, Google OAuth
    "x-api-key",         # Anthropic API key
    "x-goog-api-key",    # Google API key
})

#: Query parameters that carry a caller credential. The query string was the
#: same shared allowlist in another spelling: `params=dict(request.query_params)`
#: relayed every parameter to every destination, so a Google `?key=` sent to the
#: Grok route left this process addressed to api.x.ai.
_CREDENTIAL_QUERY_PARAMS = frozenset({
    "key", "api_key", "apikey", "access_token", "auth_token", "token",
})

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
#: Renamed from ``duplicate_credential_header`` (branch-local, never released).
#: The old name described the CHANNEL the old rule could see, and it became a
#: false statement the moment the rule spanned channels: a bearer header plus a
#: ``?key=`` is neither a duplicate nor two headers. A deny code that misnames
#: what happened is a "computer says no" with the wrong receipt attached.
DENY_MULTIPLE_CREDENTIALS   = "multiple_credentials"
DENY_FOREIGN_CREDENTIAL     = "foreign_credential"

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
    DENY_MULTIPLE_CREDENTIALS: (
        "The request carried more than one credential for this provider — "
        "counted across every channel a credential can arrive on, headers and "
        "query parameters alike — so the credential this proxy would forward is "
        "ambiguous.",
        "Send exactly one credential, by exactly one of the channels this "
        "provider accepts (see `credential_headers` and "
        "`credential_query_params`). Two credentials are two credentials, not "
        "two spellings of one, and this proxy will not guess which was meant.",
    ),
    DENY_FOREIGN_CREDENTIAL: (
        "The request carried a credential this provider does not use. It was "
        "NOT forwarded: sending it on would deliver one vendor's secret to a "
        "different vendor.",
        "Send only the credential this provider uses — see `credential_headers` "
        "and `credential_query_params` — and route the other one to the provider "
        "it belongs to.",
    ),
}

#: Deny codes about the caller's credentials rather than the caller's path. They
#: share one wire error name.
_CREDENTIAL_DENY_CODES = frozenset({
    DENY_MULTIPLE_CREDENTIALS, DENY_FOREIGN_CREDENTIAL,
})


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

    ``credential_headers`` / ``credential_query_params`` are the whole of the
    credential mapping: the ONLY secrets this destination may receive. They
    default to EMPTY, deliberately — a fifth provider added without a thought
    about credentials forwards none, so the caller gets a 401 from the vendor
    rather than the proxy quietly relaying somebody else's key. Fail-closed on a
    grant path.

    ``extra_headers`` carries provider-specific NON-credential headers (e.g.
    ``anthropic-version``). They are per-destination for the same reason: a
    header only one vendor defines has no business on a request to another.
    """
    name: str
    base: str
    path_re: re.Pattern
    allowed: tuple[str, ...]
    credential_headers: frozenset = frozenset()
    credential_query_params: frozenset = frozenset()
    extra_headers: frozenset = frozenset()

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

# The credential mapping, one row per destination. Each set names the
# credential(s) THAT VENDOR'S OWN API defines; anything else a caller sends is,
# by definition, meant for somebody else.
GROK = Provider(
    "grok", GROK_UPSTREAM, _OPENAI_PATH_RE, _OPENAI_ALLOWED,
    # xAI is OpenAI-compatible: `Authorization: Bearer <xai key>`, and nothing
    # else. It has no x-api-key surface at all.
    credential_headers=frozenset({"authorization"}),
)
TOGETHER = Provider(
    "together", TOGETHER_UPSTREAM, _OPENAI_PATH_RE, _OPENAI_ALLOWED,
    # Likewise OpenAI-compatible bearer only.
    credential_headers=frozenset({"authorization"}),
)
GEMINI = Provider(
    "gemini", GEMINI_UPSTREAM, _GEMINI_PATH_RE,
    ("models", "models/{model}", "models/{model}:{action}"),
    # Google accepts its API key as the `x-goog-api-key` header or the `key`
    # query parameter, and an OAuth bearer in `authorization`.
    credential_headers=frozenset({"x-goog-api-key", "authorization"}),
    credential_query_params=frozenset({"key"}),
)
ANTHROPIC = Provider(
    "anthropic", ANTHROPIC_UPSTREAM + "/v1", _ANTHROPIC_PATH_RE,
    ("messages", "models"),
    # Anthropic accepts EITHER an API key in `x-api-key` OR an OAuth bearer in
    # `authorization` (what the CLI sends on a subscription). Both are genuinely
    # Anthropic credentials, so both belong here — but only one may appear on a
    # single request; two are two credentials, and the screen refuses rather
    # than choosing.
    credential_headers=frozenset({"x-api-key", "authorization"}),
    extra_headers=frozenset({"anthropic-version", "anthropic-beta"}),
)

PROVIDERS: tuple[Provider, ...] = (GROK, TOGETHER, GEMINI, ANTHROPIC)

#: A provider may not accept a credential the screen cannot recognise: the
#: screen would then be unable to call that header foreign anywhere else, which
#: is the exact shape of the defect this mapping exists to close. Checked at
#: import so it can never be true at runtime, and again statically in the floor
#: tier so it cannot be true on a branch that never imports this module.
for _provider in PROVIDERS:
    _unknown = _provider.credential_headers - _CREDENTIAL_HEADERS
    if _unknown:
        raise RuntimeError(
            f"provider {_provider.name!r} accepts credential header(s) "
            f"{sorted(_unknown)} that _CREDENTIAL_HEADERS does not recognise; "
            f"they would be invisible to the foreign-credential screen"
        )
    _unknown_params = _provider.credential_query_params - _CREDENTIAL_QUERY_PARAMS
    if _unknown_params:
        raise RuntimeError(
            f"provider {_provider.name!r} accepts credential query param(s) "
            f"{sorted(_unknown_params)} that _CREDENTIAL_QUERY_PARAMS does not "
            f"recognise; they would be invisible to the foreign-credential screen"
        )
    if _provider.credential_headers & _SAFE_TRANSPORT_HEADERS:
        raise RuntimeError(
            f"provider {_provider.name!r} has a credential header that is also "
            f"forwarded to every destination by _SAFE_TRANSPORT_HEADERS"
        )
del _provider, _unknown, _unknown_params


# ---------------------------------------------------------------------------
# Credential channels — every way a secret can reach a destination
# ---------------------------------------------------------------------------
# WHAT EARNED THIS (2026-07-27, second vendor — Codex, gpt-5.5)
#
# The previous screen counted credential HEADERS. Its own stated lesson was that
# "a per-header rule cannot see a cross-header interaction" — and a rule that
# counts headers cannot see a header <-> QUERY-PARAMETER interaction either. On
# Gemini, which genuinely accepts `authorization`, `x-goog-api-key` AND `?key=`,
# a bearer plus a `?key=` passed the screen and BOTH left for Google; and
# `?key=FIRST&key=SECOND` passed and collapsed to the last value in the forward
# path, silently discarding a credential the caller sent.
#
# THE INVARIANT IS OVER THE SHAPE OF THE CREDENTIAL SET FOR A DESTINATION: how
# many credentials are addressed to it, whatever channel each arrives on. Not
# over any one channel's contents. So the channels are a TABLE, each row
# carrying the whole of that channel's definition, and the screen iterates the
# table rather than naming a channel.

@dataclass(frozen=True)
class CredentialChannel:
    """
    One way a credential can travel to a destination.

    ``read`` returns EVERY occurrence, in arrival order, including repeats. That
    is the load-bearing property: every duplicate-collapsing accessor
    (``headers[...]``, ``dict(query_params)``, ``query_params.keys()``) turns two
    credentials into one and hides the second from the count.
    """
    name: str
    #: Every name recognisable as a credential ON THIS CHANNEL — the vocabulary
    #: that makes "foreign" decidable, not what any one destination accepts.
    vocabulary: frozenset
    #: The ``Provider`` field naming what THIS destination accepts here.
    provider_field: str
    read: Callable[[Request], list[str]]
    #: How a name on this channel is written in an operator-facing message.
    label: Callable[[str], str]


def _header_names(request: Request) -> list[str]:
    """Every header name on the request, repeats included, from the RAW list."""
    return [raw_key.decode("latin-1").lower() for raw_key, _ in request.headers.raw]


def _query_param_names(request: Request) -> list[str]:
    """Every query parameter name, repeats included."""
    return [key.lower() for key, _ in request.query_params.multi_items()]


CREDENTIAL_CHANNELS: tuple[CredentialChannel, ...] = (
    CredentialChannel(
        "header", _CREDENTIAL_HEADERS, "credential_headers",
        _header_names, lambda name: name,
    ),
    CredentialChannel(
        "query", _CREDENTIAL_QUERY_PARAMS, "credential_query_params",
        _query_param_names, lambda name: f"?{name}",
    ),
)

#: A ``Provider`` field that declares a credential channel but that no channel
#: row reads is a credential the screen cannot count — the exact shape of the
#: defect above, one level up. Derived from the dataclass, so a fifth channel
#: field added to ``Provider`` next year raises HERE rather than forwarding a
#: second secret. Checked again statically in the floor tier, so it also holds
#: on a branch that never imports this module.
_DECLARED_CREDENTIAL_FIELDS = {
    field.name for field in dataclasses.fields(Provider)
    if field.name.startswith("credential_")
}
_CHANNELLED_CREDENTIAL_FIELDS = {c.provider_field for c in CREDENTIAL_CHANNELS}
if _DECLARED_CREDENTIAL_FIELDS != _CHANNELLED_CREDENTIAL_FIELDS:
    raise RuntimeError(
        "credential channel table is out of step with Provider: fields with no "
        f"channel {sorted(_DECLARED_CREDENTIAL_FIELDS - _CHANNELLED_CREDENTIAL_FIELDS)}, "
        f"channels with no field {sorted(_CHANNELLED_CREDENTIAL_FIELDS - _DECLARED_CREDENTIAL_FIELDS)}; "
        "a credential channel the screen does not read cannot be counted, and "
        "an uncounted credential is a second secret on the wire"
    )


# ---------------------------------------------------------------------------
# Forwarding gate
# ---------------------------------------------------------------------------

def _credential_presentations(request: Request) -> list[tuple[str, str]]:
    """
    Every credential occurrence on the request, as ``(channel, name)``.

    ONE ENTRY PER OCCURRENCE, not per distinct name: ``?key=A&key=B`` is two
    entries, and that is what makes it countable. Values never appear.
    """
    found: list[tuple[str, str]] = []
    for channel in CREDENTIAL_CHANNELS:
        for name in channel.read(request):
            if name in channel.vocabulary:
                found.append((channel.name, name))
    return found


_CHANNEL_BY_NAME = {channel.name: channel for channel in CREDENTIAL_CHANNELS}


def _foreign_credentials(request: Request, provider: Provider) -> list[str]:
    """
    Credentials on the request that ``provider`` does not use, on any channel.

    This is the cross-vendor disclosure: forwarding one of these hands a secret
    the caller issued for vendor A to vendor B, inside a request the caller
    authorised for something else entirely. Names only ever leave this function
    — never values.
    """
    foreign = set()
    for channel_name, name in _credential_presentations(request):
        channel = _CHANNEL_BY_NAME[channel_name]
        if name not in getattr(provider, channel.provider_field):
            foreign.add(channel.label(name))
    return sorted(foreign)


def _screen_credentials(request: Request, provider: Provider) -> Optional[str]:
    """
    Return a deny code, or None if the request carries exactly one credential
    this destination uses (or none at all).

    THE RULE: the credential forwarded to a provider is the one that provider
    uses, and only that one — where "one" is counted PER DESTINATION, over the
    union of every channel, never per header name and never per channel.

    Two refusable shapes:

      1. a credential this destination does not use, on any channel -> FOREIGN
      2. more than one credential addressed to this destination     -> MULTIPLE

    (1) is checked first because it is the disclosure; (2) is ambiguity. (2)
    subsumes every shape the previous per-header rule enumerated and the two it
    could not see:

        the same header twice                    (last-wins on the header)
        two different headers                    (both forwarded)
        a header AND a query parameter           <- invisible to a header rule
        the same query parameter twice           <- invisible to a header rule

    RULING ON THE LAST TWO: REFUSE, exactly as for the header cases, and for the
    same reason. Silently taking the last value (what the forward path did) or
    the first would trade an integrity bug for an honesty bug: the caller keeps
    a credential in their config that they believe reaches the provider and
    which this proxy discards without a word. A refusal is legible, receipted,
    and tells them what would clear it.

    WHAT THIS DELIBERATELY DOES NOT DO: it does not refuse a destination for
    accepting more than one credential FORM. Gemini accepts three, and any ONE
    of them, by any channel, still forwards — see the control rows in
    ``proxy/tests/test_passthrough_credential_wire.py``. The defect is more than
    one AT ONCE.
    """
    if _foreign_credentials(request, provider):
        return DENY_FOREIGN_CREDENTIAL

    if len(_credential_presentations(request)) > 1:
        return DENY_MULTIPLE_CREDENTIALS
    return None


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

    # ``.rstrip("/")`` is redundant against ``Provider.base_path`` (which already
    # strips) and is written here anyway: the containment test below appends the
    # separator itself, so a base that ended in "/" would compare against "//"
    # and the prefix proof would silently stop proving anything. Stated at the
    # use site it is local, and it is the shape
    # ``tests/test_url_composition_floor.py`` recognises as normalised.
    base_path = provider.base_path.rstrip("/")
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
    deny = _screen_credentials(request, provider)
    if deny:
        return None, deny

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
    Write an attributable record of a REFUSAL to the shared audit rail.

    Returns ``(receipt_id, receipt_status)``.

    ``receipt_status`` is deliberately ``"enqueued"``, not ``"recorded"``.
    ``AuditWriter`` is a fire-and-forget queue: ``write()`` returns as soon as the
    record is queued, drops silently when the queue is full, and its background
    ``_writer_loop`` swallows every exception raised while serialising or
    appending. So this function can honestly report that a record was HANDED to
    the rail; it cannot report that the record LANDED. Saying "recorded" would be
    the kind of claim this codebase exists to refuse.

    That gap is a property of the rail, shared with every other consumer
    (including the detection records ``_detect_and_audit`` writes) — see
    ``proxy/tests/test_passthrough_receipts.py::test_disclosed_rail_gap_*``.

    Never raises: a receipt failure must not turn a deny into an allow, and must
    not turn a 400 into a 500. It is never silent either — an unavailable rail is
    logged at ERROR and reported to the caller.
    """
    receipt_id = str(uuid.uuid4())
    audit = getattr(request.app.state, "audit_writer", None)

    if audit is None:
        logger.error(
            "passthrough refusal NOT RECEIPTED (no audit writer): "
            "provider=%s deny_code=%s receipt_id=%s",
            provider.name, deny_code, receipt_id,
        )
        return receipt_id, "unavailable"

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
        # Header/query KEY NAMES only — never values. Read through the same
        # multiplicity-preserving accessors the screen uses, so the receipt
        # cannot describe a request the screen did not see.
        "request_header_names": sorted(set(_header_names(request))),
        "query_param_names": sorted(set(_query_param_names(request))),
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
        return receipt_id, "unavailable"

    logger.warning(
        "passthrough refused: provider=%s deny_code=%s receipt_id=%s",
        provider.name, deny_code, receipt_id,
    )
    return receipt_id, "enqueued"


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
            if deny_code in _CREDENTIAL_DENY_CODES
            else "invalid_path"
        ),
        "deny_code": deny_code,
        "reason": reason,
        "remedy": remedy,
        "receipt_id": receipt_id,
        "receipt_status": receipt_status,
    }
    if deny_code in _CREDENTIAL_DENY_CODES:
        # Every NO carries a path to YES: name the credential(s) this
        # destination actually uses. Header NAMES are not secrets; the values
        # the caller sent are never echoed.
        body["credential_headers"] = sorted(provider.credential_headers)
        body["credential_query_params"] = sorted(provider.credential_query_params)
    else:
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


def _json_object(body: bytes) -> Optional[dict[str, Any]]:
    try:
        data = json.loads(body)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _extract_openai_usage(body: bytes) -> Optional[dict[str, Any]]:
    data = _json_object(body)
    usage = data.get("usage") if data else None
    return usage if isinstance(usage, dict) else None


def _extract_gemini_usage(body: bytes) -> Optional[dict[str, Any]]:
    data = _json_object(body)
    usage = data.get("usageMetadata") if data else None
    return usage if isinstance(usage, dict) else None


def _extract_anthropic_usage(body: bytes) -> Optional[dict[str, Any]]:
    data = _json_object(body)
    usage = data.get("usage") if data else None
    return usage if isinstance(usage, dict) else None


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


def _is_zero_count(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    return math.isfinite(v) and v == 0


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
    output_tokens: Any = None,
) -> str:
    """
    Run detection and write audit record. Returns risk_level string.
    Never raises -- returns 'ERROR' on any failure.
    """
    engine = getattr(request.app.state, "engine", None)
    audit = getattr(request.app.state, "audit_writer", None)

    if engine is None:
        return "UNKNOWN"

    if response_text == "" and output_tokens is None:
        return "UNKNOWN"

    try:
        metadata = {}
        if output_tokens is not None:
            metadata["output_tokens"] = output_tokens
        result = await engine.verify(prompt, response_text, model_id, **metadata)
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
                "evidence_depth_limited": getattr(result, "evidence_depth_limited", True),
                "detection_method": getattr(result, "detection_method", None),
                "profile_model_id": getattr(result, "profile_model_id", None),
                "gate_reason": getattr(result, "gate_reason", None),
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

    NOTE — A SIBLING FOUND AND DELIBERATELY NOT FIXED HERE (2026-07-27, round 3).
    ``upstream_headers.items()`` is the same duplicate-collapsing accessor the
    request side carried: httpx folds two ``set-cookie`` lines into
    ``set-cookie: a=1, b=2``, which RFC 6265 s3 forbids. Measured, httpx 0.28.1:
        Headers([("set-cookie","a=1"),("set-cookie","b=2")]).items()
            -> [("set-cookie", "a=1, b=2")]
        .multi_items()
            -> [("set-cookie","a=1"), ("set-cookie","b=2")]
    It is on the RESPONSE path, carries no credential, and closing it changes the
    relay contract of all four endpoints (``Response(headers=...)`` takes a
    Mapping, so the pairs would have to be written onto ``raw_headers``) and reds
    eight PRE-EXISTING tests whose fixture hands this function a plain ``dict``
    — the tier the mutation counterfactual is anchored on. Recorded in the
    ledger under ``findings_recorded_not_fixed`` rather than folded into a
    credential fix, so the scope of the change stays reviewable.
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


def _forwardable_headers(request: Request, provider: Provider) -> list[tuple[str, str]]:
    """
    The headers that may leave, for THIS destination.

    Derived per destination, never from one shared allowlist: the shared list is
    what delivered an Anthropic-style ``x-api-key`` to xAI. A credential that is
    not this provider's is not here, and the gate has already refused the
    request that carried one — two independent controls, so a weakening of
    either alone is not a disclosure.

    A LIST, from the RAW header list, not a dict: a dict comprehension over
    ``headers.items()`` keeps the LAST of any repeated name, which is the
    mechanism that made a duplicate credential silently change which key this
    proxy authenticated with. The gate refuses a repeated CREDENTIAL, so nothing
    here depends on that; the collapse is removed anyway, because a forward path
    that quietly rewrites the caller's request is the defect whatever field it
    drops.
    """
    allowed = (
        _SAFE_TRANSPORT_HEADERS
        | provider.credential_headers
        | provider.extra_headers
    )
    return [
        (raw_key.decode("latin-1"), raw_value.decode("latin-1"))
        for raw_key, raw_value in request.headers.raw
        if raw_key.decode("latin-1").lower() in allowed
    ]


def _forwardable_params(request: Request, provider: Provider) -> list[tuple[str, str]]:
    """
    The query parameters that may leave, for THIS destination.

    A credential-bearing parameter (``key``, ``access_token``, …) is forwarded
    only to a provider that uses it. Everything else passes: providers carry
    ordinary parameters and dropping them would break real calls.

    ``multi_items()``, not ``items()``, for the reason above: ``dict(...)`` over
    the query string relayed ``?alt=sse&alt=json`` as ``alt=json``, and relayed
    ``?key=FIRST&key=SECOND`` as the SECOND credential alone. Repeats are the
    caller's request; this proxy does not get to pick one.
    """
    return [
        (key, value) for key, value in request.query_params.multi_items()
        if key.lower() not in _CREDENTIAL_QUERY_PARAMS
        or key.lower() in provider.credential_query_params
    ]


async def _forward(
    request: Request,
    upstream_url: str,
    provider: Provider,
) -> tuple[bytes, int, dict]:
    """
    Forward the request to upstream_url. Returns (body, status_code, headers).
    Raises on network error.

    Security:
      - only this destination's headers are forwarded (see _forwardable_headers)
      - only this destination's credential parameters are forwarded (see
        _forwardable_params)
      - follow_redirects is False, EXPLICITLY: a provider 3xx is relayed to the
        caller, never dereferenced by us. Relying on the library default would
        make an SSRF control a property of a dependency's release notes.
      - the client comes from ``arkheia_common.egress.egress_async_client``,
        which pins ``trust_env=False``: an ambient HTTP(S)_PROXY / ALL_PROXY in
        the environment cannot interpose on a call carrying the caller's
        provider credential. Both controls are named here because both are
        passed at the call site — neither is inherited from a default.
      - connection-specific response headers are stripped (see
        _filter_response_headers)
    """
    body = await request.body()

    forward_headers = _forwardable_headers(request, provider)

    async with egress_async_client(timeout=60.0, follow_redirects=False) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=forward_headers,
            params=_forwardable_params(request, provider),
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
        response_body, status_code, response_headers = await _forward(request, upstream_url, GROK)
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
        usage = _extract_openai_usage(response_body)
        output_tokens = _output_tokens_from_usage(usage)
        if response_text is not None or _is_zero_count(output_tokens):
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)
            risk_level = await _detect_and_audit(
                request,
                prompt,
                response_text or "",
                model_id,
                output_tokens=output_tokens,
            )
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
        response_body, status_code, response_headers = await _forward(request, upstream_url, TOGETHER)
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
        usage = _extract_openai_usage(response_body)
        output_tokens = _output_tokens_from_usage(usage)
        if response_text is not None or _is_zero_count(output_tokens):
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)  # same field: "model"
            risk_level = await _detect_and_audit(
                request,
                prompt,
                response_text or "",
                model_id,
                output_tokens=output_tokens,
            )
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
        response_body, status_code, response_headers = await _forward(request, upstream_url, GEMINI)
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
        usage = _extract_gemini_usage(response_body)
        output_tokens = _output_tokens_from_usage(usage)
        if response_text is not None or _is_zero_count(output_tokens):
            prompt = _extract_gemini_prompt(request_body)
            model_id = _extract_gemini_model(path)
            risk_level = await _detect_and_audit(
                request,
                prompt,
                response_text or "",
                model_id,
                output_tokens=output_tokens,
            )
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
        response_body, status_code, response_headers = await _forward(request, upstream_url, ANTHROPIC)
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
        usage = _extract_anthropic_usage(response_body)
        output_tokens = _output_tokens_from_usage(usage)
        if response_text is not None or _is_zero_count(output_tokens):
            prompt = _extract_openai_prompt(request_body)  # Anthropic uses same messages[] format
            model_id = _extract_anthropic_model(response_body)
            risk_level = await _detect_and_audit(
                request,
                prompt,
                response_text or "",
                model_id,
                output_tokens=output_tokens,
            )
            logger.info("anthropic_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )
