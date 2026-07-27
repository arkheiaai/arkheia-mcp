"""
Adversarial suite for the passthrough forwarding gate.

WHAT IS UNDER ATTACK
--------------------
``proxy/endpoints/passthrough.py`` forwards caller traffic to provider endpoints
while relaying the caller's provider credential. An SSRF here means an attacker
uses this server, from this server's network position, to reach somewhere they
cannot reach themselves.

Every test below drives the REAL route through the raw ASGI entry point and
asserts on the ``httpx.Request`` that would have gone on the wire — never on a
mock's call arguments, which cannot see URL normalisation. See
``_passthrough_harness`` for why both of those matter.

THE DEFECT THAT MOTIVATED THIS SUITE (pre-fix, measured on the wire)
--------------------------------------------------------------------
``_OPENAI_PATH_RE`` had an ``audio/.*`` arm. ``.`` matches ``/``, so
``audio/../../admin/keys`` satisfied the allowlist, and httpx then removed the
dot segments::

    POST /proxy/grok/v1/audio/../../admin/keys
      -> https://api.x.ai/admin/keys        (200, body returned to the caller)
    POST /proxy/grok/v1/admin/keys
      -> 400 invalid_path

A prefix defeated the control entirely: every path on the provider host was
reachable, with the caller's Authorization header attached. Reproduced against a
real uvicorn socket in ``test_passthrough_wire.py``.

Each test names the pre-fix state it discriminates, per DONE.md v1.15.
"""
from __future__ import annotations

import gzip
import json
from dataclasses import dataclass
from typing import Optional

import httpx
import pytest

from proxy.endpoints import passthrough as pt
from proxy.tests._passthrough_harness import (
    OPENAI_OK,
    asgi_request,
    capture_upstream,
    json_response,
    make_app,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# The corpus. One place, so a new hostile shape is one row.
# ---------------------------------------------------------------------------

#: (route prefix, provider, expected upstream origin)
ROUTES = {
    "grok":      ("/proxy/grok/v1/",     pt.GROK,      "https://api.x.ai"),
    "together":  ("/proxy/together/v1/", pt.TOGETHER,  "https://api.together.xyz"),
    "gemini":    ("/v1beta/",            pt.GEMINI,    "https://generativelanguage.googleapis.com"),
    "anthropic": ("/v1/",                pt.ANTHROPIC, "https://api.anthropic.com"),
}

#: Hostile OpenAI-shaped paths. ``expect_deny`` is the exact deny code required.
HOSTILE_OPENAI = [
    ("audio/../../admin/keys",            pt.DENY_PATH_TRAVERSAL),
    ("audio/../../../../etc/passwd",      pt.DENY_PATH_TRAVERSAL),
    ("audio/../../..",                    pt.DENY_PATH_TRAVERSAL),
    ("audio/..//evil.com/x",              pt.DENY_PATH_TRAVERSAL),
    ("audio/%2e%2e/admin",                pt.DENY_PATH_TRAVERSAL),
    ("audio/%2E%2E/admin",                pt.DENY_PATH_TRAVERSAL),
    ("audio/x%2fy",                       pt.DENY_PATH_TRAVERSAL),
    ("audio/\\..\\..\\admin",             pt.DENY_PATH_TRAVERSAL),
    ("audio/.",                           pt.DENY_PATH_TRAVERSAL),
    ("audio/whisper",                     pt.DENY_PATH_NOT_ALLOWLISTED),
    ("audio/@evil.com/x",                 pt.DENY_PATH_NOT_ALLOWLISTED),
    ("audio/x#@evil.com",                 pt.DENY_PATH_NOT_ALLOWLISTED),
    ("audio/x?a=b",                       pt.DENY_PATH_NOT_ALLOWLISTED),
    ("admin/users",                       pt.DENY_PATH_NOT_ALLOWLISTED),
    ("internal/config",                   pt.DENY_PATH_NOT_ALLOWLISTED),
    ("",                                  pt.DENY_PATH_NOT_ALLOWLISTED),
    ("chat/completions\x00",              pt.DENY_PATH_ILLEGAL_CHARACTER),
]

#: The control rows. A differential table whose every row denies cannot
#: discriminate (DONE.md v1.15 clause 5) — these must be FORWARDED, and to an
#: exactly named URL.
ALLOWED_OPENAI = [
    ("chat/completions",    "/v1/chat/completions"),
    ("completions",         "/v1/completions"),
    ("embeddings",          "/v1/embeddings"),
    ("models",              "/v1/models"),
    ("images/generations",  "/v1/images/generations"),
    ("audio/speech",        "/v1/audio/speech"),
    ("audio/transcriptions", "/v1/audio/transcriptions"),
    ("audio/translations",  "/v1/audio/translations"),
    ("moderations",         "/v1/moderations"),
]


# ---------------------------------------------------------------------------
# ADV-1 — the headline defect: a prefix must not buy the whole host
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("route_key", ["grok", "together"])
@pytest.mark.parametrize("hostile_path", ["audio/../../admin/keys",
                                          "audio/../../../../etc/passwd"])
async def test_traversal_prefix_reaches_no_upstream(route_key, hostile_path):
    """
    Pre-fix state discriminated: ``audio/.*`` in the allowlist, which forwarded
    ``https://api.x.ai/admin/keys``. A no-op fix (regex unchanged) fails here.
    """
    prefix, provider, origin = ROUTES[route_key]
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(
            app, "POST", prefix + hostile_path,
            headers=[("authorization", "Bearer CALLER-SECRET")],
        )

    assert resp.status == 400
    assert log.count == 0, (
        f"a refused request produced upstream traffic: {log.urls()!r}"
    )
    body = resp.json()
    assert body["error"] == "invalid_path"
    assert body["deny_code"] == pt.DENY_PATH_TRAVERSAL


async def test_traversal_and_direct_path_agree():
    """
    The gate must not be defeatable by spelling. ``admin/keys`` is refused; so
    must every spelling that resolves to it.
    """
    app = make_app()
    results = {}
    for spelling in ("admin/keys", "audio/../../admin/keys", "audio/%2e%2e/%2e%2e/admin/keys"):
        with capture_upstream() as log:
            resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + spelling)
        results[spelling] = (resp.status, log.count)
    assert results == {
        "admin/keys": (400, 0),
        "audio/../../admin/keys": (400, 0),
        "audio/%2e%2e/%2e%2e/admin/keys": (400, 0),
    }


# ---------------------------------------------------------------------------
# ADV-2 — the whole hostile corpus, exact deny codes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("route_key", ["grok", "together"])
@pytest.mark.parametrize("hostile_path,expected_code", HOSTILE_OPENAI)
async def test_hostile_openai_paths_refused_with_exact_code(
    route_key, hostile_path, expected_code
):
    prefix, provider, origin = ROUTES[route_key]
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", prefix + hostile_path)

    assert resp.status == 400
    assert log.count == 0
    assert resp.json()["deny_code"] == expected_code


@pytest.mark.parametrize("allowed_path,expected_upstream_path", ALLOWED_OPENAI)
async def test_allowlisted_openai_paths_forward_to_exact_url(
    allowed_path, expected_upstream_path
):
    """The passing control rows: these must reach an exactly named URL."""
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/" + allowed_path)

    assert resp.status == 200
    assert log.count == 1
    assert str(log.last.url) == "https://api.x.ai" + expected_upstream_path


@pytest.mark.parametrize("hostile_path,expected_code", [
    ("models/..",            pt.DENY_PATH_TRAVERSAL),
    ("models/.",             pt.DENY_PATH_TRAVERSAL),
    ("models/../..",         pt.DENY_PATH_TRAVERSAL),
    ("models\x00",           pt.DENY_PATH_ILLEGAL_CHARACTER),
    ("admin/config",         pt.DENY_PATH_NOT_ALLOWLISTED),
    ("",                     pt.DENY_PATH_NOT_ALLOWLISTED),
])
async def test_hostile_gemini_paths_refused(hostile_path, expected_code):
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", "/v1beta/" + hostile_path)
    assert (resp.status, log.count) == (400, 0)
    assert resp.json()["deny_code"] == expected_code


async def test_allowed_gemini_path_forwards_to_exact_url():
    app = make_app()
    with capture_upstream(json_response({"candidates": []})) as log:
        resp = await asgi_request(
            app, "POST", "/v1beta/models/gemini-2.5-flash:generateContent",
            query_string=b"key=AIzaSyTESTTESTTESTTESTTESTTESTTEST",
        )
    assert resp.status == 200
    assert str(log.last.url) == (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.5-flash:generateContent?key=AIzaSyTESTTESTTESTTESTTESTTESTTEST"
    )


@pytest.mark.parametrize("hostile_path,expected_code", [
    ("messages\x00",          pt.DENY_PATH_ILLEGAL_CHARACTER),
    ("messages/count_tokens", pt.DENY_PATH_NOT_ALLOWLISTED),
    ("../admin",              pt.DENY_PATH_TRAVERSAL),
    ("",                      pt.DENY_PATH_NOT_ALLOWLISTED),
])
async def test_hostile_anthropic_paths_refused(hostile_path, expected_code):
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", "/v1/" + hostile_path)
    assert (resp.status, log.count) == (400, 0)
    assert resp.json()["deny_code"] == expected_code


@pytest.mark.parametrize("allowed_path,expected_url", [
    ("messages", "https://api.anthropic.com/v1/messages"),
    ("models",   "https://api.anthropic.com/v1/models"),
])
async def test_allowed_anthropic_paths_forward_to_exact_url(allowed_path, expected_url):
    app = make_app()
    with capture_upstream(json_response({"content": []})) as log:
        resp = await asgi_request(app, "POST", "/v1/" + allowed_path)
    assert resp.status == 200
    assert str(log.last.url) == expected_url


# ---------------------------------------------------------------------------
# ADV-3 — scheme and host can never be caller-derived
# ---------------------------------------------------------------------------

SCHEME_ABUSE = [
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "ftp://internal.corp/secrets",
    "http://169.254.169.254/latest/meta-data/",
    "//169.254.169.254/latest/meta-data/",
    "https://evil.com/x",
    "\\\\evil.com\\share",
]


@pytest.mark.parametrize("route_key", list(ROUTES))
@pytest.mark.parametrize("payload", SCHEME_ABUSE)
async def test_scheme_and_host_abuse_never_leaves_the_provider(route_key, payload):
    """
    file:// / gopher:// / ftp:// and absolute-URL injection: whatever the caller
    puts in the path, the request either does not happen or goes to the
    provider's own https origin. The scheme is never read from the request.
    """
    prefix, provider, origin = ROUTES[route_key]
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", prefix + payload)

    for request in log.requests:
        assert request.url.scheme == "https"
        assert str(request.url).startswith(origin + "/"), str(request.url)
    if log.count == 0:
        assert resp.status == 400


@pytest.mark.parametrize("route_key", list(ROUTES))
async def test_host_header_cannot_redirect_the_upstream(route_key):
    """
    DNS-rebinding shape: the destination is never re-derived from anything the
    caller sends. A Host header naming another origin changes nothing, and the
    Host header is not forwarded.
    """
    prefix, provider, origin = ROUTES[route_key]
    legit = {"grok": "models", "together": "models",
             "gemini": "models", "anthropic": "models"}[route_key]
    app = make_app()
    with capture_upstream() as log:
        await asgi_request(
            app, "POST", prefix + legit,
            headers=[("host", "169.254.169.254"), ("x-forwarded-host", "evil.com")],
        )
    assert log.count == 1
    assert log.last.url.host == provider.expected_host
    assert log.last.headers["host"] == provider.expected_host


async def test_screen_path_is_anchored_against_trailing_newline():
    """
    ``\\A``/``\\Z``, never ``^``/``$``: in Python ``$`` also matches immediately
    before a trailing newline, so ``^chat/completions$`` accepts
    "chat/completions\\n".

    HONEST REACHABILITY NOTE. End-to-end this arm is currently unreachable for
    ``\\n`` specifically: Starlette's own route regex is ``^…$`` and strips the
    trailing newline before the handler runs, so the handler receives the clean
    path (measured: the request forwards to https://api.x.ai/v1/chat/completions).
    An interior CR/LF makes the route not match at all (404). It IS reachable
    for other control characters — ``chat/completions\\x00`` reaches the handler
    and is refused, which the end-to-end corpus above covers.

    So this is defence in depth against a route-matching change, asserted at the
    boundary that actually owns the decision rather than through a transport
    that masks it.
    """
    assert pt._screen_path(pt.GROK, "chat/completions") is None            # control
    assert pt._screen_path(pt.GROK, "chat/completions\n") == pt.DENY_PATH_ILLEGAL_CHARACTER
    assert pt._screen_path(pt.GROK, "chat/completions\r") == pt.DENY_PATH_ILLEGAL_CHARACTER
    assert pt._screen_path(pt.GROK, "models\n") == pt.DENY_PATH_ILLEGAL_CHARACTER
    # And the regexes themselves are \Z-anchored, so a future caller using
    # .match() instead of .fullmatch() is still safe.
    for regex in (pt._OPENAI_PATH_RE, pt._GEMINI_PATH_RE, pt._ANTHROPIC_PATH_RE):
        assert regex.match("models\n") is None
    assert pt._OPENAI_PATH_RE.match("models") is not None                  # control


async def test_resolve_upstream_is_the_verifier_not_the_artifact():
    """
    ``_resolve_upstream`` takes every comparison value from the provider table,
    never from the candidate URL.

    ``%2e%2e`` is the row worth reading. httpx DECODES percent escapes into
    ``URL.path`` without removing dot segments, so "%2e%2e/%2e%2e" arrives as
    "/v1/../.." — which satisfies a naive ``startswith("/v1/")`` prefix test and
    is then normalised by the ORIGIN into an escape. Writing this test is how
    that hole in the post-condition was found; the first draft of
    ``_resolve_upstream`` had it.
    """
    for hostile in ("..//evil.com/x", "%2e%2e/%2e%2e", "%2e%2e/%2e%2e/admin",
                    "x/%2e%2e/%2e%2e/%2e%2e/admin", "%5c..%5cadmin"):
        url, deny = pt._resolve_upstream(pt.GROK, hostile)
        assert url is None, hostile
        assert deny == pt.DENY_UPSTREAM_TARGET_ESCAPED, hostile

    # A same-host oddity is NOT an escape and must not be reported as one — the
    # allowlist refuses it, the post-condition has nothing to say about it.
    url, deny = pt._resolve_upstream(pt.GROK, "@evil.com/x")
    assert url == "https://api.x.ai/v1/@evil.com/x"
    assert httpx.URL(url).host == "api.x.ai"
    assert deny is None

    # Control row: a legitimate path resolves, and to the exact string.
    url, deny = pt._resolve_upstream(pt.GROK, "chat/completions")
    assert deny is None
    assert url == "https://api.x.ai/v1/chat/completions"


@dataclass(frozen=True)
class SkewedProvider:
    """
    A provider whose verifier-owned expectations disagree with its base URL.

    ``_resolve_upstream`` only reads these five attributes, so this drives the
    REAL function with the real comparisons; only the constants it verifies
    against are varied.

    Why this exists. The scheme/host/port/prefix arms of the post-condition
    cannot be tripped through the live route today: the base is a constant
    ``https://host[/path]`` literal and string concatenation onto it cannot move
    the authority. That is the *good* news on this flow — there is no
    host-escape primitive. It also means a mutation that deletes one of those
    arms is unobservable through the route, so the arms would be untested
    decoration unless they are exercised here, at the boundary that owns them.
    They guard the refactor that makes a base URL configurable, which is exactly
    when nobody re-reads this function.
    """
    base: str
    expected_scheme: str
    expected_host: str
    expected_port: Optional[int]
    base_path: str


@pytest.mark.parametrize("skew,expect_deny", [
    # host mismatch
    (dict(base="https://api.x.ai/v1", expected_scheme="https",
          expected_host="api.together.xyz", expected_port=None,
          base_path="/v1"), True),
    # scheme mismatch
    (dict(base="https://api.x.ai/v1", expected_scheme="http",
          expected_host="api.x.ai", expected_port=None,
          base_path="/v1"), True),
    # port mismatch
    (dict(base="https://api.x.ai/v1", expected_scheme="https",
          expected_host="api.x.ai", expected_port=8443,
          base_path="/v1"), True),
    # prefix confusion: /v1beta starts with /v1 but is a different surface
    (dict(base="https://api.x.ai/v1beta", expected_scheme="https",
          expected_host="api.x.ai", expected_port=None,
          base_path="/v1"), True),
    # control row: everything agrees, so the table discriminates
    (dict(base="https://api.x.ai/v1", expected_scheme="https",
          expected_host="api.x.ai", expected_port=None,
          base_path="/v1"), False),
])
async def test_each_post_condition_arm_refuses_on_its_own(skew, expect_deny):
    provider = SkewedProvider(**skew)
    url, deny = pt._resolve_upstream(provider, "models")
    if expect_deny:
        assert url is None, skew
        assert deny == pt.DENY_UPSTREAM_TARGET_ESCAPED, skew
    else:
        assert deny is None
        assert url == "https://api.x.ai/v1/models"


async def test_post_condition_refuses_a_query_or_fragment_smuggled_in_the_path():
    """
    Reachable only with a weakened allowlist, which is the case this arm is for:
    a query string in the PATH is not a provider path, and the caller's real
    query is forwarded separately and explicitly.
    """
    for smuggled in ("chat/completions?x=1", "chat/completions#frag"):
        url, deny = pt._resolve_upstream(pt.GROK, smuggled)
        assert url is None, smuggled
        assert deny == pt.DENY_UPSTREAM_TARGET_ESCAPED, smuggled
    url, deny = pt._resolve_upstream(pt.GROK, "chat/completions")     # control
    assert (url, deny) == ("https://api.x.ai/v1/chat/completions", None)


@pytest.mark.parametrize("route_key,foreign_path", [
    ("gemini",    "chat/completions"),
    ("anthropic", "chat/completions"),
    ("grok",      "models/gemini-2.5-flash:generateContent"),
    ("together",  "messages"),
])
async def test_a_route_accepts_only_its_own_providers_allowlist(route_key, foreign_path):
    """
    Each route must screen against ITS provider's allowlist. One shared regex
    read by every route is a copy-paste away, and it silently widens three
    surfaces at once.
    """
    prefix, _provider, _origin = ROUTES[route_key]
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(app, "POST", prefix + foreign_path)
    assert (resp.status, log.count) == (400, 0)
    assert resp.json()["deny_code"] == pt.DENY_PATH_NOT_ALLOWLISTED


async def test_post_condition_holds_when_the_allowlist_is_weakened():
    """
    Defence in depth, proved rather than asserted. Restore the exact pre-fix
    ``audio/.*`` arm and drive the real route: the request must STILL be refused
    — by the resolved-URL post-condition, with its own deny code — and still
    produce zero upstream traffic.

    This is the property that makes a future regex regression non-exploitable.
    """
    import re
    permissive = re.compile(
        r"\A(chat/completions|completions|embeddings|models|images/generations"
        r"|audio/.*|moderations)\Z"
    )
    weakened = pt.Provider("grok", pt.GROK_UPSTREAM, permissive, pt.GROK.allowed)

    # The weakened regex really does admit the attack — otherwise this test
    # would pass for the wrong reason.
    assert permissive.fullmatch("audio/../../admin/keys")

    url, deny = pt._resolve_upstream(weakened, "audio/../../admin/keys")
    assert url is None
    assert deny == pt.DENY_UPSTREAM_TARGET_ESCAPED

    app = make_app()
    original = pt.GROK
    try:
        pt.GROK = weakened
        with capture_upstream() as log:
            resp = await asgi_request(app, "POST", "/proxy/grok/v1/audio/x/y/z")
    finally:
        pt.GROK = original

    # audio/x/y/z stays inside /v1 so it is allowed even weakened; the escape is
    # what must be refused. Assert the escaping one through the live route:
    assert log.count == 1
    assert str(log.last.url) == "https://api.x.ai/v1/audio/x/y/z"

    try:
        pt.GROK = weakened
        with capture_upstream() as log2:
            resp2 = await asgi_request(app, "POST", "/proxy/grok/v1/audio/x/%2e%2e/%2e%2e/%2e%2e/admin")
    finally:
        pt.GROK = original
    assert resp2.status == 400
    assert log2.count == 0


# ---------------------------------------------------------------------------
# ADV-4 — redirects
# ---------------------------------------------------------------------------

async def test_redirect_to_link_local_is_not_followed():
    """
    Pre-fix state discriminated: none — this held. It is pinned because it held
    only by an httpx DEFAULT, and an SSRF control must not be a property of a
    dependency's release notes.
    """
    def redirector(_request):
        return httpx.Response(
            302, headers={"location": "http://169.254.169.254/latest/meta-data/iam/"}
        )

    app = make_app()
    with capture_upstream(redirector) as log:
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")

    assert log.count == 1, f"the redirect was dereferenced: {log.urls()!r}"
    assert str(log.last.url) == "https://api.x.ai/v1/chat/completions"
    assert resp.status == 302
    assert resp.header("location") == "http://169.254.169.254/latest/meta-data/iam/"


async def test_follow_redirects_is_disabled_explicitly():
    """The policy is stated at the call site, not inherited."""
    app = make_app()
    with capture_upstream() as log:
        await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")
    assert log.client_kwargs == [{"timeout": 60.0, "follow_redirects": False}]


# ---------------------------------------------------------------------------
# ADV-5 — response framing and hop-by-hop headers
# ---------------------------------------------------------------------------

async def test_gzip_upstream_does_not_desync_content_length():
    """
    Pre-fix state discriminated: ``content-encoding`` was stripped while the
    upstream ``content-length`` (describing the COMPRESSED body) was relayed
    alongside the DECOMPRESSED body. Measured pre-fix: content-length 80 over a
    3043-byte body; against real uvicorn the caller received a zero-byte body.

    This fired on ordinary traffic — httpx advertises ``accept-encoding: gzip``
    on every upstream request.
    """
    payload = json.dumps({"choices": [{"message": {"content": "X" * 3000}}]}).encode()
    compressed = gzip.compress(payload)
    assert len(compressed) < len(payload)

    def gzipper(_request):
        return httpx.Response(
            200, content=compressed,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
                "content-type": "application/json",
            },
        )

    app = make_app()
    with capture_upstream(gzipper):
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")

    assert resp.status == 200
    assert resp.body == payload
    assert resp.header("content-length") == str(len(resp.body))
    assert "content-encoding" not in resp.header_names()


async def test_hop_by_hop_response_headers_are_stripped():
    def hopper(_request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Four"}}]},
            headers={
                "keep-alive": "timeout=5",
                "proxy-authenticate": "Basic realm=internal-corp",
                "proxy-authorization": "Basic aW50ZXJuYWw6cHc=",
                "upgrade": "h2c",
                "te": "trailers",
                "trailer": "X-Trailing",
                "x-request-id": "req-123",
            },
        )

    app = make_app()
    with capture_upstream(hopper):
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")

    names = resp.header_names()
    for banned in ("keep-alive", "proxy-authenticate", "proxy-authorization",
                   "upgrade", "te", "trailer", "connection", "transfer-encoding"):
        assert banned not in names, f"{banned} was relayed to the caller"
    # Positive control: an ordinary end-to-end header still passes through, so
    # the assertion above is not passing because everything was dropped.
    assert resp.header("x-request-id") == "req-123"


async def test_connection_nominated_headers_are_stripped():
    """
    RFC 9110 s7.6.1: ``Connection`` may nominate further headers as
    connection-specific. A proxy that ignores the nomination relays exactly the
    headers the origin asked it not to.
    """
    def nominator(_request):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "Four"}}]},
            headers={
                "connection": "X-Internal-Backend, X-Pool-Id",
                "x-internal-backend": "10.0.0.7:8443",
                "x-pool-id": "pool-eu-1",
                "x-request-id": "req-456",
            },
        )

    app = make_app()
    with capture_upstream(nominator):
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")

    names = resp.header_names()
    assert "x-internal-backend" not in names
    assert "x-pool-id" not in names
    assert "connection" not in names
    assert resp.header("x-request-id") == "req-456"


# ---------------------------------------------------------------------------
# ADV-6 — credentials
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("credential_header", ["authorization", "x-api-key"])
async def test_duplicate_credential_header_is_refused(credential_header):
    """
    Pre-fix state discriminated: the forward-header dict comprehension kept the
    LAST occurrence, so ``Authorization: LEGIT`` + ``Authorization: ATTACKER``
    silently authenticated as ATTACKER. Measured pre-fix on the outgoing
    request: ``authorization: Bearer ATTACKER``.
    """
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(
            app, "POST", "/proxy/grok/v1/chat/completions",
            headers=[(credential_header, "LEGIT"), (credential_header, "ATTACKER")],
        )

    assert resp.status == 400
    assert log.count == 0
    body = resp.json()
    assert body["error"] == "invalid_credential_header"
    assert body["deny_code"] == pt.DENY_DUPLICATE_CREDENTIAL


async def test_single_credential_header_is_forwarded_verbatim():
    """Control row for the test above."""
    app = make_app()
    with capture_upstream() as log:
        await asgi_request(
            app, "POST", "/proxy/grok/v1/chat/completions",
            headers=[("authorization", "Bearer LEGIT")],
        )
    assert log.last.headers["authorization"] == "Bearer LEGIT"


async def test_no_credential_is_attached_to_a_refused_destination():
    """
    The allow/deny decision runs before any credential is attached AND before
    any HTTP client exists. Both are asserted: zero requests and zero clients.
    """
    app = make_app()
    with capture_upstream() as log:
        resp = await asgi_request(
            app, "POST", "/proxy/grok/v1/audio/../../admin/keys",
            headers=[("authorization", "Bearer CALLER-SECRET"),
                     ("x-api-key", "sk-ant-CALLERKEYCALLERKEYCALLERKEY")],
        )
    assert resp.status == 400
    assert log.count == 0
    assert log.client_kwargs == []


async def test_only_allowlisted_request_headers_are_forwarded():
    app = make_app()
    with capture_upstream() as log:
        await asgi_request(
            app, "POST", "/proxy/grok/v1/chat/completions",
            headers=[
                ("authorization", "Bearer LEGIT"),
                ("cookie", "session=internal-admin"),
                ("x-forwarded-for", "10.0.0.1"),
                ("x-real-ip", "10.0.0.1"),
                ("x-arkheia-internal", "trusted"),
                ("proxy-authorization", "Basic aW50ZXJuYWw="),
            ],
        )
    sent = {k.lower() for k in log.last.headers.keys()}
    for leaked in ("cookie", "x-forwarded-for", "x-real-ip",
                   "x-arkheia-internal", "proxy-authorization"):
        assert leaked not in sent, f"{leaked} was forwarded upstream"
    assert "authorization" in sent  # positive control


# ---------------------------------------------------------------------------
# ADV-7 — what a failure tells the caller
# ---------------------------------------------------------------------------

async def test_upstream_error_leaks_no_internal_detail():
    def exploder(_request):
        raise httpx.ConnectError(
            "All connection attempts failed to 10.0.0.7:3306 (db-primary.internal)"
        )

    app = make_app()
    with capture_upstream(exploder):
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/chat/completions")

    assert resp.status == 502
    assert resp.json() == {"error": "upstream_unavailable"}
    for secret in (b"10.0.0.7", b"db-primary", b"3306", b"api.x.ai"):
        assert secret not in resp.body


async def test_refusal_body_names_the_deny_code_and_the_way_out():
    """
    Gate-9 legibility: an adverse verdict shows what was wrong, what would clear
    it, and carries a reference the operator can quote.
    """
    app = make_app()
    with capture_upstream():
        resp = await asgi_request(app, "POST", "/proxy/grok/v1/admin/users")

    body = resp.json()
    assert body["deny_code"] == pt.DENY_PATH_NOT_ALLOWLISTED
    assert body["reason"] == pt.DENY_TAXONOMY[pt.DENY_PATH_NOT_ALLOWLISTED][0]
    assert body["remedy"] == pt.DENY_TAXONOMY[pt.DENY_PATH_NOT_ALLOWLISTED][1]
    assert body["allowed"] == list(pt.GROK.allowed)
    assert "chat/completions" in body["allowed"]
    assert len(body["receipt_id"]) == 36
    # "enqueued", not "recorded" — the rail is fire-and-forget and cannot ack.
    assert body["receipt_status"] in ("enqueued", "unavailable")
    # The refusal must not echo the attacker's path back into the response.
    assert "admin/users" not in json.dumps(body)


async def test_every_deny_code_is_in_the_closed_taxonomy():
    """A refusal carrying a code with no reason/remedy is unusable to an operator."""
    codes = {v for k, v in vars(pt).items()
             if k.startswith("DENY_") and isinstance(v, str)}
    assert codes, "no deny codes discovered — this check would pass over nothing"
    assert codes == set(pt.DENY_TAXONOMY)
    for code, (reason, remedy) in pt.DENY_TAXONOMY.items():
        assert reason and remedy, code
