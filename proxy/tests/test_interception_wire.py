"""
F10 — /v1/* interception: adversarial suite driven over a REAL socket.

WHY THESE TESTS EXIST AT ALL, AND WHY THEY LOOK LIKE THIS
---------------------------------------------------------
``AIInterceptionMiddleware`` gates on ``request.url.path.startswith("/v1/")``
and then builds its destination as ``upstream_url.rstrip("/") + request.url.path``.
Both halves read ``scope["path"]``, which uvicorn fills from the raw request
target **percent-decoded and with dot segments intact**. Every HTTP client
library removes dot segments before the bytes leave the process, so an exploit
expressed through a client is normalised into something harmless and the test
reports a false negative. PR #31 banked that exact false negative on the sibling
passthrough flow.

So the attacks here go out of a bare ``socket.socket`` at a real uvicorn
process, and land at a raw TCP sink that parses nothing. ``test_premise_*``
below proves the premise first: if uvicorn ever started normalising, the whole
corpus would be exercising an unreachable input and every later assertion would
be vacuous.

WHAT "FINAL HOST" MEANS HERE
----------------------------
The ``Host:`` header on the wire is the authority httpx resolved and connected
to. Asserting it — plus ``attacker.requests == []`` on a sink at a different
origin — is what makes a cross-host claim a measurement rather than a reading
of the source.
"""
from __future__ import annotations

import json

import pytest

from proxy.tests._interception_harness import (
    ProxyServer,
    RecordingSink,
    _Canned,
    raw_request,
    resp_header,
)

pytestmark = pytest.mark.timeout(120)

BODY = b'{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'


@pytest.fixture(scope="module")
def sinks():
    """The configured upstream, and an attacker origin nothing may ever reach."""
    upstream = RecordingSink().start()
    attacker = RecordingSink().start()
    try:
        yield upstream, attacker
    finally:
        upstream.stop()
        attacker.stop()


@pytest.fixture(scope="module")
def proxy(sinks):
    upstream, _ = sinks
    with ProxyServer(ARKH_T_UPSTREAM=upstream.origin, ARKH_T_RISK="LOW") as px:
        yield px


# ---------------------------------------------------------------------------
# Premise — without this the entire corpus below is unreachable input
# ---------------------------------------------------------------------------

class TestPremise:

    def test_premise_uvicorn_hands_the_app_an_un_normalised_path(self, proxy):
        """
        The load-bearing premise: uvicorn leaves ``..`` in ``scope["path"]``, so
        the middleware really does get to decide about a traversal.

        Proven by the decision it makes. A ``/v1/../marker`` that reached the
        app is refused with ``path_escapes_prefix``. Had uvicorn normalised it,
        the app would have seen ``/marker``, the ``/v1/`` prefix test would have
        been false, the middleware would never have run, and FastAPI would have
        404ed — which is exactly what the next test shows a CLIENT produces.
        """
        _, status, hdrs, body = raw_request(proxy.port, "/v1/../marker-premise",
                                            body=BODY)
        payload = json.loads(body)
        assert payload["deny_code"] == "path_escapes_prefix", (
            f"expected the middleware to see '..'; got status={status} "
            f"body={body!r}"
        )

    def test_premise_a_client_library_normalises_the_exploit_away(self, proxy):
        """
        The false negative this whole file exists to avoid, demonstrated.

        ``httpx`` — like ``TestClient`` and every other client — removes dot
        segments before the bytes leave the process, so the same exploit arrives
        as ``/marker-premise``: not under ``/v1/``, never intercepted, 404. A
        suite written through a client would have reported "no traversal here"
        for a path that traverses on a real socket.
        """
        import httpx as _httpx
        r = _httpx.post(f"http://127.0.0.1:{proxy.port}/v1/../marker-premise",
                        content=BODY, timeout=15)
        assert r.status_code == 404
        assert "x-arkheia-risk" not in r.headers

    def test_premise_attacker_sink_is_actually_reachable(self, sinks):
        """
        Negative-control for every ``attacker.requests == []`` assertion below.

        A sink that cannot be reached at all would make those assertions pass
        without proving anything, which is the "looked in the wrong place"
        failure mode DONE.md v1.19 names.
        """
        _, attacker = sinks
        n0 = len(attacker.requests)
        raw_request(attacker.port, "/v1/direct-control", body=b"x")
        assert len(attacker.requests) == n0 + 1
        assert attacker.requests[-1].target == "/v1/direct-control"


# ---------------------------------------------------------------------------
# Cross-host SSRF — the question the config-derived destination raises
# ---------------------------------------------------------------------------

#: Every shape that could plausibly move the authority of
#: ``upstream_url.rstrip("/") + request.url.path``.
CROSS_HOST_VECTORS = [
    "//{atk}/v1/x",                 # protocol-relative
    "/v1/x/../..//{atk}/y",         # traversal into a protocol-relative tail
    "/v1/@{atk}/x",                 # userinfo injection
    "/v1/x#@{atk}/y",               # fragment-then-authority
    "/v1/x?@{atk}/y",               # query-then-authority
    "http://{atk}/v1/x",            # absolute-form request target
    "https://{atk}/v1/x",           # absolute-form, other scheme
    "/v1/%2f%2f{atk}/x",            # encoded protocol-relative
    "/v1/..%2f..%2f%2f{atk}/x",     # encoded traversal + protocol-relative
    "/v1/\\\\{atk}/x",              # backslash authority (IE/.NET style)
    "/v1/x%00.{atk}/y",             # NUL truncation
    "/v1/x%0d%0aHost:+{atk}",       # CRLF header injection into the target
]


class TestCrossHostSSRF:

    @pytest.mark.parametrize("template", CROSS_HOST_VECTORS)
    def test_no_vector_moves_the_final_host(self, proxy, sinks, template):
        """
        The destination is CONFIG-derived, so cross-host SSRF is a live question
        here in a way it was not for the sibling flow's constant table.

        Answered by measurement, twice over: the ``Host:`` header the proxy put
        on the wire is the authority it connected to, and the attacker origin
        must record nothing.
        """
        upstream, attacker = sinks
        target = template.format(atk=attacker.authority)
        n_up, n_atk = len(upstream.requests), len(attacker.requests)

        try:
            raw_request(proxy.port, target, body=BODY)
        except Exception:
            # A malformed target the server rejects at the HTTP layer never
            # reaches the middleware; that is a pass for this assertion, and the
            # attacker check below still runs.
            pass

        assert len(attacker.requests) == n_atk, (
            f"{target!r} reached the ATTACKER origin — cross-host SSRF is live"
        )
        for req in upstream.requests[n_up:]:
            assert req.host == upstream.authority, (
                f"{target!r} moved the final host to {req.host!r}"
            )

    def test_redirect_to_link_local_metadata_is_not_dereferenced(self, sinks):
        """
        The upstream answers 302 → attacker origin. Following it would be an
        open cross-host relay with the caller's credential attached.

        Today this holds only because ``httpx.AsyncClient()`` defaults
        ``follow_redirects`` to False. A default is not a control: it is a
        third-party decision that can change under us on a dependency bump.
        The floor invariant pins the explicit kwarg; this pins the behaviour.
        """
        _, attacker = sinks
        redirector = RecordingSink(canned=_Canned(
            status=302, reason="Found",
            headers=[("location", f"http://{attacker.authority}/latest/meta-data/"),
                     ("content-type", "text/plain")],
            body=b"redirecting",
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=redirector.origin, ARKH_T_RISK="LOW") as px:
                n_atk = len(attacker.requests)
                raw_request(px.port, "/v1/chat/completions", body=BODY)
            assert len(redirector.requests) == 1
            assert len(attacker.requests) == n_atk, (
                "the 302 was dereferenced — a redirect is a cross-host relay"
            )
        finally:
            redirector.stop()

    def test_metadata_host_in_request_headers_does_not_move_the_destination(
        self, proxy, sinks
    ):
        """
        DNS-rebinding shape / Host-header repointing: the destination must not
        be derived from anything the caller sends. Asserted on the wire.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        raw_request(
            proxy.port, "/v1/chat/completions", body=BODY,
            extra_headers=[("X-Forwarded-Host", "169.254.169.254"),
                           ("Forwarded", "host=169.254.169.254")],
        )
        assert len(upstream.requests) == n0 + 1
        assert upstream.requests[-1].host == upstream.authority


# ---------------------------------------------------------------------------
# Path confinement — the /v1/ prefix is the ONLY gate this flow has
# ---------------------------------------------------------------------------

#: Each entry escapes the ``/v1/`` prefix that decided the request was
#: interceptable. ``httpx`` removes dot segments when it builds the URL, so the
#: resolved request-target on the wire is the escaped one.
ESCAPE_VECTORS = [
    ("/v1/../admin/keys", "/admin/keys"),
    ("/v1/../../admin/keys", "/admin/keys"),
    ("/v1/%2e%2e/admin/keys", "/admin/keys"),
    ("/v1/%2E%2E%2fadmin%2fkeys", "/admin/keys"),
    ("/v1/./../admin", "/admin"),
    ("/v1/a/b/../../../internal", "/internal"),
]


#: Double-encoded escapes. uvicorn decodes ONCE, so ``%252f`` arrives as the
#: literal text ``%2f`` — which httpx then leaves encoded, so the resolved-URL
#: post-condition sees a confined path while a lenient origin decodes the
#: escape and leaves ``/v1/`` anyway. Only the raw-path pre-condition sees it.
DOUBLE_ENCODED_VECTORS = [
    "/v1/..%252fadmin",
    "/v1/..%252Fadmin",          # uppercase: the marker match must be case-folded
    "/v1/%252e%252e/admin",
    "/v1/..%255c..%255cadmin",
    "/v1/..\\..\\admin",     # literal backslash, no encoding at all
]


class TestPathConfinement:

    @pytest.mark.parametrize("target", DOUBLE_ENCODED_VECTORS)
    def test_double_encoded_and_backslash_escapes_are_refused_at_the_route(
        self, proxy, sinks, target
    ):
        """
        Driven end to end, because the pre-condition being CALLED is a separate
        fact from the pre-condition being CORRECT — the campaign showed a
        mutant that deleted the call site surviving a corpus that only tested
        the function.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        _, status, hdrs, body = raw_request(proxy.port, target, body=BODY)
        assert len(upstream.requests) == n0, (
            f"{target!r} was forwarded as "
            f"{upstream.requests[-1].target!r}"
        )
        assert json.loads(body)["deny_code"] == "unsafe_path_encoding"
        assert resp_header(hdrs, "x-arkheia-risk") == "REFUSED"

    def test_the_callers_host_header_is_not_relayed_to_the_provider(
        self, proxy, sinks
    ):
        """
        httpx HONOURS an explicit ``host`` in the header list while still
        connecting to the URL's authority, so relaying the caller's Host sends
        a provider a request addressed to somewhere else — a routing and
        cache-poisoning primitive.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        raw_request(proxy.port, "/v1/chat/completions", body=BODY,
                    extra_headers=[("X-Probe", "1")])
        assert len(upstream.requests) == n0 + 1
        assert upstream.requests[-1].host == upstream.authority
        assert len(upstream.requests[-1].header_values("host")) == 1

    @pytest.mark.parametrize("target,escaped", ESCAPE_VECTORS)
    def test_path_may_not_escape_the_v1_prefix_that_authorised_it(
        self, proxy, sinks, target, escaped
    ):
        """
        ``startswith("/v1/")`` is the whole authorisation decision this flow
        makes. If the resolved path leaves ``/v1/``, the decision was made about
        a different request than the one that was sent — with the caller's
        ``Authorization`` attached to the escape.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        _, status, hdrs, _ = raw_request(
            proxy.port, target, body=BODY,
            extra_headers=[("Authorization", "Bearer CALLER-SECRET")],
        )
        forwarded = upstream.requests[n0:]
        assert forwarded == [] or not forwarded[-1].target.startswith(escaped), (
            f"{target!r} was forwarded to {forwarded[-1].target!r} — it escaped "
            f"the /v1/ prefix that authorised interception"
        )

    def test_escaped_request_does_not_carry_the_caller_credential(
        self, proxy, sinks
    ):
        """A traversal that also leaks the caller's key is the compounding harm."""
        upstream, _ = sinks
        n0 = len(upstream.requests)
        raw_request(
            proxy.port, "/v1/../admin/keys", body=BODY,
            extra_headers=[("Authorization", "Bearer CALLER-SECRET")],
        )
        for req in upstream.requests[n0:]:
            if not req.target.startswith("/v1/"):
                assert "Bearer CALLER-SECRET" not in req.header_values("authorization"), (
                    "the caller's credential rode an escaped path to "
                    f"{req.target!r}"
                )

    def test_legitimate_v1_path_still_forwards_unharmed(self, proxy, sinks):
        """Positive control: confinement must not break the normal path."""
        upstream, _ = sinks
        n0 = len(upstream.requests)
        _, status, hdrs, body = raw_request(
            proxy.port, "/v1/chat/completions", body=BODY)
        assert len(upstream.requests) == n0 + 1
        assert upstream.requests[-1].target == "/v1/chat/completions"
        assert status == 200
        assert resp_header(hdrs, "x-arkheia-risk") == "LOW"


# ---------------------------------------------------------------------------
# Header handling on the forward leg
# ---------------------------------------------------------------------------

#: RFC 9110 §7.6.1 connection-specific header fields. A proxy that relays any of
#: these is relaying a hop-by-hop control to a party it was not addressed to.
HOP_BY_HOP = [
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
]


class TestForwardHeaders:

    def test_duplicate_authorization_is_not_silently_resolved(self, proxy, sinks):
        """
        ``{k: v for k, v in request.headers.items()}`` keeps the LAST occurrence
        (Starlette's ``Headers.items()`` deliberately yields every pair). Two
        ``Authorization`` headers therefore authenticate as the second one while
        the caller and any log believe the first was used.

        No legitimate client sends two. Silently picking one is a smuggling
        primitive, not a convenience.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        _, status, hdrs, _ = raw_request(
            proxy.port, "/v1/chat/completions", body=BODY,
            extra_headers=[("Authorization", "Bearer LEGIT"),
                           ("Authorization", "Bearer ATTACKER")],
        )
        forwarded = upstream.requests[n0:]
        if forwarded:
            assert "Bearer ATTACKER" not in forwarded[-1].header_values("authorization"), (
                "the smuggled second credential is what reached the upstream"
            )

    @pytest.mark.parametrize("name", HOP_BY_HOP)
    def test_hop_by_hop_headers_are_not_relayed(self, proxy, sinks, name):
        """
        ``proxy-authenticate: Basic realm=internal-corp`` relayed to a provider
        is an internal-topology leak; ``upgrade`` / ``te`` / ``trailer`` relayed
        are protocol-confusion primitives. Only ``host`` is dropped today.
        """
        upstream, _ = sinks
        # Each value carries a marker token httpx would never emit itself, so
        # the assertion distinguishes "the CALLER's value survived" from
        # "httpx set its own connection header".
        value = {"transfer-encoding": "chunked", "te": "trailers; q=0.5-MARK",
                 "upgrade": "websocket-MARK", "keep-alive": "timeout=5-MARK",
                 "connection": "close, x-MARK", "trailer": "X-Junk-MARK",
                 "proxy-authenticate": "Basic realm=internal-corp-MARK",
                 "proxy-authorization": "Basic YWRtaW46cw-MARK",
                 "proxy-connection": "keep-alive-MARK"}[name]
        n0 = len(upstream.requests)
        try:
            raw_request(proxy.port, "/v1/chat/completions", body=BODY,
                        extra_headers=[(name, value)])
        except Exception:
            pass
        for req in upstream.requests[n0:]:
            for gname, gvalue in req.header_pairs:
                assert "MARK" not in gvalue and "chunked" not in (
                    gvalue if gname == "transfer-encoding" else ""), (
                    f"caller's hop-by-hop {name}: {value!r} was relayed to the "
                    f"upstream as {gname}: {gvalue!r}"
                )

    def test_connection_nominated_headers_are_stripped(self, proxy, sinks):
        """
        ``Connection: x-internal-token`` nominates that header as hop-by-hop.
        Relaying it defeats the nomination and leaks the field onward.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        raw_request(proxy.port, "/v1/chat/completions", body=BODY,
                    extra_headers=[("Connection", "x-internal-token, close"),
                                   ("X-Internal-Token", "s3cr3t-hop")])
        for req in upstream.requests[n0:]:
            assert "s3cr3t-hop" not in req.header_values("x-internal-token"), (
                "a Connection-nominated header was relayed past its hop"
            )

    def test_exactly_one_content_length_reaches_the_upstream(self, proxy, sinks):
        """
        The caller's ``content-length`` is forwarded verbatim while httpx also
        frames the body. Two framing headers that disagree are a request
        smuggling primitive; two that agree are still a latent one.
        """
        upstream, _ = sinks
        n0 = len(upstream.requests)
        raw_request(proxy.port, "/v1/chat/completions", body=BODY)
        assert len(upstream.requests) == n0 + 1
        req = upstream.requests[-1]
        lengths = req.header_values("content-length")
        assert len(lengths) == 1, f"upstream saw content-length {lengths!r}"
        assert int(lengths[0]) == len(req.body) == len(BODY)


# ---------------------------------------------------------------------------
# Response relay
# ---------------------------------------------------------------------------

class TestResponseRelay:

    def test_upstream_error_status_is_not_reported_as_success(self, sinks):
        """
        A transparent proxy that turns 429 into 200 makes a rate-limit
        indistinguishable from a completion. Every retry/backoff path in every
        client SDK keys off the status line.
        """
        sink = RecordingSink(canned=_Canned(
            status=429, reason="Too Many Requests",
            headers=[("retry-after", "60"), ("content-type", "application/json")],
            body=b'{"error":{"type":"rate_limit_error"}}',
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=sink.origin, ARKH_T_RISK="LOW") as px:
                _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                    body=BODY)
            assert status == 429, f"upstream 429 was relayed to the caller as {status}"
            assert body == b'{"error":{"type":"rate_limit_error"}}'
        finally:
            sink.stop()

    def test_upstream_content_type_survives_the_relay(self, sinks):
        """
        Dropping ``content-type`` leaves a JSON completion untyped. Clients that
        branch on it (every provider SDK does) cannot parse the answer.
        """
        sink = RecordingSink(canned=_Canned(
            headers=[("content-type", "application/json; charset=utf-8")],
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=sink.origin, ARKH_T_RISK="LOW") as px:
                _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                    body=BODY)
            assert resp_header(hdrs, "content-type") == "application/json; charset=utf-8"
        finally:
            sink.stop()

    def test_content_length_matches_the_bytes_actually_served(self, sinks):
        """
        PR #31's framing desync, checked on this flow: httpx advertises
        ``accept-encoding: gzip`` on every upstream request and transparently
        decodes the reply, so any relayed ``content-length`` describes the
        COMPRESSED body while the served bytes are the decompressed ones.
        Measured on the wire, not inferred.
        """
        payload = b'{"choices":[{"message":{"content":"' + b"x" * 3000 + b'"}}]}'
        import gzip
        gz = gzip.compress(payload)
        sink = RecordingSink(canned=_Canned(
            headers=[("content-type", "application/json"),
                     ("content-encoding", "gzip"),
                     ("content-length", str(len(gz)))],
            body=gz,
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=sink.origin, ARKH_T_RISK="LOW") as px:
                _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                    body=BODY)
            declared = resp_header(hdrs, "content-length")
            assert body == payload, "the caller did not receive the decoded payload"
            if declared is not None:
                assert int(declared) == len(body), (
                    f"content-length {declared} describes neither the served "
                    f"{len(body)} bytes"
                )
            assert resp_header(hdrs, "content-encoding") is None, (
                "content-encoding was relayed over an already-decoded body"
            )
        finally:
            sink.stop()

    def test_hop_by_hop_response_headers_are_not_relayed_to_the_caller(self, sinks):
        sink = RecordingSink(canned=_Canned(
            headers=[("content-type", "application/json"),
                     ("proxy-authenticate", "Basic realm=internal-corp"),
                     ("keep-alive", "timeout=5")],
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=sink.origin, ARKH_T_RISK="LOW") as px:
                _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                    body=BODY)
            assert resp_header(hdrs, "proxy-authenticate") is None
            assert resp_header(hdrs, "keep-alive") is None
        finally:
            sink.stop()


# ---------------------------------------------------------------------------
# Fail-open must not fabricate
# ---------------------------------------------------------------------------

class TestFailOpenDoesNotFabricate:

    def test_detector_crash_returns_the_upstream_answer_not_a_local_one(self, sinks):
        """
        THE sharpest defect class for a fabrication-detection product: on
        detector failure the middleware re-enters ``call_next``, which serves
        the proxy's OWN local routes. The caller receives content the model
        never produced, at HTTP 200, labelled only ``X-Arkheia-Risk: ERROR``.

        Fail-open means "do not block". It cannot mean "substitute a different
        answer".
        """
        sink = RecordingSink(canned=_Canned(
            body=b'{"choices":[{"message":{"content":"UPSTREAM-ANSWER"}}]}',
            headers=[("content-type", "application/json")],
        )).start()
        try:
            with ProxyServer(ARKH_T_UPSTREAM=sink.origin, ARKH_T_RISK="LOW",
                             ARKH_T_ENGINE="raise") as px:
                _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                    body=BODY)
            assert b"UPSTREAM-ANSWER" in body, (
                f"detector crash served {body!r} instead of the upstream answer"
            )
            assert b"local" not in body
        finally:
            sink.stop()

    def test_detector_crash_in_standalone_mode_does_not_empty_the_body(self):
        """
        Standalone mode: ``call_next`` has already been consumed, so the
        recovery path's second ``call_next`` yields nothing and the caller gets
        a 200 with ZERO bytes. The pre-existing suite asserts only the header,
        so this passed unnoticed.
        """
        with ProxyServer(ARKH_T_UPSTREAM="", ARKH_T_RISK="LOW",
                         ARKH_T_ENGINE="raise") as px:
            _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                body=BODY)
        assert resp_header(hdrs, "x-arkheia-risk") == "ERROR"
        assert len(body) > 0, (
            "the recovery path served an EMPTY body — fail-open destroyed the "
            "response it was meant to let through"
        )

    def test_unreachable_upstream_is_not_answered_from_local_routes(self):
        """
        Upstream down: the caller must learn that, not receive a locally
        generated 200 that looks like a completion.
        """
        import socket as _socket
        s = _socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        with ProxyServer(ARKH_T_UPSTREAM=f"http://127.0.0.1:{dead}",
                         ARKH_T_RISK="LOW") as px:
            _, status, hdrs, body = raw_request(px.port, "/v1/chat/completions",
                                                body=BODY)
        assert b'"content":"local"' not in body, (
            "an unreachable upstream was answered from the proxy's own routes"
        )
        # An `or` here would be a permissive assertion: a 200 carrying the word
        # "upstream" would satisfy it, and the mutation campaign caught exactly
        # that (M35 survived the weaker form). The status line is what every
        # client SDK branches on, so it is asserted on its own.
        assert status == 502, (
            f"upstream outage surfaced as status={status} body={body!r}"
        )
        assert json.loads(body)["deny_code"] == "upstream_unreachable"
