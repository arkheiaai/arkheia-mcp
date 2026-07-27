"""
WIRE-LEVEL proof of the credential boundary: which secret reaches which vendor.

THE DEFECT THIS WAS WRITTEN AGAINST
-----------------------------------
The forwarded-header allowlist was GLOBAL: one set containing both
``authorization`` and ``x-api-key``, applied to all four providers. So a caller
who sends both — the ordinary shape when one client is configured for two
vendors, or when a gateway attaches every credential it holds — had BOTH
delivered to whichever single destination the route resolved to. Reproduced by a
second vendor (Codex, gpt-5.5) on this branch: Grok received a Bearer token AND
an Anthropic-style ``x-api-key``.

The previous round's duplicate-credential check could not see it. That check
counts REPEATED INSTANCES OF ONE header name; this is TWO DIFFERENT header
names, each appearing once. A per-header rule cannot see a cross-header
interaction.

The same hole existed in the query string: ``params=dict(request.query_params)``
relayed every parameter to every destination, so a Google ``?key=`` handed to the
Grok route left for api.x.ai.

WHY THIS FILE USES TWO REAL SOCKETS
-----------------------------------
A client library normalises, reorders, folds and re-cases headers, and a mock
transport records call ARGUMENTS rather than bytes. Neither can answer "which
credential headers did the destination actually receive?". Here:

  * the CALLER speaks HTTP/1.1 down a raw ``socket.socket`` to a real uvicorn
    server running the real router;
  * the DESTINATION is a real TCP origin (``DestinationSink``) that reads the
    literal request head off the wire and records it.

Nothing between them is patched — not httpx, not the transport. The only thing
substituted is each provider's ``base`` constant, via ``dataclasses.replace``, so
the traffic lands on the sink instead of the real vendor.

DELIBERATELY SYMBOL-FREE
------------------------
This module references no name this change introduced (``dataclasses.replace``
copies whatever fields exist), so it runs unchanged against the pre-fix file as a
genuine red run. Measured, 2026-07-27, Python 3.12.13:

    git stash && .venv/bin/python -m pytest proxy/tests/test_passthrough_credential_wire.py
        -> 3 failed, 3 passed          (the three controls pass; the three
                                        boundary tests fail)
    (restored)                          -> 6 passed

CREDENTIAL FIXTURES ARE OBVIOUSLY FAKE
--------------------------------------
Every credential value below is the literal string ``NOT-A-REAL-CREDENTIAL-…``.
No vendor prefix (``sk-``, ``xai-``, ``AIza``) appears anywhere in this file:
those shapes are what secret scanners match, and a fixture that trips gitleaks
costs a CI cycle for nothing. A real credential value is never printed, logged or
committed.
"""
from __future__ import annotations

import dataclasses
import json
import socket
import threading
import time
from typing import Optional

import pytest
import uvicorn
from fastapi import FastAPI

from proxy.endpoints import passthrough as pt

# --- fixtures that could not possibly be live credentials -------------------
FAKE_BEARER = "Bearer NOT-A-REAL-CREDENTIAL-bearer-fixture"
FAKE_ANTHROPIC_KEY = "NOT-A-REAL-CREDENTIAL-anthropic-header-fixture"
FAKE_GOOGLE_KEY = "NOT-A-REAL-CREDENTIAL-google-query-fixture"

#: Every header name that can carry a caller credential, from THIS test's point
#: of view. Deliberately written here rather than imported from the module under
#: test: a check that asks the subject what to check agrees with it by
#: construction.
CREDENTIAL_HEADER_NAMES = {
    "authorization", "x-api-key", "x-goog-api-key", "proxy-authorization",
    "api-key", "cookie",
}


# ---------------------------------------------------------------------------
# A real destination on a real socket
# ---------------------------------------------------------------------------

class DestinationSink:
    """
    A minimal TCP origin that records the literal request head it received.

    Not an ASGI app and not a mock transport: the recorded header list is what
    arrived on the connection, in the order and casing it arrived in.
    """

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.2)
        self.port: int = self._listener.getsockname()[1]
        self.received: list[dict] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # -- server ------------------------------------------------------------
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:  # pragma: no cover - listener closed
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:  # pragma: no cover - client vanished
                    return
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            headers: list[tuple[str, str]] = []
            for line in lines[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers.append((key.strip().lower(), value.strip()))
            length = 0
            for key, value in headers:
                if key == "content-length":
                    length = int(value)
            body = rest
            while len(body) < length:
                chunk = conn.recv(65536)
                if not chunk:  # pragma: no cover
                    break
                body += chunk

            self.received.append({
                "request_line": lines[0],
                "headers": headers,
                "body": body,
            })

            payload = json.dumps({
                # one body that satisfies all three extractors, so the sink is
                # provider-agnostic and the detection path is never the reason a
                # test passes or fails.
                "choices": [{"message": {"content": "ok"}}],
                "content": [{"type": "text", "text": "ok"}],
                "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
            }).encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + payload
            )
        except Exception:  # pragma: no cover - infrastructure
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._listener.close()
        self._thread.join(timeout=5)

    # -- what the destination saw -----------------------------------------
    def credential_headers(self, index: int = -1) -> set[str]:
        """Credential header NAMES on a recorded request. Never the values."""
        return {
            name for name, _value in self.received[index]["headers"]
            if name in CREDENTIAL_HEADER_NAMES
        }

    def header_value(self, name: str, index: int = -1) -> Optional[str]:
        for key, value in self.received[index]["headers"]:
            if key == name:
                return value
        return None

    def any_request_carried(self, header_name: str) -> bool:
        return any(
            header_name in {k for k, _ in entry["headers"]}
            for entry in self.received
        )

    def request_lines(self) -> list[str]:
        return [entry["request_line"] for entry in self.received]


# ---------------------------------------------------------------------------
# The proxy, on its own real socket, with every provider pointed at the sink
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def wire():
    sink = DestinationSink()

    app = FastAPI()
    app.include_router(pt.router)
    app.state.engine = None
    app.state.audit_writer = None

    # Only the base URL constant moves. Everything the gate verifies against is
    # derived from `base`, so the provider stays internally consistent, and
    # `replace` copies whatever fields the dataclass has — pre-fix or post-fix.
    originals = {name: getattr(pt, name)
                 for name in ("GROK", "TOGETHER", "ANTHROPIC", "GEMINI")}
    local = f"http://127.0.0.1:{sink.port}"
    pt.GROK = dataclasses.replace(originals["GROK"], base=local + "/v1")
    pt.TOGETHER = dataclasses.replace(originals["TOGETHER"], base=local + "/v1")
    pt.ANTHROPIC = dataclasses.replace(originals["ANTHROPIC"], base=local + "/v1")
    pt.GEMINI = dataclasses.replace(originals["GEMINI"], base=local + "/v1beta")

    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if server.started and server.servers:
            break
        time.sleep(0.02)
    else:  # pragma: no cover - infrastructure failure
        for name, value in originals.items():
            setattr(pt, name, value)
        sink.close()
        pytest.fail("uvicorn did not start; this test observed nothing")

    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield port, sink
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        for name, value in originals.items():
            setattr(pt, name, value)
        sink.close()


def raw_call(port: int, target: str, header_lines: list[str]) -> tuple[int, bytes]:
    """
    Send literal bytes to the proxy; read literal bytes back.

    The credential headers are written into the request as text, so no client
    library gets the chance to drop, fold or reorder them.
    """
    body = b'{"model":"test-model","messages":[{"role":"user","content":"hi"}]}'
    head = (
        f"POST {target} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        + "".join(f"{line}\r\n" for line in header_lines)
        + "\r\n"
    ).encode()

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(head + body)
        sock.settimeout(10)
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
    finally:
        sock.close()

    raw = b"".join(chunks)
    response_head, _, response_body = raw.partition(b"\r\n\r\n")
    status = int(response_head.decode("latin-1").split("\r\n")[0].split(" ")[1])
    return status, response_body


# ---------------------------------------------------------------------------
# CRED-1 — the reproduction: one vendor's key must never reach another vendor
# ---------------------------------------------------------------------------

def test_grok_never_receives_an_anthropic_style_api_key(wire):
    """
    CODEX'S EXACT CASE. One accepted request carrying both an ``authorization``
    and an ``x-api-key``, on the ordinary path — no attack, just a caller
    configured for two vendors.

    Pre-fix, measured on this sink: the request was FORWARDED (200) and the
    destination received BOTH credential headers.
    """
    port, sink = wire
    before = len(sink.received)

    status, body = raw_call(port, "/proxy/grok/v1/chat/completions", [
        f"Authorization: {FAKE_BEARER}",
        f"X-Api-Key: {FAKE_ANTHROPIC_KEY}",
    ])

    delivered = sink.received[before:]
    leaked = [
        entry for entry in delivered
        if "x-api-key" in {k for k, _ in entry["headers"]}
    ]
    assert not leaked, (
        "the destination received a credential header it does not use: "
        f"{sorted({k for k, _ in leaked[0]['headers']} & CREDENTIAL_HEADER_NAMES)}"
    )
    assert status == 400, f"a mixed-credential request was accepted: {body!r}"
    assert delivered == [], "a refused request produced upstream traffic"


def test_anthropic_never_receives_two_different_credential_headers(wire):
    """
    The same interaction at a destination that legitimately accepts EITHER
    header. Both at once is not two ways of saying one thing — it is two
    credentials, at most one of which the caller meant for this vendor, and the
    proxy cannot tell which.

    Pre-fix: forwarded, with both headers on the wire.
    """
    port, sink = wire
    before = len(sink.received)

    status, body = raw_call(port, "/v1/messages", [
        f"Authorization: {FAKE_BEARER}",
        f"X-Api-Key: {FAKE_ANTHROPIC_KEY}",
        "Anthropic-Version: 2023-06-01",
    ])

    delivered = sink.received[before:]
    both = [
        entry for entry in delivered
        if {"authorization", "x-api-key"} <= {k for k, _ in entry["headers"]}
    ]
    assert not both, "the destination received two different credential headers"
    assert status == 400, f"an ambiguous-credential request was accepted: {body!r}"
    assert delivered == []


def test_a_google_style_api_key_in_the_query_never_reaches_xai(wire):
    """
    The sibling in the query string. ``params=dict(request.query_params)`` was
    the same shared allowlist in another spelling: every parameter to every
    destination.

    Pre-fix: the request line that reached the sink carried the key.
    """
    port, sink = wire
    before = len(sink.received)

    status, body = raw_call(
        port, f"/proxy/grok/v1/chat/completions?key={FAKE_GOOGLE_KEY}",
        [f"Authorization: {FAKE_BEARER}"],
    )

    delivered = sink.received[before:]
    assert not [e for e in delivered if "key=" in e["request_line"]], (
        f"a credential query parameter reached the wrong vendor: "
        f"{[e['request_line'] for e in delivered]}"
    )
    assert status == 400, f"a foreign credential parameter was accepted: {body!r}"
    assert delivered == []


# ---------------------------------------------------------------------------
# CRED-2 — the control rows. A boundary that refuses everything is not a
# boundary; each destination must still receive ITS OWN credential, verbatim.
# ---------------------------------------------------------------------------

def test_grok_receives_exactly_its_own_credential(wire):
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(port, "/proxy/grok/v1/chat/completions", [
        f"Authorization: {FAKE_BEARER}",
    ])

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1, f"expected exactly one upstream call, got {len(delivered)}"
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"authorization"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("authorization") == FAKE_BEARER


def test_anthropic_receives_exactly_its_own_credential(wire):
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(port, "/v1/messages", [
        f"X-Api-Key: {FAKE_ANTHROPIC_KEY}",
        "Anthropic-Version: 2023-06-01",
    ])

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"x-api-key"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("x-api-key") == FAKE_ANTHROPIC_KEY


def test_gemini_still_receives_its_own_query_key(wire):
    """
    The parameter filter must not become a blanket ban: Google's API key travels
    in the query, and this is the destination that uses it.
    """
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(
        port,
        f"/v1beta/models/gemini-2.5-flash:generateContent?key={FAKE_GOOGLE_KEY}",
        [],
    )

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    assert f"key={FAKE_GOOGLE_KEY}" in delivered[0]["request_line"], (
        f"Google's own credential parameter was dropped: {delivered[0]['request_line']}"
    )


# ---------------------------------------------------------------------------
# CRED-3 — the multiplicity is per DESTINATION, across every channel
#
# WHAT EARNED THIS (2026-07-27, found by a second vendor — Codex, gpt-5.5, on
# the fix for the round-2 defect above)
# ---------------------------------------------------------------------------
# Round 2's own stated lesson was "a per-header rule cannot see a cross-header
# interaction". It then shipped a gate that counts credential HEADERS — so it
# cannot see a header ⇄ QUERY-PARAMETER interaction either, nor a repeated query
# parameter. Gemini is the destination where that is reachable, because Google
# genuinely accepts three credential FORMS (`authorization`, `x-goog-api-key`,
# `?key=`), and the round-2 screen looked at exactly one channel.
#
# Codex proved both, at a real socket, against the round-2 code:
#
#   POST /v1beta/models/…:generateContent?key=<google>   + Authorization: Bearer …
#       -> 200, and the destination received BOTH the bearer header AND the key
#          in its request line: two credentials forwarded on one request.
#   POST /v1beta/models/…:generateContent?key=FIRST&key=SECOND
#       -> 200, and the destination received ONE key — SECOND. The query-string
#          twin of the `Authorization` last-wins defect round 1 fixed: the
#          caller's first credential was silently discarded.
#
# The invariant is therefore over the SHAPE OF THE CREDENTIAL SET FOR A
# DESTINATION — how many credentials are addressed to it, whatever channel each
# arrives on — not over any one channel's contents.
#
# The nuance that must survive: Gemini accepts more than one credential FORM,
# and exactly one of them by ANY channel must still work. The defect is more
# than one AT ONCE. The control rows below are what make this a boundary rather
# than a ban.


def test_gemini_never_receives_a_header_credential_and_a_query_credential(wire):
    """
    CODEX'S EXACT CASE 1. A bearer in the header AND Google's key in the query,
    both credentials this destination legitimately accepts — one at a time.

    Round-2 code, measured on this sink: 200, and the destination received the
    authorization header AND `key=` in its request line.
    """
    port, sink = wire
    before = len(sink.received)

    status, body = raw_call(
        port,
        f"/v1beta/models/gemini-2.5-flash:generateContent?key={FAKE_GOOGLE_KEY}",
        [f"Authorization: {FAKE_BEARER}"],
    )

    delivered = sink.received[before:]
    both = [
        entry for entry in delivered
        if "authorization" in {k for k, _ in entry["headers"]}
        and "key=" in entry["request_line"]
    ]
    assert not both, (
        "the destination received TWO credentials on one request — a header one "
        f"and a query one: {[e['request_line'] for e in both]}"
    )
    assert status == 400, (
        f"a request carrying two credentials for one destination was accepted: {body!r}"
    )
    assert delivered == [], "a refused request produced upstream traffic"


def test_gemini_never_silently_collapses_a_repeated_query_credential(wire):
    """
    CODEX'S EXACT CASE 2. `?key=FIRST&key=SECOND`.

    Round-2 code, measured on this sink: 200, and the request line that reached
    the destination carried SECOND and not FIRST — a credential the caller sent
    was discarded without anyone being told. That is the query-string twin of
    the `Authorization` last-wins defect this branch already refused for
    headers, and it is refused here for the same reason: a silent drop trades an
    integrity bug for an honesty bug.
    """
    port, sink = wire
    before = len(sink.received)

    first = FAKE_GOOGLE_KEY + "-FIRST"
    second = FAKE_GOOGLE_KEY + "-SECOND"
    status, body = raw_call(
        port,
        "/v1beta/models/gemini-2.5-flash:generateContent"
        f"?key={first}&key={second}",
        [],
    )

    collapsed = [
        entry for entry in sink.received[before:]
        if second in entry["request_line"] and first not in entry["request_line"]
    ]
    assert not collapsed, (
        "the destination received the LAST of two credentials and the first was "
        f"silently dropped: {[e['request_line'] for e in collapsed]}"
    )
    assert status == 400, f"a repeated credential parameter was accepted: {body!r}"
    assert sink.received[before:] == [], "a refused request produced upstream traffic"


# ---------------------------------------------------------------------------
# CRED-4 — the control rows. Gemini accepts three credential FORMS; each of
# them, alone, must still reach Google verbatim. A screen that refused these
# would have traded a disclosure for an outage.
# ---------------------------------------------------------------------------

def test_gemini_receives_its_own_header_key_alone(wire):
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(
        port, "/v1beta/models/gemini-2.5-flash:generateContent",
        [f"X-Goog-Api-Key: {FAKE_GOOGLE_KEY}"],
    )

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"x-goog-api-key"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("x-goog-api-key") == FAKE_GOOGLE_KEY


def test_gemini_receives_its_own_oauth_bearer_alone(wire):
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(
        port, "/v1beta/models/gemini-2.5-flash:generateContent",
        [f"Authorization: {FAKE_BEARER}"],
    )

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"authorization"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("authorization") == FAKE_BEARER
    assert "key=" not in delivered[0]["request_line"]


def test_together_receives_exactly_its_own_credential(wire):
    """The fourth destination. Enumerated so no provider is proved by analogy."""
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(port, "/proxy/together/v1/chat/completions", [
        f"Authorization: {FAKE_BEARER}",
    ])

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"authorization"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("authorization") == FAKE_BEARER


def test_anthropic_receives_its_own_oauth_bearer_alone(wire):
    """
    Anthropic's second accepted FORM, alone. Round 2 proved x-api-key alone;
    a destination that accepts either must be shown to accept either.
    """
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(port, "/v1/messages", [
        f"Authorization: {FAKE_BEARER}",
        "Anthropic-Version: 2023-06-01",
    ])

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    seen = {k for k, _ in delivered[0]["headers"]} & CREDENTIAL_HEADER_NAMES
    assert seen == {"authorization"}, f"destination saw credential headers {sorted(seen)}"
    assert sink.header_value("authorization") == FAKE_BEARER


def test_a_repeated_ordinary_parameter_is_not_collapsed(wire):
    """
    The counterpart to the ruling: multiplicity is preserved for parameters that
    are NOT credentials, rather than the whole query string being flattened.
    `dict(request.query_params)` dropped the first of any repeated parameter —
    a silent alteration of the caller's request, credential or not.
    """
    port, sink = wire
    before = len(sink.received)

    status, _body = raw_call(
        port,
        "/v1beta/models/gemini-2.5-flash:generateContent"
        f"?key={FAKE_GOOGLE_KEY}&alt=sse&alt=json",
        [],
    )

    assert status == 200
    delivered = sink.received[before:]
    assert len(delivered) == 1
    line = delivered[0]["request_line"]
    assert "alt=sse" in line and "alt=json" in line, (
        f"a repeated non-credential parameter was collapsed: {line}"
    )
