"""
Wire-level proof for the passthrough forwarding gate.

WHY A SECOND TRANSPORT
----------------------
The rest of this flow's tests drive the ASGI app directly. That is the right
instrument — no HTTP client will deliver an un-normalised path — but it means the
whole suite shares one decode path, and a decode fault that cancels out under a
single transport is invisible (DONE.md floor invariant 10). These tests run a
REAL uvicorn server on a real socket and speak HTTP/1.1 down a raw
``socket.socket``, so the request line is the literal bytes an attacker sends and
the response is the literal bytes a caller receives.

Two facts only this transport can establish:

  * uvicorn does NOT remove dot segments — it percent-decodes the request target
    and hands the raw path to the app. So ``/proxy/grok/v1/audio/../../admin/keys``
    really is reachable from the network, and the ASGI-scope harness is faithful
    rather than contrived.

  * a content-length that disagrees with the body is a framing fault the caller
    sees as a TRUNCATED RESPONSE. Pre-fix, uvicorn raised "Response content
    longer than Content-Length" and put ZERO body bytes on the wire under a
    non-zero content-length.

DELIBERATELY SYMBOL-FREE
------------------------
This module imports nothing this flow added — only the router. That is what lets
it run unchanged against the pre-fix file as a genuine red run:

    git stash && pytest proxy/tests/test_passthrough_wire.py   # 2 failed
"""
from __future__ import annotations

import gzip
import json
import socket
import threading
import time
from typing import Optional

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from unittest.mock import patch

from proxy.endpoints.passthrough import router

#: Bound before any patching — patching ``passthrough.httpx.AsyncClient`` mutates
#: the httpx module itself, so a factory that re-reads the name recurses.
_REAL_ASYNC_CLIENT = httpx.AsyncClient

BODY = json.dumps({"choices": [{"message": {"content": "X" * 3000}}]}).encode()
GZIPPED = gzip.compress(BODY)


def _upstream(request: httpx.Request) -> httpx.Response:
    """A stand-in origin. Reports the path it was actually asked for."""
    if request.url.path != "/v1/chat/completions":
        return httpx.Response(
            200, json={"reached": request.url.path},
            headers={"content-type": "application/json"},
        )
    # The ordinary case: a provider that gzips, because they all do.
    return httpx.Response(
        200, content=GZIPPED,
        headers={
            "content-encoding": "gzip",
            "content-length": str(len(GZIPPED)),
            "content-type": "application/json",
        },
    )


def _client_factory(**kwargs):
    passthru = {k: v for k, v in kwargs.items() if k not in ("timeout", "transport")}
    return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(_upstream), **passthru)


@pytest.fixture(scope="module")
def wire_server():
    app = FastAPI()
    app.include_router(router)
    app.state.engine = None
    app.state.audit_writer = None

    patcher = patch("proxy.endpoints.passthrough.httpx.AsyncClient", _client_factory)
    patcher.start()

    # Port 0 -> the OS picks a free one, so concurrent agents cannot collide.
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
        patcher.stop()
        pytest.fail("uvicorn did not start; this test observed nothing")

    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        patcher.stop()


def raw_exchange(port: int, request_line: str, extra: str = "") -> tuple[int, dict, bytes]:
    """
    Send literal bytes; read literal bytes. Returns (status, headers, body).

    ``Connection: close`` so the body is delimited by EOF as well as by
    content-length — that is what makes a framing disagreement observable
    instead of hanging.
    """
    payload = (
        f"{request_line} HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 13\r\n"
        "Connection: close\r\n"
        f"{extra}"
        "\r\n"
        '{"model":"m"}'
    ).encode()

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        sock.sendall(payload)
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
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()
    return status, headers, body


def test_uvicorn_does_not_normalise_dot_segments(wire_server):
    """
    The premise the whole adversarial suite rests on. If uvicorn normalised the
    path, the traversal corpus would be testing something that cannot happen.

    Asserted by observation, not by reading the docs: send a dot-segment path to
    a route that echoes what it received.
    """
    status, _headers, body = raw_exchange(
        wire_server, "POST /proxy/grok/v1/audio/../../admin/keys"
    )
    # Whatever the verdict, it must be the PASSTHROUGH's verdict — a 404 would
    # mean the server rewrote the path and this test proves nothing.
    assert status != 404, (
        "the server normalised the request target; the traversal corpus is "
        "not exercising a reachable input"
    )
    assert body, "no response body — nothing was observed"


def test_traversal_prefix_does_not_reach_the_provider_host(wire_server):
    """
    RED against the pre-fix file: pre-fix this returned 200 with
    ``{"reached": "/admin/keys"}``.
    """
    status, _headers, body = raw_exchange(
        wire_server, "POST /proxy/grok/v1/audio/../../admin/keys",
        extra="Authorization: Bearer CALLER-SECRET\r\n",
    )
    assert status == 400, f"forwarded a traversal path: {body!r}"
    assert json.loads(body)["error"] == "invalid_path"
    assert b"reached" not in body

    # Positive control on the same connection shape: the legitimate path works,
    # so the assertion above is not passing because everything is refused.
    ok_status, _ok_headers, ok_body = raw_exchange(
        wire_server, "POST /proxy/grok/v1/models"
    )
    assert ok_status == 200
    assert json.loads(ok_body) == {"reached": "/v1/models"}


def test_gzip_response_is_framed_correctly_on_the_wire(wire_server):
    """
    RED against the pre-fix file: pre-fix the wire carried
    ``content-length: 80`` with 0 body bytes, and the server logged
    "Response content longer than Content-Length".
    """
    status, headers, body = raw_exchange(
        wire_server, "POST /proxy/grok/v1/chat/completions"
    )
    assert status == 200
    assert len(body) == len(BODY), (
        f"caller received {len(body)} body bytes; upstream sent {len(BODY)} "
        f"(content-length header said {headers.get('content-length')!r})"
    )
    assert body == BODY
    assert headers.get("content-length") == str(len(BODY))
    assert "content-encoding" not in headers
