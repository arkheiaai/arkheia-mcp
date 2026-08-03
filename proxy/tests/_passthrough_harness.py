"""
Shared harness for the passthrough adversarial / receipt suites.

Two things the pre-existing suite could not do, and why each is load-bearing.

1. **Drive the app the way a wire client does.**
   Every HTTP client — including ``TestClient`` and every ``httpx`` transport —
   removes dot segments from the request URL *before it sends it*. So a test
   that asks ``TestClient`` for ``/proxy/grok/v1/audio/../../admin`` never
   delivers that path to the application; it delivers ``/proxy/admin`` and gets
   a 404. The attack is invisible to any test written through a client.

   A real server does NOT normalise: uvicorn percent-decodes the request target
   and hands the raw path to the ASGI app. ``asgi_request`` builds exactly that
   scope, so the path under test is the path the endpoint sees.
   ``proxy/tests/test_passthrough_wire.py`` corroborates this against a real
   uvicorn socket — two transports, per the "advertised identifier" floor rule.

2. **Assert on the bytes that leave, not on a mock's call args.**
   ``capture_upstream`` substitutes a REAL ``httpx.AsyncClient`` over a
   ``MockTransport``. Everything httpx does to build a request — URL parsing and
   dot-segment removal, header serialisation, content-length computation,
   redirect policy — runs for real, and the captured object is the
   ``httpx.Request`` that would have gone on the wire. A ``MagicMock`` client
   (what the pre-existing suite uses) records the *arguments* and therefore
   cannot see any of it: ``url="https://api.x.ai/v1/audio/../../admin"`` and
   ``url="https://api.x.ai/admin"`` are indistinguishable to it.

   The real class is bound at import, BEFORE any patching: the module under test
   does ``import httpx`` and reads ``httpx.AsyncClient``, so patching
   ``proxy.endpoints.passthrough.httpx.AsyncClient`` mutates the httpx module
   itself and a factory that re-reads the name recurses forever.
"""
from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from unittest.mock import patch

import httpx
from fastapi import FastAPI

from proxy.endpoints.passthrough import router

#: Bound before any patch() call — see module docstring.
_REAL_ASYNC_CLIENT = httpx.AsyncClient


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

def make_app(engine: Any = None, audit_writer: Any = None) -> FastAPI:
    """A FastAPI app carrying only the passthrough router and the state it reads."""
    app = FastAPI()
    app.include_router(router)
    app.state.engine = engine
    app.state.audit_writer = audit_writer
    return app


# ---------------------------------------------------------------------------
# Raw ASGI driver
# ---------------------------------------------------------------------------

@dataclass
class AsgiResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> Optional[str]:
        name = name.lower()
        for k, v in self.headers:
            if k.lower() == name:
                return v
        return None

    def header_names(self) -> set[str]:
        return {k.lower() for k, _ in self.headers}

    def json(self) -> Any:
        return json.loads(self.body)


async def asgi_request(
    app: FastAPI,
    method: str,
    path: str,
    *,
    query_string: bytes = b"",
    headers: Optional[list[tuple[str, str]]] = None,
    body: bytes = b"{}",
) -> AsgiResponse:
    """
    Call ``app`` with the scope uvicorn would build.

    ``path`` is used verbatim: percent-decoded, dot segments intact — exactly
    what a real server hands the application.
    """
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1"))
                   for k, v in (headers or [])]
    if not any(k == b"content-type" for k, _ in raw_headers):
        raw_headers.append((b"content-type", b"application/json"))
    raw_headers.append((b"content-length", str(len(body)).encode()))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8", "surrogateescape"),
        "query_string": query_string,
        "root_path": "",
        "headers": raw_headers,
        "client": ("127.0.0.1", 51234),
        "server": ("127.0.0.1", 8098),
    }

    messages: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict) -> None:
        messages.append(message)

    await app(scope, receive, send)

    start = next(m for m in messages if m["type"] == "http.response.start")
    payload = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    return AsgiResponse(
        status=start["status"],
        headers=[(k.decode("latin-1"), v.decode("latin-1")) for k, v in start["headers"]],
        body=payload,
    )


# ---------------------------------------------------------------------------
# Upstream capture
# ---------------------------------------------------------------------------

@dataclass
class UpstreamLog:
    """What the module actually did with the network."""
    requests: list[httpx.Request] = field(default_factory=list)
    client_kwargs: list[dict] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.requests)

    @property
    def last(self) -> httpx.Request:
        assert self.requests, "no upstream request was made"
        return self.requests[-1]

    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]


def json_response(payload: dict, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    def _responder(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json=payload)
    return _responder


OPENAI_OK = json_response({"choices": [{"message": {"content": "Four"}}]})


@contextlib.contextmanager
def capture_upstream(responder: Callable[[httpx.Request], httpx.Response] = OPENAI_OK):
    """
    Patch the module's httpx client with a REAL client over ``MockTransport``.

    Yields an ``UpstreamLog`` recording every request that would have left and
    the kwargs every client was constructed with (so redirect policy is an
    assertable fact, not a claim about a default).
    """
    log = UpstreamLog()

    def _factory(**kwargs):
        log.client_kwargs.append(dict(kwargs))

        def _handler(request: httpx.Request) -> httpx.Response:
            log.requests.append(request)
            return responder(request)

        passthru = {k: v for k, v in kwargs.items()
                    if k not in ("timeout", "transport")}
        return _REAL_ASYNC_CLIENT(transport=httpx.MockTransport(_handler), **passthru)

    with patch("proxy.endpoints.passthrough.httpx.AsyncClient", _factory):
        yield log
