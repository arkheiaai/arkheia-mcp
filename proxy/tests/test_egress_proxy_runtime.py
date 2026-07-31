from __future__ import annotations

import http.server
import json
import threading
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from pydantic import SecretStr
from starlette.requests import Request

from arkheia_common.egress import egress_async_client
from mcp_server.proxy_client import ProxyClient
from mcp_server.tools import providers
from proxy.endpoints import passthrough
from proxy.middleware.interception import AIInterceptionMiddleware
from proxy.registry.client import RegistryClient


class _TargetEndpoint(http.server.BaseHTTPRequestHandler):
    requests: list[dict] = []
    routes: dict[str, tuple[int, bytes, str]] = {}

    def do_GET(self):  # noqa: N802 - http.server hook
        self._handle()

    def do_POST(self):  # noqa: N802 - http.server hook
        self._handle()

    def _handle(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        type(self).requests.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        path = self.path.split("?", 1)[0]
        status, payload, content_type = type(self).routes.get(
            path, (200, b"{}", "application/json")
        )
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


class _AttackerProxyEndpoint(http.server.BaseHTTPRequestHandler):
    requests: list[dict] = []

    def do_CONNECT(self):  # noqa: N802 - http.server hook
        self._record()
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 - http.server hook
        self._record()
        self._deny()

    def do_POST(self):  # noqa: N802 - http.server hook
        self._record()
        self._deny()

    def _record(self) -> None:
        length = int(self.headers.get("content-length", "0") or "0")
        body = self.rfile.read(length) if length else b""
        type(self).requests.append({
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })

    def _deny(self) -> None:
        self.send_response(502)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _Server:
    def __init__(
        self,
        server: http.server.ThreadingHTTPServer,
        thread: threading.Thread,
        handler,
    ):
        self._server = server
        self._thread = thread
        self._handler = handler

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    @property
    def requests(self) -> list[dict]:
        return self._handler.requests

    def clear(self) -> None:
        self._handler.requests = []

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _json_bytes(data: dict) -> bytes:
    return json.dumps(data).encode("utf-8")


@pytest.fixture
def target_server():
    _TargetEndpoint.requests = []
    _TargetEndpoint.routes = {
        "/credentialed-target": (200, _json_bytes({"ok": True}), "application/json"),
        "/profiles": (200, _json_bytes({"profiles": []}), "application/json"),
        "/v1/events/proxy": (202, _json_bytes({"accepted": True}), "application/json"),
        "/oauth/token": (
            200,
            _json_bytes({"access_token": "target-access-token"}),
            "application/json",
        ),
        "/oauth/userinfo": (
            200,
            _json_bytes({"email": "user@example.test", "name": "User"}),
            "application/json",
        ),
        "/passthrough": (
            200,
            _json_bytes({"choices": [{"message": {"content": "provider answer"}}]}),
            "application/json",
        ),
        "/v1/chat/completions": (
            200,
            _json_bytes({"choices": [{"message": {"content": "intercepted answer"}}]}),
            "application/json",
        ),
        "/detect/verify": (
            200,
            _json_bytes({
                "risk_level": "LOW",
                "confidence": 0.9,
                "features_triggered": [],
                "detection_id": "det-local",
                "detection_method": "test",
                "evidence_depth_limited": False,
            }),
            "application/json",
        ),
        "/audit/log": (
            200,
            _json_bytes({"events": [], "summary": {}}),
            "application/json",
        ),
        "/api/generate": (
            200,
            _json_bytes({"response": "ollama answer", "eval_count": 1}),
            "application/json",
        ),
    }
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _TargetEndpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    handle = _Server(server, thread, _TargetEndpoint)
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture
def attacker_proxy():
    _AttackerProxyEndpoint.requests = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AttackerProxyEndpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    handle = _Server(server, thread, _AttackerProxyEndpoint)
    try:
        yield handle
    finally:
        handle.close()


def _point_proxy_env(monkeypatch: pytest.MonkeyPatch, proxy_url: str) -> None:
    for name in (
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.setenv(name, proxy_url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)


def _header(request: dict, name: str) -> str | None:
    lowered = name.lower()
    for key, value in request["headers"].items():
        if key.lower() == lowered:
            return value
    return None


def _request_for_path(server: _Server, path: str) -> dict:
    for request in server.requests:
        if request["path"].split("?", 1)[0] == path:
            return request
    raise AssertionError(f"{path} was not requested; saw {[r['path'] for r in server.requests]}")


async def _assert_plain_httpx_proxy_capture_is_observable(target_server: _Server) -> None:
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.post(
            f"{target_server.url}/credentialed-target",
            headers={"Authorization": "Bearer attacker-visible"},
            json={"probe": True},
        )
    assert response.status_code == 502


async def _assert_plain_httpx_https_proxy_connect_is_observable() -> None:
    async with httpx.AsyncClient(timeout=2.0) as client:
        with pytest.raises(httpx.HTTPError):
            await client.post(
                "https://credentialed-provider.example.test/v1/chat/completions",
                headers={"Authorization": "Bearer https-attacker-routable"},
                json={"probe": True},
            )


async def _forward_passthrough(target_server: _Server) -> None:
    async def receive():
        return {
            "type": "http.request",
            "body": b'{"messages":[{"role":"user","content":"hi"}]}',
            "more_body": False,
        }

    request = Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/proxy/grok/v1/chat/completions",
        "raw_path": b"/proxy/grok/v1/chat/completions",
        "query_string": b"",
        "headers": [
            (b"authorization", b"Bearer passthrough-provider-secret"),
            (b"content-type", b"application/json"),
        ],
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
    }, receive)

    body, status_code, _headers = await passthrough._forward(
        request,
        f"{target_server.url}/passthrough",
    )
    assert status_code == 200
    assert b"provider answer" in body


async def _forward_interception(target_server: _Server) -> None:
    app = FastAPI()
    app.add_middleware(AIInterceptionMiddleware)
    app.state.engine = None
    app.state.settings = SimpleNamespace(
        detection=SimpleNamespace(
            upstream_url=target_server.url,
            high_risk_action="warn",
            unknown_action="pass",
        )
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://proxy-under-test",
        trust_env=False,
    ) as client:
        response = await client.post(
            "/v1/chat/completions",
            headers={"Authorization": "Bearer intercepted-provider-secret"},
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )
    assert response.status_code == 200
    assert b"intercepted answer" in response.content


@pytest.mark.asyncio
async def test_credentialed_production_egress_ignores_ambient_proxy_capture(
    target_server,
    attacker_proxy,
    monkeypatch,
    tmp_path,
):
    _point_proxy_env(monkeypatch, attacker_proxy.url)

    await _assert_plain_httpx_proxy_capture_is_observable(target_server)
    assert attacker_proxy.requests, "negative control did not observe proxy capture"
    assert any(
        _header(request, "authorization") == "Bearer attacker-visible"
        for request in attacker_proxy.requests
    )

    await _assert_plain_httpx_https_proxy_connect_is_observable()
    assert any(
        request["method"] == "CONNECT"
        and request["path"] == "credentialed-provider.example.test:443"
        for request in attacker_proxy.requests
    ), "negative control did not observe HTTPS proxy CONNECT capture"

    attacker_proxy.clear()
    target_server.clear()

    async with egress_async_client(timeout=2.0) as client:
        response = await client.post(
            f"{target_server.url}/credentialed-target",
            headers={"Authorization": "Bearer direct-helper-secret"},
            json={"probe": True},
        )
    assert response.status_code == 200

    registry = RegistryClient(
        base_url=target_server.url,
        api_key=SecretStr("registry-secret"),
        profile_dir=str(tmp_path),
        router=SimpleNamespace(reload=lambda: None),
    )
    assert await registry.pull() == {"updated": [], "skipped": [], "errors": []}

    import proxy.detection_adapter as detection_adapter

    # ENV, not module attributes. `sweep/mcp-governance-adapter-push` replaced the
    # import-time `DETECTION_ADAPTER_*` constants with `detection_adapter._config()`,
    # which reads os.environ at CALL time. Setting env drives the same read the
    # production path takes, so this test still configures the real flow — and it
    # still proves the point it exists for: the push below must reach
    # `target_server` directly, never the ambient capture proxy.
    monkeypatch.setenv("DETECTION_ADAPTER_URL", target_server.url)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", "adapter-secret")
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", "adapter-key-id")
    await detection_adapter.push_event(
        "tenant",
        "source",
        "completion",
        {"prompt_hash": "abc"},
        "LOW",
    )

    import proxy.auth as auth

    monkeypatch.setattr(auth, "GOOGLE_CLIENT_ID", "google-client")
    monkeypatch.setattr(auth, "GOOGLE_CLIENT_SECRET", "google-client-secret")
    monkeypatch.setattr(auth, "GOOGLE_REDIRECT_URI", "http://localhost/auth/callback")
    monkeypatch.setattr(auth, "GOOGLE_TOKEN_URL", f"{target_server.url}/oauth/token")
    monkeypatch.setattr(auth, "GOOGLE_USERINFO_URL", f"{target_server.url}/oauth/userinfo")
    assert (await auth.exchange_google_code("oauth-code"))["email"] == "user@example.test"

    await _forward_passthrough(target_server)
    await _forward_interception(target_server)

    proxy_client = ProxyClient(target_server.url, api_key="ak_unused")
    assert (await proxy_client.verify("prompt", "response", "gpt-4o"))["source"] == "local"
    assert await proxy_client.get_audit_log() == {"events": [], "summary": {}}

    monkeypatch.setenv("OLLAMA_BASE_URL", target_server.url)
    assert (await providers.call_ollama("prompt", model="phi4"))["response"] == "ollama answer"

    assert attacker_proxy.requests == []
    assert _header(_request_for_path(target_server, "/credentialed-target"), "authorization") == (
        "Bearer direct-helper-secret"
    )
    assert _header(_request_for_path(target_server, "/profiles"), "authorization") == (
        "Bearer registry-secret"
    )
    assert _header(_request_for_path(target_server, "/v1/events/proxy"), "x-arkheia-signature")
    assert b"google-client-secret" in _request_for_path(target_server, "/oauth/token")["body"]
    assert _header(_request_for_path(target_server, "/oauth/userinfo"), "authorization") == (
        "Bearer target-access-token"
    )
    assert _header(_request_for_path(target_server, "/passthrough"), "authorization") == (
        "Bearer passthrough-provider-secret"
    )
    assert _header(_request_for_path(target_server, "/v1/chat/completions"), "authorization") == (
        "Bearer intercepted-provider-secret"
    )
