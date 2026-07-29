from __future__ import annotations

import base64
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from arkheia_common.hosted_authority import (
    ALLOW_UNSAFE_HOSTED_URL_ENV,
    DEFAULT_HOSTED_API_URL,
    HostedAuthorityDecision,
    HostedAuthorityError,
    authorize_hosted_base_url,
)
from mcp_server.proxy_client import ProxyClient
from proxy.audit.decision_journal import KEY_LOAD_UNAVAILABLE, KEY_SOURCE_NONE
from proxy.crypto.profile_crypto import DynamicKeyLoader

ROOT = Path(__file__).resolve().parents[1]


class _CaptureEndpoint(http.server.BaseHTTPRequestHandler):
    requests: list[dict] = []
    payload: bytes = b"{}"
    status: int = 200

    def do_POST(self):  # noqa: N802 - http.server hook
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        type(self).requests.append({
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
        })
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).payload)))
        self.end_headers()
        self.wfile.write(type(self).payload)

    def log_message(self, *args):
        pass


@pytest.fixture
def capture_server():
    _CaptureEndpoint.requests = []
    _CaptureEndpoint.status = 200
    key = secrets.token_bytes(32)
    _CaptureEndpoint.payload = json.dumps({
        "profile_key": base64.b64encode(key).decode("ascii"),
    }).encode("utf-8")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CaptureEndpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    class _Server:
        profile_key = key

        @property
        def url(self) -> str:
            host, port = server.server_address[:2]
            return f"http://{host}:{port}"

        @property
        def requests(self) -> list[dict]:
            return _CaptureEndpoint.requests

    try:
        yield _Server()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_default_policy_allows_only_default_https_arkheia_origin(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)

    decision = authorize_hosted_base_url(DEFAULT_HOSTED_API_URL)
    assert decision.base_url == DEFAULT_HOSTED_API_URL
    assert decision.origin == DEFAULT_HOSTED_API_URL
    assert decision.self_hosted is False

    with pytest.raises(HostedAuthorityError):
        authorize_hosted_base_url("http://arkheia-proxy-production.up.railway.app")
    with pytest.raises(HostedAuthorityError):
        authorize_hosted_base_url("https://arkheia-proxy-production.up.railway.app.evil.test")
    with pytest.raises(HostedAuthorityError):
        authorize_hosted_base_url("https://evil.test")


def test_default_policy_preserves_local_self_hosted_authorities(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)

    for url in (
        "http://127.0.0.1:8098",
        "http://localhost:8098",
        "http://10.2.3.4:8098/base",
        "https://arkheia-proxy.local",
    ):
        decision = authorize_hosted_base_url(url)
        assert decision.base_url == url.rstrip("/")
        assert decision.allow_unsafe is False
        assert decision.self_hosted is True


def test_unsafe_opt_in_is_required_for_custom_hosted_authorities(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    with pytest.raises(HostedAuthorityError):
        authorize_hosted_base_url("https://custom.example.test")

    monkeypatch.setenv(ALLOW_UNSAFE_HOSTED_URL_ENV, "1")
    decision = authorize_hosted_base_url("https://custom.example.test")
    assert decision.base_url == "https://custom.example.test"
    assert decision.allow_unsafe is True


def _run_install_hosted_url_validation(url: str, *, allow_unsafe: bool = False):
    env = os.environ.copy()
    env["ARKHEIA_HOSTED_URL"] = url
    env["PATH"] = f"{Path(sys.executable).parent}{os.pathsep}{env.get('PATH', '')}"
    if allow_unsafe:
        env[ALLOW_UNSAFE_HOSTED_URL_ENV] = "1"
    else:
        env.pop(ALLOW_UNSAFE_HOSTED_URL_ENV, None)
    return subprocess.run(
        ["bash", str(ROOT / "install.sh"), "--validate-hosted-url-only"],
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )


def _last_stdout_line(result) -> str:
    return result.stdout.strip().splitlines()[-1]


def test_installer_refuses_custom_public_hosted_url_before_key_egress():
    result = _run_install_hosted_url_validation("https://evil.example.test")

    assert result.returncode != 0
    assert "hosted URL is not the approved Arkheia production authority" in result.stderr
    assert "Refusing ARKHEIA_HOSTED_URL=https://evil.example.test" in result.stderr


def test_installer_allows_default_private_and_explicitly_opted_in_custom_urls():
    default = _run_install_hosted_url_validation(DEFAULT_HOSTED_API_URL)
    assert default.returncode == 0, default.stderr
    assert _last_stdout_line(default) == DEFAULT_HOSTED_API_URL

    private = _run_install_hosted_url_validation("http://127.0.0.1:8098/base/")
    assert private.returncode == 0, private.stderr
    assert _last_stdout_line(private) == "http://127.0.0.1:8098/base"

    custom = _run_install_hosted_url_validation(
        "https://custom.example.test/root",
        allow_unsafe=True,
    )
    assert custom.returncode == 0, custom.stderr
    assert _last_stdout_line(custom) == "https://custom.example.test/root"


def test_installer_key_bearing_curls_use_authorized_hosted_url_not_raw_env():
    source = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert '"${AUTHORIZED_HOSTED_URL}/v1/provision"' in source
    assert '"${AUTHORIZED_HOSTED_URL}/v1/detect"' in source
    assert '"${HOSTED_URL}/v1/provision"' not in source
    assert '"${HOSTED_URL}/v1/detect"' not in source


@pytest.mark.asyncio
async def test_detect_verify_does_not_send_api_key_to_foreign_hosted_url(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    client = ProxyClient(
        base_url="http://local-proxy.invalid",
        hosted_url="https://evil.test",
        api_key="ak_live_should_not_leave",
    )
    client._local_available = False

    post = AsyncMock()
    with patch("httpx.AsyncClient.post", post):
        result = await client.verify("prompt", "response", "gpt-4o")

    assert result["error"] == "hosted_authority_rejected"
    post.assert_not_called()


@pytest.mark.asyncio
async def test_detect_verify_sends_api_key_to_custom_host_only_after_opt_in(monkeypatch):
    monkeypatch.setenv(ALLOW_UNSAFE_HOSTED_URL_ENV, "1")
    client = ProxyClient(
        base_url="http://local-proxy.invalid",
        hosted_url="https://evil.test",
        api_key="ak_live_explicitly_opted_in",
    )
    client._local_available = False

    hosted_response = MagicMock()
    hosted_response.json.return_value = {
        "risk": "LOW",
        "confidence": 0.9,
        "features_triggered": [],
        "detection_id": "det_custom",
    }
    hosted_response.raise_for_status = MagicMock()

    post = AsyncMock(return_value=hosted_response)
    with patch("httpx.AsyncClient.post", post):
        result = await client.verify("prompt", "response", "gpt-4o")

    assert result["source"] == "hosted"
    post.assert_awaited_once()
    assert post.await_args.args[0] == "https://evil.test/v1/detect"
    assert post.await_args.kwargs["headers"] == {
        "X-Arkheia-Key": "ak_live_explicitly_opted_in",
    }


@pytest.mark.asyncio
async def test_detect_verify_posts_to_the_authorized_base_url_not_the_configured_url():
    client = ProxyClient(
        base_url="http://local-proxy.invalid",
        hosted_url="https://configured-authority.test/original",
        api_key="ak_live_authorized_base",
    )
    client._local_available = False

    hosted_response = MagicMock()
    hosted_response.json.return_value = {
        "risk": "LOW",
        "confidence": 0.9,
        "features_triggered": [],
        "detection_id": "det_authorized",
    }
    hosted_response.raise_for_status = MagicMock()
    post = AsyncMock(return_value=hosted_response)
    calls = []

    def fake_authorize(url):
        calls.append(url)
        return HostedAuthorityDecision(
            base_url="https://authorized-authority.test/base",
            origin="https://authorized-authority.test",
            allow_unsafe=True,
        )

    with patch("mcp_server.proxy_client.authorize_hosted_base_url", side_effect=fake_authorize), \
            patch("httpx.AsyncClient.post", post):
        result = await client.verify("prompt", "response", "gpt-4o")

    assert result["source"] == "hosted"
    assert calls == ["https://configured-authority.test/original"]
    post.assert_awaited_once()
    assert post.await_args.args[0] == "https://authorized-authority.test/base/v1/detect"
    assert post.await_args.kwargs["headers"] == {"X-Arkheia-Key": "ak_live_authorized_base"}


@pytest.mark.asyncio
async def test_profile_key_fetch_does_not_send_api_key_to_foreign_hosted_url(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    loader = DynamicKeyLoader("https://evil.test", "ak_live_should_not_leave")

    post = AsyncMock()
    with patch("httpx.AsyncClient.post", post):
        assert await loader._fetch_from_hosted() is None
    post.assert_not_called()
    assert loader.last_error_type == "HostedAuthorityError"


@pytest.mark.asyncio
async def test_profile_key_authority_rejection_is_recorded_in_key_load_decision(monkeypatch):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    loader = DynamicKeyLoader("https://evil.test", "ak_live_should_not_leave")

    with patch("httpx.AsyncClient.post", AsyncMock()) as post:
        assert await loader.fetch_key() is None

    post.assert_not_called()
    rows, dropped = loader.decision_journal.drain()
    assert dropped == 0
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_UNAVAILABLE
    assert rows[0]["key_source"] == KEY_SOURCE_NONE
    assert rows[0]["hosted_origin"] == "https://evil.test"
    assert rows[0]["error_type"] == "HostedAuthorityError"


@pytest.mark.asyncio
async def test_profile_key_fetch_allows_local_self_hosted_url_without_unsafe_opt_in(
    capture_server, monkeypatch
):
    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    loader = DynamicKeyLoader(capture_server.url, "ak_live_self_hosted")

    assert await loader._fetch_from_hosted() == capture_server.profile_key
    assert len(capture_server.requests) == 1
    assert capture_server.requests[0]["path"] == "/v1/profile-key"
    assert capture_server.requests[0]["headers"]["X-Arkheia-Key"] == "ak_live_self_hosted"


@pytest.mark.asyncio
async def test_profile_key_fetch_sends_api_key_to_custom_host_only_after_opt_in(monkeypatch):
    monkeypatch.setenv(ALLOW_UNSAFE_HOSTED_URL_ENV, "1")
    key = secrets.token_bytes(32)
    response = httpx.Response(
        200,
        json={"profile_key": base64.b64encode(key).decode("ascii")},
        request=httpx.Request("POST", "https://evil.test/v1/profile-key"),
    )
    post = AsyncMock(return_value=response)
    loader = DynamicKeyLoader("https://evil.test", "ak_live_explicitly_opted_in")

    with patch("httpx.AsyncClient.post", post):
        assert await loader._fetch_from_hosted() == key
    post.assert_awaited_once()
    assert post.await_args.args[0] == "https://evil.test/v1/profile-key"
    assert post.await_args.kwargs["headers"] == {
        "X-Arkheia-Key": "ak_live_explicitly_opted_in",
    }


@pytest.mark.asyncio
async def test_profile_key_fetch_posts_to_the_authorized_base_url_not_the_configured_url():
    key = secrets.token_bytes(32)
    response = httpx.Response(
        200,
        json={"profile_key": base64.b64encode(key).decode("ascii")},
        request=httpx.Request("POST", "https://authorized-authority.test/base/v1/profile-key"),
    )
    post = AsyncMock(return_value=response)
    calls = []

    def fake_authorize(url):
        calls.append(url)
        return HostedAuthorityDecision(
            base_url="https://authorized-authority.test/base",
            origin="https://authorized-authority.test",
            allow_unsafe=True,
        )

    loader = DynamicKeyLoader(
        "https://configured-authority.test/original",
        "ak_live_authorized_profile_key",
    )
    with patch("proxy.crypto.profile_crypto.authorize_hosted_base_url", side_effect=fake_authorize), \
            patch("httpx.AsyncClient.post", post):
        assert await loader._fetch_from_hosted() == key

    assert calls == ["https://configured-authority.test/original"]
    post.assert_awaited_once()
    assert post.await_args.args[0] == "https://authorized-authority.test/base/v1/profile-key"
    assert post.await_args.kwargs["headers"] == {
        "X-Arkheia-Key": "ak_live_authorized_profile_key",
    }


@pytest.mark.asyncio
async def test_detect_and_profile_key_share_the_same_authority_policy(monkeypatch):
    """
    One opt-in variable must govern both key-bearing hosted paths.

    This drives both callers against the same foreign origin with the opt-in off,
    then on. If either path forks the policy, one half of this test changes
    behaviour while the other does not.
    """
    foreign = "https://foreign-authority.test"

    monkeypatch.delenv(ALLOW_UNSAFE_HOSTED_URL_ENV, raising=False)
    client = ProxyClient("http://local.invalid", hosted_url=foreign, api_key="ak_detect")
    client._local_available = False
    with patch("httpx.AsyncClient.post", AsyncMock()) as detect_post:
        detect_blocked = await client.verify("p", "r", "m")
    assert detect_blocked["error"] == "hosted_authority_rejected"
    detect_post.assert_not_called()

    loader = DynamicKeyLoader(foreign, "ak_profile")
    with patch("httpx.AsyncClient.post", AsyncMock()) as profile_post:
        assert await loader._fetch_from_hosted() is None
    profile_post.assert_not_called()

    monkeypatch.setenv(ALLOW_UNSAFE_HOSTED_URL_ENV, "1")
    hosted_response = MagicMock()
    hosted_response.json.return_value = {
        "risk": "LOW",
        "confidence": 0.1,
        "features_triggered": [],
        "detection_id": "det",
    }
    hosted_response.raise_for_status = MagicMock()
    profile_response = httpx.Response(
        200,
        json={"profile_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii")},
        request=httpx.Request("POST", f"{foreign}/v1/profile-key"),
    )

    client = ProxyClient("http://local.invalid", hosted_url=foreign, api_key="ak_detect")
    client._local_available = False
    loader = DynamicKeyLoader(foreign, "ak_profile")
    with patch("httpx.AsyncClient.post", AsyncMock(side_effect=[hosted_response, profile_response])) as post:
        assert (await client.verify("p", "r", "m"))["source"] == "hosted"
        assert await loader._fetch_from_hosted() is not None

    assert [call.args[0] for call in post.await_args_list] == [
        f"{foreign}/v1/detect",
        f"{foreign}/v1/profile-key",
    ]
