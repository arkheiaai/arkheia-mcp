from __future__ import annotations

import http.server
import threading
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from arkheia_common import egress
from proxy.registry.client import RegistryClient


class _RecordingServer:
    def __init__(self, body: bytes = b"ok", content_type: str = "text/plain") -> None:
        self.body = body
        self.content_type = content_type
        self.records: list[dict[str, Any]] = []
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "_RecordingServer":
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                owner.records.append({
                    "method": "GET",
                    "path": self.path,
                    "headers": dict(self.headers.items()),
                })
                self.send_response(200)
                self.send_header("Content-Type", owner.content_type)
                self.send_header("Content-Length", str(len(owner.body)))
                self.end_headers()
                self.wfile.write(owner.body)

            def log_message(self, _format: str, *args: Any) -> None:
                return

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    @property
    def url(self) -> str:
        assert self._server is not None
        host, port = self._server.server_address
        return f"http://{host}:{port}"


class _Validator:
    def verify_checksum(self, content: bytes, checksum: str) -> bool:
        return True

    def validate(self, content: bytes) -> dict[str, Any]:
        assert content == b"profile: runtime-proof\n"
        return {"model_id": "gpt-4o"}


class _Router:
    def __init__(self) -> None:
        self.reloads = 0

    async def reload(self) -> None:
        self.reloads += 1


def test_egress_factories_force_trust_env_false(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, dict[str, Any]] = {}

    class FakeClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["sync"] = kwargs

    class FakeAsyncClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["async"] = kwargs

    monkeypatch.setattr(egress.httpx, "Client", FakeClient)
    monkeypatch.setattr(egress.httpx, "AsyncClient", FakeAsyncClient)

    egress.egress_client(timeout=1.0)
    egress.egress_async_client(timeout=2.0)

    assert captured["sync"]["trust_env"] is False
    assert captured["async"]["trust_env"] is False
    with pytest.raises(ValueError):
        egress.egress_client(trust_env=True)
    with pytest.raises(ValueError):
        egress.egress_async_client(trust_env=True)


@pytest.mark.asyncio
async def test_registry_download_does_not_use_ambient_proxy_with_bearer_key(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    secret = "ak_live_runtime_proxy_capture_key"

    with (
        _RecordingServer(body=b"profile: runtime-proof\n") as target,
        _RecordingServer(body=b"proxied") as proxy,
    ):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            monkeypatch.setenv(name, proxy.url)
        for name in ("NO_PROXY", "no_proxy"):
            monkeypatch.setenv(name, "")

        async with httpx.AsyncClient(timeout=2.0) as raw_client:
            raw_resp = await raw_client.get(
                f"{target.url}/positive-control",
                headers={"Authorization": "Bearer raw-control"},
            )
        assert raw_resp.status_code == 200
        assert proxy.records, (
            "positive control failed: raw httpx did not use the ambient HTTP_PROXY, "
            "so this runtime proof would not observe the leak class"
        )
        assert any(
            record["headers"].get("Authorization") == "Bearer raw-control"
            for record in proxy.records
        )

        proxy.records.clear()
        target.records.clear()
        router = _Router()
        client = RegistryClient(
            base_url=target.url,
            api_key=SecretStr(secret),
            profile_dir=str(tmp_path),
            router=router,
            validator=_Validator(),
        )

        applied = await client._download_and_apply({
            "model_id": "gpt-4o",
            "checksum": "",
            "download_url": f"{target.url}/profiles/gpt-4o.yaml",
        })

    assert applied is True
    assert router.reloads == 1
    assert (tmp_path / "gpt-4o.yaml").read_bytes() == b"profile: runtime-proof\n"
    assert proxy.records == [], (
        "ambient proxy captured the credentialed registry profile download"
    )
    assert any(
        record["path"] == "/profiles/gpt-4o.yaml"
        and record["headers"].get("Authorization") == f"Bearer {secret}"
        for record in target.records
    ), "target server did not receive the authorized profile download"
