"""B336 High3: actual registry download authority and durable refusal path."""
import json
import logging
import traceback
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlsplit

import httpx
import pytest
from pydantic import SecretStr

from proxy.registry import client as registry_module
from proxy.registry.client import RegistryApplyError, RegistryClient
from proxy.registry.receipts import OUTCOME_PROFILE_APPLY_FAILED, OUTCOME_PROFILE_DOWNLOAD_FAILED
from proxy.registry.validator import ProfileValidator
from proxy.tests._receipt_probe import ReceiptProbe
from proxy.tests.test_registry import VALID_CHECKSUM, VALID_PROFILE, VALID_YAML

_BASE = "https://registry.example.test"
_GOOD = _BASE + "/profiles/download?model_id=llama-3-70b"
_PRIVATE_PART = "local-fixture-" + "p" * 32
_BAD = [
    "https://foreign.example.test/profile",
    "http://registry.example.test/profile",
    "https://registry.example.test:444/profile",
    "https://user:local@registry.example.test/profile",
    "/relative/profile",
    "//registry.example.test/profile",
    _GOOD + "#fragment",
    "https://registry.example.test:invalid/profile",
    "ftp://registry.example.test/profile",
    "https://xn--.example.test/profile",
    "https://registry.example.test./profile",
    "https://registry.example.test:0/profile",
    False, 0, 1, [], {},
]


def _meta(url, model_id="llama-3-70b"):
    return {"model_id": model_id, "version": "2.0", "checksum": VALID_CHECKSUM, "download_url": url}


def _client(tmp_path, base=_BASE, writer=None):
    material = MagicMock(spec=SecretStr)
    material.get_secret_value.return_value = "local-fixture-" + "k" * 32
    router = AsyncMock()
    router.get = MagicMock(return_value=VALID_PROFILE)
    client = RegistryClient(base, material, str(tmp_path / "profiles"), router,
                            validator=ProfileValidator(), audit_writer=writer)
    return client, material, router


def _http(monkeypatch, handler):
    requests, get_args = [], []

    def transport(request):
        requests.append(request)
        return handler(request)

    class RecordingClient(httpx.AsyncClient):
        async def get(self, url, **kwargs):
            get_args.append((url, kwargs.copy()))
            return await super().get(url, **kwargs)

    def factory(**kwargs):
        return RecordingClient(transport=httpx.MockTransport(transport), trust_env=False, **kwargs)

    monkeypatch.setattr(registry_module, "egress_async_client", factory)
    return requests, get_args


@pytest.mark.asyncio
@pytest.mark.parametrize("url", _BAD)
async def test_refused_download_does_not_read_key_or_contact_transport(tmp_path, monkeypatch, url):
    client, material, router = _client(tmp_path)
    target = tmp_path / "profiles/llama-3-70b.yaml"
    target.parent.mkdir()
    target.write_bytes(b"original-profile")
    requests, _ = _http(monkeypatch, lambda _: httpx.Response(200, content=VALID_YAML))
    with pytest.raises(RegistryApplyError) as caught:
        await client._download_and_apply(_meta(url))
    assert caught.value.outcome == OUTCOME_PROFILE_DOWNLOAD_FAILED
    assert material.get_secret_value.call_count == 0
    assert requests == []
    assert target.read_bytes() == b"original-profile"
    router.reload.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("base,url", [
    ("https://REGISTRY.example.test:443", _GOOD),
    ("http://registry.example.test:80", "http://registry.example.test/profiles/download"),
    ("http://registry:8200", "http://registry:8200/profiles/download"),
    ("http://[::1]:8200", "http://[::1]:8200/profiles/download"),
    ("https://bücher.example", "https://xn--bcher-kva.example/profiles/download"),
    ("https://configured:local@registry.example.test", _GOOD),
])
async def test_wire_origin_positive_controls_apply_real_profile(tmp_path, monkeypatch, base, url):
    client, material, router = _client(tmp_path, base)
    requests, _ = _http(monkeypatch, lambda _: httpx.Response(200, content=VALID_YAML))
    assert await client._download_and_apply(_meta(url)) is True
    assert (tmp_path / "profiles/llama-3-70b.yaml").read_bytes() == VALID_YAML
    assert len(requests) == 1
    assert requests[0].headers["Authorization"] == "Bearer " + material.get_secret_value.return_value
    assert requests[0].url.raw_host == httpx.URL(url).raw_host
    router.reload.assert_awaited_once()


@pytest.mark.asyncio
async def test_equivalent_ip_spellings_do_not_expand_wire_origin(tmp_path, monkeypatch):
    client, material, _ = _client(tmp_path, "http://[::1]:8200")
    requests, _ = _http(monkeypatch, lambda _: httpx.Response(200, content=VALID_YAML))
    with pytest.raises(RegistryApplyError):
        await client._download_and_apply(_meta("http://[0:0::1]:8200/profiles/download"))
    assert material.get_secret_value.call_count == 0 and requests == []


@pytest.mark.asyncio
async def test_validated_object_is_requested_with_redirects_explicitly_disabled(tmp_path, monkeypatch):
    client, _, _ = _client(tmp_path)
    _, calls = _http(monkeypatch, lambda _: httpx.Response(200, content=VALID_YAML))
    assert await client._download_and_apply(_meta(_GOOD))
    assert isinstance(calls[0][0], httpx.URL)
    assert calls[0][1]["follow_redirects"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [*_BAD, None, ""])
async def test_pull_receipts_every_refused_url_and_continues(tmp_path, monkeypatch, caplog, url):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        client, material, _ = _client(tmp_path, writer=probe.writer)
        old = tmp_path / "profiles/refused-profile.yaml"
        old.parent.mkdir()
        old.write_bytes(b"original-profile")

        def handler(request):
            if request.url.path == "/profiles":
                return httpx.Response(200, json={"profiles": [_meta(url, "refused-profile"), _meta(_GOOD)]})
            return httpx.Response(200, content=VALID_YAML)

        requests, calls = _http(monkeypatch, handler)
        caplog.set_level(logging.ERROR, logger="proxy.registry.client")
        result = await client.pull()
        assert result["updated"] == ["llama-3-70b"]
        assert len(result["errors"]) == 1
        assert len(requests) == 2  # listing and the following authorized profile
        assert material.get_secret_value.call_count == 2
        assert all(call[1].get("follow_redirects") is False for call in calls)
        assert old.read_bytes() == b"original-profile"
        rows = probe.rows()
        refused = [row for row in rows if row.get("model_id") == "refused-profile"]
        assert len(refused) == 1
        missing = url is None or url == ""
        assert refused[0]["outcome"] == (OUTCOME_PROFILE_APPLY_FAILED if missing else OUTCOME_PROFILE_DOWNLOAD_FAILED)
        origin = refused[0]["download_origin"]
        if origin is not None:
            parsed = urlsplit(origin)
            assert parsed.scheme and parsed.netloc
            assert parsed.username is None and parsed.password is None
            assert parsed.path == parsed.query == parsed.fragment == ""
            assert origin == f"{parsed.scheme}://{parsed.netloc}"
        if isinstance(url, str) and "user:local@" in url:
            assert "user:local" not in json.dumps(rows)
    finally:
        await probe.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["redirect", "http", "transport"])
async def test_download_errors_do_not_echo_urls_into_api_receipts_or_app_logs(tmp_path, monkeypatch, caplog, mode):
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await probe.start()
    try:
        client, _, router = _client(tmp_path, writer=probe.writer)
        old = tmp_path / "profiles/llama-3-70b.yaml"
        old.parent.mkdir()
        old.write_bytes(b"original-profile")
        source = _GOOD + "&private=" + _PRIVATE_PART

        def handler(request):
            if request.url.path == "/profiles":
                return httpx.Response(200, json={"profiles": [_meta(source)]})
            if mode == "redirect":
                return httpx.Response(302, headers={"Location": "https://foreign.example.test/private/" + _PRIVATE_PART})
            if mode == "http":
                return httpx.Response(500)
            raise httpx.ConnectError("fixture transport " + source, request=request)

        requests, _ = _http(monkeypatch, handler)
        caplog.set_level(logging.ERROR, logger="proxy.registry.client")
        result = await client.pull()
        assert len(requests) == 2
        assert result["updated"] == [] and len(result["errors"]) == 1
        assert old.read_bytes() == b"original-profile"
        router.reload.assert_not_awaited()
        assert probe.rows()[0]["outcome"] == OUTCOME_PROFILE_DOWNLOAD_FAILED
        app_logs = "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("proxy."))
        for surface in (json.dumps(result), probe.raw_bytes().decode(), app_logs):
            assert _PRIVATE_PART not in surface
            assert "foreign.example.test/private" not in surface
        if mode == "redirect":
            assert "registry profile download redirect refused" in result["errors"][0]
        with pytest.raises(RegistryApplyError) as caught:
            await client._download_and_apply(_meta(source))
        formatted = "".join(traceback.format_exception(caught.value))
        assert _PRIVATE_PART not in formatted
    finally:
        await probe.stop()
