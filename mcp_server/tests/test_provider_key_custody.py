from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest

from mcp_server.tool_registry import PolicyViolation, REGISTRY
from mcp_server.tools import providers


class _LeakingClient:
    def __init__(self, secret: str, seen: dict[str, bool]):
        self._secret = secret
        self._seen = seen

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def post(self, url: str, **kwargs: Any):
        rendered = f"url={url} kwargs={kwargs!r}"
        self._seen["outbound_had_secret"] = self._secret in rendered
        raise RuntimeError(f"transport failure carried {rendered}")


class _ProviderResponse:
    def __init__(self, provider: str):
        self.provider = provider

    def raise_for_status(self):
        return None

    def json(self):
        if self.provider == "google":
            return {
                "candidates": [{"content": {"parts": [{"text": "stub"}]}}],
                "usageMetadata": {},
            }
        return {
            "choices": [{"message": {"content": "stub"}}],
            "usage": {},
        }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("env_name", "secret", "call"),
    [
        (
            "XAI_API_KEY",
            "xai-" + "A" * 40,
            lambda prompt: providers.call_grok(prompt),
        ),
        (
            "GOOGLE_API_KEY",
            "AIzaSy" + "B" * 33,
            lambda prompt: providers.call_gemini(prompt),
        ),
        (
            "TOGETHER_API_KEY",
            "tg-" + "C" * 48,
            lambda prompt: providers.call_together(prompt),
        ),
    ],
)
async def test_provider_transport_exception_does_not_return_or_log_api_key(
    monkeypatch,
    caplog,
    env_name: str,
    secret: str,
    call: Callable[[str], Any],
):
    seen = {"outbound_had_secret": False}
    monkeypatch.setenv(env_name, secret)
    monkeypatch.setattr(
        providers.httpx,
        "AsyncClient",
        lambda *a, **k: _LeakingClient(secret, seen),
    )

    with caplog.at_level(logging.ERROR, logger=providers.logger.name):
        result = await call("prompt that must be hashed, not echoed")

    assert seen["outbound_had_secret"], (
        "positive control failed: the fake transport never observed the API key "
        "in the request arguments, so this was not a leak-bearing path"
    )
    rendered_result = json.dumps(result, sort_keys=True)
    assert result["error"] == "RuntimeError"
    assert result["response"] == "[provider_error: RuntimeError]"
    assert secret not in rendered_result
    assert secret not in caplog.text
    assert "transport failure carried" not in rendered_result
    assert "transport failure carried" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_name", "call"),
    [
        ("xai", lambda prompt: providers.call_grok(prompt)),
        ("google", lambda prompt: providers.call_gemini(prompt)),
        ("together", lambda prompt: providers.call_together(prompt)),
    ],
)
async def test_provider_calls_obtain_keys_only_through_custody(
    monkeypatch,
    provider_name: str,
    call: Callable[[str], Any],
):
    for env_name in ("XAI_API_KEY", "GOOGLE_API_KEY", "TOGETHER_API_KEY"):
        monkeypatch.delenv(env_name, raising=False)

    secret = f"custody-{provider_name}-secret"
    custody_calls: list[str] = []
    outbound: list[str] = []

    def fake_provider_api_key(provider: str) -> str:
        custody_calls.append(provider)
        return secret

    async def fake_provider_post(provider: str, client: Any, url: str, **kwargs: Any):
        assert provider == provider_name
        rendered = repr(kwargs)
        assert secret in rendered, "positive control: custody key reached the request"
        outbound.append(rendered)
        return _ProviderResponse(provider)

    monkeypatch.setattr(providers, "provider_api_key", fake_provider_api_key)
    monkeypatch.setattr(providers, "_provider_post", fake_provider_post)

    result = await call("prompt")

    assert custody_calls == [provider_name]
    assert outbound, "provider call never reached the outbound chokepoint"
    assert result["error"] is None
    assert result["response"] == "stub"


@pytest.mark.asyncio
async def test_provider_http_chokepoint_refuses_when_cloud_egress_disabled(monkeypatch):
    class _TripwireClient:
        called = False

        async def post(self, url: str, **kwargs: Any):
            self.called = True
            raise AssertionError("client.post must not run when egress is disabled")

    registry = dict(REGISTRY)
    registry["run_grok"] = replace(REGISTRY["run_grok"], network_egress=False)
    monkeypatch.setattr(providers, "REGISTRY", registry)

    client = _TripwireClient()
    with pytest.raises(PolicyViolation) as exc:
        await providers._provider_post("xai", client, "https://api.x.ai/v1/chat/completions")

    assert "network egress" in str(exc.value)
    assert client.called is False


@pytest.mark.asyncio
async def test_gemini_parse_failure_uses_named_placeholder_not_raw_exception(
    monkeypatch,
    caplog,
):
    secret = "AIzaSy" + "D" * 33
    monkeypatch.setenv("GOOGLE_API_KEY", secret)

    class _BadShapeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"candidates": []}

    class _BadShapeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, url: str, **kwargs: Any):
            assert secret in repr(kwargs), "positive control: key is in query params"
            return _BadShapeResponse()

    monkeypatch.setattr(providers.httpx, "AsyncClient", lambda *a, **k: _BadShapeClient())

    with caplog.at_level(logging.ERROR, logger=providers.logger.name):
        result = await providers.call_gemini("prompt")

    rendered_result = json.dumps(result, sort_keys=True)
    assert result["error"] == "parse_error"
    assert result["response"] == "[provider_error: parse_error]"
    assert secret not in rendered_result
    assert secret not in caplog.text
