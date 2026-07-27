from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import pytest

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
