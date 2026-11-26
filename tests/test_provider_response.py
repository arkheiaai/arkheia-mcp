"""The optional provider_response input of arkheia_verify: forwarded unchanged, checked for shape and size only."""

import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server import server as srv
from mcp_server.proxy_client import (
    MAX_PROVIDER_RESPONSE_BYTES,
    ProxyClient,
    check_provider_response,
)

REPLY = {"id": "chatcmpl-x", "choices": [{"message": {"content": "hi"}, "extra": {"n": [1, 2, {"z": None}]}}]}
OK = {"risk": "LOW", "assessed": True, "evidence_depth_limited": False, "confidence": 0.1,
      "detection_id": "det_0123456789abcdef"}


def _client():
    return ProxyClient(base_url="", hosted_url="https://hosted.example.test", api_key="ak_live_testkey")


def _hosted():
    r = MagicMock()
    r.json.return_value = dict(OK)
    r.raise_for_status = MagicMock()
    return r


@pytest.mark.asyncio
async def test_forwarded_unchanged():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_hosted()) as post:
        await _client().verify("p", "r", "m", provider_response=REPLY)
    assert post.call_args.kwargs["json"]["provider_response"] == REPLY


@pytest.mark.asyncio
async def test_without_it_the_body_is_as_before():
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_hosted()) as post:
        await _client().verify("p", "r", "m")
    assert post.call_args.kwargs["json"] == {"model": "m", "response": "r", "prompt": "p"}


def test_string_form_is_parsed():
    assert check_provider_response(json.dumps(REPLY)) == (REPLY, None)
    assert check_provider_response(REPLY) == (REPLY, None)
    assert check_provider_response(None) == (None, None)


@pytest.mark.parametrize("bad", [42, True, [1, 2], "not json", "[1,2]", "42", '"s"', "null"])
def test_non_object_is_rejected(bad):
    value, err = check_provider_response(bad)
    assert value is None and "must be a JSON object" in err


def test_oversize_is_rejected():
    big = {"blob": "x" * (MAX_PROVIDER_RESPONSE_BYTES + 10)}
    assert "too large" in check_provider_response(big)[1]
    assert "too large" in check_provider_response(json.dumps(big))[1]


@pytest.mark.asyncio
async def test_tool_never_echoes_or_logs_it(caplog):
    marker = "SENTINEL-q7q7q7q7q7q7q7q7"
    reply = dict(REPLY, note=marker)
    caplog.set_level(logging.DEBUG)
    with patch.object(srv, "proxy", _client()), \
            patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_hosted()) as post:
        out = await srv.arkheia_verify("p", "r", "m", provider_response=reply)
        out2 = await srv.arkheia_verify("p", "r", "m", provider_response=json.dumps(reply))
        assert post.call_args_list[0].kwargs["json"]["provider_response"] == reply
        assert post.call_args_list[1].kwargs["json"]["provider_response"] == reply
        bad = await srv.arkheia_verify("p", "r", "m", provider_response="{" + marker)
        arr = await srv.arkheia_verify("p", "r", "m", provider_response=[marker])
        huge = await srv.arkheia_verify("p", "r", "m", provider_response={"b": marker + "x" * MAX_PROVIDER_RESPONSE_BYTES})
        assert post.call_count == 2, "rejected input sent nothing"
    assert out["risk_level"] == "LOW"
    assert "must be a JSON object" in bad["error"] and "must be a JSON object" in arr["error"]
    assert "too large" in huge["error"]
    for o in (out, out2, bad, arr, huge):
        assert marker not in json.dumps(o)
    assert marker not in caplog.text
