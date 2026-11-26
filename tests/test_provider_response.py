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


G = "For a full assessment, ask your model provider to include detailed output in its response."


@pytest.mark.asyncio
async def test_guidance_only_for_the_exact_allowed_message():
    async def run(message):
        r = _hosted()
        r.json.return_value = dict(OK, message=message)
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=r):
            return await _client().verify("p", "r", "m")

    assert (await run(G))["guidance"] == G
    for bad in [G + " ", " " + G, G + " Also: secret.", "Note: " + G, G.lower(), G[:-1], "other", "", None, 5, [G], {"m": G}]:
        out = await run(bad)
        assert "guidance" not in out, repr(bad)
        assert "secret" not in json.dumps(out)


# ---- through the MCP framework: every malformed value reaches the fixed message ----

MARKER = "SENTINEL-k3k3k3k3k3k3k3k3"
MALFORMED = [
    [MARKER],
    [{"note": MARKER}],
    [[MARKER]],
    json.dumps([MARKER]),
    json.dumps([{"note": MARKER}]),
    42,
    -1.5,
    True,
    False,
    "{" + MARKER,
]


def _args(**extra):
    return dict({"prompt": "p", "response": "r", "model": "m"}, **extra)


def _text(result) -> str:
    return json.dumps([getattr(c, "text", str(c)) for c in result]) if isinstance(result, (list, tuple)) else str(result)


def test_published_schema_is_unchanged_and_neutral():
    tool = srv.mcp._tool_manager.get_tool("arkheia_verify")
    prop = tool.parameters["properties"]["provider_response"]
    assert prop["anyOf"] == [{"type": "object"}, {"type": "string"}, {"type": "null"}]
    assert prop["default"] is None
    assert "provider_response" not in tool.parameters.get("required", [])


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", MALFORMED, ids=lambda v: type(v).__name__ + ":" + repr(v)[:20])
async def test_tool_manager_never_echoes_malformed(bad, caplog):
    caplog.set_level(logging.DEBUG)
    with patch.object(srv.proxy, "verify", new_callable=AsyncMock) as verify:
        result = await srv.mcp.call_tool("arkheia_verify", _args(provider_response=bad))
    assert verify.await_count == 0, "a refused value sends nothing"
    text = _text(result)
    assert "must be a JSON object" in text
    assert MARKER not in text
    assert MARKER not in caplog.text


@pytest.mark.asyncio
async def test_tool_manager_forwards_object_and_string(caplog):
    caplog.set_level(logging.DEBUG)
    reply = dict(REPLY, note=MARKER)
    with patch.object(srv, "proxy", _client()), \
            patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_hosted()) as post:
        r1 = await srv.mcp.call_tool("arkheia_verify", _args(provider_response=reply))
        r2 = await srv.mcp.call_tool("arkheia_verify", _args(provider_response=json.dumps(reply)))
        r3 = await srv.mcp.call_tool("arkheia_verify", _args())
    sent = [c.kwargs["json"] for c in post.call_args_list]
    assert sent[0]["provider_response"] == reply
    assert sent[1]["provider_response"] == reply
    assert "provider_response" not in sent[2]
    for r in (r1, r2, r3):
        assert '\\"risk_level\\": \\"LOW\\"' in _text(r)
        assert MARKER not in _text(r)
    assert MARKER not in caplog.text


# ---- real stdio child, real JSON-RPC, against a loopback stand-in for the hosted service ----

import http.server
import os
import sys
import tempfile
import threading
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

_ROOT = Path(__file__).resolve().parent.parent


class _StandIn(http.server.BaseHTTPRequestHandler):
    seen: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        type(self).seen.append(json.loads(body))
        out = json.dumps(OK).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.mark.asyncio
async def test_stdio_protocol_never_echoes_malformed_and_forwards_valid():
    _StandIn.seen = []
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _StandIn)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.server"],
        cwd=str(_ROOT),
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "PYTHONPATH": str(_ROOT),
             "PYTHONDONTWRITEBYTECODE": "1", "ARKHEIA_PROXY_URL": "",
             "ARKHEIA_API_KEY": "ak_live_DUMMYDUMMYDUMMY00",
             "ARKHEIA_HOSTED_URL": f"http://127.0.0.1:{httpd.server_address[1]}",
             "MEMORY_DB_PATH": ":memory:"},
    )
    reply = dict(REPLY, note=MARKER)
    with tempfile.TemporaryFile(mode="w+") as errlog:
        try:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    rendered = []
                    for bad in MALFORMED:
                        res = await session.call_tool("arkheia_verify", _args(provider_response=bad))
                        out = res.model_dump_json()
                        assert res.isError is False, out
                        assert "must be a JSON object" in out
                        rendered.append(out)
                    assert _StandIn.seen == [], "a refused value sends nothing"
                    ok1 = await session.call_tool("arkheia_verify", _args(provider_response=reply))
                    ok2 = await session.call_tool("arkheia_verify", _args(provider_response=json.dumps(reply)))
                    rendered += [ok1.model_dump_json(), ok2.model_dump_json()]
        finally:
            httpd.shutdown()
            httpd.server_close()
        errlog.seek(0)
        logs = errlog.read()
    assert [s["provider_response"] for s in _StandIn.seen] == [reply, reply]
    assert '\\"risk_level\\": \\"LOW\\"' in rendered[-1]
    for out in rendered:
        assert MARKER not in out
    assert "CallToolRequest" in logs, "server log was captured"
    assert MARKER not in logs
