"""
Tests for MCP Trust Server tools.

PASSING CRITERIA:
  1. arkheia_verify calls ProxyClient.verify with correct args
  2. arkheia_verify returns the proxy response unchanged
  3. arkheia_verify returns UNKNOWN when proxy is unavailable (no exception raised)
  4. arkheia_audit_log calls ProxyClient.get_audit_log with correct args
  5. arkheia_audit_log enforces limit <= 500
  6. arkheia_audit_log returns empty log when proxy unavailable (no exception raised)
  7. MCP server never raises an exception to the orchestrator -- all errors are UNKNOWN
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.proxy_client import ProxyClient


# ---------------------------------------------------------------------------
# ProxyClient unit tests
# ---------------------------------------------------------------------------

class TestProxyClientVerify:

    @pytest.mark.asyncio
    async def test_verify_calls_correct_endpoint(self):
        """CRITERION 1: verify() POSTs to /detect/verify."""
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client

            mock_resp = AsyncMock()
            mock_resp.json.return_value = {
                "risk_level": "LOW",
                "confidence": 0.9,
                "features_triggered": [],
                "detection_id": "test-uuid",
            }
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp

            client = ProxyClient("http://localhost:8099")
            result = await client.verify(
                prompt="What is Python?",
                response="Python is a programming language.",
                model_id="claude-sonnet-4-6",
            )

            call_args = mock_client.post.call_args
            assert "/detect/verify" in call_args.args[0]
            payload = call_args.kwargs["json"]
            assert payload["prompt"] == "What is Python?"
            assert payload["response"] == "Python is a programming language."
            assert payload["model_id"] == "claude-sonnet-4-6"

    @pytest.mark.asyncio
    async def test_verify_returns_proxy_response(self):
        """CRITERION 2: verify() returns proxy response dict."""
        expected = {
            "risk_level": "HIGH",
            "confidence": 0.92,
            "features_triggered": ["unique_word_ratio"],
            "detection_id": "abc-123",
        }
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_resp = MagicMock()              # synchronous mock -- raise_for_status is sync
            mock_resp.json.return_value = expected
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp

            client = ProxyClient("http://localhost:8099")
            result = await client.verify("q", "a", "gpt-4o")

        assert result == expected

    @pytest.mark.asyncio
    async def test_verify_returns_unknown_on_connect_error(self):
        """CRITERION 3: ConnectError -> UNKNOWN, no exception raised."""
        import httpx as _httpx
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.post.side_effect = _httpx.ConnectError("refused")

            client = ProxyClient("http://localhost:8099")
            result = await client.verify("q", "a", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert "error" in result
        assert result["error"] == "proxy_unavailable"

    @pytest.mark.asyncio
    async def test_verify_returns_unknown_on_timeout(self):
        """CRITERION 3 (timeout): TimeoutException -> UNKNOWN."""
        import httpx as _httpx
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.post.side_effect = _httpx.TimeoutException("timeout")

            client = ProxyClient("http://localhost:8099")
            result = await client.verify("q", "a", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "proxy_timeout"

    @pytest.mark.asyncio
    async def test_verify_passes_session_id(self):
        """session_id is included in payload when provided."""
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_resp = AsyncMock()
            mock_resp.json.return_value = {"risk_level": "LOW", "confidence": 0.0,
                                           "features_triggered": [], "detection_id": "x"}
            mock_resp.raise_for_status = MagicMock()
            mock_client.post.return_value = mock_resp

            client = ProxyClient("http://localhost:8099")
            await client.verify("q", "a", "gpt-4o", session_id="session-xyz")

            payload = mock_client.post.call_args.kwargs["json"]
            assert payload.get("session_id") == "session-xyz"


class TestProxyClientAuditLog:

    @pytest.mark.asyncio
    async def test_audit_log_calls_correct_endpoint(self):
        """CRITERION 4: get_audit_log() GETs /audit/log."""
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_resp = AsyncMock()
            mock_resp.json.return_value = {"events": [], "summary": {}}
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp

            client = ProxyClient("http://localhost:8099")
            await client.get_audit_log(limit=25)

            call_args = mock_client.get.call_args
            assert "/audit/log" in call_args.args[0]
            params = call_args.kwargs.get("params", {})
            assert params["limit"] == 25

    @pytest.mark.asyncio
    async def test_audit_log_returns_empty_on_unavailable(self):
        """CRITERION 6: Unavailable proxy -> empty log, no exception."""
        import httpx as _httpx
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = _httpx.ConnectError("refused")

            client = ProxyClient("http://localhost:8099")
            result = await client.get_audit_log()

        assert result["events"] == []
        assert "error" in result


# ---------------------------------------------------------------------------
# MCP tool behaviour (integration-style, mocked proxy)
# ---------------------------------------------------------------------------

class TestMCPToolBehaviour:
    """
    Tests that exercise the MCP tool functions directly (not via stdio transport).
    Mocks the ProxyClient to avoid requiring a live proxy.
    """

    @pytest.mark.asyncio
    async def test_arkheia_verify_tool(self):
        """CRITERION 1-2: arkheia_verify tool forwards to proxy and returns result."""
        from mcp_server import server as mcp_server_module

        expected = {"risk_level": "LOW", "confidence": 0.8,
                    "features_triggered": [], "detection_id": "uuid-test"}

        original_proxy = mcp_server_module.proxy
        mock_proxy = AsyncMock(spec=ProxyClient)
        mock_proxy.verify.return_value = expected
        mcp_server_module.proxy = mock_proxy

        try:
            # FastMCP decorates in-place -- call the function directly
            result = await mcp_server_module.arkheia_verify(
                prompt="test", response="test response", model="gpt-4o"
            )
            assert result == expected
            mock_proxy.verify.assert_called_once_with(
                prompt="test", response="test response", model_id="gpt-4o"
            )
        finally:
            mcp_server_module.proxy = original_proxy

    @pytest.mark.asyncio
    async def test_arkheia_verify_returns_unknown_on_proxy_failure(self):
        """CRITERION 7: Tool never raises -- UNKNOWN returned on proxy failure."""
        from mcp_server import server as mcp_server_module

        original_proxy = mcp_server_module.proxy
        mock_proxy = AsyncMock(spec=ProxyClient)
        mock_proxy.verify.return_value = {
            "risk_level": "UNKNOWN",
            "confidence": 0.0,
            "features_triggered": [],
            "error": "proxy_unavailable",
        }
        mcp_server_module.proxy = mock_proxy

        try:
            result = await mcp_server_module.arkheia_verify(
                prompt="test", response="test", model="gpt-4o"
            )
            assert result["risk_level"] == "UNKNOWN"
            assert "error" in result
        finally:
            mcp_server_module.proxy = original_proxy

    @pytest.mark.asyncio
    async def test_arkheia_audit_log_limit_capped(self):
        """CRITERION 5: limit capped at 500 in server.py."""
        from mcp_server import server as mcp_server_module

        original_proxy = mcp_server_module.proxy
        mock_proxy = AsyncMock(spec=ProxyClient)
        mock_proxy.get_audit_log.return_value = {"events": [], "summary": {}}
        mcp_server_module.proxy = mock_proxy

        try:
            await mcp_server_module.arkheia_audit_log(limit=9999)
            call_kwargs = mock_proxy.get_audit_log.call_args.kwargs
            assert call_kwargs["limit"] <= 500
        finally:
            mcp_server_module.proxy = original_proxy
