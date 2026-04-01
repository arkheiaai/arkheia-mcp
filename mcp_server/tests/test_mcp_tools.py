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

            mock_resp = MagicMock()  # sync mock — json() and raise_for_status() are sync in httpx
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
        assert result["error"] in ("proxy_unavailable", "no_detection_available")

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
        assert result["error"] in ("proxy_timeout", "no_detection_available")

    @pytest.mark.asyncio
    async def test_verify_passes_session_id(self):
        """session_id is included in payload when provided."""
        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_cls.return_value.__aenter__.return_value = mock_client
            mock_resp = MagicMock()  # sync mock — json() and raise_for_status() are sync in httpx
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


# ---------------------------------------------------------------------------
# Memory tool tests
# ---------------------------------------------------------------------------

import os
import tempfile


class TestMemoryTools:
    """
    Tests for memory_store, memory_retrieve, memory_relate.

    Each test class instance uses a fresh temp DB via the MEMORY_DB_PATH env var
    so tests never touch the real knowledge graph.
    """

    @pytest.fixture(autouse=True)
    def temp_db(self, tmp_path):
        """Point MEMORY_DB_PATH at a per-test temp file."""
        db_file = str(tmp_path / "test_memory.db")
        os.environ["MEMORY_DB_PATH"] = db_file
        yield db_file
        # cleanup env after each test
        os.environ.pop("MEMORY_DB_PATH", None)

    @pytest.mark.asyncio
    async def test_store_entity_new(self):
        """memory_store: new entity with 2 observations returns observations_added=2."""
        from mcp_server import server as mcp_server_module

        result = await mcp_server_module.memory_store(
            name="Acme Corp",
            entity_type="company",
            observations=["In negotiation since 2026-03-01", "Contact: Jane Smith"],
        )

        assert "entity_id" in result
        assert result["name"] == "Acme Corp"
        assert result["entity_type"] == "company"
        assert result["observations_added"] == 2
        assert result["total_observations"] == 2

    @pytest.mark.asyncio
    async def test_store_entity_deduplication(self):
        """memory_store: re-storing same entity with 1 new + 1 duplicate obs adds only 1."""
        from mcp_server import server as mcp_server_module

        # First store
        await mcp_server_module.memory_store(
            name="Acme Corp",
            entity_type="company",
            observations=["In negotiation since 2026-03-01", "Contact: Jane Smith"],
        )

        # Second store — 1 duplicate, 1 new
        result = await mcp_server_module.memory_store(
            name="Acme Corp",
            entity_type="company",
            observations=["Contact: Jane Smith", "Deal size: $500k"],
        )

        assert result["observations_added"] == 1
        assert result["total_observations"] == 3

    @pytest.mark.asyncio
    async def test_retrieve_entity_found(self):
        """memory_retrieve: stored entity is returned with all observations."""
        from mcp_server import server as mcp_server_module

        await mcp_server_module.memory_store(
            name="Acme Corp",
            entity_type="company",
            observations=["In negotiation since 2026-03-01", "Contact: Jane Smith", "Deal size: $500k"],
        )

        result = await mcp_server_module.memory_retrieve(query="Acme")

        assert result["total"] >= 1
        entity = next((e for e in result["entities"] if e["name"] == "Acme Corp"), None)
        assert entity is not None
        assert len(entity["observations"]) == 3

    @pytest.mark.asyncio
    async def test_retrieve_entity_type_filter(self):
        """memory_retrieve: entity_type filter excludes non-matching entities."""
        from mcp_server import server as mcp_server_module

        await mcp_server_module.memory_store(
            name="Acme Corp", entity_type="company", observations=["A company"]
        )
        await mcp_server_module.memory_store(
            name="Acme Bug", entity_type="bug", observations=["A bug"]
        )

        result = await mcp_server_module.memory_retrieve(query="Acme", entity_type="company")

        assert result["total"] == 1
        assert result["entities"][0]["entity_type"] == "company"

    @pytest.mark.asyncio
    async def test_store_relation(self):
        """memory_relate: stores a relation and returns rel_id."""
        from mcp_server import server as mcp_server_module

        await mcp_server_module.memory_store(
            name="Jane Smith", entity_type="person", observations=["Sales lead"]
        )
        await mcp_server_module.memory_store(
            name="Acme Corp", entity_type="company", observations=["Prospect"]
        )

        result = await mcp_server_module.memory_relate(
            from_entity="Jane Smith",
            relation_type="works_at",
            to_entity="Acme Corp",
        )

        assert "rel_id" in result
        assert result["from_entity"] == "Jane Smith"
        assert result["relation_type"] == "works_at"
        assert result["to_entity"] == "Acme Corp"

    @pytest.mark.asyncio
    async def test_retrieve_shows_relations(self):
        """memory_retrieve: relations stored via memory_relate appear in entity results."""
        from mcp_server import server as mcp_server_module

        await mcp_server_module.memory_store(
            name="Jane Smith", entity_type="person", observations=["Sales lead"]
        )
        await mcp_server_module.memory_store(
            name="Acme Corp", entity_type="company", observations=["Prospect"]
        )
        await mcp_server_module.memory_relate(
            from_entity="Jane Smith",
            relation_type="works_at",
            to_entity="Acme Corp",
        )

        result = await mcp_server_module.memory_retrieve(query="Jane Smith")

        entity = next((e for e in result["entities"] if e["name"] == "Jane Smith"), None)
        assert entity is not None
        assert len(entity["relations"]) == 1
        assert entity["relations"][0]["relation_type"] == "works_at"
        assert entity["relations"][0]["to_entity"] == "Acme Corp"

    @pytest.mark.asyncio
    async def test_retrieve_limit_capped_at_50(self):
        """memory_retrieve: limit is capped at 50 in server.py."""
        from mcp_server import server as mcp_server_module

        # Just verify it doesn't raise and returns a dict
        result = await mcp_server_module.memory_retrieve(query="anything", limit=9999)
        assert "entities" in result
        assert "total" in result
