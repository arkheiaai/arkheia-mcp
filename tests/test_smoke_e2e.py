"""
End-to-end smoke test for the Arkheia MCP Trust Server.

Spawns the REAL server as a subprocess, talks to it over stdio using the
MCP SDK client, and verifies the complete detection chain works.

No mocks. No fakes. Real process, real pipes, real JSON-RPC.

Stages:
  1. Server lifecycle -- starts, responds to initialize, lists tools
  2. Graceful degradation -- no proxy, no API key -> UNKNOWN (not crash)
  3. Hosted fallback -- no proxy, with API key -> real detection result
  4. Local proxy -- if port 8098 is up, verify local detection path

Run:
    cd C:\\arkheia-mcp
    pytest tests/test_smoke_e2e.py -v

Stage 3 requires ARKHEIA_API_KEY (reads from C:\\keys\\master.env if available).
Stage 4 auto-skips if local proxy is not running.
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp import ClientSession


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ROOT = Path(__file__).resolve().parent.parent  # arkheia-mcp repo root


def _load_api_key() -> str | None:
    """Try to load ARKHEIA_API_KEY from environment or master.env."""
    key = os.environ.get("ARKHEIA_API_KEY")
    if key:
        return key
    master_env = Path("C:/keys/master.env")
    if master_env.exists():
        for line in master_env.read_text().splitlines():
            if line.startswith("ARKHEIA_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _port_open(host: str, port: int) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except (OSError, TimeoutError):
        return False


def _server_params(env_overrides: dict | None = None) -> StdioServerParameters:
    """Build StdioServerParameters for the MCP server."""
    env = {
        **os.environ,
        "PYTHONPATH": str(_ROOT),
        # Ensure clean state -- no leftover env vars
        "ARKHEIA_PROXY_URL": "http://localhost:19999",  # nothing listening
        "ARKHEIA_API_KEY": "",
        "ARKHEIA_HOSTED_URL": "https://app.arkheia.ai",
        # Use a temp memory DB so tests don't pollute real data
        "MEMORY_DB_PATH": str(_ROOT / "tests" / "_test_memory.db"),
    }
    if env_overrides:
        env.update(env_overrides)

    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "mcp_server.server"],
        env=env,
        cwd=str(_ROOT),
    )


TEST_PROMPT = "What is the capital of France?"
TEST_RESPONSE = "The capital of France is Paris. It has been the capital since the 10th century."
TEST_MODEL = "gpt-4o"


# ---------------------------------------------------------------------------
# Stage 1: Server Lifecycle
# ---------------------------------------------------------------------------

class TestServerLifecycle:
    """Verify the MCP server starts, initializes, and lists tools."""

    @pytest.mark.asyncio
    async def test_server_starts_and_initializes(self):
        """Server responds to MCP initialize handshake."""
        async with stdio_client(_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                result = await session.initialize()
                assert result is not None, "initialize() returned None"
                assert result.capabilities is not None

    @pytest.mark.asyncio
    async def test_tool_list_includes_arkheia_verify(self):
        """arkheia_verify must be in the tool list."""
        async with stdio_client(_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = [t.name for t in tools_result.tools]

                assert "arkheia_verify" in tool_names, (
                    f"arkheia_verify missing from tools: {tool_names}"
                )

    @pytest.mark.asyncio
    async def test_tool_list_contains_expected_tools(self):
        """All documented tools are present."""
        expected = {
            "arkheia_verify",
            "arkheia_audit_log",
            "run_grok",
            "run_gemini",
            "run_ollama",
            "run_together",
            "memory_store",
            "memory_retrieve",
            "memory_relate",
        }
        async with stdio_client(_server_params()) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools_result = await session.list_tools()
                tool_names = {t.name for t in tools_result.tools}
                missing = expected - tool_names
                assert not missing, f"Missing tools: {missing}"


# ---------------------------------------------------------------------------
# Stage 2: Graceful Degradation (no proxy, no API key)
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    """No proxy running, no API key. Must return UNKNOWN, never crash."""

    @pytest.mark.asyncio
    async def test_verify_returns_unknown_not_crash(self):
        """arkheia_verify returns UNKNOWN risk when no detection path available."""
        env = {
            "ARKHEIA_PROXY_URL": "http://localhost:19999",  # nothing listening
            "ARKHEIA_API_KEY": "",                           # no hosted fallback
        }
        async with stdio_client(_server_params(env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "arkheia_verify",
                    arguments={
                        "prompt": TEST_PROMPT,
                        "response": TEST_RESPONSE,
                        "model": TEST_MODEL,
                    },
                )
                assert result is not None, "call_tool returned None"
                assert len(result.content) > 0, "Empty content in response"

                text = result.content[0].text
                data = json.loads(text)

                assert data["risk_level"] == "UNKNOWN", (
                    f"Expected UNKNOWN, got {data['risk_level']}"
                )
                assert "error" in data, "Expected error field in response"
                assert data["error"] in (
                    "no_detection_available",
                    "all_detection_paths_failed",
                    "proxy_unavailable",
                ), f"Unexpected error: {data['error']}"

    @pytest.mark.asyncio
    async def test_audit_log_returns_empty_not_crash(self):
        """arkheia_audit_log returns empty log when proxy down."""
        env = {
            "ARKHEIA_PROXY_URL": "http://localhost:19999",
            "ARKHEIA_API_KEY": "",
        }
        async with stdio_client(_server_params(env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "arkheia_audit_log",
                    arguments={"limit": 10},
                )
                assert result is not None
                text = result.content[0].text
                data = json.loads(text)

                assert data["events"] == [], "Expected empty events list"
                assert "error" in data


# ---------------------------------------------------------------------------
# Stage 3: Hosted Fallback (no proxy, with API key)
# ---------------------------------------------------------------------------

_api_key = _load_api_key()


@pytest.mark.skipif(
    not _api_key,
    reason="ARKHEIA_API_KEY not available (set env var or C:\\keys\\master.env)",
)
class TestHostedFallback:
    """Local proxy down, but API key set. Hosted API at app.arkheia.ai should work."""

    @pytest.mark.xfail(
        reason="BLOCKED: app.arkheia.ai/v1/detect returns 404 — hosted detection "
               "endpoint not deployed. Paying customers with API keys but no local "
               "proxy get UNKNOWN on every call. Must deploy hosted detection API "
               "before removing this xfail.",
        strict=True,
    )
    @pytest.mark.asyncio
    async def test_verify_returns_real_detection(self):
        """Hosted fallback returns a real risk assessment, not UNKNOWN."""
        env = {
            "ARKHEIA_PROXY_URL": "http://localhost:19999",  # nothing listening
            "ARKHEIA_API_KEY": _api_key,
        }
        async with stdio_client(_server_params(env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "arkheia_verify",
                    arguments={
                        "prompt": TEST_PROMPT,
                        "response": TEST_RESPONSE,
                        "model": TEST_MODEL,
                    },
                )
                text = result.content[0].text
                data = json.loads(text)

                assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH"), (
                    f"Expected real risk level, got {data['risk_level']}. "
                    f"Error: {data.get('error')}"
                )
                # Hosted responses should have source marker
                assert data.get("source") == "hosted", (
                    f"Expected source='hosted', got {data.get('source')}"
                )


# ---------------------------------------------------------------------------
# Stage 4: Local Proxy (if running)
# ---------------------------------------------------------------------------

_proxy_up = _port_open("127.0.0.1", 8098)


@pytest.mark.skipif(
    not _proxy_up,
    reason="Local proxy not running on port 8098",
)
class TestLocalProxy:
    """Enterprise Proxy running locally. Full detection path."""

    @pytest.mark.asyncio
    async def test_verify_via_local_proxy(self):
        """Detection via local Enterprise Proxy returns valid result."""
        env = {
            "ARKHEIA_PROXY_URL": "http://localhost:8098",
            "ARKHEIA_API_KEY": "",  # don't need hosted fallback
        }
        async with stdio_client(_server_params(env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "arkheia_verify",
                    arguments={
                        "prompt": TEST_PROMPT,
                        "response": TEST_RESPONSE,
                        "model": TEST_MODEL,
                    },
                )
                text = result.content[0].text
                data = json.loads(text)

                assert data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "UNKNOWN"), (
                    f"Invalid risk_level: {data['risk_level']}"
                )
                # Local proxy results should have detection_id
                if data["risk_level"] != "UNKNOWN":
                    assert "detection_id" in data, "Local detection missing detection_id"
                    assert data.get("confidence", 0) > 0, "Expected non-zero confidence"

    @pytest.mark.asyncio
    async def test_audit_log_via_local_proxy(self):
        """Audit log retrieval works via local proxy."""
        env = {
            "ARKHEIA_PROXY_URL": "http://localhost:8098",
            "ARKHEIA_API_KEY": "",
        }
        async with stdio_client(_server_params(env)) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(
                    "arkheia_audit_log",
                    arguments={"limit": 5},
                )
                text = result.content[0].text
                data = json.loads(text)

                # Should have the expected structure
                assert "events" in data, "Missing events key"
                assert "summary" in data, "Missing summary key"
                assert isinstance(data["events"], list)
