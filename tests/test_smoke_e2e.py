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
import warnings
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
        "ARKHEIA_HOSTED_URL": "https://arkheia-proxy-production.up.railway.app",
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


# ---------------------------------------------------------------------------
# NOT-OBSERVED reporting
#
# Per ~/.claude/DONE.md floor-invariant 9(d): "an outcome that produced no
# observation must not be counted as a success. A timeout, a crash, a skip, a
# `None` return, an empty result set — none of these observed the thing they were
# meant to observe... the only honest buckets are observed-good, observed-bad and
# not-observed, and the third must be visible in the verdict."
#
# `warnings.warn` is used deliberately rather than relying on the skip reason:
# pytest ALWAYS prints its "warnings summary" section under default flags,
# whereas skip reasons only appear with `-rs`. Since this file now runs inside
# the REQUIRED `unit-tests` context, a stage that did not run is named in the
# gating job's output on every PR, and cannot be mistaken for a pass.
# ---------------------------------------------------------------------------

def _report_not_observed(stage: str, claim: str, why: str) -> None:
    warnings.warn(
        f"NOT-OBSERVED: {stage} did not run, so the claim below was neither "
        f"confirmed nor refuted — this is NOT a pass (DONE.md floor 9(d)). "
        f"CLAIM: {claim} REASON NOT RUN: {why}",
        UserWarning,
        stacklevel=1,
    )


HOSTED_404_CLAIM = (
    "app.arkheia.ai/v1/detect returns 404 — hosted detection endpoint not "
    "deployed, so paying customers with an API key but no local proxy get "
    "UNKNOWN on every call."
)

_HOSTED_SKIP_REASON = (
    "NOT-OBSERVED: ARKHEIA_API_KEY not available (set env var or "
    "C:\\keys\\master.env) — the hosted-404 claim was not evaluated"
)

if not _api_key:
    _report_not_observed(
        stage="Stage 3 (TestHostedFallback, hosted detection fallback)",
        claim=HOSTED_404_CLAIM,
        why="ARKHEIA_API_KEY is not set. NOTE: this repo has NO GitHub Actions "
            "secret named ARKHEIA_API_KEY (verified `gh secret list` empty, "
            "2026-07-26), so this stage skips in CI unconditionally.",
    )


@pytest.mark.skipif(not _api_key, reason=_HOSTED_SKIP_REASON)
class TestHostedFallback:
    """Local proxy down, but API key set. Hosted API at app.arkheia.ai should work."""

    # NOTE ON `strict`: this xfail was previously `strict=True`. That was
    # DECEPTIVE, not rigorous. `strict=True` means "fail the suite if this
    # unexpectedly passes" — a tripwire that fires the moment hosted detection is
    # deployed. But the mark sits under the class-level `skipif` above, and a skip
    # short-circuits xfail evaluation, so the tripwire could never fire. Verified:
    # the last real run (smoke-test.yml run 29727531417, 2026-07-20) reported
    # `TestHostedFallback::test_verify_returns_real_detection SKIPPED`. A strict
    # xfail that never evaluates reads as a rigorous check while asserting
    # nothing, which is worse than no mark at all.
    #
    # `strict` is therefore removed rather than left as an unfulfillable promise.
    # The blocked claim is instead carried by (a) HOSTED_404_CLAIM above, (b) the
    # loud NOT-OBSERVED warning, which surfaces in the REQUIRED `unit-tests` job
    # on every PR, and (c) tests/test_ci_enforcement_floor.py INV-4, which fails
    # the build if any strict xfail is nested under a conditional skip again.
    #
    # Restoring `strict=True` is correct ONLY once this can actually run — i.e.
    # once an ARKHEIA_API_KEY secret exists and hosted detection is deployed.
    @pytest.mark.xfail(
        reason=f"BLOCKED: {HOSTED_404_CLAIM} Must deploy hosted detection API "
               "before removing this xfail. NOT strict — see the note above: a "
               "strict xfail under a conditional skip can never fire.",
        strict=False,
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

# Same not-observed treatment as Stage 3 (sibling instance of the same class of
# defect — a skip that reads as a pass). This stage skips in CI by construction:
# no CI job starts the Enterprise Proxy on :8098.
if not _proxy_up:
    _report_not_observed(
        stage="Stage 4 (TestLocalProxy, detection via local Enterprise Proxy)",
        claim="Detection via a local Enterprise Proxy on :8098 returns a valid "
              "risk level, a detection_id and a non-zero confidence.",
        why="nothing is listening on 127.0.0.1:8098. No CI job starts the proxy, "
            "so this stage never runs in CI.",
    )


@pytest.mark.skipif(
    not _proxy_up,
    reason="NOT-OBSERVED: local proxy not running on port 8098 — the local "
           "detection path was not exercised",
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
