"""
Arkheia MCP Server — trust verification tools for Claude orchestrators.

Exposes two tools:
  arkheia_verify    — score a (prompt, response, model) tuple for fabrication risk
  arkheia_audit_log — retrieve structured audit evidence for a session

Reliability contract: a detection-backend outage must NEVER become a tool error. Both tools delegate to
mcp_server.proxy_client.ProxyClient, which tries the local proxy first, falls back to the hosted API
(ARKHEIA_API_KEY), and fails OPEN — returning an honest UNKNOWN/empty result rather than raising. (The
previous inline httpx + raise_for_status path bricked the tools when the local proxy was down.)
"""

import os

from mcp.server.fastmcp import FastMCP
from mcp_server.proxy_client import ProxyClient

ARKHEIA_PROXY_URL = os.getenv("ARKHEIA_PROXY_URL", "http://localhost:8099")

mcp = FastMCP("arkheia-trust")


def _client() -> ProxyClient:
    """Local-first client with hosted fallback + fail-open (see mcp_server/proxy_client.py)."""
    return ProxyClient(base_url=ARKHEIA_PROXY_URL)


@mcp.tool()
async def arkheia_verify(prompt: str, response: str, model: str) -> dict:
    """
    Verify whether an AI response shows signs of fabrication.

    Args:
        prompt:   The original prompt sent to the model
        response: The model's response to evaluate
        model:    The model identifier (e.g. 'gpt-4o', 'llama-3-70b')

    Returns:
        risk_level / confidence / features on success. If neither the local proxy nor the hosted API is
        reachable it fails OPEN with risk_level "UNKNOWN" and an `error` field — i.e. "NOT assessed",
        which a caller must treat as unverified rather than a clean bill (never a 500).
    """
    return await _client().verify(prompt, response, model)


@mcp.tool()
async def arkheia_audit_log(session_id: str | None = None, limit: int = 50) -> dict:
    """
    Retrieve structured audit evidence for compliance review.

    Args:
        session_id: Optional session to scope the log (None = all recent)
        limit:      Max number of events to return (default 50)

    Returns:
        events / summary on success; on a backend outage it fails OPEN with an empty log and an `error`
        field rather than raising. (Audit log is local-proxy only — no hosted fallback.)
    """
    return await _client().get_audit_log(session_id=session_id, limit=limit)


if __name__ == "__main__":
    mcp.run()
