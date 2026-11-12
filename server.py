"""
Arkheia MCP Server — trust verification tools for Claude orchestrators.

Exposes two tools:
  arkheia_verify    — score a (prompt, response, model) tuple for fabrication risk
  arkheia_audit_log — retrieve structured audit evidence for a session
"""

import os
import httpx
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

ARKHEIA_PROXY_URL = os.getenv("ARKHEIA_PROXY_URL", "http://localhost:8099")

mcp = FastMCP("arkheia-trust")


@mcp.tool()
async def arkheia_verify(prompt: str, response: str, model: str) -> dict:
    """
    Verify whether an AI response shows signs of fabrication.

    Args:
        prompt:   The original prompt sent to the model
        response: The model's response to evaluate
        model:    The model identifier (e.g. 'gpt-4o', 'llama-3-70b')

    Returns:
        risk_level:   LOW / MEDIUM / HIGH
        confidence:   0.0 – 1.0
        features:     Which signals triggered
        evidence:     Specific spans of concern (if any)
    """
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{ARKHEIA_PROXY_URL}/detect/verify",
            json={"prompt": prompt, "response": response, "model": model},
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


@mcp.tool()
async def arkheia_audit_log(session_id: str | None = None, limit: int = 50) -> dict:
    """
    Retrieve structured audit evidence for compliance review.

    Args:
        session_id: Optional session to scope the log (None = all recent)
        limit:      Max number of events to return (default 50)

    Returns:
        events: List of detection events with timestamps, risk levels, evidence
        summary: Aggregate counts by risk level
    """
    async with httpx.AsyncClient() as client:
        params = {"limit": limit}
        if session_id:
            params["session_id"] = session_id
        r = await client.get(
            f"{ARKHEIA_PROXY_URL}/audit/log",
            params=params,
            timeout=10.0,
        )
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    mcp.run()
