"""
Arkheia MCP Trust Server -- Product 1.

Exposes two tools to Claude (or any MCP-compatible orchestrator):
  arkheia_verify      -- score a (prompt, response, model) triple for fabrication risk
  arkheia_audit_log   -- retrieve structured audit evidence

The server is a thin connector. All detection intelligence lives in the
Arkheia Enterprise Proxy (proxy/). This server just bridges MCP tool calls
to HTTP calls on the proxy.

Transport: stdio (default for Claude Desktop / Claude Code)
           HTTP/SSE available via mcp SDK for custom integrations

System prompt to activate Product 1 in a Claude deployment:
  "You have access to the arkheia_verify tool. Call it on every response you
   receive from any model or tool before acting on that response or surfacing
   it to the user.

   Rules:
   - HIGH risk: do not surface the response. Log detection_id, request
     clarification from source.
   - UNKNOWN risk: flag for human review. Include detection_id in your response.
   - MEDIUM risk: surface with a brief confidence note.
   - LOW risk: surface normally.

   Never skip this verification step, even for responses that appear obviously
   correct."
"""

import os
import logging

from mcp.server.fastmcp import FastMCP
from mcp_server.proxy_client import ProxyClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

# Proxy URL from environment -- no default hardcoded key
ARKHEIA_PROXY_URL = os.environ.get("ARKHEIA_PROXY_URL", "http://localhost:8099")

mcp = FastMCP("arkheia-trust")
proxy = ProxyClient(ARKHEIA_PROXY_URL)


@mcp.tool()
async def arkheia_verify(prompt: str, response: str, model: str) -> dict:
    """
    Verify whether an AI response shows signs of fabrication.

    Call this on EVERY model response before acting on it or surfacing it to
    the user. Do not skip for responses that appear obviously correct.

    Args:
        prompt:   The original prompt sent to the model
        response: The model's response to evaluate
        model:    The model identifier (e.g. 'gpt-4o', 'llama-3-70b',
                  'claude-sonnet-4-6')

    Returns:
        risk_level:          LOW / MEDIUM / HIGH / UNKNOWN
        confidence:          0.0 to 1.0
        features_triggered:  Which behavioural signals fired
        detection_id:        UUID for audit log correlation
        error:               Set if detection could not complete (UNKNOWN risk)

    Risk level guidance:
        HIGH    -- do not surface response; log detection_id; request clarification
        UNKNOWN -- flag for human review; include detection_id in your response
        MEDIUM  -- surface with brief confidence note
        LOW     -- surface normally
    """
    result = await proxy.verify(prompt=prompt, response=response, model_id=model)
    logger.debug(
        "arkheia_verify: model=%s risk=%s confidence=%.2f",
        model,
        result.get("risk_level", "?"),
        result.get("confidence", 0.0),
    )
    return result


@mcp.tool()
async def arkheia_audit_log(session_id: str | None = None, limit: int = 50) -> dict:
    """
    Retrieve structured audit evidence for compliance review.

    Args:
        session_id: Optional -- scope log to a specific session (None = all recent)
        limit:      Max number of events to return (default 50, max 500)

    Returns:
        events:  List of detection events with timestamps, risk levels, detection_ids
        summary: Aggregate counts by risk level {"LOW": n, "MEDIUM": n, ...}
        error:   Set if audit log could not be retrieved
    """
    limit = min(limit, 500)
    result = await proxy.get_audit_log(session_id=session_id, limit=limit)
    logger.debug(
        "arkheia_audit_log: events=%d summary=%s",
        len(result.get("events", [])),
        result.get("summary", {}),
    )
    return result


if __name__ == "__main__":
    mcp.run()
