"""
Arkheia MCP Trust Server -- Product 1.

Exposes tools to Claude (or any MCP-compatible orchestrator):

  Detection & audit:
    arkheia_verify      -- score a (prompt, response, model) triple
    arkheia_audit_log   -- retrieve structured audit evidence

  Provider wrappers (single source of truth for all inference):
    run_grok            -- call xAI Grok + screen through Arkheia
    run_gemini          -- call Google Gemini + screen through Arkheia
    run_ollama          -- call local Ollama model + screen through Arkheia

All provider tools:
  1. Check the tool registry (default deny)
  2. Call the provider API
  3. Call arkheia_verify on the response
  4. Return both the response and the risk assessment

If it didn't go through here, it's not in the audit log.

Transport: stdio (default — Claude Code / Claude Desktop)
           HTTP/SSE available via mcp SDK for custom integrations
"""

import os
import logging

from mcp.server.fastmcp import FastMCP
from mcp_server.proxy_client import ProxyClient
from mcp_server.tool_registry import check, PolicyViolation
from mcp_server.tools.providers import call_grok, call_gemini, call_ollama, call_together
from mcp_server.tools.memory import store_entity, retrieve_entities, store_relation

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

ARKHEIA_PROXY_URL = os.environ.get("ARKHEIA_PROXY_URL", "http://localhost:8098")
ARKHEIA_HOSTED_URL = os.environ.get("ARKHEIA_HOSTED_URL", "https://app.arkheia.ai")
ARKHEIA_API_KEY = os.environ.get("ARKHEIA_API_KEY")

mcp   = FastMCP("arkheia-trust")
proxy = ProxyClient(
    base_url=ARKHEIA_PROXY_URL,
    hosted_url=ARKHEIA_HOSTED_URL,
    api_key=ARKHEIA_API_KEY,
)


# ---------------------------------------------------------------------------
# Detection & audit
# ---------------------------------------------------------------------------

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
    check("arkheia_verify")
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
    check("arkheia_audit_log")
    limit = min(limit, 500)
    result = await proxy.get_audit_log(session_id=session_id, limit=limit)
    logger.debug(
        "arkheia_audit_log: events=%d summary=%s",
        len(result.get("events", [])),
        result.get("summary", {}),
    )
    return result


# ---------------------------------------------------------------------------
# Provider wrappers — single source of truth for all inference
# ---------------------------------------------------------------------------

@mcp.tool()
async def run_grok(
    prompt: str,
    model: str = "grok-4-fast-non-reasoning",
) -> dict:
    """
    Call xAI Grok and screen the response through Arkheia.

    Use this instead of calling Grok directly — ensures every response
    is in the audit log.

    Args:
        prompt: The prompt to send to Grok
        model:  Grok model ID (default: grok-4-fast-non-reasoning)
                Options: grok-4-fast-reasoning, grok-4-1-fast-reasoning,
                         grok-3, grok-code-fast-1

    Returns:
        response:           The model's response text
        model:              Model ID used
        prompt_hash:        SHA-256 of the prompt (for reproducibility)
        arkheia:            Full detection result (risk_level, confidence, etc.)
        error:              Set if provider call failed
    """
    try:
        check("run_grok")
    except PolicyViolation as e:
        return {"error": str(e), "risk_level": "UNKNOWN"}

    provider_result = await call_grok(prompt, model)
    risk = await proxy.verify(
        prompt=prompt,
        response=provider_result["response"],
        model_id=model,
    )
    logger.info(
        "run_grok: model=%s risk=%s confidence=%.2f",
        model, risk.get("risk_level", "?"), risk.get("confidence", 0.0),
    )
    return {**provider_result, "arkheia": risk}


@mcp.tool()
async def run_gemini(
    prompt: str,
    model: str = "gemini-2.5-flash",
) -> dict:
    """
    Call Google Gemini and screen the response through Arkheia.

    Use this instead of calling Gemini directly — ensures every response
    is in the audit log.

    Args:
        prompt: The prompt to send to Gemini
        model:  Gemini model ID (default: gemini-2.5-flash)
                Options: gemini-2.5-pro, gemini-2.5-flash

    Returns:
        response:     The model's response text
        model:        Model ID used
        prompt_hash:  SHA-256 of the prompt
        arkheia:      Full detection result
        error:        Set if provider call failed
    """
    try:
        check("run_gemini")
    except PolicyViolation as e:
        return {"error": str(e), "risk_level": "UNKNOWN"}

    provider_result = await call_gemini(prompt, model)
    risk = await proxy.verify(
        prompt=prompt,
        response=provider_result["response"],
        model_id=model,
    )
    logger.info(
        "run_gemini: model=%s risk=%s confidence=%.2f",
        model, risk.get("risk_level", "?"), risk.get("confidence", 0.0),
    )
    return {**provider_result, "arkheia": risk}


@mcp.tool()
async def run_ollama(
    prompt: str,
    model: str = "phi4:14b",
) -> dict:
    """
    Call a local Ollama model and screen the response through Arkheia.

    No network egress — local inference only. Use for cost-sensitive or
    privacy-sensitive workloads where cloud models are not appropriate.

    Args:
        prompt: The prompt to send to Ollama
        model:  Ollama model name (default: phi4:14b)
                Available: phi4:14b, phi4-reasoning:14b, llama3.1:70b,
                           deepseek-coder:33b-instruct, qwen2:72b-instruct,
                           codellama:34b-instruct, mixtral:8x7b, ouro:latest

    Returns:
        response:     The model's response text
        model:        Model ID used
        prompt_hash:  SHA-256 of the prompt
        eval_count:   Token count (if available)
        arkheia:      Full detection result
        error:        Set if provider call failed
    """
    try:
        check("run_ollama")
    except PolicyViolation as e:
        return {"error": str(e), "risk_level": "UNKNOWN"}

    provider_result = await call_ollama(prompt, model)
    risk = await proxy.verify(
        prompt=prompt,
        response=provider_result["response"],
        model_id=model,
    )
    logger.info(
        "run_ollama: model=%s risk=%s confidence=%.2f",
        model, risk.get("risk_level", "?"), risk.get("confidence", 0.0),
    )
    return {**provider_result, "arkheia": risk}


@mcp.tool()
async def run_together(
    prompt: str,
    model: str = "moonshotai/Kimi-K2.5",
) -> dict:
    """
    Call Together AI and screen the response through Arkheia.

    Use this instead of calling Together AI directly — ensures every response
    is in the audit log.

    Args:
        prompt: The prompt to send to the model
        model:  Together AI model ID (default: moonshotai/Kimi-K2.5)
                Options: moonshotai/Kimi-K2.5, meta-llama/Llama-3.3-70B-Instruct-Turbo,
                         deepseek-ai/DeepSeek-R1, Qwen/Qwen2.5-72B-Instruct-Turbo

    Returns:
        response:     The model's response text
        model:        Model ID used
        prompt_hash:  SHA-256 of the prompt
        usage:        Token usage if available
        arkheia:      Full detection result (risk_level, confidence, etc.)
        error:        Set if provider call failed

    Note: Kimi K2.5 is a thinking model — it uses 100-500 tokens internally
    before producing output. max_tokens is set to 2048 automatically.
    """
    try:
        check("run_together")
    except PolicyViolation as e:
        return {"error": str(e), "risk_level": "UNKNOWN"}

    provider_result = await call_together(prompt, model)
    risk = await proxy.verify(
        prompt=prompt,
        response=provider_result["response"],
        model_id=model,
    )
    logger.info(
        "run_together: model=%s risk=%s confidence=%.2f",
        model, risk.get("risk_level", "?"), risk.get("confidence", 0.0),
    )
    return {**provider_result, "arkheia": risk}


@mcp.tool()
async def memory_store(name: str, entity_type: str, observations: list[str]) -> dict:
    """
    Store an entity and its observations in the persistent knowledge graph.

    Use this to remember facts across sessions. Entities are upserted by name+type.
    Observations are deduplicated — storing the same observation twice is safe.

    Args:
        name:         Entity name (e.g. "Acme Corp", "pr-reviewer agent", "auth-middleware bug")
        entity_type:  Category (e.g. "company", "agent", "bug", "decision", "person")
        observations: List of factual statements about this entity
                      (e.g. ["In negotiation since 2026-03-01", "Contact: Jane Smith"])

    Returns:
        entity_id:           UUID of the stored entity
        name:                Entity name
        entity_type:         Entity type
        observations_added:  Number of new observations added this call
        total_observations:  Total observations stored for this entity
    """
    check("memory_store")
    return await store_entity(name=name, entity_type=entity_type, observations=observations)


@mcp.tool()
async def memory_retrieve(query: str, entity_type: str | None = None, limit: int = 10) -> dict:
    """
    Retrieve entities and their observations from the persistent knowledge graph.

    Searches entity names containing the query string. Returns matching entities
    with all stored observations and known relations.

    Args:
        query:        Search string — matches entity names (case-insensitive LIKE)
        entity_type:  Optional filter — only return entities of this type
        limit:        Max entities to return (default 10, max 50)

    Returns:
        entities:  List of matching entities, each with:
                     entity_id, name, entity_type, created_at,
                     observations: [{"content": ..., "created_at": ...}],
                     relations: [{"relation_type": ..., "to_entity": ...}]
        total:     Total count of matches (before limit)
    """
    check("memory_retrieve")
    limit = min(limit, 50)
    return await retrieve_entities(query=query, entity_type=entity_type, limit=limit)


@mcp.tool()
async def memory_relate(from_entity: str, relation_type: str, to_entity: str) -> dict:
    """
    Store a named relationship between two entities in the knowledge graph.

    Both entities must already exist (use memory_store first).
    Relations are directional: from_entity --[relation_type]--> to_entity

    Args:
        from_entity:   Name of the source entity
        relation_type: Relationship label (e.g. "reports_to", "blocks", "owns", "assigned_to")
        to_entity:     Name of the target entity

    Returns:
        rel_id:        UUID of the stored relation
        from_entity:   Source entity name
        relation_type: Relation type
        to_entity:     Target entity name
    """
    check("memory_relate")
    return await store_relation(from_entity=from_entity, relation_type=relation_type, to_entity=to_entity)


if __name__ == "__main__":
    mcp.run()
