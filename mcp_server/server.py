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
from typing import Any

import anyio
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from mcp_server.proxy_client import ProxyClient
from mcp_server.tool_registry import (
    REGISTRY,
    assert_registry_covers,
    check,
    check_receipted,
    PolicyViolation,
)
from mcp_server.tools.providers import call_grok, call_gemini, call_ollama, call_together
from mcp_server.tools.memory import store_entity, retrieve_entities, store_relation

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

ARKHEIA_PROXY_URL = os.environ.get("ARKHEIA_PROXY_URL", "http://localhost:8098")
ARKHEIA_HOSTED_URL = os.environ.get("ARKHEIA_HOSTED_URL", "https://arkheia-proxy-production.up.railway.app")
ARKHEIA_API_KEY = os.environ.get("ARKHEIA_API_KEY")

class GatedFastMCP(FastMCP):
    """
    FastMCP with the tool-registry gate at the DISPATCH chokepoint.

    WHY THIS EXISTS — the per-body check is not a gate on its own
    ------------------------------------------------------------
    ``check()`` as the first statement of every tool body is defence in depth, and
    it is only as complete as the set of bodies that remembered to call it. Every
    way of reaching execution WITHOUT passing the gate was a way past it:

      * a new ``@mcp.tool`` whose author forgets the call (the static floor
        invariant INV-1 catches this at review time, but only for functions written
        in ``mcp_server/server.py`` and only for names it can parse);
      * a tool registered AFTER boot — ``mcp.add_tool(fn, name="anything")`` — which
        is advertised by ``tools/list``, dispatchable by ``tools/call``, and
        completely invisible to ``startup_policy_selfcheck()``, because that ran at
        boot and never runs again;
      * the same function registered under a second, unpoliced NAME
        (``mcp.add_tool(memory_store, name="mem_write")``): the body's
        ``check("memory_store")`` passes happily while the name the orchestrator
        actually invoked was never policed at all.

    Overriding ``call_tool`` closes the class rather than the instances: FastMCP
    binds ``self.call_tool`` as the protocol handler in ``__init__``, so EVERY
    ``tools/call`` — for any name, registered whenever, by any means — passes the
    receipted gate before the framework resolves the tool. An unknown name is now a
    *recorded* default-deny instead of a bare framework ``ToolError`` that left no
    trace of the attempt.

    ``list_tools`` is the matching half. Advertising a tool no policy covers is how
    an orchestrator is invited to call it, so an ungoverned name is withheld from
    the advertisement — and, because withholding it silently would be its own
    fail-silent hole, logged at error level naming the tool. The pair is fail-closed
    on both surfaces: not advertised, and denied if called anyway.

    THE ONE THING THIS DOES NOT COVER, stated rather than implied: a direct
    in-process call of a decorated coroutine (``await srv.memory_store(...)``)
    does not go through ``call_tool``, so it is gated only by the body's own
    ``check()`` and leaves no receipt. That path is not reachable by an
    orchestrator — it is our own library use — and the body check is proved to
    reach the identical verdict by the differential test in
    ``mcp_server/tests/test_tool_gate_adversarial.py``.
    """

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        # The gate, at the only point every orchestrator-driven call must pass.
        # A deny raises PolicyViolation — recorded first, then re-raised — so the
        # framework never resolves, and never runs, an unpoliced tool.
        await check_receipted(
            name,
            call_site="dispatch",
            # Names only. Argument VALUES carry prompts and observation text and
            # have no place in a policy receipt.
            argument_keys=list(arguments) if isinstance(arguments, dict) else None,
        )
        return await super().call_tool(name, arguments)

    async def list_tools_ungated(self):
        """
        The RAW advertisement, before the ungoverned-tool filter.

        ``startup_policy_selfcheck`` must read this and not ``list_tools``: the
        filter's whole job is to make an ungoverned tool disappear from the
        advertisement, and a coverage check fed the filtered set would compare the
        registry against a list the registry had just been used to build. It would
        agree with itself for exactly the drift it exists to catch.
        """
        return await FastMCP.list_tools(self)

    async def list_tools(self):
        advertised = await FastMCP.list_tools(self)
        governed = [t for t in advertised if t.name in REGISTRY]
        ungoverned = sorted(t.name for t in advertised if t.name not in REGISTRY)
        if ungoverned:
            logger.error(
                "tool-registry gate: WITHHOLDING %d ungoverned tool(s) from "
                "tools/list: %s. Each is registered with the MCP framework but has "
                "no ToolPolicy, so it is not advertised — and any call to it will be "
                "denied. This is a fail-closed response to a registration that "
                "should not exist; fix the registration or add a policy.",
                len(ungoverned), ungoverned,
            )
        return governed


mcp   = GatedFastMCP("arkheia-trust")
proxy = ProxyClient(
    base_url=ARKHEIA_PROXY_URL,
    hosted_url=ARKHEIA_HOSTED_URL,
    api_key=ARKHEIA_API_KEY,
)


# ---------------------------------------------------------------------------
# Detection & audit
# ---------------------------------------------------------------------------

@mcp.tool(annotations=ToolAnnotations(
    title="Verify LLM Output for Fabrication",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
))
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


@mcp.tool(annotations=ToolAnnotations(
    title="Retrieve Fabrication Detection History",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
))
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

def _policy_refusal(e: PolicyViolation) -> dict:
    """
    The refusal payload the four provider tools return instead of raising.

    The shape is inherited (``risk_level: UNKNOWN`` renders a POLICY refusal as
    DETECTION uncertainty, which conflates two different things and is pinned as an
    inconsistency in ``TestRefusalContract`` rather than endorsed). What is added
    here is the recourse: which branch denied, what would clear it, and the id of
    the row that recorded the refusal.

    ``receipt_id: None`` / ``receipt: "unrecorded"`` is the honest answer for a
    direct in-process call, where the body's own ``check()`` denied and no receipt
    was written. It is NOT filled with a plausible-looking value, because "there is
    no receipt" and "there is a receipt you have not looked up" must not read the
    same to the caller.
    """
    return {
        "error": str(e),
        "risk_level": "UNKNOWN",
        "policy_denied": True,
        "deny_code": e.code,
        "remedy": e.remedy,
        "receipt_id": e.receipt_id,
        "receipt": e.receipt_status or "unrecorded",
    }

@mcp.tool(annotations=ToolAnnotations(
    title="Call xAI Grok with Fabrication Screening",
    readOnlyHint=True,
    destructiveHint=False,
    openWorldHint=True,
))
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
        return _policy_refusal(e)

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


@mcp.tool(annotations=ToolAnnotations(
    title="Call Google Gemini with Fabrication Screening",
    readOnlyHint=True,
    destructiveHint=False,
    openWorldHint=True,
))
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
        return _policy_refusal(e)

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


@mcp.tool(annotations=ToolAnnotations(
    title="Call Local Ollama Model with Fabrication Screening",
    readOnlyHint=True,
    destructiveHint=False,
    openWorldHint=False,
))
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
        return _policy_refusal(e)

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


@mcp.tool(annotations=ToolAnnotations(
    title="Call Together AI with Fabrication Screening",
    readOnlyHint=True,
    destructiveHint=False,
    openWorldHint=True,
))
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
        return _policy_refusal(e)

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


@mcp.tool(annotations=ToolAnnotations(
    title="Store Entity in Knowledge Graph",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
))
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


@mcp.tool(annotations=ToolAnnotations(
    title="Search Knowledge Graph",
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
))
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


@mcp.tool(annotations=ToolAnnotations(
    title="Create Relationship Between Entities",
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
))
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


def startup_policy_selfcheck() -> None:
    """
    Fail closed at startup unless every advertised tool is covered by REGISTRY.

    REGISTRY is a *shadow* allowlist: FastMCP's decorator registry is what decides
    which names are advertised via ``tools/list`` and which ``call_tool`` will
    dispatch — an unknown name is refused by FastMCP's own ``ToolError`` and never
    reaches ``check()``. So a tool decorated here but missing from REGISTRY is
    reachable by every orchestrator with no policy covering it. Refusing to start
    is the only fail-closed answer.

    ``tests/test_tool_gate_floor.py`` INV-2 catches the same drift statically in
    CI; this is the runtime backstop, and it is the check that still holds once
    REGISTRY is loaded from a signed/remote policy store (the documented
    enterprise upgrade hook), where a static parse cannot see the contents.

    Reads ``list_tools_ungated`` deliberately — see that method. Feeding this the
    FILTERED advertisement would make it compare the registry against a list the
    registry had just filtered, so it would report clean for precisely the drift it
    exists to catch.
    """
    advertised = [t.name for t in anyio.run(mcp.list_tools_ungated)]
    assert_registry_covers(advertised)
    logger.info(
        "tool-registry policy self-check OK: %d advertised tools, all covered",
        len(advertised),
    )


if __name__ == "__main__":
    startup_policy_selfcheck()
    mcp.run()
