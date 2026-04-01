"""
Tool registry and policy gate.

Defines which tools the MCP Trust Server is allowed to expose.
Default deny: any tool not in REGISTRY cannot be called.

Policy rules are evaluated synchronously before the tool body executes.
A PolicyViolation exception bubbles up as a structured MCP error — the
orchestrator sees a refusal, not a crash.

Hook for enterprise upgrade:
  - Load REGISTRY from a signed YAML / remote policy store
  - Add caller-identity checks (which session, which agent)
  - Add per-tool rate limits
  - Add audit record for every policy check (pass + deny)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Permission(str, Enum):
    READ    = "read"      # query / retrieve
    EXECUTE = "execute"   # call a model or tool
    WRITE   = "write"     # mutate persistent state
    DEPLOY  = "deploy"    # push to production systems


@dataclass
class ToolPolicy:
    name: str
    permissions: list[Permission]
    description: str = ""
    network_egress: bool = True        # False = local-only (no outbound HTTP)
    requires_human_confirm: bool = False  # True = block until explicit approval


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------

REGISTRY: dict[str, ToolPolicy] = {
    # ── Detection & audit (read-only) ────────────────────────────────────────
    "arkheia_verify": ToolPolicy(
        name="arkheia_verify",
        permissions=[Permission.READ],
        network_egress=True,
        description="Screen an AI response for fabrication risk",
    ),
    "arkheia_audit_log": ToolPolicy(
        name="arkheia_audit_log",
        permissions=[Permission.READ],
        network_egress=False,
        description="Retrieve structured audit evidence",
    ),
    # ── External inference (execute + egress) ────────────────────────────────
    "run_grok": ToolPolicy(
        name="run_grok",
        permissions=[Permission.READ, Permission.EXECUTE],
        network_egress=True,
        description="Call xAI Grok API and screen response through Arkheia",
    ),
    "run_gemini": ToolPolicy(
        name="run_gemini",
        permissions=[Permission.READ, Permission.EXECUTE],
        network_egress=True,
        description="Call Google Gemini API and screen response through Arkheia",
    ),
    "run_together": ToolPolicy(
        name="run_together",
        permissions=[Permission.READ, Permission.EXECUTE],
        network_egress=True,
        description="Call Together AI API (Kimi K2.5 etc.) and screen response through Arkheia",
    ),
    # ── Local inference (execute, no egress) ─────────────────────────────────
    "run_ollama": ToolPolicy(
        name="run_ollama",
        permissions=[Permission.READ, Permission.EXECUTE],
        network_egress=False,
        description="Call local Ollama model and screen response through Arkheia",
    ),
    # ── Memory (local SQLite knowledge graph, no egress) ─────────────────────
    "memory_store": ToolPolicy(
        name="memory_store",
        permissions=[Permission.READ, Permission.WRITE],
        network_egress=False,
        description="Store an entity and observations in the persistent knowledge graph",
    ),
    "memory_retrieve": ToolPolicy(
        name="memory_retrieve",
        permissions=[Permission.READ],
        network_egress=False,
        description="Retrieve entities and their observations from the knowledge graph",
    ),
    "memory_relate": ToolPolicy(
        name="memory_relate",
        permissions=[Permission.READ, Permission.WRITE],
        network_egress=False,
        description="Store a named relationship between two entities in the knowledge graph",
    ),
}


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------

class PolicyViolation(Exception):
    """Raised when a tool call violates the allowlist or a policy rule."""
    def __init__(self, tool_name: str, reason: str):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Policy violation for '{tool_name}': {reason}")


def check(tool_name: str) -> ToolPolicy:
    """
    Look up tool_name in the registry.

    Returns the ToolPolicy if allowed.
    Raises PolicyViolation if the tool is not registered (default deny).

    Call this as the FIRST statement in every MCP tool body.
    """
    policy = REGISTRY.get(tool_name)
    if policy is None:
        raise PolicyViolation(
            tool_name,
            f"not in allowlist — default deny. "
            f"Known tools: {sorted(REGISTRY.keys())}",
        )
    return policy
