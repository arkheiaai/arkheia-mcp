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

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType


class Permission(str, Enum):
    READ    = "read"      # query / retrieve
    EXECUTE = "execute"   # call a model or tool
    WRITE   = "write"     # mutate persistent state
    DEPLOY  = "deploy"    # push to production systems


@dataclass(frozen=True)
class ToolPolicy:
    """An immutable policy record.

    IMMUTABILITY IS A SECURITY PROPERTY HERE, NOT A STYLE CHOICE.

    ``check()`` returns the REGISTRY's own instance (``policy is
    REGISTRY[name]``, pinned in mcp_server/tests/test_tool_registry_gate.py).
    Sharing one instance with every caller is correct ONLY while that instance
    cannot be written to. While this class was a plain ``@dataclass`` with a
    ``list`` field, every gated tool body — ``check()`` is documented as "the
    FIRST statement in every MCP tool body" — held a writable handle on the
    gate's own decision data::

        p = check("memory_store")          # local-only, READ+WRITE
        p.network_egress = True            # wrote THROUGH to REGISTRY
        p.permissions.append(Permission.DEPLOY)
        check("memory_store")              # widened for EVERY caller, for the
                                           # life of the process

    Two distinct defences are required and both are load-bearing:

    * ``frozen=True`` refuses attribute ASSIGNMENT (``p.network_egress = True``
      raises ``FrozenInstanceError``).
    * Every field must hold an IMMUTABLE VALUE. ``frozen=True`` protects the
      binding, not the object bound: a ``list``/``dict``/``set`` field is still
      mutable in place on a frozen dataclass, and ``permissions`` — the field
      ``check()`` itself reads — was exactly that. ``__post_init__`` therefore
      coerces it to a ``tuple``, so the guarantee holds however a caller
      constructs a policy.

    Any field added here must likewise hold an immutable value; that is enforced
    by tests/test_tool_gate_floor.py INV-5, not left to review.
    """

    name: str
    permissions: tuple[Permission, ...]
    description: str = ""
    network_egress: bool = True        # False = local-only (no outbound HTTP)
    requires_human_confirm: bool = False  # True = block until explicit approval

    def __post_init__(self) -> None:
        # Coerce rather than reject: policies are constructed with list literals
        # throughout the repo and by anyone extending the allowlist, and a
        # rejected construction would just push people back to a mutable field.
        # `object.__setattr__` is the sanctioned way to write during __init__ of
        # a frozen dataclass.
        object.__setattr__(self, "permissions", tuple(self.permissions))


# ---------------------------------------------------------------------------
# The allowlist
# ---------------------------------------------------------------------------
#
# `_REGISTRY` is the literal declaration; `REGISTRY` is the READ-ONLY view that
# every importer sees. The public name must not be writable: `check()` is the
# only place the allowlist is consulted, `assert_registry_covers()` runs ONCE at
# startup and compares names only, so a write to the allowlist after startup —
# adding an entry, or replacing a restrictive entry with a permissive one — would
# never be re-checked by anything.
#
# This is a boundary against ACCIDENT and against escalation-as-an-implicit-
# capability, not a sandbox: in-process Python has no hard boundary, and code
# that deliberately reaches for `_REGISTRY` can still write it (that is how the
# test suite installs synthetic policies). What it removes is the ability to
# widen the live allowlist merely by holding something the gate handed you.

_REGISTRY: dict[str, ToolPolicy] = {
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

#: The allowlist as every importer sees it: a read-only view over `_REGISTRY`.
#: Mutating attempts (`REGISTRY[k] = v`, `del REGISTRY[k]`) raise TypeError, and
#: the mutating dict methods (clear/update/pop/popitem/setdefault) do not exist
#: on it at all.
REGISTRY: Mapping[str, ToolPolicy] = MappingProxyType(_REGISTRY)


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------

class PolicyViolation(Exception):
    """Raised when a tool call violates the allowlist or a policy rule."""
    def __init__(self, tool_name: str, reason: str):
        self.tool_name = tool_name
        self.reason = reason
        super().__init__(f"Policy violation for '{tool_name}': {reason}")


class RegistryCoverageError(PolicyViolation):
    """
    Raised at startup when the set of tools ADVERTISED to orchestrators is not
    identical to the set of tools covered by REGISTRY.

    This exists because REGISTRY is a *shadow* allowlist: the effective allowlist
    is the MCP framework's own decorator registry, which is what decides which
    names are advertised via ``tools/list`` and which names ``call_tool`` will
    dispatch. A tool present in the framework but absent from REGISTRY is
    reachable by every orchestrator with no policy covering it. Refusing to start
    is the fail-closed answer: an ungoverned tool must never be advertised.
    """


def check(tool_name: str, *, human_confirmed: bool = False) -> ToolPolicy:
    """
    Evaluate the policy for tool_name and return it if the call is allowed.

    Args:
        tool_name:       The tool being invoked.
        human_confirmed: True only if this call site carries an explicit human
                         approval for a tool whose policy sets
                         ``requires_human_confirm``. Defaults to False, so a
                         confirm-required tool is denied unless the approval is
                         passed deliberately (fail closed).

    Returns:
        The ToolPolicy, if every policy rule allows the call. This is the
        registry's own instance, deliberately: ToolPolicy is frozen and all its
        fields hold immutable values, so a caller cannot use the returned object
        to alter what this gate decides next. Use ``dataclasses.replace()`` to
        derive a variant — it produces an independent policy.

    Raises:
        PolicyViolation, with a distinct reason per deny branch:
          * not registered            -> default deny
          * empty permission set      -> default deny (grants nothing => allows nothing)
          * requires_human_confirm    -> deny until an approval is supplied

    Call this as the FIRST statement in every MCP tool body.
    """
    policy = REGISTRY.get(tool_name)
    if policy is None:
        raise PolicyViolation(
            tool_name,
            f"not in allowlist — default deny. "
            f"Known tools: {sorted(REGISTRY.keys())}",
        )

    # A policy that grants no permission must not authorise a call. Previously
    # `permissions` was declared on every entry and read nowhere, so an entry with
    # `permissions=[]` allowed exactly as much as one granting DEPLOY.
    if not policy.permissions:
        raise PolicyViolation(
            tool_name,
            "registered with an empty permission set — default deny. A policy "
            "that grants nothing cannot authorise a call.",
        )

    # `requires_human_confirm` is documented as "block until explicit approval".
    # Before this it was read nowhere, so setting it blocked nothing at all.
    if policy.requires_human_confirm and not human_confirmed:
        raise PolicyViolation(
            tool_name,
            "requires explicit human confirmation — denied because no approval "
            "was supplied. An approving call site must pass human_confirmed=True.",
        )

    return policy


def require_network_egress(policy: ToolPolicy, *, provider: str) -> None:
    """
    Fail closed before a tool uses a cloud provider transport.

    ``network_egress`` is deliberately evaluated at the egress boundary instead
    of inside ``check()`` because local tools such as ``run_ollama`` are allowed
    to execute without Internet egress.
    """
    if not policy.network_egress:
        raise PolicyViolation(
            policy.name,
            f"network egress to {provider} is disabled by policy",
        )


def assert_registry_covers(advertised: Iterable[str]) -> None:
    """
    Fail closed unless every advertised tool has a policy and every policy covers
    an advertised tool.

    Args:
        advertised: The tool names the server actually exposes to orchestrators.

    Raises:
        RegistryCoverageError naming the specific offending tools on each side.
        The units are named rather than counted: a bare "2 tools differ" would
        hide *which* tool is ungoverned, which is the only actionable fact.
    """
    advertised_set = set(advertised)
    registry_set = set(REGISTRY)

    if not advertised_set:
        raise RegistryCoverageError(
            "<startup>",
            "no tools were advertised, so registry coverage was never actually "
            "checked. An empty check must fail, not pass.",
        )

    ungoverned = sorted(advertised_set - registry_set)
    dead_policy = sorted(registry_set - advertised_set)

    if ungoverned or dead_policy:
        raise RegistryCoverageError(
            "<startup>",
            f"registry coverage mismatch — refusing to start. "
            f"advertised but NOT in REGISTRY (ungoverned, reachable by any "
            f"orchestrator): {ungoverned}; "
            f"in REGISTRY but NOT advertised (dead policy, misleading evidence): "
            f"{dead_policy}.",
        )
