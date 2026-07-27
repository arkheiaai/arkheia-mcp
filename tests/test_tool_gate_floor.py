"""
FLOOR INVARIANT — the tool-registry allow/deny gate must actually gate.

Floor tier contract: this module is stdlib-only (``ast`` + ``pathlib``). It imports
no third-party package, opens no socket and starts no app, so it runs under a bare
``pytest`` with zero project dependencies and has zero interpreter variance.

------------------------------------------------------------------------------
Why these invariants exist (real defects, arkheia-mcp @ base 3037f0c)
------------------------------------------------------------------------------
``mcp_server/tool_registry.py`` is the published product's policy gate: it declares
an allowlist (``REGISTRY``) of ``ToolPolicy`` objects and a ``check()`` that is
documented as "Call this as the FIRST statement in every MCP tool body", with
"default deny: any tool not in REGISTRY cannot be called".

Four defects, all found 2026-07-26, all invisible to the test suite because the
gate had ZERO tests anywhere in the repo:

INV-1  ``check()`` wired in every tool body.
       Nothing asserted it. A new ``@mcp.tool`` that simply forgets the call ships
       ungoverned and no test notices.

INV-2  ``REGISTRY`` and the set of ``@mcp.tool`` functions must be identical.
       The *effective* allowlist is FastMCP's decorator registry, NOT ``REGISTRY``:
       ``await mcp.call_tool("nope", {})`` raises FastMCP's own ``ToolError`` and
       never reaches ``check()``. So ``REGISTRY`` is a SHADOW allowlist. A tool
       decorated but absent from ``REGISTRY`` is advertised and dispatchable, and
       ``check()`` inside it would then deny at runtime (or, if the call was also
       forgotten, never deny at all). Parity in BOTH directions is the compensating
       control that makes ``REGISTRY`` load-bearing.

INV-3  Every policy-control field on ``ToolPolicy`` must have a production read
       site. ``permissions`` / ``network_egress`` / ``requires_human_confirm`` were
       declared, documented ("False = local-only", "True = block until explicit
       approval") and read NOWHERE — ``git grep`` for each returned hits only inside
       the dataclass definition itself. Three decorative security controls. This is
       the same defect class as the ``verify_chain`` finding already encoded in
       ``tests/test_audit_floor.py``: a mechanism that is declared but never
       consulted provides zero enforcement.

INV-4  No second, UNGATED MCP server may exist.
       Root ``server.py`` was a duplicate ``FastMCP("arkheia-trust")`` exposing the
       same advertised tool names (``arkheia_verify``, ``arkheia_audit_log``) with no
       ``tool_registry`` import, no ``check()`` call and no allowlist — a total
       bypass of the gate. Worse, ``ARKHEIA_INSTALL.md`` documented it as the Windows
       entry point (``"args": ["C:/arkheia-mcp/server.py"]``), so the *published*
       install instructions launched the ungated server. A gate with a documented
       side door is not a gate.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Repo root: this file is <root>/tests/test_tool_gate_floor.py
ROOT = Path(__file__).resolve().parents[1]

GATE_MODULE = ROOT / "mcp_server" / "tool_registry.py"
SERVER_MODULE = ROOT / "mcp_server" / "server.py"

# Production source roots (NON-test). A read site or a gate call only counts if it
# is real production wiring, so anything under a `tests` directory is excluded.
PROD_DIRS = ("proxy", "mcp_server", "registry_server")
PROD_ROOT_FILES = ("server.py",)

# ---------------------------------------------------------------------------
# INV-3 registry: policy-control fields of ToolPolicy that MUST be consulted by
# production code. `name` and `description` are metadata, not controls.
# ---------------------------------------------------------------------------
POLICY_CONTROL_FIELDS = ("permissions", "network_egress", "requires_human_confirm")

# Controls that are declared but deliberately NOT yet enforced, each with the
# reason. This set is asserted EXACTLY, in both directions: adding a new
# unenforced control is RED, and enforcing one of these without removing it from
# here is also RED. An allowlist that can grow silently is not a floor.
KNOWN_UNENFORCED: dict[str, str] = {
    "network_egress": (
        "No egress chokepoint exists in mcp_server: mcp_server/tools/providers.py "
        "opens its own httpx client per provider, so there is nothing for the gate "
        "to deny. Enforcing it needs a design decision on WHERE the chokepoint "
        "lives (provider factory vs process-level cap) — deferred to David, "
        "explicitly named in the PR that added this floor rather than left silent."
    ),
}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _production_py_files() -> list[Path]:
    files: list[Path] = []
    for d in PROD_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in base.rglob("*.py"):
            if "tests" in p.parts:
                continue
            files.append(p)
    for name in PROD_ROOT_FILES:
        p = ROOT / name
        if p.is_file():
            files.append(p)
    return files


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _is_mcp_tool_decorator(dec: ast.expr) -> bool:
    """Match @mcp.tool and @mcp.tool(...) (any args)."""
    node = dec.func if isinstance(dec, ast.Call) else dec
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "tool"
        and isinstance(node.value, ast.Name)
        and node.value.id == "mcp"
    )


def _mcp_tool_functions(tree: ast.Module) -> dict[str, ast.AST]:
    """Map tool-function name -> its function node, for every @mcp.tool in `tree`."""
    out: dict[str, ast.AST] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if any(_is_mcp_tool_decorator(d) for d in node.decorator_list):
                out[node.name] = node
    return out


def _registry_keys(tree: ast.Module) -> set[str]:
    """Literal string keys of the module-level REGISTRY dict."""
    for node in ast.walk(tree):
        target_names: list[str] = []
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
        elif isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "REGISTRY" not in target_names:
            continue
        if isinstance(node.value, ast.Dict):
            return {
                k.value
                for k in node.value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
    return set()


def _check_call_literals(fn: ast.AST) -> set[str]:
    """String literals passed as the first positional arg to a `check(...)` call."""
    out: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if name != "check" or not node.args:
            continue
        a0 = node.args[0]
        if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
            out.add(a0.value)
    return out


def _attribute_reads(tree: ast.Module, field: str) -> int:
    """Count `<expr>.<field>` attribute loads in `tree`."""
    return sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr == field and isinstance(n.ctx, ast.Load)
    )


# ---------------------------------------------------------------------------
# INV-1 — the gate is called in every tool body
# ---------------------------------------------------------------------------

def test_inv1_every_mcp_tool_calls_the_gate():
    tree = _parse(SERVER_MODULE)
    tools = _mcp_tool_functions(tree)

    # Work-done assertion (DONE.md clause 9): a scan that scanned nothing must
    # not pass. Name the units, never just the aggregate.
    assert len(tools) >= 9, (
        f"discovered only {len(tools)} @mcp.tool functions in {SERVER_MODULE.name} "
        f"({sorted(tools)}) — the discovery is broken, not the code. This floor "
        f"must never report clean off an empty scan."
    )

    ungated = sorted(n for n, fn in tools.items() if n not in _check_call_literals(fn))
    assert not ungated, (
        f"{len(ungated)} of {len(tools)} @mcp.tool functions never call the policy "
        f"gate with their own name: {ungated}. tool_registry.check() is documented "
        f"as 'Call this as the FIRST statement in every MCP tool body'. An ungated "
        f"tool is exposed to every orchestrator with no allow/deny decision at all. "
        f"Fix: add `check(\"<tool_name>\")` to each named body."
    )


# ---------------------------------------------------------------------------
# INV-2 — REGISTRY and the decorator set are identical, BOTH directions
# ---------------------------------------------------------------------------

def test_inv2_registry_and_decorated_tools_are_in_exact_parity():
    server_tools = set(_mcp_tool_functions(_parse(SERVER_MODULE)))
    registry = _registry_keys(_parse(GATE_MODULE))

    assert registry, (
        f"parsed ZERO literal keys out of REGISTRY in {GATE_MODULE.name} — the "
        f"parser is broken, not the registry. Empty-scan must fail, not pass."
    )

    advertised_but_unpoliced = sorted(server_tools - registry)
    policed_but_not_advertised = sorted(registry - server_tools)

    assert not advertised_but_unpoliced, (
        f"{len(advertised_but_unpoliced)} tool(s) are exposed via @mcp.tool but have "
        f"NO ToolPolicy in REGISTRY: {advertised_but_unpoliced}. FastMCP's decorator "
        f"registry — not REGISTRY — decides what is advertised and dispatchable, so "
        f"such a tool is callable by any orchestrator while REGISTRY (the thing the "
        f"product calls its allowlist) has never heard of it."
    )
    assert not policed_but_not_advertised, (
        f"{len(policed_but_not_advertised)} ToolPolicy entr(ies) in REGISTRY name a "
        f"tool that no longer exists as an @mcp.tool: {policed_but_not_advertised}. "
        f"Dead policy is misleading evidence in a governance product — a reviewer "
        f"reading REGISTRY would believe a control covers a live tool."
    )


# ---------------------------------------------------------------------------
# INV-3 — every declared policy control is read by production code
# ---------------------------------------------------------------------------

def test_inv3_declared_policy_controls_have_a_production_read_site():
    gate_tree = _parse(GATE_MODULE)

    # Reads that occur ANYWHERE in production code, including the gate module
    # itself — check() consulting policy.requires_human_confirm IS enforcement.
    # What does not count is the dataclass field *declaration*, which is an
    # AnnAssign, not an attribute Load, so it is structurally excluded.
    read_counts: dict[str, int] = {}
    for path in _production_py_files():
        tree = _parse(path)
        for field in POLICY_CONTROL_FIELDS:
            read_counts[field] = read_counts.get(field, 0) + _attribute_reads(tree, field)

    unenforced = sorted(f for f in POLICY_CONTROL_FIELDS if read_counts.get(f, 0) == 0)

    assert unenforced == sorted(KNOWN_UNENFORCED), (
        f"ToolPolicy policy-control enforcement drifted from the declared floor.\n"
        f"  unenforced now : {unenforced}\n"
        f"  expected       : {sorted(KNOWN_UNENFORCED)}\n"
        f"  read counts    : { {f: read_counts.get(f, 0) for f in POLICY_CONTROL_FIELDS} }\n"
        f"A control declared on ToolPolicy but never read by production code is "
        f"DECORATIVE — it enforces nothing however well it is documented. If you "
        f"enforced one of the expected-unenforced controls, remove it from "
        f"KNOWN_UNENFORCED. If you added a new unenforced control, wire it or "
        f"record it there WITH A REASON — this assertion is exact in both "
        f"directions precisely so neither can happen silently."
    )


def test_inv3_known_unenforced_entries_each_carry_a_reason():
    """A deferral without a stated reason is an unnamed residual — the exact
    defect class this sweep exists to remove."""
    assert KNOWN_UNENFORCED, (
        "KNOWN_UNENFORCED is empty; if every control is now enforced, delete this "
        "test along with the dict rather than leaving a check that checks nothing."
    )
    thin = sorted(k for k, v in KNOWN_UNENFORCED.items() if len(v.strip()) < 40)
    assert not thin, f"KNOWN_UNENFORCED entries with no substantive reason: {thin}"

    # Each deferred control must still be a real ToolPolicy field, or the dict is
    # silently excusing a name that no longer exists.
    stale = sorted(set(KNOWN_UNENFORCED) - set(POLICY_CONTROL_FIELDS))
    assert not stale, (
        f"KNOWN_UNENFORCED names control(s) that are not in POLICY_CONTROL_FIELDS: "
        f"{stale}. A stale excuse silently widens the allowlist."
    )


# ---------------------------------------------------------------------------
# INV-4 — no second, ungated MCP server
# ---------------------------------------------------------------------------

def _defines_mcp_tools(tree: ast.Module) -> bool:
    return bool(_mcp_tool_functions(tree))


def _imports_the_gate(tree: ast.Module) -> bool:
    """True if the module imports tool_registry (directly or via re-export of the
    gated server module)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if "tool_registry" in node.module or node.module in (
                "mcp_server.server",
                "mcp_server",
            ):
                return True
        elif isinstance(node, ast.Import):
            for a in node.names:
                if "tool_registry" in a.name or a.name in ("mcp_server.server",):
                    return True
    return False


def test_inv4_no_ungated_mcp_server_module():
    offenders: list[str] = []
    for path in _production_py_files():
        tree = _parse(path)
        if not _defines_mcp_tools(tree):
            continue
        if not _imports_the_gate(tree):
            offenders.append(str(path.relative_to(ROOT)))

    assert not offenders, (
        f"{len(offenders)} production module(s) define @mcp.tool functions but never "
        f"import the policy gate: {sorted(offenders)}. Each is a complete bypass — a "
        f"second MCP server advertising tools with no allowlist and no allow/deny "
        f"decision. Root server.py was exactly this, and ARKHEIA_INSTALL.md pointed "
        f"the documented Windows install at it. Fix: re-export the gated server "
        f"(`from mcp_server.server import mcp`) rather than redefining tools."
    )
