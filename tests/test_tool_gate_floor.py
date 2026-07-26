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

------------------------------------------------------------------------------
Added 2026-07-26 by the receipted + adversarial pass on this same flow
------------------------------------------------------------------------------
INV-5  The gate is at the DISPATCH chokepoint, not only in the tool bodies.
       INV-1 can only see functions written as ``@mcp.tool`` in this one module.
       ``mcp.add_tool(fn, name="anything")`` after boot is advertised, dispatchable,
       and invisible to both INV-1 and the boot-time self-check — as is the same
       function re-registered under a second, unpoliced NAME, where the body's
       ``check("real_name")`` passes while the invoked name was never policed. So
       the FastMCP instance must be a subclass whose ``call_tool`` runs the
       RECEIPTED gate before delegating.

INV-6  Every ``build_record`` call site passes a DECISION CONSTANT.
       ``receipts.build_record`` raises ValueError on an unknown decision, and its
       callers are all in a guarded receipt path that must not let a receipt fault
       block the decision. Those two facts together mean a typo'd decision degrades
       to "a log line and no row" unless the decision can never be a typo. Pinning
       the argument to a module constant statically is what makes it never a typo:
       a misspelled constant is an ImportError/AttributeError at load, not a silent
       hole at runtime. (Compiled from the sibling registry-auth flow, where exactly
       this shape survived review.)

INV-7  A control read for EVIDENCE is not a control that is ENFORCED.
       INV-3 counted any production attribute read of a policy-control field as
       enforcement. Then the receipt work read ``policy.network_egress`` in order to
       RECORD the declared posture — and INV-3 went green, reporting a control as
       enforced when nothing had changed about whether it can deny. That is a floor
       that stopped being able to fail. INV-3 is now scoped to reads inside the
       DECISION function, and INV-7 asserts the scan is looking in the right place
       by pinning the set of functions that can raise a policy denial at all.
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
        "explicitly named in the PR that added this floor rather than left silent. "
        "NOTE (2026-07-26): the declared posture is now READ, to be recorded on the "
        "gate's decision receipt. That is evidence, not enforcement — it still "
        "cannot deny anything, so it stays here. See INV-7."
    ),
}

# ---------------------------------------------------------------------------
# INV-3/INV-7 registry: the DECISION functions — the only production functions
# permitted to raise a policy denial. A policy-control read counts as ENFORCEMENT
# only if it happens inside one of these, because only here can the value make a
# call fail. Asserted exactly (INV-7) so the enforcement scan cannot silently
# start looking in the wrong place.
# ---------------------------------------------------------------------------
DENY_FUNCTIONS = ("check", "assert_registry_covers")

# The module-level name holding the writable policy dict, and the read-only view
# every other module imports. Both are asserted to exist and to be related.
POLICY_DICT_NAME = "_POLICIES"
POLICY_VIEW_NAME = "REGISTRY"

# INV-6: the receipt-decision constants a build_record call site may name.
DECISION_CONSTANT_PREFIX = "DECISION_"


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


def _module_assignments(tree: ast.Module) -> dict[str, ast.expr]:
    """Map module-level assigned name -> its value expression."""
    out: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                out[node.target.id] = node.value
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value
    return out


def _registry_keys(tree: ast.Module) -> set[str]:
    """Literal string keys of the module-level policy dict.

    ANCHOR REPAIRED 2026-07-26: this used to read a name called ``REGISTRY`` bound
    directly to a dict literal. ``REGISTRY`` is now a ``MappingProxyType`` over the
    private ``_POLICIES``, so the old parser found no dict and returned an empty
    set — which the companion emptiness assertion in INV-2 caught as a broken
    parser rather than passing vacuously. That assertion is why this repair is a
    two-line change and not an incident.
    """
    value = _module_assignments(tree).get(POLICY_DICT_NAME)
    if isinstance(value, ast.Dict):
        return {
            k.value
            for k in value.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
    return set()


def _function_named(tree: ast.Module, name: str) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _enclosing_functions(tree: ast.Module) -> dict[ast.AST, str]:
    """Map every node inside a function body to that function's name (innermost wins)."""
    owner: dict[ast.AST, str] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            owner[node] = fn.name
    return owner


def _calls_named(fn: ast.AST, callee: str) -> list[ast.Call]:
    """Every ``callee(...)`` / ``x.callee(...)`` call inside ``fn``."""
    out: list[ast.Call] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else (f.attr if isinstance(f, ast.Attribute) else None)
        if name == callee:
            out.append(node)
    return out


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

def _enforcement_read_counts() -> dict[str, int]:
    """
    Per control field, how many reads happen INSIDE a decision function.

    ANCHOR REPAIRED 2026-07-26. This used to count reads anywhere in production
    code. Then ``_emit_gate_receipt`` read ``policy.network_egress`` in order to
    RECORD the declared posture on the decision receipt, and the invariant went
    green — reporting the control as enforced although nothing had changed about
    whether it can deny anything. A control read for evidence is not a control that
    is enforced, and a floor that cannot tell the difference has stopped being able
    to fail. Only reads inside ``DENY_FUNCTIONS`` count, because only there can the
    value make a call fail; INV-7 pins that set so this scope cannot silently drift.
    """
    counts: dict[str, int] = {f: 0 for f in POLICY_CONTROL_FIELDS}
    for path in _production_py_files():
        tree = _parse(path)
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and node.attr in counts
            ):
                continue
            if owner.get(node) in DENY_FUNCTIONS:
                counts[node.attr] += 1
    return counts


def test_inv3_declared_policy_controls_are_read_BY_THE_DECISION():
    read_counts = _enforcement_read_counts()

    unenforced = sorted(f for f in POLICY_CONTROL_FIELDS if read_counts.get(f, 0) == 0)

    assert unenforced == sorted(KNOWN_UNENFORCED), (
        f"ToolPolicy policy-control enforcement drifted from the declared floor.\n"
        f"  unenforced now : {unenforced}\n"
        f"  expected       : {sorted(KNOWN_UNENFORCED)}\n"
        f"  read counts    : { {f: read_counts.get(f, 0) for f in POLICY_CONTROL_FIELDS} }\n"
        f"A control declared on ToolPolicy but never read BY A DECISION FUNCTION "
        f"({list(DENY_FUNCTIONS)}) is DECORATIVE — it enforces nothing however well "
        f"it is documented, and reading it elsewhere (e.g. to record it on a "
        f"receipt) does not change that. If you enforced one of the "
        f"expected-unenforced controls, remove it from KNOWN_UNENFORCED. If you "
        f"added a new unenforced control, wire it or record it there WITH A REASON "
        f"— this assertion is exact in both directions precisely so neither can "
        f"happen silently."
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


# ---------------------------------------------------------------------------
# INV-2b — REGISTRY is a read-only VIEW of the policy dict
# ---------------------------------------------------------------------------

def test_inv2b_registry_is_a_readonly_view_of_the_policy_dict():
    """``check()`` hands the ALLOW path the live policy object out of the registry,
    and every module imports ``REGISTRY``. While that name was the mutable dict
    itself, ``REGISTRY["evil"] = ToolPolicy(...)`` injected a policy for an
    ungoverned tool through the public handle, and ``ToolPolicy`` being a plain
    mutable dataclass meant the object the gate RETURNED could be widened for every
    later decision in the process. The shape is pinned here rather than only in a
    unit test because it is a property of the module's structure: one writable dict,
    one read-only export, and a frozen policy record.
    """
    tree = _parse(GATE_MODULE)
    assigned = _module_assignments(tree)

    assert POLICY_DICT_NAME in assigned and isinstance(assigned[POLICY_DICT_NAME], ast.Dict), (
        f"{GATE_MODULE.name} has no module-level dict literal named "
        f"{POLICY_DICT_NAME!r}. The policy dict is the subject of INV-2's key scan; "
        f"if it was renamed, repair this floor rather than leaving the scan blind."
    )

    view = assigned.get(POLICY_VIEW_NAME)
    assert view is not None, f"{POLICY_VIEW_NAME} is not assigned at module level"
    assert isinstance(view, ast.Call), (
        f"{POLICY_VIEW_NAME} is not built by a call — it must be "
        f"MappingProxyType({POLICY_DICT_NAME}), a read-only view, so a policy "
        f"cannot be injected through the name every other module imports."
    )
    callee = view.func
    callee_name = callee.id if isinstance(callee, ast.Name) else getattr(callee, "attr", None)
    assert callee_name == "MappingProxyType", (
        f"{POLICY_VIEW_NAME} is built by {callee_name!r}, not MappingProxyType"
    )
    assert [a.id for a in view.args if isinstance(a, ast.Name)] == [POLICY_DICT_NAME], (
        f"{POLICY_VIEW_NAME} does not proxy {POLICY_DICT_NAME}"
    )

    # ToolPolicy must be frozen: the gate returns the live object on ALLOW.
    policy_cls = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.ClassDef) and n.name == "ToolPolicy"),
        None,
    )
    assert policy_cls is not None, "ToolPolicy class not found"
    frozen = False
    for dec in policy_cls.decorator_list:
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "frozen" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    frozen = True
    assert frozen, (
        "ToolPolicy is not @dataclass(frozen=True). check() returns the registry's "
        "OWN policy object on the allow path, so a mutable one lets any caller widen "
        "the policy for every subsequent decision in the process without ever "
        "touching the registry."
    )


# ---------------------------------------------------------------------------
# INV-5 — the gate is at the DISPATCH chokepoint
# ---------------------------------------------------------------------------

def _fastmcp_subclasses(tree: ast.Module) -> dict[str, ast.ClassDef]:
    out: dict[str, ast.ClassDef] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            b.id if isinstance(b, ast.Name) else getattr(b, "attr", None)
            for b in node.bases
        }
        if "FastMCP" in base_names:
            out[node.name] = node
    return out


def test_inv5_dispatch_is_gated_by_the_receipted_check():
    """Every orchestrator-driven call arrives at ``call_tool``. INV-1 can only see
    ``@mcp.tool`` functions in this one module, so it cannot see a tool registered
    after boot (``mcp.add_tool(fn, name="anything")`` — advertised, dispatchable,
    and invisible to the boot-time self-check) nor the same function re-registered
    under a second, unpoliced NAME, where the body's own ``check("real_name")``
    passes while the invoked name was never policed at all.
    """
    tree = _parse(SERVER_MODULE)
    subclasses = _fastmcp_subclasses(tree)
    assert subclasses, (
        f"{SERVER_MODULE.name} defines no FastMCP subclass, so the framework's own "
        f"dispatch runs ungated: any tool reachable by name executes without the "
        f"gate having a say. Fix: subclass FastMCP, override call_tool to await "
        f"check_receipted(name) first, and construct the server from the subclass."
    )

    # The server instance must be built from a gated subclass, not bare FastMCP.
    instance_calls = [
        c for name, c in _module_assignments(tree).items()
        if name == "mcp" and isinstance(c, ast.Call)
    ]
    assert instance_calls, "no module-level `mcp = ...(...)` server construction found"
    built_with = instance_calls[0].func
    built_name = built_with.id if isinstance(built_with, ast.Name) else getattr(built_with, "attr", None)
    assert built_name in subclasses, (
        f"the server instance is built with {built_name!r}, which is not one of the "
        f"gated subclasses {sorted(subclasses)}. A gated subclass nobody instantiates "
        f"gates nothing."
    )

    gated = subclasses[built_name]
    overrides = {
        n.name: n for n in gated.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "call_tool" in overrides, (
        f"{built_name} does not override call_tool — the one method every tools/call "
        f"passes through."
    )
    receipted = _calls_named(overrides["call_tool"], "check_receipted")
    assert receipted, (
        f"{built_name}.call_tool does not call check_receipted(...). Calling the "
        f"unreceipted check() here would gate the dispatch but leave the decision "
        f"off the record, which is the defect the receipted axis exists to close."
    )
    # The gate must run on the DISPATCHED name, not a constant.
    arg0 = receipted[0].args[0] if receipted[0].args else None
    assert isinstance(arg0, ast.Name) and arg0.id == "name", (
        f"{built_name}.call_tool passes {ast.dump(arg0) if arg0 else 'nothing'} to "
        f"check_receipted, not the dispatched `name`. Gating a hard-coded name while "
        f"dispatching a caller-supplied one is a gate that always says yes."
    )


def test_inv5b_startup_selfcheck_reads_the_UNFILTERED_advertisement():
    """The gated ``list_tools`` withholds ungoverned tools from the advertisement.
    Feeding that filtered list to the coverage self-check would make the check
    compare the registry against a list the registry had just filtered — it would
    agree with itself for exactly the drift it exists to catch, which is the
    'a check that passes by finding nothing' failure in its purest form.
    """
    tree = _parse(SERVER_MODULE)
    fn = _function_named(tree, "startup_policy_selfcheck")
    assert fn is not None, "startup_policy_selfcheck() is gone — INV-2's runtime backstop"

    read_names = {
        n.attr for n in ast.walk(fn)
        if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)
    }
    assert "list_tools_ungated" in read_names, (
        "startup_policy_selfcheck does not read list_tools_ungated. If it reads the "
        "filtered list_tools instead, an ungoverned tool is removed from the "
        "advertisement by the filter and the coverage check then sees perfect parity "
        "— reporting clean for the precise condition it exists to refuse."
    )
    assert "list_tools" not in read_names or "list_tools_ungated" in read_names


# ---------------------------------------------------------------------------
# INV-6 — every receipt decision argument is a constant, not a runtime string
# ---------------------------------------------------------------------------

def _is_decision_constant(node: ast.expr | None) -> bool:
    """
    True only for a NAME referring to a ``DECISION_*`` constant.

    Extracted from the invariant so it can carry a negative self-test: a check that
    passes by finding nothing must prove it can find something (DONE.md v1.19), and
    the mutation run found exactly this gap — weakening the type test survived,
    because every call site in the tree today happens to be the accepted shape, so
    nothing in the repo exercised the rejecting branch.
    """
    if isinstance(node, ast.Attribute):
        return node.attr.startswith(DECISION_CONSTANT_PREFIX)
    if isinstance(node, ast.Name):
        return node.id.startswith(DECISION_CONSTANT_PREFIX)
    return False


def test_inv6_negative_self_test_the_predicate_can_reject():
    """The rejecting branch, exercised directly. Without this, INV-6 passes over a
    clean tree whether or not it is still capable of failing."""
    def expr(src: str) -> ast.expr:
        return ast.parse(src, mode="eval").body

    # Accepted: a module constant, qualified or bare.
    assert _is_decision_constant(expr("receipts.DECISION_DENIED"))
    assert _is_decision_constant(expr("DECISION_ALLOWED"))

    # Rejected: every shape that reintroduces a runtime-typo'd decision.
    for bad in (
        '"denied"',                     # a bare string literal
        "decision",                     # a variable
        "f'{prefix}denied'",            # an f-string
        "verdict.value",                # an attribute that is not a DECISION_*
        "outcomes[key]",                # a lookup
        "str(decision)",                # a call
        "None",
    ):
        assert not _is_decision_constant(expr(bad)), f"{bad} must be rejected"
    assert not _is_decision_constant(None)


def test_inv6_build_record_decisions_are_named_constants():
    """``receipts.build_record`` raises ValueError on an unknown decision and every
    caller sits in a guarded receipt path (correctly — a receipt failure must not
    block the decision). Those two facts compose into a hole: a typo'd decision
    yields a log line and NO ROW, so the caller-boundary guarantee is gone while the
    fail-open posture still looks right. This was found on the sibling registry-auth
    flow. The static fix is to make a typo impossible: the argument must be a NAME
    referring to a DECISION_* constant, so a misspelling is an AttributeError or
    NameError at import rather than a silent gap at runtime.
    """
    offenders: list[str] = []
    sites = 0

    for path in _production_py_files():
        tree = _parse(path)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            fname = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if fname != "build_record":
                continue
            sites += 1
            decision = next((kw.value for kw in node.keywords if kw.arg == "decision"), None)
            rel = f"{path.relative_to(ROOT)}:{node.lineno}"
            if decision is None:
                offenders.append(f"{rel} (no decision= keyword)")
                continue
            if not _is_decision_constant(decision):
                offenders.append(f"{rel} (decision={ast.dump(decision)[:80]})")

    # Work-done assertion (DONE.md clause 9): a scan that found no call sites must
    # not report clean. If build_record is ever renamed this fails loudly instead of
    # quietly covering nothing.
    assert sites >= 1, (
        "found ZERO build_record(...) call sites in production code — the scan is "
        "broken, not the code. This invariant must never pass off an empty scan."
    )
    assert not offenders, (
        f"{len(offenders)} of {sites} build_record call site(s) pass a decision that "
        f"is not a DECISION_* constant: {offenders}. A runtime string here degrades "
        f"a malformed decision into 'a log line and no receipt', because the caller "
        f"correctly refuses to let a receipt fault block the decision."
    )


# ---------------------------------------------------------------------------
# INV-7 — the enforcement scan is looking in the right place
# ---------------------------------------------------------------------------

def _policy_deny_raising_functions() -> dict[str, list[str]]:
    """Production functions that raise a PolicyViolation (or subclass) BY NAME."""
    found: dict[str, list[str]] = {}
    for path in _production_py_files():
        tree = _parse(path)
        owner = _enclosing_functions(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                continue
            f = node.exc.func
            exc_name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if exc_name in ("PolicyViolation", "RegistryCoverageError"):
                fn_name = owner.get(node, "<module>")
                found.setdefault(fn_name, []).append(
                    f"{path.relative_to(ROOT)}:{node.lineno}"
                )
    return found


def test_inv7_the_set_of_policy_deny_sites_is_pinned():
    """INV-3 only counts a control as ENFORCED if it is read inside DENY_FUNCTIONS.
    That scope is only meaningful if DENY_FUNCTIONS really is where denials happen —
    otherwise the enforcement scan looks in the wrong place, and looking in the wrong
    place is indistinguishable from a clean bill of health. So pin the set exactly:
    a new function that can refuse a call must either be added to DENY_FUNCTIONS
    (and its control reads then count) or it is an unreviewed denial site.
    """
    found = _policy_deny_raising_functions()
    assert found, (
        "found ZERO functions raising PolicyViolation in production code. Either the "
        "gate no longer refuses anything, or this scan is broken; both are red."
    )
    assert sorted(found) == sorted(DENY_FUNCTIONS), (
        f"policy-denial sites drifted.\n"
        f"  raising now : { {k: v for k, v in sorted(found.items())} }\n"
        f"  expected    : {sorted(DENY_FUNCTIONS)}\n"
        f"INV-3 counts a policy control as ENFORCED only when it is read inside one "
        f"of the expected functions. A denial site outside that set means either the "
        f"enforcement scan is now blind to real enforcement, or a refusal has been "
        f"added somewhere nobody reviewed. Update DENY_FUNCTIONS deliberately."
    )
