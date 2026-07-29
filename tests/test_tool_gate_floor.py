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


#: The names the allowlist declaration may be bound to. `_REGISTRY` is the
#: literal dict; `REGISTRY` is the read-only view over it (INV-5c). Both are
#: accepted so this parser reads the DECLARATION wherever it lives, but only a
#: literal `ast.Dict` is ever parsed — a computed allowlist would yield zero keys
#: and trip the empty-scan assertion in INV-2 rather than pass quietly.
REGISTRY_DECL_NAMES = ("REGISTRY", "_REGISTRY")


def _registry_keys(tree: ast.Module) -> set[str]:
    """Literal string keys of the module-level allowlist dict."""
    for node in ast.walk(tree):
        target_names: list[str] = []
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]
        elif isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not any(n in target_names for n in REGISTRY_DECL_NAMES):
            continue
        if isinstance(node.value, ast.Dict):
            return {
                k.value
                for k in node.value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
    return set()


def _module_assignments(tree: ast.Module) -> dict[str, ast.expr]:
    """Map module-level (top-level only) assigned name -> its value expression."""
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


def _classdef(tree: ast.Module, name: str) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == name:
            return node
    return None


def _dataclass_decorator_kwargs(cls: ast.ClassDef) -> dict[str, ast.expr] | None:
    """Keyword args of the @dataclass decorator on `cls`, or None if absent.

    Returns an empty dict for a bare ``@dataclass`` (no parentheses / no kwargs),
    which is distinct from None (not a dataclass at all)."""
    for dec in cls.decorator_list:
        node = dec.func if isinstance(dec, ast.Call) else dec
        dec_name = (
            node.id if isinstance(node, ast.Name)
            else node.attr if isinstance(node, ast.Attribute)
            else None
        )
        if dec_name != "dataclass":
            continue
        if isinstance(dec, ast.Call):
            return {kw.arg: kw.value for kw in dec.keywords if kw.arg}
        return {}
    return None


def _annotated_fields(cls: ast.ClassDef) -> dict[str, str]:
    """Map field name -> its annotation rendered as source text."""
    return {
        node.target.id: ast.unparse(node.annotation)
        for node in cls.body
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
    }


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
# INV-5 — the gate's own state cannot be written by the code it governs
# ---------------------------------------------------------------------------

#: Annotations a ToolPolicy field may carry. A policy field must hold a value
#: that CANNOT be mutated in place, because `check()` hands the registry's own
#: instance to every caller. Asserted as an allowlist rather than a denylist of
#: `list`/`dict`/`set`: a denylist would miss `deque`, `bytearray`, a mutable
#: dataclass, or any type invented later.
IMMUTABLE_FIELD_ANNOTATIONS = (
    "str",
    "bool",
    "int",
    "float",
    "bytes",
    "Permission",
    "tuple[Permission, ...]",
    "tuple[str, ...]",
    "frozenset[str]",
)


def test_inv5a_tool_policy_is_a_frozen_dataclass():
    """Reproduced 2026-07-27 on master @ 8d22dc5 — a LIVE privilege escalation:

        p = check("memory_store")   # declared local-only, READ+WRITE
        p.network_egress = True
        p.permissions.append(Permission.DEPLOY)
        check("memory_store")       # egress-permitted + DEPLOY, process-wide

    `check()` returns REGISTRY's own instance (the suite pins `policy is
    REGISTRY[name]`), so while ToolPolicy was a plain `@dataclass` every caller
    of the gate — i.e. every gated tool body, since check() is documented as the
    FIRST statement in each — held a writable handle on the gate's decision data
    and could widen its own permissions and everyone else's for the life of the
    process.
    """
    cls = _classdef(_parse(GATE_MODULE), "ToolPolicy")
    assert cls is not None, (
        f"ToolPolicy is not defined in {GATE_MODULE.name} — this floor cannot "
        f"report clean off a class it did not find."
    )

    kwargs = _dataclass_decorator_kwargs(cls)
    assert kwargs is not None, "ToolPolicy is no longer a @dataclass"

    frozen = kwargs.get("frozen")
    assert isinstance(frozen, ast.Constant) and frozen.value is True, (
        "ToolPolicy must be declared @dataclass(frozen=True). Without it, "
        "`check(name).network_egress = True` writes THROUGH to REGISTRY and "
        "silently widens the allowlist for every subsequent caller."
    )


def test_inv5b_every_tool_policy_field_is_annotated_immutable():
    """`frozen=True` protects the BINDING, not the object bound: a list, dict or
    set field is still mutable in place on a frozen dataclass. `permissions` —
    the field `check()` itself reads — was `list[Permission]`, so
    `check(name).permissions.append(Permission.DEPLOY)` granted DEPLOY to a
    read-only tool even had the class been frozen."""
    cls = _classdef(_parse(GATE_MODULE), "ToolPolicy")
    assert cls is not None
    fields_ = _annotated_fields(cls)

    # Work-done assertion: an empty field map would make the sweep vacuous.
    assert sorted(fields_) == [
        "description", "name", "network_egress", "permissions",
        "requires_human_confirm",
    ], f"ToolPolicy fields drifted: {sorted(fields_)}"

    mutable = sorted(
        f"{n}: {a}" for n, a in fields_.items()
        if a not in IMMUTABLE_FIELD_ANNOTATIONS
    )
    assert not mutable, (
        f"ToolPolicy field(s) annotated with a mutable type: {mutable}. Allowed "
        f"annotations: {list(IMMUTABLE_FIELD_ANNOTATIONS)}. A caller handed such "
        f"a field can mutate it IN PLACE and the write lands in REGISTRY. If the "
        f"new control genuinely needs a collection, use tuple/frozenset and add "
        f"the annotation here deliberately."
    )


def test_inv5c_the_public_registry_name_is_a_read_only_view():
    """LATE REGISTRATION. `assert_registry_covers()` runs ONCE at startup and
    compares NAMES only; nothing re-reads the allowlist afterwards. So a write to
    the public REGISTRY name after startup — adding an entry, or replacing a
    restrictive entry with a permissive one — would never be re-checked by
    anything. The public name must therefore not be a bare mutable dict."""
    assigns = _module_assignments(_parse(GATE_MODULE))

    assert "REGISTRY" in assigns, (
        f"no module-level REGISTRY assignment found in {GATE_MODULE.name} — the "
        f"parser is broken, not the code. Empty-scan must fail, not pass."
    )

    value = assigns["REGISTRY"]
    assert not isinstance(value, ast.Dict), (
        "REGISTRY is assigned a bare dict literal, so every importer of the gate "
        "can write the allowlist: `REGISTRY['x'] = ToolPolicy(...)` after the "
        "startup self-check has already passed. Declare the literal as _REGISTRY "
        "and expose `REGISTRY = MappingProxyType(_REGISTRY)`."
    )
    assert (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id == "MappingProxyType"
    ), (
        f"REGISTRY must be a MappingProxyType view over the declaration; found "
        f"`{ast.unparse(value)}`."
    )
    assert (
        len(value.args) == 1
        and isinstance(value.args[0], ast.Name)
        and value.args[0].id == "_REGISTRY"
    ), (
        f"REGISTRY must wrap _REGISTRY itself, not a copy of it — a copy would "
        f"be a second, silently divergent allowlist. Found "
        f"`{ast.unparse(value)}`."
    )

    # And the thing it wraps must still be the literal declaration this floor
    # parses for INV-2, so the two invariants cannot describe different objects.
    assert isinstance(assigns.get("_REGISTRY"), ast.Dict), (
        "_REGISTRY must be a literal dict declaration."
    )


def test_inv5d_no_production_module_writes_the_allowlist():
    """The read-only view is a boundary against ACCIDENT, not a sandbox: code can
    still reach for `_REGISTRY` deliberately. Nothing in PRODUCTION may do so —
    if a future policy loader needs to install policies, it must be a named,
    reviewed entry point rather than a bare write from an unrelated module."""
    offenders: list[str] = []
    for path in _production_py_files():
        tree = _parse(path)
        for node in ast.walk(tree):
            # `_REGISTRY[...] = ...`, `del _REGISTRY[...]`, `_REGISTRY.clear()`
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                if node.value.id in REGISTRY_DECL_NAMES and not isinstance(
                    node.ctx, ast.Load
                ):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in REGISTRY_DECL_NAMES
                and node.func.attr in (
                    "clear", "update", "pop", "popitem", "setdefault", "__setitem__",
                )
            ):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")

    # The gate module declares the literal, which is not a write to a container
    # that already exists, so it must not appear here either.
    assert sorted(offenders) == [], (
        f"production code writes the tool allowlist at: {sorted(offenders)}. "
        f"Every such write happens AFTER assert_registry_covers() has passed and "
        f"is re-checked by nothing."
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
# INV-6 — orchestrator dispatch goes through the receipted gate
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


def _calls_named(fn: ast.AST, callee: str) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
        if name == callee:
            out.append(node)
    return out


def _func(tree: ast.Module, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def test_inv6_dispatch_is_gated_by_the_receipted_check():
    tree = _parse(SERVER_MODULE)
    subclasses = _fastmcp_subclasses(tree)
    assert subclasses, (
        f"{SERVER_MODULE.name} defines no FastMCP subclass. Bare FastMCP dispatch "
        "can resolve late-registered or aliased tools before the tool-registry "
        "gate records a decision."
    )

    instance = _module_assignments(tree).get("mcp")
    assert isinstance(instance, ast.Call), "no module-level mcp = ...(...) construction found"
    built_with = instance.func.id if isinstance(instance.func, ast.Name) else getattr(instance.func, "attr", None)
    assert built_with in subclasses, (
        f"mcp is constructed with {built_with!r}, not a gated FastMCP subclass "
        f"from {sorted(subclasses)}"
    )

    methods = {
        n.name: n
        for n in subclasses[built_with].body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "call_tool" in methods, (
        f"{built_with} does not override call_tool, the dispatch method every "
        "orchestrator-driven tools/call reaches."
    )
    calls = _calls_named(methods["call_tool"], "check_receipted")
    assert calls, (
        f"{built_with}.call_tool never calls check_receipted(...). Calling bare "
        "check() would gate the call but leave the decision unreceipted."
    )
    arg0 = calls[0].args[0] if calls[0].args else None
    assert isinstance(arg0, ast.Name) and arg0.id == "name", (
        f"{built_with}.call_tool does not pass the dispatched name to "
        f"check_receipted; got {ast.dump(arg0) if arg0 else 'no positional arg'}"
    )


def test_inv6b_receipted_check_returns_the_allow_decision_not_just_policy():
    fn = _func(_parse(GATE_MODULE), "check_receipted")
    assert fn is not None, "check_receipted is missing"

    returns = [n.value for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value]
    assert returns, "check_receipted has no value return on the allow path"
    assert any(isinstance(value, ast.Name) and value.id == "decision" for value in returns), (
        "check_receipted must return the GateDecision it just receipted so the "
        "allow caller can see receipt_id and receipt_status."
    )

    policy_returns = [
        ast.unparse(value)
        for value in returns
        if isinstance(value, ast.Attribute) and value.attr == "policy"
    ]
    assert not policy_returns, (
        "check_receipted returned only the ToolPolicy and discarded the receipt "
        f"status on the allow path: {policy_returns}"
    )


def test_inv6c_dispatch_carries_the_derived_receipt_status_to_the_result():
    tree = _parse(SERVER_MODULE)
    subclasses = _fastmcp_subclasses(tree)
    instance = _module_assignments(tree).get("mcp")
    assert isinstance(instance, ast.Call), "no module-level mcp = ...(...) construction found"
    built_with = instance.func.id if isinstance(instance.func, ast.Name) else getattr(instance.func, "attr", None)
    call_tool = next(
        n
        for n in subclasses[built_with].body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "call_tool"
    )

    receipted_names: set[str] = set()
    for node in ast.walk(call_tool):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        value = node.value.value if isinstance(node.value, ast.Await) else node.value
        if (
            isinstance(target, ast.Name)
            and isinstance(value, ast.Call)
            and (
                (isinstance(value.func, ast.Name) and value.func.id == "check_receipted")
                or getattr(value.func, "attr", None) == "check_receipted"
            )
        ):
            receipted_names.add(target.id)

    assert receipted_names, (
        "GatedFastMCP.call_tool calls check_receipted but does not keep the "
        "GateDecision; the allow-path receipt status would be discarded."
    )

    carriers = [
        call
        for call in _calls_named(call_tool, "_attach_tool_gate_receipt")
        if any(isinstance(arg, ast.Name) and arg.id in receipted_names for arg in call.args)
    ]
    assert carriers, (
        "GatedFastMCP.call_tool keeps the receipted decision but never passes it "
        "to the result-carriage helper."
    )

    helper = _func(tree, "_attach_tool_gate_receipt")
    assert helper is not None, "_attach_tool_gate_receipt is missing"
    decision_attrs = {
        n.attr
        for n in ast.walk(helper)
        if (
            isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Name)
            and n.value.id == "decision"
            and isinstance(n.ctx, ast.Load)
        )
    }
    assert {"receipt_id", "receipt_status"} <= decision_attrs, (
        "result carriage must read receipt_id and receipt_status from the "
        f"GateDecision; saw decision attributes {sorted(decision_attrs)}"
    )
    literal_statuses = []
    for node in ast.walk(helper):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if (
                isinstance(key, ast.Constant)
                and key.value == "receipt_status"
                and isinstance(value, ast.Constant)
            ):
                literal_statuses.append(value.lineno)
    assert literal_statuses == [], (
        "receipt_status carriage is hard-coded instead of derived from the "
        f"GateDecision at line(s) {literal_statuses}."
    )


def test_inv6d_startup_selfcheck_reads_the_unfiltered_tool_list():
    tree = _parse(SERVER_MODULE)
    fn = next(
        (
            n
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "startup_policy_selfcheck"
        ),
        None,
    )
    assert fn is not None, "startup_policy_selfcheck is missing"
    attrs = {
        n.attr
        for n in ast.walk(fn)
        if isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load)
    }
    assert "list_tools_ungated" in attrs, (
        "startup_policy_selfcheck must inspect the unfiltered advertisement. "
        "Using list_tools() would let the registry filter hide an ungoverned tool "
        "from the very self-check meant to catch it."
    )


# ---------------------------------------------------------------------------
# INV-7 — tool-gate receipt decisions are constants
# ---------------------------------------------------------------------------

DECISION_CONSTANT_PREFIX = "DECISION_"


def _is_decision_constant(node: ast.expr | None) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr.startswith(DECISION_CONSTANT_PREFIX)
    if isinstance(node, ast.Name):
        return node.id.startswith(DECISION_CONSTANT_PREFIX)
    return False


def test_inv7_tool_gate_build_record_decisions_are_named_constants():
    tree = _parse(GATE_MODULE)
    offenders: list[str] = []
    sites = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
        if name != "build_record":
            continue
        sites += 1
        decision = next((kw.value for kw in node.keywords if kw.arg == "decision"), None)
        if not _is_decision_constant(decision):
            offenders.append(
                f"{GATE_MODULE.name}:{node.lineno} decision="
                f"{ast.dump(decision) if decision is not None else '<missing>'}"
            )

    assert sites >= 2, (
        "found fewer than two tool-gate build_record call sites; this invariant "
        "must see both allow and deny receipt branches."
    )
    assert offenders == [], (
        "tool-gate receipt decisions must be DECISION_* constants, not runtime "
        f"strings or variables: {offenders}"
    )


def test_inv7_negative_self_test_decision_constant_predicate_rejects_runtime_strings():
    bad = ast.parse('receipts.build_record(decision="denied")', mode="eval").body
    assert isinstance(bad, ast.Call)
    decision = next(kw.value for kw in bad.keywords if kw.arg == "decision")
    assert not _is_decision_constant(decision)
