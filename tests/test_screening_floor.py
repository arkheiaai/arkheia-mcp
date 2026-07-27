"""
FLOOR INVARIANT — provider inference may not reach a caller without its
Arkheia verdict attached.

Floor tier contract: this test is stdlib-only (``ast`` + ``pathlib``). It imports
no third-party package, opens no socket and starts no app, so it runs under a bare
``pytest`` with zero project dependencies and has zero interpreter variance.

------------------------------------------------------------------------------
Why this invariant exists
------------------------------------------------------------------------------
``mcp_server/server.py`` advertises the product claim this repository is sold on:

    Provider wrappers (single source of truth for all inference)
      run_grok   -- call xAI Grok + screen through Arkheia
      ...
    If it didn't go through here, it's not in the audit log.

The word that matters is *mandatory*. Screening is mandatory only if there is
NO return path out of a provider wrapper that carries model output without the
verdict that screened it. Today that holds — every wrapper calls
``proxy.verify()`` unconditionally — but it holds only because four functions
happen to be written correctly, and NOTHING enforced it: at base 3037f0c the
four provider wrappers had **zero tests in any suite**, in CI or out
(``tests/test_smoke_e2e.py`` names them in a ``tools/list`` assertion and never
calls them). "Every wrapper calls verify" was a property of the source that no
check could observe, which is the *presence is not effect* class: a docstring
promising screening is not screening.

This floor check makes the claim structurally enforced instead of merely true.
It is deliberately STATIC: it cannot be skipped, it costs milliseconds, and it
observes every provider wrapper including ones added tomorrow.

------------------------------------------------------------------------------
What is asserted
------------------------------------------------------------------------------
Discovery is BEHAVIOUR-driven, not name-driven, so a new unscreened wrapper
cannot evade the check by not being called ``run_*``:

  INV-1  Population is non-zero, and every function that calls a provider is
         named in the verdict. A run over zero provider call sites FAILS
         (DONE.md floor entry 9: a measurement gate must fail when it measures
         nothing).
  INV-2  Every function containing a provider call also calls ``proxy.verify``.
  INV-3  The screening call is UNCONDITIONAL — at the top level of the function
         body, never nested in an ``if`` / ``try`` / loop / ``with``, so no
         configuration or exception can skip it.
  INV-4  Screening happens AFTER the provider call, and no ``return`` sits
         between them (a wrapper may refuse BEFORE calling a provider — that
         path returns no model output — but once output exists it may not leave
         unscreened).
  INV-5  Every ``return`` reachable after the provider call references the
         screening result. This is the load-bearing one: it is what makes
         "mandatory" a property of the code rather than of the current author.
  INV-6  The screened response text is derived from the provider result, not a
         literal or an unrelated variable — screening the wrong bytes is not
         screening.
  INV-7  Every function anywhere in production code that calls a name imported
         from ``mcp_server.tools.providers`` is one of the screened functions.
         Closes the "call the provider from an unscreened helper" evasion.
  INV-8  A module that reaches provider egress may not do so through machinery
         this analyser cannot follow (``exec``/``eval``, ``import_module`` or
         ``__import__`` with a non-literal name, ``getattr`` on the provider
         module with a non-literal attribute). Such a module is reported as a
         VIOLATION rather than passed over, because a clean report there would
         mean "nothing was observed", not "nothing is wrong".

------------------------------------------------------------------------------
Call-form coverage — what is OBSERVED and what is NOT, by name
------------------------------------------------------------------------------
The set-equality claim in INV-1 is only as strong as the set of call forms this
analyser can see. The first version recorded ``from ... import call_x`` and
matched only a bare ``call_x(...)`` node, so SEVEN of nine written forms were
invisible — including the ordinary ``import ... as providers`` /
``providers.call_grok(...)``. A floor that claims set equality while blind to
the commonest attribute form is claiming a guarantee it does not have.

OBSERVED (each pinned by a negative control below):
  1. ``from M import call_grok``                    -> ``call_grok(...)``
  2. ``from M import call_grok as cg``              -> ``cg(...)``
  3. ``import M``                                   -> ``M.call_grok(...)``
  4. ``import M as providers``                      -> ``providers.call_grok(...)``
  5. ``from pkg import providers``                  -> ``providers.call_grok(...)``
  6. ``p = importlib.import_module("M")``           -> ``p.call_grok(...)``
  7. ``p = __import__("M", ...)``                   -> ``p.call_grok(...)``
  8. ``fn = getattr(providers, "call_grok")``       -> ``fn(...)``
  9. ``_call = providers.call_grok``                -> ``_call(...)``
Forms 3-9 were all invisible before this revision.

FLAGGED, not resolved — reported as INV-8 so they cannot pass silently:
  A. ``exec(...)`` / ``eval(...)`` in a provider-reaching module
  B. ``import_module(<non-literal>)`` / ``__import__(<non-literal>)``
  C. ``getattr(<provider module>, <non-literal>)``

NOT OBSERVED — genuine gaps, stated so they are not mistaken for absence:
  D. Container dispatch: ``REG = {"grok": providers.call_grok}``; ``REG[k](p)``.
     Bindings are tracked through assignment to a NAME, not into dict/list/set
     literals.
  E. Instance or class attributes: ``self.fn = providers.call_grok``;
     ``self.fn(p)``. No attribute-of-self dataflow is modelled.
  F. ``functools.partial(providers.call_grok, ...)`` and any other wrapping
     callable-factory.
  G. Cross-module indirection: this analyser is per-module, so a helper in
     module A that wraps a provider and is re-exported and called from module B
     is seen in A (INV-7) but the chain is not followed into B.
  H. Provider egress that never touches ``mcp_server.tools.providers`` at all —
     e.g. a raw ``httpx`` POST straight to a vendor endpoint. The whole check is
     anchored on that module, so this is out of scope BY CONSTRUCTION, not
     covered. It is the largest residual hole and it is not closable by static
     analysis of this module alone.
``test_call_form_coverage_ledger_is_accurate`` executes this ledger: every
OBSERVED form must produce a violation, every FLAGGED form must produce INV-8,
and every NOT-OBSERVED form must still be silent — so the list above cannot go
stale in either direction without a test failing.

Every invariant is paired with a NEGATIVE CONTROL below (``test_detects_*``)
that feeds the analyser a deliberately-broken module and asserts it reports
that specific violation. Without those, this file would be a check that passes
without checking.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

# Repo root: this file is <root>/tests/test_screening_floor.py
ROOT = Path(__file__).resolve().parents[1]

SERVER = ROOT / "mcp_server" / "server.py"

# The module that owns raw provider egress. Any name imported from here is a
# provider call: it performs inference and returns model output.
PROVIDER_MODULE = "mcp_server.tools.providers"

# The screening callable. ``proxy`` is the module-level ProxyClient in server.py.
SCREEN_OBJ = "proxy"
SCREEN_ATTR = "verify"

# The keyword argument carrying the bytes that get screened.
SCREENED_TEXT_KWARG = "response"

# Production source roots for INV-7 (test packages excluded — a call site only
# counts if it is real production wiring).
PROD_DIRS = ("mcp_server", "proxy", "registry_server")
PROD_ROOT_FILES = ("server.py",)

# The declared inference surface: every function that may call a provider.
# Asserted as SET EQUALITY, so this fails in both directions — a wrapper that
# stops calling its provider AND a new, undeclared inference path both go red.
EXPECTED_PROVIDER_WRAPPERS = {
    "run_grok",
    "run_gemini",
    "run_ollama",
    "run_together",
}


# ---------------------------------------------------------------------------
# Analyser — pure functions over source text, so it can be run against
# deliberately-broken input by the negative controls below.
# ---------------------------------------------------------------------------

PROVIDER_PKG, PROVIDER_LEAF = PROVIDER_MODULE.rsplit(".", 1)


def _attr_chain(node: ast.AST) -> str | None:
    """Dotted source text of a Name/Attribute chain (``a.b.c``), else None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _str_const(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _provider_bindings(tree: ast.AST) -> tuple[set[str], set[str], list[tuple[int, str]]]:
    """
    Resolve every local name that reaches provider egress.

    Returns ``(callables, module_aliases, dynamic)``:
      callables      local names that ARE a provider callable
      module_aliases local names / dotted prefixes bound to the provider MODULE
      dynamic        (lineno, description) for accesses that cannot be resolved
                     statically — reported as INV-8 rather than passed over,
                     because an unhandled form is NOT-OBSERVED, not absent.

    Iterated to a fixpoint: a binding can chain (module alias -> attribute ->
    local name), and one pass would miss the second link.
    """
    callables: set[str] = set()
    aliases: set[str] = set()
    dynamic: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        # from mcp_server.tools.providers import call_grok [as cg]
        if isinstance(node, ast.ImportFrom) and node.module == PROVIDER_MODULE:
            for a in node.names:
                callables.add(a.asname or a.name)
        # from mcp_server.tools import providers [as p]
        elif isinstance(node, ast.ImportFrom) and node.module == PROVIDER_PKG:
            for a in node.names:
                if a.name == PROVIDER_LEAF:
                    aliases.add(a.asname or a.name)
        # import mcp_server.tools.providers [as p]
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == PROVIDER_MODULE:
                    aliases.add(a.asname or a.name)

    for _ in range(4):  # fixpoint; depth of realistic binding chains
        before = (len(callables), len(aliases), len(dynamic))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if not targets:
                continue
            v = node.value

            # p = importlib.import_module("mcp_server.tools.providers")
            # p = __import__("mcp_server.tools.providers", ...)
            if isinstance(v, ast.Call):
                fname = _attr_chain(v.func) or ""
                if fname in ("importlib.import_module", "import_module", "__import__"):
                    arg = _str_const(v.args[0]) if v.args else None
                    if arg == PROVIDER_MODULE:
                        aliases.update(targets)
                # fn = getattr(providers, "call_grok")
                # fn = getattr(providers, "call_grok")  — literal attribute only;
                # the non-literal form is reported as INV-8 in the scan below.
                elif fname == "getattr" and len(v.args) >= 2:
                    if _attr_chain(v.args[0]) in aliases and _str_const(v.args[1]):
                        callables.update(targets)

            # _call = providers.call_grok        (module alias -> callable)
            chain = _attr_chain(v) if isinstance(v, ast.Attribute) else None
            if chain and chain.rsplit(".", 1)[0] in aliases:
                callables.update(targets)
            # cg = call_grok                     (callable -> another name)
            if isinstance(v, ast.Name) and v.id in callables:
                callables.update(targets)

        if (len(callables), len(aliases), len(dynamic)) == before:
            break

    # Un-analysable machinery ANYWHERE in the module — not only in an
    # assignment. The first cut only inspected `x = import_module(...)`, which
    # missed the indirect form `def load(n): return import_module(n)`.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _attr_chain(node.func) or ""
        if isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval"):
            dynamic.append((
                node.lineno,
                f"`{node.func.id}()` in a module that reaches provider egress — "
                "any call it performs is invisible to static analysis",
            ))
        elif fname in ("importlib.import_module", "import_module", "__import__"):
            if not (node.args and _str_const(node.args[0]) is not None):
                dynamic.append((
                    node.lineno,
                    f"`{fname}(...)` with a NON-LITERAL module argument — the "
                    "imported module cannot be identified statically, so a "
                    "provider import here would be invisible to this check",
                ))
        elif fname == "getattr" and len(node.args) >= 2:
            base = _attr_chain(node.args[0])
            if base in aliases and _str_const(node.args[1]) is None:
                dynamic.append((
                    node.lineno,
                    f"`getattr({base}, <non-literal>)` on the provider module — "
                    "the attribute cannot be identified statically",
                ))

    return callables, aliases, sorted(set(dynamic))


def _provider_names(tree: ast.AST) -> set[str]:
    """Back-compatible view: local names that are provider callables."""
    return _provider_bindings(tree)[0]


def _is_screen_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == SCREEN_ATTR
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == SCREEN_OBJ
    )


def _called_name(
    node: ast.AST,
    callables: set[str] | None = None,
    aliases: set[str] | None = None,
) -> str | None:
    """
    Resolve a Call/Await(Call) to the provider callable it invokes, else None.

    Handles the bare form (``call_grok(...)``) and the ATTRIBUTE form
    (``providers.call_grok(...)``, ``mcp_server.tools.providers.call_grok(...)``).
    The attribute form used to be invisible: ``_called_name`` only matched
    ``ast.Name``, so an aliased module import walked straight past a floor that
    claimed population set equality.
    """
    if isinstance(node, ast.Await):
        node = node.value
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute) and aliases:
        chain = _attr_chain(node.func)
        if chain and chain.rsplit(".", 1)[0] in aliases:
            return node.func.attr
    return None


def _loaded_names(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _functions(tree: ast.AST) -> list[ast.AsyncFunctionDef | ast.FunctionDef]:
    return [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
    ]


def analyse(source: str, filename: str = "<source>") -> dict:
    """
    Analyse one module. Returns:
      {
        "screened":   [function names that call a provider AND screen it],
        "violations": [(inv, function, detail), ...],
        "provider_call_sites": {function_name: [provider names]},
      }
    """
    tree = ast.parse(source, filename=filename)
    providers, aliases, dynamic = _provider_bindings(tree)
    violations: list[tuple[str, str, str]] = []
    screened: list[str] = []
    call_sites: dict[str, list[str]] = {}

    def _provider_call(sub: ast.AST) -> str | None:
        """The provider callable this node invokes, or None."""
        name = _called_name(sub, providers, aliases)
        if name is None:
            return None
        if name in providers:
            return name
        # Any attribute called ON the provider module is provider egress —
        # the module exists to perform inference, so a new function added to it
        # is covered without editing this check.
        inner = sub.value if isinstance(sub, ast.Await) else sub
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute):
            chain = _attr_chain(inner.func)
            if chain and chain.rsplit(".", 1)[0] in aliases:
                return name
        return None

    # --- INV-8: un-analysable access to provider egress --------------------
    # Reported BEFORE any per-function work: if the module reaches providers
    # through machinery this analyser cannot follow, a clean report from the
    # other invariants would mean "nothing was observed", not "nothing is wrong".
    if (providers or aliases or PROVIDER_MODULE in source):
        for lineno, detail in dynamic:
            violations.append((
                "INV-8", f"<module>:{lineno}",
                detail + " — this check cannot observe that path, and an "
                "unobserved path must not be rendered as a clean one.",
            ))

    for fn in _functions(tree):
        body = fn.body
        # --- locate the provider call among TOP-LEVEL statements ------------
        prov_idx: int | None = None
        prov_target: str | None = None
        prov_names: list[str] = []

        for i, stmt in enumerate(body):
            for sub in ast.walk(stmt):
                name = _provider_call(sub)
                if name is not None:
                    prov_names.append(name)
                    if prov_idx is None:
                        prov_idx = i
                        if isinstance(stmt, ast.Assign) and isinstance(
                            stmt.targets[0], ast.Name
                        ):
                            prov_target = stmt.targets[0].id

        if not prov_names:
            continue

        call_sites[fn.name] = prov_names

        # --- INV-2/INV-3: unconditional screening at top level -------------
        screen_idx: int | None = None
        screen_target: str | None = None
        screen_call: ast.Call | None = None
        for i, stmt in enumerate(body):
            value = stmt.value if isinstance(stmt, (ast.Assign, ast.Expr)) else None
            if isinstance(value, ast.Await):
                value = value.value
            if value is not None and _is_screen_call(value):
                screen_idx = i
                screen_call = value
                if isinstance(stmt, ast.Assign) and isinstance(
                    stmt.targets[0], ast.Name
                ):
                    screen_target = stmt.targets[0].id
                break

        if screen_idx is None:
            nested = any(_is_screen_call(n) for n in ast.walk(fn))
            if nested:
                violations.append((
                    "INV-3", fn.name,
                    f"{SCREEN_OBJ}.{SCREEN_ATTR}() is CONDITIONAL — nested inside a "
                    "branch/try/loop, so a configuration or exception can skip "
                    "screening. It must sit at the top level of the function body.",
                ))
            else:
                violations.append((
                    "INV-2", fn.name,
                    f"calls provider {prov_names} but NEVER calls "
                    f"{SCREEN_OBJ}.{SCREEN_ATTR}() — model output reaches the caller "
                    "unscreened.",
                ))
            continue

        # --- INV-4: order, and no early return between the two -------------
        if screen_idx < (prov_idx or 0):
            violations.append((
                "INV-4", fn.name,
                f"{SCREEN_OBJ}.{SCREEN_ATTR}() runs BEFORE the provider call — it "
                "cannot have screened this response.",
            ))
        else:
            for stmt in body[(prov_idx or 0) + 1:screen_idx]:
                if any(isinstance(n, ast.Return) for n in ast.walk(stmt)):
                    violations.append((
                        "INV-4", fn.name,
                        "a `return` sits between the provider call and screening — "
                        "that path returns model output with no verdict.",
                    ))
                    break

        # --- INV-5: every post-provider return carries the verdict ---------
        if screen_target is None:
            violations.append((
                "INV-5", fn.name,
                f"the result of {SCREEN_OBJ}.{SCREEN_ATTR}() is discarded (not "
                "bound to a name), so no return can carry it.",
            ))
        else:
            prov_lineno = body[prov_idx or 0].lineno
            for node in ast.walk(fn):
                if not isinstance(node, ast.Return) or node.lineno <= prov_lineno:
                    continue
                if node.value is None or screen_target not in _loaded_names(node.value):
                    violations.append((
                        "INV-5", fn.name,
                        f"return at line {node.lineno} does not reference the "
                        f"screening result `{screen_target}` — model output can leave "
                        "this function with no verdict attached.",
                    ))

        # --- INV-6: the screened bytes come from the provider result -------
        kwarg = None
        if screen_call is not None:
            for kw in screen_call.keywords:
                if kw.arg == SCREENED_TEXT_KWARG:
                    kwarg = kw.value
        if kwarg is None:
            violations.append((
                "INV-6", fn.name,
                f"{SCREEN_OBJ}.{SCREEN_ATTR}() is called without an explicit "
                f"`{SCREENED_TEXT_KWARG}=` keyword — what got screened is not "
                "statically knowable.",
            ))
        elif prov_target is None or prov_target not in _loaded_names(kwarg):
            violations.append((
                "INV-6", fn.name,
                f"`{SCREENED_TEXT_KWARG}=` passed to "
                f"{SCREEN_OBJ}.{SCREEN_ATTR}() is not derived from the provider "
                f"result (expected a reference to `{prov_target}`) — the wrong bytes "
                "are being screened.",
            ))

        screened.append(fn.name)

    return {
        "screened": screened,
        "violations": violations,
        "provider_call_sites": call_sites,
    }


def _production_py_files() -> list[Path]:
    files: list[Path] = []
    for d in PROD_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in base.rglob("*.py"):
            if "tests" in p.relative_to(ROOT).parts:
                continue
            files.append(p)
    for f in PROD_ROOT_FILES:
        p = ROOT / f
        if p.exists():
            files.append(p)
    return sorted(files)


# ---------------------------------------------------------------------------
# The invariant, against real source
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def report() -> dict:
    assert SERVER.is_file(), f"MCP server source not found at {SERVER}"
    return analyse(SERVER.read_text(encoding="utf-8"), str(SERVER))


def test_population_is_non_zero_and_named(report: dict) -> None:
    """
    INV-1 — the gate must fail when it measures nothing, and must NAME the
    units of work it did (DONE.md floor entry 9(a)): reporting only "no
    violations" over zero call sites is the same sentence as "nothing was
    examined".
    """
    sites = report["provider_call_sites"]
    assert sites, (
        f"INV-1 FAILED: analysed {SERVER} and found ZERO provider call sites. "
        "Either the provider-egress module moved (update PROVIDER_MODULE) or "
        "every wrapper was deleted. A screening check with nothing to screen is "
        "not evidence of screening."
    )
    # Set EQUALITY, not a lower bound. A `>= 4` bound fails only when the
    # population shrinks; the clause is that a counter must fail in BOTH
    # directions. Equality also means a new provider wrapper cannot land without
    # a human editing this contract — which is the point, because a wrapper
    # nobody declared is exactly the one likely to be unscreened.
    assert set(sites) == EXPECTED_PROVIDER_WRAPPERS, (
        "INV-1 FAILED: the set of functions that call a provider changed.\n"
        f"  expected: {sorted(EXPECTED_PROVIDER_WRAPPERS)}\n"
        f"  found:    {sorted(sites)}\n"
        f"  missing:  {sorted(EXPECTED_PROVIDER_WRAPPERS - set(sites))}\n"
        f"  new:      {sorted(set(sites) - EXPECTED_PROVIDER_WRAPPERS)}\n"
        "A wrapper that stopped calling its provider, or a provider import that "
        "was rebound, shrinks this population silently. A NEW entry means a new "
        "inference path — declare it here, deliberately."
    )
    assert set(report["screened"]) == EXPECTED_PROVIDER_WRAPPERS, (
        "INV-1 FAILED: a function calls a provider but is not in the screened "
        f"set. screened = {sorted(report['screened'])}, "
        f"call sites = {sorted(sites)}."
    )


def test_every_provider_wrapper_screens_mandatorily(report: dict) -> None:
    """INV-2..INV-6 — the whole claim, on the real shipped source."""
    assert report["violations"] == [], (
        "MANDATORY SCREENING VIOLATED in "
        + str(SERVER)
        + ":\n"
        + "\n".join(
            f"  [{inv}] {fn}: {detail}" for inv, fn, detail in report["violations"]
        )
    )


def test_no_provider_call_outside_a_screened_function() -> None:
    """
    INV-7 — a provider may only be called from a function that screens it.
    Closes the evasion where the wrapper is clean but an unscreened helper
    (or a second entry-point module) calls the provider directly.
    """
    screened_per_file: dict[str, list[str]] = {}
    unscreened: list[str] = []
    examined = 0

    for path in _production_py_files():
        source = path.read_text(encoding="utf-8")
        if PROVIDER_MODULE not in source:
            continue
        examined += 1
        rel = str(path.relative_to(ROOT))
        rep = analyse(source, rel)
        screened_per_file[rel] = rep["screened"]
        for fn, provs in rep["provider_call_sites"].items():
            if fn not in rep["screened"]:
                unscreened.append(f"{rel}::{fn} calls {provs}")

    assert examined > 0, (
        "INV-7 FAILED: no production module imports "
        f"{PROVIDER_MODULE!r}. Either provider egress moved or this check is "
        "examining nothing — it must not report clean over an empty population."
    )
    assert not unscreened, (
        "INV-7 FAILED — provider inference reachable without screening:\n"
        + "\n".join(f"  {u}" for u in unscreened)
    )
    # Positive control on the same population: at least one file really did
    # contain screened wrappers, so `not unscreened` cannot pass vacuously.
    assert any(screened_per_file.values()), (
        "INV-7 FAILED: modules importing the provider module were examined but "
        f"NONE contained a screened wrapper. Screened per file: {screened_per_file}"
    )


# ---------------------------------------------------------------------------
# NEGATIVE CONTROLS — proof the analyser can fail, one per invariant.
#
# Each feeds a deliberately-broken module. Without these the assertions above
# would pass on an analyser that returned `violations == []` unconditionally.
# ---------------------------------------------------------------------------

_PREAMBLE = f"""
from {PROVIDER_MODULE} import call_grok
"""


def _invs(source: str) -> list[str]:
    return [inv for inv, _fn, _d in analyse(source)["violations"]]


def test_analyser_accepts_a_correct_wrapper() -> None:
    """
    The adverse control's control. If the analyser rejected everything, every
    ``test_detects_*`` below would pass while the real assertion was broken.
    """
    good = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    risk = await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return {**provider_result, "arkheia": risk}
"""
    rep = analyse(good)
    assert rep["violations"] == [], rep["violations"]
    assert rep["screened"] == ["run_grok"]


def test_detects_missing_screening() -> None:
    """INV-2 — a wrapper that never screens."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    return provider_result
"""
    assert "INV-2" in _invs(bad)


def test_detects_conditional_screening() -> None:
    """INV-3 — screening behind a feature flag / try, i.e. skippable."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    risk = None
    if SCREENING_ENABLED:
        risk = await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return {**provider_result, "arkheia": risk}
"""
    assert "INV-3" in _invs(bad)


def test_detects_early_return_before_screening() -> None:
    """INV-4 — a fast path that returns provider output before screening."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    if provider_result.get("error"):
        return provider_result
    risk = await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return {**provider_result, "arkheia": risk}
"""
    assert "INV-4" in _invs(bad)


def test_detects_return_without_verdict() -> None:
    """INV-5 — screened, then returned without the verdict attached."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    risk = await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return provider_result
"""
    assert "INV-5" in _invs(bad)


def test_detects_discarded_verdict() -> None:
    """INV-5 — screening called for its side effect only; verdict unbindable."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return provider_result
"""
    assert "INV-5" in _invs(bad)


def test_detects_screening_the_wrong_bytes() -> None:
    """INV-6 — screening the prompt, or a literal, instead of the output."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    risk = await proxy.verify(prompt=prompt, response="", model_id=model)
    return {**provider_result, "arkheia": risk}
"""
    assert "INV-6" in _invs(bad)


def test_detects_screening_before_the_provider_call() -> None:
    """INV-4 — a verdict computed before the response existed."""
    bad = _PREAMBLE + """
async def run_grok(prompt, model="m"):
    risk = await proxy.verify(prompt=prompt, response=prompt, model_id=model)
    provider_result = await call_grok(prompt, model)
    return {**provider_result, "arkheia": risk}
"""
    assert "INV-4" in _invs(bad)


def test_detects_unscreened_helper() -> None:
    """
    INV-7 — the wrapper is clean but a helper reaches the provider directly.
    Reported as INV-2 against the helper, and the helper is NOT in `screened`.
    """
    bad = _PREAMBLE + """
async def _fast_path(prompt, model):
    return await call_grok(prompt, model)

async def run_grok(prompt, model="m"):
    provider_result = await call_grok(prompt, model)
    risk = await proxy.verify(prompt=prompt, response=provider_result["response"], model_id=model)
    return {**provider_result, "arkheia": risk}
"""
    rep = analyse(bad)
    assert "_fast_path" in rep["provider_call_sites"]
    assert "_fast_path" not in rep["screened"]
    assert any(inv == "INV-2" and fn == "_fast_path" for inv, fn, _ in rep["violations"])


def test_empty_population_is_not_clean() -> None:
    """
    INV-1 — a module with no provider calls yields no violations, which is
    exactly why `violations == []` may never be read as "screening verified".
    The population assertion is the load-bearing one.
    """
    rep = analyse("def unrelated():\n    return 1\n")
    assert rep["violations"] == []          # no violations...
    assert rep["provider_call_sites"] == {}  # ...because nothing was examined
    assert rep["screened"] == []


# ---------------------------------------------------------------------------
# CALL-FORM COVERAGE  (Codex review, PR #17 finding 2)
#
# Reproduced before the fix, feeding nine written forms of the SAME unscreened
# provider call to the analyser:
#
#   OBSERVED   A from-import, bare call          violations=['INV-2']
#   OBSERVED   B from-import with alias          violations=['INV-2']
#   INVISIBLE  C import M; M.call_grok(...)      violations=[]
#   INVISIBLE  D import M as providers           violations=[]
#   INVISIBLE  E from pkg import providers       violations=[]
#   INVISIBLE  F importlib.import_module         violations=[]
#   INVISIBLE  G getattr(providers, "call_grok") violations=[]
#   INVISIBLE  H __import__                      violations=[]
#   INVISIBLE  I _call = providers.call_grok     violations=[]
#   => OBSERVED 2, INVISIBLE 7
#
# Seven unscreened inference paths that the floor rendered as clean, while
# INV-1 advertised population SET EQUALITY. The equality claim was false: the
# population it compared was "call sites written in one of two forms", not
# "call sites".
#
# After: OBSERVED 9, INVISIBLE 0, with three further forms FLAGGED as INV-8
# (un-analysable rather than absent) and four named residual gaps.
# ---------------------------------------------------------------------------

_M = PROVIDER_MODULE
_PKG, _LEAF = _M.rsplit(".", 1)


def _unscreened(body_import: str, call: str) -> str:
    """An unscreened provider call, written in a given form."""
    return f"{body_import}\nasync def run_x(p):\n    out = await {call}\n    return out\n"


# Every form the analyser must SEE. Keyed by the ledger name in the module
# docstring so the two cannot drift apart silently.
OBSERVED_FORMS = {
    "1 from-import bare":        _unscreened(f"from {_M} import call_grok", "call_grok(p)"),
    "2 from-import aliased":     _unscreened(f"from {_M} import call_grok as cg", "cg(p)"),
    "3 dotted module import":    _unscreened(f"import {_M}", f"{_M}.call_grok(p)"),
    "4 aliased module import":   _unscreened(f"import {_M} as providers", "providers.call_grok(p)"),
    "5 from-package module":     _unscreened(f"from {_PKG} import {_LEAF}", f"{_LEAF}.call_grok(p)"),
    "6 importlib.import_module": _unscreened(
        f'import importlib\nproviders = importlib.import_module("{_M}")', "providers.call_grok(p)"),
    "7 __import__":              _unscreened(
        f'providers = __import__("{_M}", fromlist=["call_grok"])', "providers.call_grok(p)"),
    "8 getattr literal":         f"import {_M} as providers\n"
                                 'async def run_x(p):\n    fn = getattr(providers, "call_grok")\n'
                                 "    out = await fn(p)\n    return out\n",
    "9 rebound local name":      _unscreened(
        f"import {_M} as providers\n_call = providers.call_grok", "_call(p)"),
}

# Forms the analyser cannot RESOLVE but must not pass over in silence.
FLAGGED_FORMS = {
    "A exec": f"import {_M} as providers\n"
              'async def run_x(p):\n    exec("out = providers.call_grok(p)")\n'
              '    return locals()["out"]\n',
    "B import_module non-literal": "import importlib\n"
              "def load(name):\n    return importlib.import_module(name)\n"
              f'providers = load("{_M}")\n'
              "async def run_x(p):\n    out = await providers.call_grok(p)\n    return out\n",
    "C getattr non-literal": f"import {_M} as providers\n"
              "async def run_x(p, which):\n    fn = getattr(providers, which)\n"
              "    out = await fn(p)\n    return out\n",
}

# Genuine residual gaps. Named, so that "no violation" here is read as
# NOT-OBSERVED rather than as absence of a problem.
UNOBSERVED_FORMS = {
    "D container dispatch": f"import {_M} as providers\n"
              'REG = {"grok": providers.call_grok}\n'
              "async def run_x(p, k):\n    out = await REG[k](p)\n    return out\n",
    "E instance attribute": f"import {_M} as providers\n"
              "class C:\n    def __init__(self):\n        self.fn = providers.call_grok\n"
              "    async def run_x(self, p):\n        out = await self.fn(p)\n        return out\n",
    "F functools.partial": f"import functools\nimport {_M} as providers\n"
              "bound = functools.partial(providers.call_grok, temperature=0)\n"
              "async def run_x(p):\n    out = await bound(p)\n    return out\n",
    "H raw httpx bypass": "import httpx\n"
              "async def run_x(p):\n    async with httpx.AsyncClient() as c:\n"
              '        r = await c.post("https://api.x.ai/v1/chat", json={"m": p})\n'
              "    return r.json()\n",
}


@pytest.mark.parametrize("form", sorted(OBSERVED_FORMS))
def test_observed_call_form_is_not_invisible(form: str) -> None:
    """
    Each of the nine written forms of an unscreened provider call must be
    reported. Forms 3-9 all returned [] before this revision.
    """
    rep = analyse(OBSERVED_FORMS[form])
    invs = [i for i, _f, _d in rep["violations"]]
    assert invs, (
        f"call form {form!r} is INVISIBLE to the floor: the module contains an "
        "unscreened provider call and the analyser reported no violation and "
        f"no call sites ({rep['provider_call_sites']}). INV-1 claims population "
        "SET EQUALITY; that claim is false for any form not observed here."
    )
    # Positive control: it is reported for the RIGHT reason — the wrapper never
    # screens — not incidentally via INV-8.
    assert "INV-2" in invs, (
        f"form {form!r} reported {invs}, expected INV-2 (calls a provider and "
        "never screens). A different code means the call was detected by "
        "accident rather than resolved."
    )
    assert rep["provider_call_sites"], (
        f"form {form!r} produced a violation but named NO call site — the "
        "report cannot say which function performs inference."
    )


@pytest.mark.parametrize("form", sorted(FLAGGED_FORMS))
def test_unanalysable_call_form_is_flagged_not_ignored(form: str) -> None:
    """
    INV-8. These forms cannot be resolved statically. The requirement is not
    that they be understood — it is that they never render as clean.
    """
    rep = analyse(FLAGGED_FORMS[form])
    invs = [i for i, _f, _d in rep["violations"]]
    assert "INV-8" in invs, (
        f"un-analysable form {form!r} produced {invs or '[]'} — a module that "
        "reaches provider egress through machinery this checker cannot follow "
        "must fail loudly. Silence here is indistinguishable from a clean "
        "result, which is the not-observed-vs-absent confusion."
    )
    detail = " ".join(d for _i, _f, d in rep["violations"])
    assert "cannot" in detail or "invisible" in detail, (
        f"INV-8 fired for {form!r} but the message does not say WHAT could not "
        f"be observed: {detail!r}"
    )


@pytest.mark.parametrize("form", sorted(UNOBSERVED_FORMS))
def test_known_gap_is_still_a_gap(form: str) -> None:
    """
    The residual holes, pinned as holes.

    This asserts these forms are still SILENT. That is deliberate: the ledger in
    the module docstring names them as NOT OBSERVED, and if someone later
    extends coverage to one of them this test fails and forces the ledger to be
    corrected. A coverage claim is only useful if its stated limits are true.
    """
    rep = analyse(UNOBSERVED_FORMS[form])
    invs = [i for i, _f, _d in rep["violations"]]
    assert not invs, (
        f"form {form!r} is documented as NOT OBSERVED but the analyser now "
        f"reports {invs}. Coverage improved — update the ledger in this "
        "module's docstring and move this entry to OBSERVED_FORMS."
    )


def test_call_form_coverage_ledger_is_accurate() -> None:
    """
    The docstring ledger is the coverage claim. Assert it enumerates exactly
    the forms exercised above, so the prose cannot outrun the tests.
    """
    doc = __doc__ or ""
    assert "Call-form coverage" in doc, "the coverage ledger is missing"
    for section, forms in (
        ("OBSERVED", OBSERVED_FORMS),
        ("FLAGGED", FLAGGED_FORMS),
        ("NOT OBSERVED", UNOBSERVED_FORMS),
    ):
        assert section in doc, f"ledger has no {section} section"
        for form in forms:
            key = form.split(" ", 1)[0]
            assert f"\n  {key}." in doc, (
                f"form {form!r} is exercised by a test but is not listed under "
                f"{section} in the ledger — the stated coverage is incomplete."
            )
    # The counts a reader relies on.
    assert len(OBSERVED_FORMS) == 9, len(OBSERVED_FORMS)
    assert len(FLAGGED_FORMS) == 3, len(FLAGGED_FORMS)
    assert len(UNOBSERVED_FORMS) == 4, len(UNOBSERVED_FORMS)


def test_production_source_uses_no_unanalysable_provider_access() -> None:
    """
    INV-8 against the real tree. If this fails, the other invariants' clean
    report over that module means nothing.
    """
    offenders = []
    examined = 0
    for path in _production_py_files():
        source = path.read_text(encoding="utf-8")
        if PROVIDER_MODULE not in source:
            continue
        examined += 1
        rep = analyse(source, str(path.relative_to(ROOT)))
        for inv, fn, detail in rep["violations"]:
            if inv == "INV-8":
                offenders.append(f"  {path.relative_to(ROOT)} {fn}: {detail}")
    assert examined > 0, (
        "INV-8 examined ZERO modules — no production file references "
        f"{PROVIDER_MODULE}. This check must not report clean over an empty "
        "population."
    )
    assert not offenders, (
        "provider egress reached through un-analysable machinery:\n"
        + "\n".join(offenders)
    )
