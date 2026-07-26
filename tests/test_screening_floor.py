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

# Floor: the four shipped provider wrappers. A lower number means a wrapper was
# deleted or stopped calling its provider; the check must not silently shrink.
MIN_SCREENED_WRAPPERS = 4


# ---------------------------------------------------------------------------
# Analyser — pure functions over source text, so it can be run against
# deliberately-broken input by the negative controls below.
# ---------------------------------------------------------------------------

def _provider_names(tree: ast.AST) -> set[str]:
    """Names imported from the provider-egress module."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == PROVIDER_MODULE:
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def _is_screen_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == SCREEN_ATTR
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == SCREEN_OBJ
    )


def _called_name(node: ast.AST) -> str | None:
    """Return the bare callee name of a Call/Await(Call), else None."""
    if isinstance(node, ast.Await):
        node = node.value
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id
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
    providers = _provider_names(tree)
    violations: list[tuple[str, str, str]] = []
    screened: list[str] = []
    call_sites: dict[str, list[str]] = {}

    for fn in _functions(tree):
        body = fn.body
        # --- locate the provider call among TOP-LEVEL statements ------------
        prov_idx: int | None = None
        prov_target: str | None = None
        prov_names: list[str] = []

        for i, stmt in enumerate(body):
            for sub in ast.walk(stmt):
                name = _called_name(sub)
                if name in providers:
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
    assert len(report["screened"]) >= MIN_SCREENED_WRAPPERS, (
        f"INV-1 FAILED: expected at least {MIN_SCREENED_WRAPPERS} screened "
        f"provider wrappers, found {len(report['screened'])}: "
        f"{sorted(report['screened'])}. Provider call sites seen: {sites}. "
        "A wrapper that stopped calling its provider, or a provider import that "
        "was renamed, shrinks this population silently — which is why the bound "
        "is asserted in both directions."
    )
    # Positive control: the four shipped wrappers are individually present, so a
    # population that merely reaches the count with different members still fails.
    for name in ("run_grok", "run_gemini", "run_ollama", "run_together"):
        assert name in sites, (
            f"INV-1 FAILED: {name} no longer contains a provider call. If the "
            "tool was intentionally removed, remove it here too — do not let the "
            "population shrink unobserved."
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
