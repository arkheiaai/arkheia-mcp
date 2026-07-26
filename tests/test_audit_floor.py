"""
FLOOR INVARIANT — a tamper/verify mechanism that is COMPUTED must be REACHED by
a real entry point.

Floor tier contract: this test is stdlib-only (``ast`` + ``pathlib``). It imports
no third-party package, opens no socket, and starts no app. It reasons purely over
source text, so it runs under a bare ``pytest`` with zero project dependencies and
has zero interpreter variance.

------------------------------------------------------------------------------
Why this invariant exists (real defect, arkheia-mcp @ base 3ef2bd7)
------------------------------------------------------------------------------
``proxy/audit/writer.py`` advertises a *tamper-evident* audit log: every record
is written with ``seq`` / ``prev_hash`` / ``this_hash`` forming a hash chain, and
``AuditWriter.verify_chain()`` walks that chain to report any break.

But ``verify_chain()`` was **never invoked anywhere in production code** — its only
other textual mention was its own error-log string. A verifier that is never
called provides *zero* tamper detection: the chain is computed on every write, yet
nothing ever checks it, so the "tamper-evident" property was inert.
``proxy/license/integrity.verify_integrity`` had the same defect, with a docstring
that claimed "At startup, verifies that compiled detection modules have not been
tampered with" while nothing at startup called it.

------------------------------------------------------------------------------
CODEX FINDING 3 (2026-07-26) — presence mistaken for effect
------------------------------------------------------------------------------
The first version of this floor check asserted only that *an AST Call node named
after the mechanism exists somewhere in non-test code*. That is satisfied by:

    def never_called():
        verify_integrity(Path("."))

REPRODUCED before fixing: both real lifespan calls were replaced with ``pass`` and
a ``never_called()`` like the above was added to ``proxy/main.py``. The guard
reported ``1 passed``. So the guard could be fully green while the hole it exists
to close was wide open — the exact "presence mistaken for effect" class swept out
of 36 gates on 2026-07-26 (13 had it). A dead function is the Python spelling of a
dead local.

The check now demands **reachability from a declared, verified entry point**: at
least one call site must sit in a scope that startup actually executes. Existence
of a call node anywhere is no longer sufficient, and "there is a call site but
nothing reaches it" is reported as its own, distinct failure.

------------------------------------------------------------------------------
What the reachability model DOES and DOES NOT cover
------------------------------------------------------------------------------
MODELLED
  * module scope of each declared entry file (import-time statements such as
    ``app = create_app()``);
  * direct and transitive calls, by callee name — ``obj.method()`` resolves to any
    production ``def method``, and ``fn()`` to any production ``def fn``;
  * class bodies, which execute when their enclosing scope executes (their methods
    do NOT become reachable for free);
  * decorator expressions, which evaluate in the enclosing scope;
  * framework-invoked entry points that source never calls, declared explicitly in
    ``ENTRY_POINTS`` and each required to prove its wiring (the FastAPI lifespan is
    passed as ``FastAPI(lifespan=lifespan)``, never called).

NOT MODELLED — deliberately conservative, so the failure mode is a loud red
("register the entry point") and never a silent pass:
  * transitive import-time execution of modules other than the declared entry
    files (importing ``proxy.main`` also runs every module it imports);
  * dispatch through a variable, a dict of handlers, ``getattr``,
    ``functools.partial``, a scheduler registration, or a thread/task target;
  * dynamic import (``importlib.import_module``);
  * name collisions: two production functions with the same name are treated as one
    resolution target, so reachability is over-approximated in that one respect;
  * whether the reachable call is on a branch that actually executes at runtime (an
    ``if`` guard can still skip it — this is static reachability, not a proof of
    execution). The runtime proof that the lifespan call really fires lives in the
    behavioural suites run by the required ``unit-tests`` context.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Repo root: this file is <root>/tests/test_audit_floor.py
ROOT = Path(__file__).resolve().parents[1]

# Production source roots (NON-test). Anything under a `tests` directory is
# excluded — a call site only counts if it is real production wiring.
PROD_DIRS = ("proxy", "mcp_server", "registry_server")
PROD_ROOT_FILES = ("server.py",)

# The seeded registry of tamper/verify mechanisms that MUST be REACHED from a real
# entry point. Map: callable name -> file (relative to root) where it is defined,
# used only for an actionable failure message. Add mechanisms here as they land.
TAMPER_VERIFY_MECHANISMS = {
    "verify_chain": "proxy/audit/writer.py",
    # Added 2026-07-26. Same defect, second instance: `verify_integrity` is the
    # binary-integrity check for the compiled detection modules (.so/.pyd) —
    # `scripts/build_release.py` writes an `integrity_manifest.json` next to each
    # compiled module at build time, and NOTHING in production ever verified it.
    # Its only callers were three tests. A tamper check with no production call
    # site means the shipped binaries were never actually verified: the
    # "tamper-evident" property advertised in proxy/license/integrity.py's module
    # docstring ("At startup, verifies that compiled detection modules have not
    # been tampered with") was simply not happening at startup. GREEN fix wires
    # it into the proxy lifespan alongside verify_chain (proxy/main.py).
    "verify_integrity": "proxy/license/integrity.py",
}

# Scopes the runtime really enters. `<module>` means the module's own top-level
# statements (they run on import). A function entry point must additionally PROVE
# it is wired, because nothing in source calls it: `wiring` names the call and the
# keyword that must receive it, e.g. FastAPI(lifespan=lifespan).
ENTRY_POINTS: dict[str, dict] = {
    "proxy/main.py::<module>": {
        "why": "top-level statements of the proxy's entry module — `app = "
               "create_app()` executes on import, i.e. on every process start",
        "wiring": None,
    },
    "proxy/main.py::lifespan": {
        "why": "the FastAPI lifespan: uvicorn runs it on every proxy startup, "
               "before the app serves any traffic",
        "wiring": ("FastAPI", "lifespan"),
    },
}


def _production_py_files() -> list[Path]:
    files: list[Path] = []
    for d in PROD_DIRS:
        for p in sorted((ROOT / d).rglob("*.py")):
            # Skip any file that lives under a `tests` package.
            if "tests" in p.relative_to(ROOT).parts:
                continue
            files.append(p)
    for f in PROD_ROOT_FILES:
        p = ROOT / f
        if p.exists():
            files.append(p)
    return files


def _production_sources() -> dict[str, str]:
    return {
        p.relative_to(ROOT).as_posix(): p.read_text(encoding="utf-8")
        for p in _production_py_files()
    }


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _callee_name(call: ast.Call) -> str:
    """The simple name being called: `a.b.verify_chain()` -> 'verify_chain'."""
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Call):
        return _callee_name(func)
    return ""


class CallGraph:
    """
    A name-resolved call graph over a set of Python sources.

    Scope ids are ``"<relpath>::<qualname>"``, with ``<module>`` for top-level
    statements. Edges are (scope -> callee simple name), resolved against every
    ``def`` of that name; a class body is an automatic edge from its enclosing
    scope, because a class body executes when that scope executes.
    """

    def __init__(self, sources: dict[str, str]) -> None:
        self.unparsed: list[str] = []
        self.scopes: dict[str, str] = {}
        self.calls: dict[str, set[str]] = {}
        self.auto: dict[str, set[str]] = {}
        self.defs_by_name: dict[str, set[str]] = {}
        self.sites: dict[str, list[tuple[str, str, int]]] = {}
        # Keyed by (file, called-name, keyword). FILE-SCOPED deliberately: a
        # global key let `registry_server/main.py`'s own
        # `FastAPI(lifespan=lifespan)` satisfy the wiring proof for
        # `proxy/main.py::lifespan`, so deleting the proxy's wiring stayed GREEN
        # (observed as mutation M23). Wiring in another file proves nothing about
        # this entry point.
        self.kwarg_names: dict[tuple[str, str, str], set[str]] = {}
        for rel, src in sorted(sources.items()):
            try:
                tree = ast.parse(src)
            except (SyntaxError, UnicodeDecodeError) as exc:
                self.unparsed.append(f"{rel}: {exc}")
                continue
            self._scope(tree, rel, "<module>", "module")

    # -- construction ------------------------------------------------------

    def _scope(self, node: ast.AST, rel: str, qual: str, kind: str) -> None:
        qn = f"{rel}::{qual}"
        self.scopes[qn] = kind
        calls = self.calls.setdefault(qn, set())
        auto = self.auto.setdefault(qn, set())
        children: list[tuple[ast.AST, str, str]] = []

        def child_qual(name: str) -> str:
            return name if qual == "<module>" else f"{qual}.{name}"

        def visit(n: ast.AST) -> None:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                cq = child_qual(n.name)
                children.append((n, cq, "function"))
                self.defs_by_name.setdefault(n.name, set()).add(f"{rel}::{cq}")
                for dec in n.decorator_list:
                    visit(dec)  # decorators evaluate in THIS scope
                return
            if isinstance(n, ast.ClassDef):
                cq = child_qual(n.name)
                children.append((n, cq, "class"))
                auto.add(f"{rel}::{cq}")  # a class body runs when this scope runs
                for dec in n.decorator_list:
                    visit(dec)
                return
            if isinstance(n, ast.Call):
                name = _callee_name(n)
                if name:
                    calls.add(name)
                    self.sites.setdefault(name, []).append((qn, rel, n.lineno))
                base = _dotted(n.func).split(".")[-1]
                for kw in n.keywords:
                    if kw.arg and isinstance(kw.value, ast.Name):
                        self.kwarg_names.setdefault(
                            (rel, base, kw.arg), set()
                        ).add(kw.value.id)
            for ch in ast.iter_child_nodes(n):
                visit(ch)

        for stmt in getattr(node, "body", []):
            visit(stmt)

        for child, cq, ckind in children:
            self._scope(child, rel, cq, ckind)

    # -- queries -----------------------------------------------------------

    def is_defined(self, name: str) -> bool:
        return name in self.defs_by_name

    def reachable(self, entries: list[str]) -> set[str]:
        seen: set[str] = set()
        queue = list(entries)
        while queue:
            qn = queue.pop()
            if qn in seen or qn not in self.scopes:
                continue
            seen.add(qn)
            queue.extend(self.auto.get(qn, ()))
            for name in self.calls.get(qn, ()):
                queue.extend(self.defs_by_name.get(name, ()))
        return seen

    def call_sites(self, name: str) -> list[str]:
        return [
            f"{rel}:{line} (in {qn.split('::', 1)[1]})"
            for qn, rel, line in self.sites.get(name, [])
        ]

    def reachable_call_sites(self, name: str, reached: set[str]) -> list[str]:
        return [
            f"{rel}:{line} (in {qn.split('::', 1)[1]})"
            for qn, rel, line in self.sites.get(name, [])
            if qn in reached
        ]

    def receives_kwarg(self, rel: str, call_base: str, kwarg: str, name: str) -> bool:
        return name in self.kwarg_names.get((rel, call_base, kwarg), set())


def _entry_problems(graph: CallGraph) -> list[str]:
    """Every declared entry point must exist and, if a function, prove its wiring."""
    problems: list[str] = []
    for entry, meta in sorted(ENTRY_POINTS.items()):
        rel, qual = entry.split("::", 1)
        if entry not in graph.scopes:
            problems.append(
                f"{entry} is declared as an entry point ({meta['why']}) but no such "
                f"scope exists in production source. Either the file/function was "
                f"renamed or moved, or ENTRY_POINTS is stale — and while it is "
                f"stale, reachability is measured from the wrong root, so nothing "
                f"derived from it can be trusted."
            )
            continue
        wiring = meta.get("wiring")
        if wiring is None:
            continue
        call_base, kwarg = wiring
        fn_name = qual.rsplit(".", 1)[-1]
        if not graph.receives_kwarg(rel, call_base, kwarg, fn_name):
            problems.append(
                f"{entry} is declared as a framework-invoked entry point, but "
                f"{rel} never passes {kwarg!r} as "
                f"{call_base}(..., {kwarg}={fn_name}). Nothing in source calls it "
                f"either, so there is NO evidence the runtime ever enters it. An "
                f"entry point that cannot be shown to be wired is not an entry "
                f"point. Fix: restore the wiring, or update ENTRY_POINTS to name "
                f"the real one."
            )
    return problems


def test_entry_points_are_real_and_wired():
    """
    Reachability is only as good as its roots, so the roots are checked first.

    Without this, deleting `lifespan=lifespan` from `FastAPI(...)` would leave
    every mechanism still 'reachable' from a function the runtime no longer enters.
    """
    graph = CallGraph(_production_sources())
    assert not graph.unparsed, (
        "production file(s) could not be parsed, so they were NOT examined; an "
        "unobserved file must never count as clean:\n  - "
        + "\n  - ".join(graph.unparsed)
    )
    assert graph.scopes, "no production scopes discovered — floor scan misconfigured"
    assert ENTRY_POINTS, "ENTRY_POINTS is empty — reachability has no root."
    problems = _entry_problems(graph)
    assert not problems, (
        f"declared entry point(s) that are not real ({len(ENTRY_POINTS)} entry "
        f"point(s) checked against {len(graph.scopes)} production scope(s)):\n  - "
        + "\n  - ".join(problems)
    )


def test_tamper_verify_mechanisms_are_reachable_from_an_entry_point():
    """Every seeded tamper/verify mechanism must be REACHED, not merely mentioned."""
    sources = _production_sources()
    assert sources, "no production source files discovered — floor scan misconfigured"
    graph = CallGraph(sources)
    assert not graph.unparsed, (
        "production file(s) could not be parsed, so they were NOT examined:\n  - "
        + "\n  - ".join(graph.unparsed)
    )

    entry_problems = _entry_problems(graph)
    assert not entry_problems, (
        "NOT OBSERVED — reachability cannot be measured because an entry point is "
        "wrong. This is a failure, not a pass:\n  - " + "\n  - ".join(entry_problems)
    )

    reached = graph.reachable(list(ENTRY_POINTS))
    # Work done, with units named (floor 9(a)).
    assert len(reached) > len(ENTRY_POINTS), (
        f"reachability from {sorted(ENTRY_POINTS)} reached only {len(reached)} "
        f"scope(s) out of {len(graph.scopes)} — the traversal did no work, so a "
        f"'not reachable' verdict below would be meaningless."
    )

    failures: list[str] = []
    for name, defined_in in sorted(TAMPER_VERIFY_MECHANISMS.items()):
        if not graph.is_defined(name):
            failures.append(
                f"{name!r}: expected to be defined (registry says {defined_in}) "
                f"but no def found in production source — update the registry or "
                f"restore the mechanism."
            )
            continue
        all_sites = graph.call_sites(name)
        live = graph.reachable_call_sites(name, reached)
        if not all_sites:
            failures.append(
                f"{name!r} (defined in {defined_in}) is COMPUTED but never invoked "
                f"in production code: no call site at all. A tamper/verify "
                f"mechanism that is never called provides zero protection. Fix: "
                f"call it from a path startup actually takes (e.g. the lifespan "
                f"self-check in proxy/main.py)."
            )
        elif not live:
            failures.append(
                f"{name!r} (defined in {defined_in}) has {len(all_sites)} call "
                f"site(s) — {', '.join(all_sites)} — but NONE of them is reachable "
                f"from any entry point in {sorted(ENTRY_POINTS)}. Every caller is "
                f"itself dead code, so the mechanism still never runs: this is "
                f"presence mistaken for effect, which is exactly what this "
                f"invariant exists to reject. Fix: call it from a scope startup "
                f"actually enters, or declare the real entry point in ENTRY_POINTS "
                f"and prove its wiring."
            )

    assert not failures, (
        f"tamper/verify mechanism(s) not reachable from a real entry point "
        f"({len(TAMPER_VERIFY_MECHANISMS)} mechanism(s) checked; {len(reached)} of "
        f"{len(graph.scopes)} production scope(s) reachable from "
        f"{sorted(ENTRY_POINTS)}):\n  - " + "\n  - ".join(failures)
    )


# ---------------------------------------------------------------------------
# Positive controls — the reachability model must be able to fail, and must fail
# on exactly the shape Codex used.
# ---------------------------------------------------------------------------

_WIRED_MAIN = (
    "from contextlib import asynccontextmanager\n"
    "from fastapi import FastAPI\n"
    "\n"
    "@asynccontextmanager\n"
    "async def lifespan(app):\n"
    "{lifespan_body}"
    "    yield\n"
    "\n"
    "def create_app():\n"
    "    return FastAPI(title='x', lifespan=lifespan)\n"
    "\n"
    "app = create_app()\n"
)

_MECHANISM_MODULE = "def verify_integrity(module_dir):\n    return True\n"


def _probe_graph(lifespan_body: str, extra: str = "") -> tuple[CallGraph, set[str]]:
    graph = CallGraph({
        "proxy/main.py": _WIRED_MAIN.format(lifespan_body=lifespan_body) + extra,
        "proxy/license/integrity.py": _MECHANISM_MODULE,
    })
    return graph, graph.reachable(list(ENTRY_POINTS))


def test_reachability_positive_control_dead_function_does_not_count():
    """
    Codex finding 3, frozen as a test.

    A call site inside a function nothing calls must NOT satisfy the invariant.
    Before the fix, this exact shape gave `1 passed` on the real tree with both
    live lifespan calls replaced by `pass`.
    """
    dead = "\ndef never_called():\n    verify_integrity('.')\n"
    graph, reached = _probe_graph("    pass\n", extra=dead)
    assert _entry_problems(graph) == [], _entry_problems(graph)
    assert graph.is_defined("verify_integrity")
    # The call node DOES exist — this is what the old guard saw and accepted.
    assert len(graph.call_sites("verify_integrity")) == 1, graph.call_sites(
        "verify_integrity"
    )
    # ...and it is NOT reachable, which is what the new guard demands.
    assert graph.reachable_call_sites("verify_integrity", reached) == [], (
        "REACHABILITY CONTROL FAILED: a call inside `never_called()` was counted "
        "as live. A dead function is the Python spelling of a dead local; if this "
        "passes, the guard is satisfiable while the hole is open."
    )
    assert "proxy/main.py::never_called" not in reached, sorted(reached)

    # NEGATIVE CONTROL (pinning): the identical call, moved into the lifespan, MUST
    # be reachable — otherwise the assertion above would pass against a model that
    # simply never reaches anything.
    graph2, reached2 = _probe_graph("    verify_integrity('.')\n")
    live = graph2.reachable_call_sites("verify_integrity", reached2)
    assert len(live) == 1 and live[0].startswith("proxy/main.py:"), live


def test_reachability_follows_real_paths():
    """Transitive calls, method calls, class bodies and module scope."""
    # Transitive: lifespan -> helper -> mechanism.
    helper = "\ndef _self_check():\n    verify_integrity('.')\n"
    graph, reached = _probe_graph("    _self_check()\n", extra=helper)
    assert graph.reachable_call_sites("verify_integrity", reached), sorted(reached)

    # Method call resolved by name: lifespan -> writer.verify_chain().
    g = CallGraph({
        "proxy/main.py": _WIRED_MAIN.format(
            lifespan_body="    w = Writer()\n    w.verify_chain()\n"
        ),
        "proxy/audit/writer.py": (
            "class Writer:\n"
            "    def verify_chain(self):\n"
            "        return {'ok': True}\n"
        ),
    })
    r = g.reachable(list(ENTRY_POINTS))
    assert g.reachable_call_sites("verify_chain", r), sorted(r)

    # A method of a class is NOT reachable just because the class body is.
    g2 = CallGraph({
        "proxy/main.py": _WIRED_MAIN.format(lifespan_body="    pass\n")
        + "\nclass Unused:\n    def helper(self):\n        verify_integrity('.')\n",
        "proxy/license/integrity.py": _MECHANISM_MODULE,
    })
    r2 = g2.reachable(list(ENTRY_POINTS))
    assert "proxy/main.py::Unused" in r2, "a class body runs when its module runs"
    assert "proxy/main.py::Unused.helper" not in r2, sorted(r2)
    assert g2.reachable_call_sites("verify_integrity", r2) == [], (
        "a method body must not be reachable merely because its class is defined."
    )

    # Module-scope call is reachable (import-time execution).
    g3 = CallGraph({
        "proxy/main.py": _WIRED_MAIN.format(lifespan_body="    pass\n")
        + "\nverify_integrity('.')\n",
        "proxy/license/integrity.py": _MECHANISM_MODULE,
    })
    r3 = g3.reachable(list(ENTRY_POINTS))
    assert g3.reachable_call_sites("verify_integrity", r3), sorted(r3)

    # A call nested inside `try:` / `for:` inside the lifespan still counts — that
    # is the real shape of proxy/main.py's integrity self-check.
    g4, r4 = _probe_graph(
        "    try:\n"
        "        for d in ['.']:\n"
        "            verify_integrity(d)\n"
        "    except Exception:\n"
        "        pass\n"
    )
    assert g4.reachable_call_sites("verify_integrity", r4), sorted(r4)


def test_entry_point_wiring_positive_control():
    """Losing `lifespan=lifespan` must be a failure, not a silent re-rooting."""
    unwired = _WIRED_MAIN.format(lifespan_body="    verify_integrity('.')\n").replace(
        ", lifespan=lifespan", ""
    )
    graph = CallGraph(
        {"proxy/main.py": unwired, "proxy/license/integrity.py": _MECHANISM_MODULE}
    )
    problems = _entry_problems(graph)
    assert len(problems) == 1, problems
    assert "never passes 'lifespan' as FastAPI(..., lifespan=lifespan)" in problems[0], (
        problems
    )

    # A renamed / missing entry scope is also reported, not skipped.
    renamed = CallGraph(
        {"proxy/main.py": unwired.replace("async def lifespan", "async def startup")}
    )
    rproblems = _entry_problems(renamed)
    assert len(rproblems) == 1 and "no such scope exists" in rproblems[0], rproblems

    # Wiring in ANOTHER file must not satisfy this entry point. This exact hole
    # was live: registry_server/main.py has its own FastAPI(lifespan=lifespan), and
    # with a globally-keyed lookup, deleting proxy/main.py's wiring stayed GREEN
    # (mutation M23).
    cross_file = CallGraph({
        "proxy/main.py": unwired,
        "registry_server/main.py": (
            "from fastapi import FastAPI\n"
            "async def lifespan(app):\n"
            "    yield\n"
            "app = FastAPI(lifespan=lifespan)\n"
        ),
    })
    xproblems = _entry_problems(cross_file)
    assert len(xproblems) == 1 and "proxy/main.py never passes" in xproblems[0], (
        "the wiring proof must be FILE-SCOPED: another module's "
        f"FastAPI(lifespan=lifespan) says nothing about this one. Got: {xproblems}"
    )

    # NEGATIVE control — the wired form must produce NO problem, so the assertions
    # above are pinned to the defect rather than to a check that always complains.
    ok = CallGraph({
        "proxy/main.py": _WIRED_MAIN.format(lifespan_body="    pass\n"),
        "proxy/license/integrity.py": _MECHANISM_MODULE,
    })
    assert _entry_problems(ok) == [], _entry_problems(ok)
