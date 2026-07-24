"""
FLOOR INVARIANT — a tamper/verify mechanism that is COMPUTED must have a live
call site.

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
nothing ever checks it, so the "tamper-evident" property was inert. This floor
check makes that class of defect fail CI: a verify/tamper mechanism must be wired
to a real call site, not left as an aspirational "hook for enterprise upgrade".

The GREEN fix wires ``verify_chain()`` into the proxy lifespan as a startup
integrity self-check (``proxy/main.py``).
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

# The seeded registry of tamper/verify mechanisms that MUST be wired to a live
# call site. Map: callable name -> file (relative to root) where it is defined,
# used only for an actionable failure message. Add mechanisms here as they land.
TAMPER_VERIFY_MECHANISMS = {
    "verify_chain": "proxy/audit/writer.py",
}


def _production_py_files() -> list[Path]:
    files: list[Path] = []
    for d in PROD_DIRS:
        for p in (ROOT / d).rglob("*.py"):
            # Skip any file that lives under a `tests` package.
            if "tests" in p.relative_to(ROOT).parts:
                continue
            files.append(p)
    for f in PROD_ROOT_FILES:
        p = ROOT / f
        if p.exists():
            files.append(p)
    return files


def _is_defined(name: str, files: list[Path]) -> bool:
    """True if `name` is defined as a function/method anywhere in the tree."""
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
                return True
    return False


def _live_call_sites(name: str, files: list[Path]) -> list[str]:
    """
    Return "path:line" for every real *call* to `name` in production code.

    A call is an AST ``Call`` whose callee is either ``obj.<name>(...)`` (Attribute)
    or a bare ``<name>(...)`` (Name). String mentions and the ``def`` itself are
    NOT calls, so they are correctly ignored.
    """
    sites: list[str] = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(ROOT)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            called = (
                (isinstance(func, ast.Attribute) and func.attr == name)
                or (isinstance(func, ast.Name) and func.id == name)
            )
            if called:
                sites.append(f"{rel}:{node.lineno}")
    return sites


def test_tamper_verify_mechanisms_have_live_call_site():
    """Every seeded tamper/verify mechanism must be called from production code."""
    files = _production_py_files()
    assert files, "no production source files discovered — floor scan misconfigured"

    failures: list[str] = []
    for name, defined_in in TAMPER_VERIFY_MECHANISMS.items():
        if not _is_defined(name, files):
            failures.append(
                f"{name!r}: expected to be defined (registry says {defined_in}) "
                f"but no def found — update the registry or restore the mechanism."
            )
            continue
        sites = _live_call_sites(name, files)
        if not sites:
            failures.append(
                f"{name!r} (defined in {defined_in}) is COMPUTED but never invoked "
                f"in production code: no live call site. A tamper/verify mechanism "
                f"that is never called provides zero protection. Fix: wire it to a "
                f"real call site (e.g. a startup self-check or an admin endpoint)."
            )

    assert not failures, "tamper/verify mechanism(s) without a live call site:\n  - " + "\n  - ".join(failures)
