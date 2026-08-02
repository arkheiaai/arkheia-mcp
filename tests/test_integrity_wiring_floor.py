"""
FLOOR INVARIANT — a security control that nothing calls is not a control.

THE DEFECT THIS WAS COMPILED FROM
---------------------------------
``proxy/license/integrity.py`` opened with *"At startup, verifies that compiled
detection modules (.so/.pyd) have not been tampered with"*. It did not. A grep
across every branch of this repo found callers of ``verify_integrity`` **only in
``tests/``** — no lifespan hook, no entry point, nothing. The module had unit
tests, passed them, was documented in the commercial-protection spec, and was
dead in every deployed process for its entire life. Nobody noticed because the
tests exercised the function directly, which is exactly the shape that hides it:
a control with green tests and no caller looks healthier than one with neither.

Its runtime verdict is now receipted (``verify_and_receipt``), and a receipt
mechanism that nothing invokes is worth even less than an uncalled check — it
produces the *appearance* of an evidence trail with no events in it.

THE INVARIANT
-------------
Every entry point this module declares in ``RUNTIME_ENTRY_POINTS`` must be
CALLED from at least one non-test Python file under ``proxy/``. Callers are
discovered by parsing the tree, never enumerated, so the invariant covers files
that do not exist yet.

Stdlib-only (``ast``, ``pathlib``) so it runs in the dependency-free floor tier
where nothing can skip it. Carries its own negative self-test, per DONE.md
floor invariant 9 / v1.19: a check whose success condition is "I found a caller"
must prove it reports a violation when there is none, or "looking in the wrong
place" is indistinguishable from a clean bill of health.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PROXY = REPO_ROOT / "proxy"

#: The runtime entry points of the binary-integrity control. Each must have a
#: live caller in production code.
RUNTIME_ENTRY_POINTS = ("verify_and_receipt",)


def _production_python_files() -> list[Path]:
    """Every .py under proxy/ that is not a test and not a package marker."""
    out = []
    for path in sorted(PROXY.rglob("*.py")):
        parts = set(path.parts)
        if "tests" in parts or "__pycache__" in parts:
            continue
        if path.name.startswith("test_") or path.name.startswith("_receipt_probe"):
            continue
        out.append(path)
    return out


def _called_names(tree: ast.AST) -> set[str]:
    """Names invoked as calls anywhere in a parsed module."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def _callers_of(entry_point: str, files: list[Path]) -> list[Path]:
    found = []
    for path in files:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        if entry_point in _called_names(tree):
            found.append(path)
    return found


def test_the_integrity_control_is_wired_into_production_code():
    files = _production_python_files()
    assert files, "scanner found no production files under proxy/ — it is looking in the wrong place"

    for entry_point in RUNTIME_ENTRY_POINTS:
        callers = _callers_of(entry_point, files)
        assert callers, (
            f"{entry_point}() is called by no production file under {PROXY}. "
            f"The binary-integrity control is dead code again: it will never run "
            f"in a deployed process, so no tamper verdict is ever reached and no "
            f"receipt is ever written. Scanned {len(files)} files."
        )


def test_the_scanner_can_actually_report_a_violation(tmp_path):
    """
    NEGATIVE SELF-TEST — the check must be able to fail.

    Runs the same discovery over a synthetic tree that calls something else, and
    requires it to find no caller. Without this, a scanner that silently matched
    nothing (wrong root, wrong parse) would look identical to a wired control.
    """
    decoy = tmp_path / "decoy.py"
    decoy.write_text("def lifespan():\n    verify_something_else(1)\n")

    assert _callers_of("verify_and_receipt", [decoy]) == []
    # Positive control: the scanner does find a call when one is present.
    wired = tmp_path / "wired.py"
    wired.write_text("async def lifespan():\n    await verify_and_receipt(d, w)\n")
    assert _callers_of("verify_and_receipt", [wired]) == [wired]


def test_the_entry_points_named_here_still_exist():
    """
    A renamed entry point would make the invariant above pass vacuously — it
    would look for a name nobody calls anymore and... no: it would FAIL. This
    guards the opposite direction, that the names are real, so the invariant is
    never guarding a function that no longer exists.
    """
    source = (PROXY / "license" / "integrity.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    defined = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    missing = [name for name in RUNTIME_ENTRY_POINTS if name not in defined]
    assert not missing, (
        f"RUNTIME_ENTRY_POINTS names {missing} which proxy/license/integrity.py "
        f"no longer defines — update this floor to the control's real entry points"
    )
