"""
FLOOR INVARIANT — the halt rule must be exhaustive over its own verdict vocabulary.

THE DEFECT THIS WAS COMPILED FROM
---------------------------------
``proxy/license/integrity.py`` declared three verdicts and halted on exactly one::

    if record["verdict"] == VERDICT_TAMPERED:
        raise TamperDetected(record["detail"])

Read as a whole that is an enumerated DENY-list, which means every verdict not
named in it defaulted to *boot anyway*. Nobody decided that ``unverifiable``
should not halt over compiled binaries; it simply was not mentioned. A second
vendor reproduced the consequence: drop a tampered ``features.cpython-312-
darwin.so`` into a directory, delete ``integrity_manifest.json``, and
``verify_integrity`` returned ``True``.

This is the shape of DONE.md floor invariant 8 in a different costume — a gate job
present in ``needs`` but missing its ``case`` arm inherits the previous
iteration's result, so an unnamed outcome is silently reported as someone else's
success. Here an unnamed verdict is silently reported as permission to run.

The fix inverted the default: :data:`NON_HALTING_VERDICTS` is an allow-list, so a
verdict added tomorrow halts until someone deliberately exempts it. That closes
the class only if the inversion cannot be quietly undone, which is what this file
is for.

THE INVARIANT — four parts
--------------------------
1. Every verdict the module DECLARES (discovered by parsing the source for
    ``VERDICT_*`` assignments — never enumerated here) is classified: either
    exempted in ``NON_HALTING_VERDICTS`` or observed to halt.
2. An UNDECLARED verdict — a hypothetical future value, or a corrupted record —
    halts. This is the fail-closed default itself, asserted directly.
3. Both policy functions route through the shared rule, so they cannot drift
    apart: ``verify_integrity`` and ``verify_and_receipt`` must not contain their
    own comparison against a verdict constant.
4. Every declared verdict has a risk level, and an unknown one is HIGH — so a new
    verdict cannot land in the audit rail's low-risk bucket by omission.

Stdlib-only (``ast``, ``pathlib``) so it runs in the dependency-free ``floor``
tier, which has no paths filter and therefore cannot be skipped. Carries its own
negative self-test per DONE.md floor invariant 9 / v1.19.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
INTEGRITY_SOURCE = REPO_ROOT / "proxy" / "license" / "integrity.py"

#: The functions whose halt decision must go through the shared rule.
POLICY_FUNCTIONS = ("verify_integrity", "verify_and_receipt")

#: The name of the shared rule they must call.
HALT_RULE = "should_halt"


def _tree() -> ast.Module:
    return ast.parse(INTEGRITY_SOURCE.read_text(encoding="utf-8"))


def declared_verdicts(tree: ast.Module) -> dict[str, str]:
    """
    ``{constant name: verdict string}`` for every module-level ``VERDICT_* = "..."``.

    DISCOVERED, never enumerated: a verdict added next year is covered by this
    file as written, which is the whole point of a floor invariant.
    """
    found: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Name)
                and target.id.startswith("VERDICT_")
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
            ):
                found[target.id] = node.value.value
    return found


def _comparisons_against_verdicts(tree: ast.Module, function: str, names: set[str]) -> list[str]:
    """Verdict constants a named function compares against directly."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != function:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Compare):
                for operand in [inner.left, *inner.comparators]:
                    if isinstance(operand, ast.Name) and operand.id in names:
                        hits.append(operand.id)
    return hits


def _calls_in(tree: ast.Module, function: str) -> set[str]:
    called: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != function:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                if isinstance(inner.func, ast.Name):
                    called.add(inner.func.id)
                elif isinstance(inner.func, ast.Attribute):
                    called.add(inner.func.attr)
    return called


# ---------------------------------------------------------------------------
# Static half — runs with pytest alone, no project dependencies
# ---------------------------------------------------------------------------


def test_the_scanner_finds_the_verdicts_it_is_guarding():
    """
    A check that passes by finding nothing must prove it can find something
    (DONE.md v1.19). If the discovery breaks, every assertion below passes
    vacuously over an empty set.
    """
    verdicts = declared_verdicts(_tree())
    assert len(verdicts) >= 3, (
        f"discovered only {verdicts} in {INTEGRITY_SOURCE} — the scanner is "
        f"looking in the wrong place, so the rest of this floor is vacuous"
    )
    assert "VERDICT_TAMPERED" in verdicts


def test_the_policy_functions_do_not_reimplement_the_halt_rule():
    """
    PART 3. The halt decision existed twice — once in ``verify_integrity``, once
    in ``verify_and_receipt`` — and only the second one runs in production. Two
    copies of a security decision drift, and a mutant deleting one is caught only
    by the other's tests. Both must delegate.
    """
    tree = _tree()
    verdict_names = set(declared_verdicts(tree))
    for function in POLICY_FUNCTIONS:
        called = _calls_in(tree, function)
        assert HALT_RULE in called, (
            f"{function}() does not call {HALT_RULE}() — its halt decision is "
            f"open-coded, so it can disagree with the other policy function and "
            f"with the allow-list that makes the default fail-closed"
        )
        reimplemented = _comparisons_against_verdicts(tree, function, verdict_names)
        assert not reimplemented, (
            f"{function}() compares directly against {sorted(set(reimplemented))}. "
            f"An enumerated comparison is a deny-list: any verdict it does not "
            f"name defaults to 'continue', which is the fail-open that let a "
            f"deleted manifest boot tampered binaries. Use {HALT_RULE}()."
        )


def test_the_scanner_can_actually_report_a_violation(tmp_path):
    """
    NEGATIVE SELF-TEST. Run the same discovery over a synthetic module that DOES
    open-code the comparison, and require both detections to fire — otherwise a
    silently-broken parse is indistinguishable from a compliant module.
    """
    bad = ast.parse(
        "VERDICT_TAMPERED = 'tampered'\n"
        "def verify_integrity(d):\n"
        "    if rec['verdict'] == VERDICT_TAMPERED:\n"
        "        raise TamperDetected()\n"
    )
    names = set(declared_verdicts(bad))
    assert names == {"VERDICT_TAMPERED"}, "verdict discovery failed on a known input"
    assert _comparisons_against_verdicts(bad, "verify_integrity", names) == ["VERDICT_TAMPERED"]
    assert HALT_RULE not in _calls_in(bad, "verify_integrity")

    good = ast.parse(
        "VERDICT_TAMPERED = 'tampered'\n"
        "def verify_integrity(d):\n"
        "    if should_halt(rec):\n"
        "        raise TamperDetected()\n"
    )
    good_names = set(declared_verdicts(good))
    assert _comparisons_against_verdicts(good, "verify_integrity", good_names) == []
    assert HALT_RULE in _calls_in(good, "verify_integrity")


# ---------------------------------------------------------------------------
# Behavioural half — the rule itself. Imports the module, still stdlib-only.
# ---------------------------------------------------------------------------


def _integrity_module():
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_integrity_floor_probe", INTEGRITY_SOURCE
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_every_declared_verdict_is_classified_halt_or_no_halt():
    """
    PART 1. Not "the ones we thought of" — every verdict the module declares. A
    new verdict that nobody classified must not be able to reach production, and
    the honest place to notice is here rather than in an incident.
    """
    integrity = _integrity_module()
    verdicts = declared_verdicts(_tree())
    assert verdicts, "no verdicts discovered"

    unclassified = []
    for const_name, value in sorted(verdicts.items()):
        exempt = value in integrity.NON_HALTING_VERDICTS
        halts = integrity.should_halt({"verdict": value})
        if exempt == halts:
            unclassified.append((const_name, value, exempt, halts))
    assert not unclassified, (
        f"verdicts whose halt classification is incoherent: {unclassified}. Each "
        f"declared verdict must either be exempted in NON_HALTING_VERDICTS or "
        f"halt — never both and never neither."
    )


def test_an_unknown_verdict_halts():
    """
    PART 2. The fail-closed default, asserted directly. This is the single
    assertion that would have caught the P1 class before it shipped: it does not
    care which verdicts exist, only that anything unrecognised refuses.
    """
    integrity = _integrity_module()
    for unknown in ("", "unknown", "probably_fine", "VERIFIED", None, "no_manifest"):
        assert integrity.should_halt({"verdict": unknown}) is True, (
            f"verdict {unknown!r} does not halt. An unrecognised verdict must "
            f"refuse to continue; permitting it is how an unnamed outcome becomes "
            f"a bypass."
        )
    assert integrity.should_halt({}) is True, "a record with no verdict must halt"


def test_the_exemptions_are_exactly_the_two_states_that_must_boot():
    """
    The allow-list is the entire attack surface of this design, so it is pinned.
    Widening it is a deliberate act that shows up in a diff on this line.

    ``verified``     — everything present is recorded and matches.
    ``unverifiable`` — nothing compiled AND no manifest: a source checkout, which
                       is how the proxy actually deploys today. If this one is
                       ever removed, production stops booting.
    """
    integrity = _integrity_module()
    assert integrity.NON_HALTING_VERDICTS == frozenset({"verified", "unverifiable"}), (
        f"NON_HALTING_VERDICTS is {sorted(integrity.NON_HALTING_VERDICTS)}. Each "
        f"member is a state in which a proxy with unverified binaries is allowed "
        f"to serve traffic, so an addition needs its own justification and test "
        f"row in proxy/tests/test_integrity_manifest_states.py."
    )


def test_every_declared_verdict_has_a_risk_level_and_unknown_is_high():
    """
    PART 4. The audit rail buckets by ``risk_level``. A verdict with no mapping
    would either raise a KeyError from inside the function producing the finding,
    or — worse, if someone "fixed" that with a permissive default — land an
    adverse verdict in the LOW bucket and out of every alerting surface.
    """
    integrity = _integrity_module()
    for const_name, value in sorted(declared_verdicts(_tree()).items()):
        assert value in integrity._RISK_LEVEL, (
            f"{const_name} ({value!r}) has no risk level, so its receipt cannot "
            f"be bucketed by the audit rail"
        )
    assert integrity._risk_level_for("a_verdict_nobody_mapped") == "HIGH"


def test_the_artifact_globs_have_one_owner():
    """
    The missing-manifest ruling turns on whether compiled artifacts are PRESENT,
    so the glob set that answers that question is now security-relevant. It was
    declared twice — once in the library, once in ``scripts/build_release.py``
    documented as a mirror. Parsed statically rather than imported so this stays
    in the dependency-free tier.
    """
    build_release = REPO_ROOT / "scripts" / "build_release.py"
    tree = ast.parse(build_release.read_text(encoding="utf-8"))
    redeclared = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "COMPILED_ARTIFACT_GLOBS"
            for t in node.targets
        )
    ]
    assert not redeclared, (
        f"{build_release} redeclares COMPILED_ARTIFACT_GLOBS at line "
        f"{redeclared[0].lineno}. It must import the definition from "
        f"proxy.license.integrity: a mirror that drifts LOW would let a compiled "
        f"artifact exist that the runtime presence check never notices, which "
        f"reopens the missing-manifest bypass."
    )
    imported = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "proxy.license.integrity"
        and any(alias.name == "COMPILED_ARTIFACT_GLOBS" for alias in node.names)
        for node in ast.walk(tree)
    )
    assert imported, (
        f"{build_release} neither declares nor imports COMPILED_ARTIFACT_GLOBS — "
        f"this check has stopped observing anything"
    )
