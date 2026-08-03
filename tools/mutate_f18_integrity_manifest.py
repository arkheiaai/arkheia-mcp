#!/usr/bin/env python3
"""
Mutation harness for F18 — Binary integrity verification (compiled .so/.pyd).

WHY THIS EXISTS AT ALL
----------------------
F18 had NO mutation campaign. The previous round proved its claims with red-run
probes (0/3 -> 3/3), which is real evidence that the fix moved something, but it
is evidence about the FIX, not about the TESTS. A red-run probe answers "did
behaviour change?". A mutation run answers the question that actually protects the
control: "if someone deletes this decision next year, does anything go red?"

The gap was not academic. A second vendor reproduced a full bypass on the branch
that had already been proved with red-runs — delete ``integrity_manifest.json``
over a compiled ``.so`` and the process booted tampered binaries. The decision
that was missing had no test, and no red-run probe was ever going to say so.

Sibling flows in this repo carry ``tools/mutate_f<N>_*.py`` (F1, F5, F20, F22 and
the detection adapter). This is F18's, built to the same shape so the numbers are
comparable.

WHAT THE MUTANTS TARGET
-----------------------
Every decision that stands between a tampered binary and a served request:
the missing-manifest asymmetry, the compiled-artifact presence detector and its
glob set, the allow-list halt rule, the unlisted-artifact check, the manifest
entry-name validation, the unreadable-module path, the risk-level mapping, and
the raise sites in BOTH policy functions plus the lifespan that calls them.

TRAPS THIS HARNESS IS BUILT AGAINST
-----------------------------------
1. **Stale bytecode.** A same-length restore can leave Python serving the mutated
   ``.pyc``. Every trial clears ``__pycache__`` across the tree, before AND after.
2. **A void run reported as clean** (DONE.md floor invariant 9). Zero mutants
   generated, or any mutant that fails to APPLY, produces a non-zero exit and the
   units are NAMED — never a green line over an unmeasured run.
3. **Equivalent mutants.** A mutant that survives because it did not change
   observable behaviour is a defect in the MUTANT, not a hole in the tests.
   Withdrawn ones are recorded in ``WITHDRAWN`` below with the reason, rather than
   deleted — the record of what was tried and rejected is the useful part.

A KILL IS NOT PROOF EITHER: the permissive-assertion class
(``pytest.raises(Exception)``, ``assert x != y``) is invisible to mutation. Read
the survivors, and read the assertions.

Usage:
    python tools/mutate_f18_integrity_manifest.py [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

INTEGRITY = "proxy/license/integrity.py"
MAIN = "proxy/main.py"

#: The suites that are supposed to protect this flow. Deliberately the WHOLE
#: covering set rather than the new file alone — a mutant killed only by the test
#: written in the same commit tells you less than one killed by the flow's
#: existing coverage.
TEST_CMD = [
    sys.executable, "-m", "pytest",
    "proxy/tests/test_integrity_manifest_states.py",
    "proxy/tests/test_integrity_runtime_receipt.py",
    "proxy/tests/test_integrity_manifest_receipt.py",
    "tests/test_integrity_halt_floor.py",
    "tests/test_integrity_wiring_floor.py",
    "tests/test_encrypted_profiles.py",
    "tests/test_build_pipeline.py",
    "-x", "-q", "-p", "no:cacheprovider", "--timeout=180",
]


@dataclass
class Mutant:
    mid: str
    path: str
    old: str
    new: str
    intent: str
    #: A semantics-PRESERVING edit, expected to SURVIVE. It proves the harness
    #: edits a line that actually executes without claiming a hole when nothing
    #: changed. Counted separately from real survivors.
    control: bool = False


MUTANTS: list[Mutant] = [
    # --- Controls: the harness edits live lines ------------------------------
    Mutant(
        "M1", INTEGRITY,
        "    present = [p.name for p in compiled_artifacts(module_dir)]",
        "    present = [p.name for p in compiled_artifacts(module_dir)]\n"
        "    present = list(present)  # noqa: PLW0127",
        "CONTROL (semantics-preserving): proves the harness edits a line on the "
        "executed path. Expected to SURVIVE.",
        control=True,
    ),

    # --- THE P1: the missing-manifest asymmetry ------------------------------
    Mutant(
        "M2", INTEGRITY,
        "    if not manifest_path.exists():\n        if present:",
        "    if not manifest_path.exists():\n        if False:",
        "RESTORE THE P1 EXACTLY: no manifest is always `unverifiable`, so a "
        "tampered .so with the manifest deleted boots. This is the mutant that "
        "nothing on the parent branch could kill.",
    ),
    Mutant(
        "M3", INTEGRITY,
        "            if path.is_dir():\n                continue\n            found[path.name] = path",
        "            found[path.name] = path",
        "count directories as compiled artifacts — a source checkout with a "
        "directory named *.so would be refused boot (false positive in a control "
        "that must not cry wolf)",
    ),
    Mutant(
        "M4", INTEGRITY,
        "    found: dict[str, Path] = {}\n"
        "    for pattern in COMPILED_ARTIFACT_GLOBS:",
        "    found: dict[str, Path] = {}\n"
        "    return []\n"
        "    for pattern in COMPILED_ARTIFACT_GLOBS:",
        "blind the presence detector — it always reports 'nothing compiled', so "
        "the missing-manifest branch always takes the benign path",
    ),
    Mutant(
        "M5", INTEGRITY,
        'COMPILED_ARTIFACT_GLOBS = ("*.so", "*.pyd")',
        'COMPILED_ARTIFACT_GLOBS = ("*.pyd",)',
        "drift the glob set LOW — .so files become invisible to both the manifest "
        "generator and the presence check on every Linux/macOS build",
    ),

    # --- The halt rule: fail-closed by default ------------------------------
    Mutant(
        "M6", INTEGRITY,
        "    return record.get(\"verdict\") not in NON_HALTING_VERDICTS",
        "    return record.get(\"verdict\") == VERDICT_TAMPERED",
        "revert the allow-list to the pre-fix deny-list — the class defect, not "
        "just the instance: any verdict not named defaults to 'continue'",
    ),
    Mutant(
        "M7", INTEGRITY,
        "    return record.get(\"verdict\") not in NON_HALTING_VERDICTS",
        "    return False",
        "never halt at all — the control becomes decorative while still emitting "
        "a HIGH receipt, which is the worst shape (evidence of a refusal that "
        "did not happen)",
    ),
    Mutant(
        "M8", INTEGRITY,
        "NON_HALTING_VERDICTS = frozenset({VERDICT_VERIFIED, VERDICT_UNVERIFIABLE})",
        "NON_HALTING_VERDICTS = frozenset(\n"
        "    {VERDICT_VERIFIED, VERDICT_UNVERIFIABLE, VERDICT_TAMPERED}\n"
        ")",
        "exempt `tampered` — widen the allow-list, which is the one line where "
        "this design can be quietly undone",
    ),
    Mutant(
        "M9", INTEGRITY,
        "NON_HALTING_VERDICTS = frozenset({VERDICT_VERIFIED, VERDICT_UNVERIFIABLE})",
        "NON_HALTING_VERDICTS = frozenset({VERDICT_VERIFIED})",
        "THE OTHER DIRECTION — make `unverifiable` halt unconditionally. Proves "
        "the production-boot property is pinned and not merely asserted in prose: "
        "the deployed proxy is a source checkout and must still start.",
    ),

    # --- The unlisted-artifact check (the second hole) ----------------------
    Mutant(
        "M10", INTEGRITY,
        "    unlisted = [name for name in present if name not in manifest]",
        "    unlisted = []",
        "remove the unlisted-artifact check — truncate the manifest to drop one "
        "entry, tamper that module, and the verdict is `verified` over 1 of 1",
    ),
    Mutant(
        "M11", INTEGRITY,
        "    if unlisted:\n        record[\"unlisted_artifacts\"] = unlisted\n        return _finish(",
        "    if unlisted:\n        record[\"unlisted_artifacts\"] = unlisted\n        return _finish(\n"
        "            VERDICT_VERIFIED,\n            \"all_modules_matched\",\n            \"\",\n        ) or _finish(",
        "downgrade the unlisted finding to a pass while still recording the names "
        "— a receipt that names the problem and reports success",
    ),

    # --- Manifest-shape and entry-name validation --------------------------
    Mutant(
        "M12", INTEGRITY,
        "        or Path(name).is_absolute()\n        or Path(name).name != name",
        "        or False",
        "stop validating entry names — a manifest key of `../outside.so` or "
        "`/etc/hosts` steers the verifier out of its own directory",
    ),
    Mutant(
        "M13", INTEGRITY,
        "    if not isinstance(manifest, dict):",
        "    if False:",
        "let a non-object manifest through to the emptiness check, collapsing two "
        "different operator actions into one reason",
    ),
    Mutant(
        "M14", INTEGRITY,
        "    if not manifest:",
        "    if False:",
        "restore the emptied-manifest bypass closed by the previous round — a "
        "regression guard for work that is already landed",
    ),

    # --- The unreadable-module path ----------------------------------------
    Mutant(
        "M15", INTEGRITY,
        "            try:\n"
        "                actual_hash = _sha256_file(module_path)\n"
        "            except OSError as exc:",
        "            try:\n"
        "                actual_hash = _sha256_file(module_path)\n"
        "            except _NeverRaised as exc:",
        "let the unreadable-module OSError escape again — no verdict is produced, "
        "so NO RECEIPT is written for the outcome that most needs one",
    ),

    # --- Risk bucketing -----------------------------------------------------
    Mutant(
        "M16", INTEGRITY,
        '    return _RISK_LEVEL.get(verdict, "HIGH")',
        '    return _RISK_LEVEL.get(verdict, "LOW")',
        "an unmapped verdict lands in the LOW bucket, so a new adverse verdict "
        "would be invisible to every surface that alerts on HIGH",
    ),

    # --- The raise sites, in both policy functions --------------------------
    Mutant(
        "M17", INTEGRITY,
        "    if should_halt(record):\n        raise TamperDetected(record[\"detail\"])\n    return True",
        "    return True",
        "delete the raise from `verify_integrity` — the LIBRARY entry point",
    ),
    Mutant(
        "M18", INTEGRITY,
        "    if should_halt(record):\n        raise TamperDetected(record[\"detail\"]) from receipt_failure",
        "    if False:\n        raise TamperDetected(record[\"detail\"]) from receipt_failure",
        "delete the raise from `verify_and_receipt` — THE ONE PRODUCTION RUNS. "
        "The parent PR asked a reviewer to check whether anything kills this.",
    ),

    # --- The lifespan that calls it ----------------------------------------
    Mutant(
        "M19", MAIN,
        "        except TamperDetected as exc:",
        "        except _TamperDetectedNever as exc:",
        "break the handler's exception name in the lifespan. Counted as a real "
        "mutant: it changes observable behaviour (a NameError replaces the "
        "TamperDetected, and the audit writer is never stopped). Its job is to "
        "show the boot test observes the handler itself, not just the raise.",
    ),
    Mutant(
        "M20", MAIN,
        "            await audit_writer.stop()\n            raise",
        "            await audit_writer.stop()",
        "SWALLOW THE HALT IN THE LIFESPAN — log CRITICAL and serve anyway. The "
        "highest-severity outcome available to this flow: every verdict correct, "
        "every receipt written, and the process runs tampered binaries.",
    ),
]


#: Mutants tried and WITHDRAWN, with the reason. Kept because a withdrawn mutant
#: is a finding about the harness, and deleting it silently is how a campaign
#: starts looking cleaner than it is.
WITHDRAWN = [
    {
        "id": "W1",
        "mutation": "change `manifest_is_symlink` to always record False",
        "reason": (
            "EQUIVALENT for every behavioural assertion. The field is recorded for "
            "a human reading the receipt and drives no decision — by design (see "
            "S15: a symlinked manifest is recorded, not refused). A mutant that "
            "cannot change an outcome cannot be killed by an outcome-observing "
            "test, and reporting it as a survivor would be a false finding about "
            "test coverage rather than a true one about the code."
        ),
    },
    {
        "id": "W2",
        "mutation": "delete the `record['compiled_artifacts_present']` assignment",
        "reason": (
            "NOT a security decision and NOT equivalent — it is asserted directly "
            "by the P1 test, so it would be killed. Withdrawn as uninformative: it "
            "measures whether a field the same commit added is asserted, which is "
            "circular. `present` is exercised as a DECISION by M2/M4/M5 instead."
        ),
    },
    {
        "id": "W3",
        "mutation": "reorder the unlisted-artifact check before the per-module loop",
        "reason": (
            "WITHDRAWN as a real behaviour change that is arguably an improvement, "
            "not a fault: it changes which reason wins when a module is BOTH "
            "modified and another is unlisted. A mutant must encode a defect, and "
            "this one encodes a defensible design choice. The precedence is pinned "
            "by S6/S9b holding `module_mismatch` for a mixed state instead."
        ),
    },
]


@dataclass
class Result:
    mid: str
    intent: str
    applied: bool
    verdict: str  # KILLED | SURVIVED | NOT_APPLIED
    detail: str = ""
    control: bool = False


def clear_pycache(root: Path) -> None:
    for d in root.rglob("__pycache__"):
        if ".venv" in d.parts or ".git" in d.parts:
            continue
        shutil.rmtree(d, ignore_errors=True)


def run_suite(root: Path) -> tuple[bool, str]:
    proc = subprocess.run(TEST_CMD, cwd=root, capture_output=True, text=True)
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-1500:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    root = REPO_ROOT
    results: list[Result] = []

    if not MUTANTS:
        print("NO MUTANTS DEFINED — a campaign that generates nothing must not "
              "report clean (DONE.md floor invariant 9).", file=sys.stderr)
        return 1

    clear_pycache(root)
    green, out = run_suite(root)
    if not green:
        print("BASELINE IS RED — refusing to run. A mutation verdict over a red "
              "baseline means nothing.\n" + out, file=sys.stderr)
        return 1
    print(f"baseline: GREEN ({len(MUTANTS)} mutants queued)\n")

    for m in MUTANTS:
        target = root / m.path
        original = target.read_text()
        if m.old not in original:
            results.append(Result(
                m.mid, m.intent, False, "NOT_APPLIED",
                "anchor text not found — the mutant never reached the interpreter",
                m.control,
            ))
            print(f"  {m.mid} NOT_APPLIED  {m.intent[:70]}")
            continue
        if original.count(m.old) != 1:
            results.append(Result(
                m.mid, m.intent, False, "NOT_APPLIED",
                f"anchor is ambiguous ({original.count(m.old)} matches)",
                m.control,
            ))
            print(f"  {m.mid} NOT_APPLIED  {m.intent[:70]}")
            continue

        clear_pycache(root)
        target.write_text(original.replace(m.old, m.new, 1))
        clear_pycache(root)
        try:
            passed, out = run_suite(root)
        finally:
            target.write_text(original)
            clear_pycache(root)

        verdict = "SURVIVED" if passed else "KILLED"
        results.append(Result(
            m.mid, m.intent, True, verdict, "" if passed else out[-400:], m.control
        ))
        print(f"  {m.mid} {verdict:9s} {m.intent[:70]}")

    clear_pycache(root)
    green_after, out_after = run_suite(root)

    applied = [r for r in results if r.applied]
    killed = [r for r in applied if r.verdict == "KILLED" and not r.control]
    survived = [r for r in applied if r.verdict == "SURVIVED" and not r.control]
    controls_ok = [r for r in applied if r.control and r.verdict == "SURVIVED"]
    controls_bad = [r for r in applied if r.control and r.verdict == "KILLED"]
    not_applied = [r for r in results if not r.applied]

    # ONE verdict; the exit code and the printed sentence are both derived FROM
    # it, never decided separately (DONE.md floor invariant 9 corollary).
    verdict = "CLEAN"
    if not applied:
        verdict = "VOID"
    elif not_applied:
        verdict = "INCOMPLETE"
    elif survived:
        verdict = "SURVIVORS"
    if controls_bad:
        verdict = "CONTROL_FAILED"
    if not green_after:
        verdict = "BASELINE_DIRTY"

    real = [m for m in MUTANTS if not m.control]
    print("\n" + "=" * 74)
    print(f"verdict              : {verdict}")
    print(f"mutants generated    : {len(MUTANTS)}  ({len(real)} real, "
          f"{len(MUTANTS) - len(real)} control)")
    print(f"mutants APPLIED      : {len(applied)}   <- the work-done number")
    print(f"KILLED (real)        : {len(killed)}")
    print(f"SURVIVED (real)      : {len(survived)}")
    for r in survived:
        print(f"    - {r.mid}: {r.intent}")
    print(f"controls SURVIVED    : {len(controls_ok)} (expected)")
    print(f"controls KILLED      : {len(controls_bad)} (must be 0)")
    print(f"NOT APPLIED          : {len(not_applied)}  <- NOT-OBSERVED, never "
          f"folded into KILLED")
    for r in not_applied:
        print(f"    - {r.mid}: {r.detail}")
    print(f"withdrawn (recorded) : {len(WITHDRAWN)}")
    for w in WITHDRAWN:
        print(f"    - {w['id']}: {w['mutation']}")
    print(f"final baseline       : {'GREEN' if green_after else 'RED'}")
    print("=" * 74)
    if verdict != "CLEAN":
        print("NOT CLEAN — see the named units above.")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "flow": "Binary integrity verification (compiled .so/.pyd)",
            "flow_id": "F18",
            "verdict": verdict,
            "totals": {
                "generated": len(MUTANTS),
                "real": len(real),
                "applied": len(applied),
                "killed": len(killed),
                "survived": len(survived),
                "not_applied": len(not_applied),
                "controls_survived_as_expected": len(controls_ok),
                "controls_unexpectedly_killed": len(controls_bad),
                "withdrawn": len(WITHDRAWN),
            },
            "survivors": [{"id": r.mid, "intent": r.intent} for r in survived],
            "not_applied": [{"id": r.mid, "reason": r.detail} for r in not_applied],
            "withdrawn": WITHDRAWN,
            "final_baseline_green": green_after,
            "results": [r.__dict__ for r in results],
        }, indent=2))

    return 0 if verdict == "CLEAN" else 2


if __name__ == "__main__":
    sys.exit(main())
