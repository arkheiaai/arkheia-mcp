#!/usr/bin/env python3
"""
Mutation harness for the tool-registry allow/deny gate (flow F1).

WHY THIS EXISTS
---------------
The gate's suites pass. That is necessary and not sufficient: a test that cannot
fail is worse than no test, because it converts an open defect into a closed one
on the ledger. This harness answers the only question that matters about a suite —
*if the control were removed, would anything notice?* — by removing each control,
one at a time, and requiring a named test to go RED.

Each mutant is a real weakening of a real control: drop the dispatch gate, unfreeze
the policy, stop validating the decision word, report a receipt as written when it
was not. A SURVIVED mutant is a hole in the suite and is reported as such — never
summarised away.

DONE.md floor ledger #9 compliance, deliberately:
  * the verdict asserts WORK WAS DONE (a run that generated zero mutants, or reached
    zero targets, is a FAILURE, not "all mutants killed");
  * every not-killed unit is NAMED, never only counted;
  * the three buckets are KILLED / SURVIVED / NOT-OBSERVED, and a mutant whose run
    errored before the suite could judge it lands in the third — never in the first;
  * one verdict drives the exit code, the JSON and the printed sentence.

USAGE
    python tools/mutate_f1_tool_gate.py [--json] [--only ID[,ID...]]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = str(ROOT / ".venv" / "bin" / "python") if (ROOT / ".venv" / "bin" / "python").exists() else sys.executable

GATE = "mcp_server/tool_registry.py"
SERVER = "mcp_server/server.py"
RAIL = "mcp_server/receipts.py"

UNIT_SUITE = ["mcp_server/tests"]
FLOOR_SUITE = ["tests/test_tool_gate_floor.py"]


@dataclass
class Mutant:
    id: str
    file: str
    old: str
    new: str
    control: str
    #: Which suite must go red. The floor tier is run with its own collection rules.
    suite: str = "unit"
    #: Substring of the test id(s) expected to fail. Asserted, so a mutant that is
    #: killed by an UNRELATED test is reported as such rather than counted as clean
    #: coverage of the control it was aimed at.
    expect: str = ""
    killed_by: list[str] = field(default_factory=list)


MUTANTS: list[Mutant] = [
    # --- A. the dispatch chokepoint --------------------------------------------
    Mutant(
        "M1", SERVER,
        "        await check_receipted(\n            name,\n            call_site=\"dispatch\",",
        "        await _skipped(\n            name,\n            call_site=\"dispatch\",",
        "dispatch gate present at all",
        expect="late_registered",
    ),
    Mutant(
        "M2", SERVER,
        "        governed = [t for t in advertised if t.name in REGISTRY]",
        "        governed = list(advertised)  # MUTANT: advertise ungoverned tools",
        "ungoverned tools withheld from tools/list",
        expect="WITHHELD",
    ),
    Mutant(
        "M3", SERVER,
        "anyio.run(mcp.list_tools_ungated)",
        "anyio.run(mcp.list_tools)",
        "boot self-check reads the UNFILTERED advertisement",
        expect="selfcheck",
    ),
    Mutant(
        "M4", SERVER,
        "        await check_receipted(\n            name,",
        "        await check_receipted(\n            \"arkheia_verify\",",
        "the gate decides about the DISPATCHED name",
        expect="",
    ),
    # --- B. fail-closed on malformed input -------------------------------------
    Mutant(
        "M5", GATE,
        "    if not isinstance(tool_name, str):",
        "    if False:  # MUTANT: accept any type as a tool name",
        "non-str tool name is a deny, not a TypeError",
        expect="malformed",
    ),
    Mutant(
        "M6", GATE,
        "    if not policy.permissions:",
        "    if False:  # MUTANT: empty permission set authorises",
        "empty permission set is default-deny",
        expect="empty_permission",
    ),
    Mutant(
        "M7", GATE,
        "    if policy.requires_human_confirm and not human_confirmed:",
        "    if False:  # MUTANT: confirm requirement blocks nothing",
        "requires_human_confirm blocks without approval",
        expect="confirm",
    ),
    Mutant(
        "M8", GATE,
        "    policy = REGISTRY.get(tool_name)\n    if policy is None:",
        "    policy = REGISTRY.get(tool_name)\n    if False:",
        "default deny for an unregistered name",
        expect="",
    ),
    # --- C. runtime mutation of policy -----------------------------------------
    Mutant(
        "M9", GATE,
        "@dataclass(frozen=True)\nclass ToolPolicy:",
        "@dataclass\nclass ToolPolicy:",
        "the policy the gate returns cannot be widened",
        expect="widened",
    ),
    Mutant(
        "M10", GATE,
        "REGISTRY: Mapping[str, ToolPolicy] = MappingProxyType(_POLICIES)",
        "REGISTRY: Mapping[str, ToolPolicy] = _POLICIES  # MUTANT: writable",
        "the public registry handle rejects injection",
        expect="injection",
    ),
    Mutant(
        "M11", GATE,
        '        permissions=(Permission.READ,),\n        network_egress=True,\n        description="Screen an AI response for fabrication risk",',
        '        permissions=[Permission.READ],\n        network_egress=True,\n        description="Screen an AI response for fabrication risk",',
        "no shipped policy holds a mutable permission container",
        expect="mutable_permission",
    ),
    # --- D. the receipt --------------------------------------------------------
    Mutant(
        "M12", GATE,
        "        ok = await receipts.emit(resolved, record)",
        "        ok = True  # MUTANT: report written without writing",
        "the receipt actually reaches disk",
        expect="",
    ),
    Mutant(
        "M13", GATE,
        "    return receipt_id, (\n        receipts.STATUS_RECORDED if ok else receipts.STATUS_UNRECORDED\n    )",
        "    return receipt_id, receipts.STATUS_RECORDED  # MUTANT: always claim recorded",
        "an unwritten receipt is surfaced as unrecorded",
        expect="FAILING_receipt",
    ),
    Mutant(
        "M14", GATE,
        "        violation.receipt_id = receipt_id\n        violation.receipt_status = status",
        "        pass  # MUTANT: refusal carries no receipt id",
        "the refusal carries its receipt id",
        expect="",
    ),
    Mutant(
        "M15", GATE,
        "        violation.args = (\n            f\"{violation.args[0]} [receipt {receipt_id}: {status}]\",\n        ) + violation.args[1:]",
        "        pass  # MUTANT: receipt id not in the message the orchestrator sees",
        "the receipt id is in the refusal MESSAGE",
        expect="MESSAGE",
    ),
    Mutant(
        "M16", GATE,
        '        "deny_code": None if violation is None else violation.code,',
        '        "deny_code": None,  # MUTANT: refusals are indistinguishable',
        "each deny branch is recorded with its own code",
        expect="code",
    ),
    Mutant(
        "M17", GATE,
        '        "permissions_applied": (\n            None if policy is None else sorted(p.value for p in policy.permissions)\n        ),',
        '        "permissions_applied": ["read"],  # MUTANT: not the applied grant',
        "the allow row records the grant actually applied",
        expect="policy_actually_applied",
    ),
    Mutant(
        "M18", GATE,
        '        "human_confirmed": human_confirmed,',
        '        "human_confirmed": False,  # MUTANT: an override leaves no trace',
        "a supplied human approval is recorded",
        expect="approval",
    ),
    Mutant(
        "M19", GATE,
        "        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE)",
        "        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)",
        "the receipt file is not world-readable",
        expect="world_readable",
    ),
    # --- the named hazard: a receipt fault must not vanish ---------------------
    Mutant(
        "M20", GATE,
        "        try:\n            record = receipts.build_record(\n                receipt_id=receipt_id,\n                tool=tool_label,\n                decision=receipts.DECISION_UNREPRESENTABLE,",
        "        if True:\n            return receipt_id, receipts.STATUS_UNRECORDED\n        try:\n            record = receipts.build_record(\n                receipt_id=receipt_id,\n                tool=tool_label,\n                decision=receipts.DECISION_UNREPRESENTABLE,",
        "an unbuildable record still lands (the sibling-flow hazard)",
        expect="UNBUILDABLE",
    ),
    Mutant(
        "M21", RAIL,
        "    if decision not in _DECISIONS:",
        "    if False:  # MUTANT: rail accepts any decision word",
        "the rail rejects an unknown decision",
        expect="unknown_decision",
    ),
    Mutant(
        "M22", RAIL,
        "    if find_receipt(log_path, receipt_id) is None:",
        "    if False:  # MUTANT: enqueued is reported as landed",
        "emit() confirms the row landed rather than that it was enqueued",
        expect="",
    ),
    # --- E. the decision itself ------------------------------------------------
    Mutant(
        "M23", GATE,
        "    if decision.violation is not None:\n        raise decision.violation",
        "    if False:\n        raise decision.violation  # MUTANT: deny is not enforced",
        "check_receipted raises on deny",
        expect="",
    ),
    Mutant(
        "M24", GATE,
        "@dataclass(frozen=True)\nclass GateDecision:",
        "@dataclass\nclass GateDecision:",
        "the decision record is immutable",
        expect="gate_decision_is_immutable",
    ),
    # --- the FLOOR's own invariants must be able to fail -----------------------
    Mutant(
        "M25", "tests/test_tool_gate_floor.py",
        "            if owner.get(node) in DENY_FUNCTIONS:",
        "            if True:  # MUTANT: count evidence reads as enforcement",
        "INV-3 counts only reads inside a DECISION function",
        suite="floor",
        expect="inv3",
    ),
    Mutant(
        "M26", "tests/test_tool_gate_floor.py",
        "    if isinstance(node, ast.Name):\n        return node.id.startswith(DECISION_CONSTANT_PREFIX)\n    return False",
        "    if isinstance(node, ast.Name):\n        return node.id.startswith(DECISION_CONSTANT_PREFIX)\n    return True  # MUTANT: accept anything",
        "INV-6's predicate can REJECT (negative self-test)",
        suite="floor",
        expect="inv6",
    ),

    # --- the FLOOR must go red when the SOURCE regresses ----------------------
    # M1-M4 and M9-M11 prove the UNIT suite notices. These prove the deterministic
    # floor tier — the check that runs with zero interpreter variance, on every PR,
    # with no paths filter — notices independently. A floor that only agrees with
    # the unit suite adds nothing.
    Mutant(
        "M27", SERVER,
        "        await check_receipted(\n            name,\n            call_site=\"dispatch\",",
        "        await _skipped(\n            name,\n            call_site=\"dispatch\",",
        "FLOOR INV-5 sees the dispatch gate removed",
        suite="floor",
        expect="inv5",
    ),
    Mutant(
        "M28", SERVER,
        'mcp   = GatedFastMCP("arkheia-trust")',
        'mcp   = FastMCP("arkheia-trust")  # MUTANT: ungated instance',
        "FLOOR INV-5 sees the server built from bare FastMCP",
        suite="floor",
        expect="inv5",
    ),
    Mutant(
        "M29", SERVER,
        "anyio.run(mcp.list_tools_ungated)",
        "anyio.run(mcp.list_tools)",
        "FLOOR INV-5b sees the self-check fed the filtered advertisement",
        suite="floor",
        expect="inv5b",
    ),
    Mutant(
        "M30", GATE,
        "REGISTRY: Mapping[str, ToolPolicy] = MappingProxyType(_POLICIES)",
        "REGISTRY: Mapping[str, ToolPolicy] = _POLICIES  # MUTANT: writable",
        "FLOOR INV-2b sees the registry export become writable",
        suite="floor",
        expect="inv2b",
    ),
    Mutant(
        "M31", GATE,
        "@dataclass(frozen=True)\nclass ToolPolicy:",
        "@dataclass\nclass ToolPolicy:",
        "FLOOR INV-2b sees ToolPolicy unfrozen",
        suite="floor",
        expect="inv2b",
    ),
    Mutant(
        "M32", GATE,
        "                decision=receipts.DECISION_ALLOWED,\n                event_type=GATE_EVENT_TYPE,",
        "                decision=verdict_word,\n                event_type=GATE_EVENT_TYPE,",
        "FLOOR INV-6 sees a runtime string passed as the decision",
        suite="floor",
        expect="inv6",
    ),
    Mutant(
        "M34", SERVER,
        "if __name__ == \"__main__\":\n    startup_policy_selfcheck()\n    mcp.run()",
        "if __name__ == \"__main__\":\n    mcp.run()  # MUTANT: no boot coverage check",
        "FLOOR INV-8 sees an entry point skip the boot self-check",
        suite="floor",
        expect="inv8",
    ),
    Mutant(
        "M35", "server.py",
        "if __name__ == \"__main__\":\n    startup_policy_selfcheck()\n    mcp.run()",
        "if __name__ == \"__main__\":\n    mcp.run()  # MUTANT: root shim skips the check",
        "FLOOR INV-8 sees the ROOT entry point skip the boot self-check",
        suite="floor",
        expect="inv8",
    ),
    Mutant(
        "M33", GATE,
        "    if policy.requires_human_confirm and not human_confirmed:",
        "    if policy.network_egress and not human_confirmed:",
        "FLOOR INV-3/INV-7 see a control move in or out of the decision",
        suite="floor",
        expect="inv3",
    ),
]


def run_suite(which: str) -> subprocess.CompletedProcess:
    if which == "floor":
        cmd = [PYTHON, "-m", "pytest", *FLOOR_SUITE, "-q",
               "-o", 'python_files=test_*_floor.py', "-p", "no:cacheprovider"]
    else:
        cmd = [PYTHON, "-m", "pytest", *UNIT_SUITE, "-q", "-p", "no:cacheprovider"]
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=900)


def failing_tests(out: str) -> list[str]:
    return sorted(
        line.split(" ")[1] for line in out.splitlines()
        if line.startswith("FAILED ") and len(line.split(" ")) > 1
    ) or sorted(
        line[len("FAILED "):].split(" ")[0] for line in out.splitlines()
        if line.startswith("FAILED ")
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--only", default="")
    args = ap.parse_args()

    selected = [m for m in MUTANTS if not args.only or m.id in args.only.split(",")]

    # ---- baseline: the suites must be GREEN before any mutant means anything.
    baseline = {}
    for which in ("unit", "floor"):
        proc = run_suite(which)
        baseline[which] = proc.returncode
        if proc.returncode != 0:
            print(f"BASELINE {which} SUITE IS RED — no mutant result can be trusted.")
            print(proc.stdout[-4000:])
            return 2

    killed: list[dict] = []
    survived: list[dict] = []
    not_observed: list[dict] = []

    for m in selected:
        path = ROOT / m.file
        original = path.read_text()
        occurrences = original.count(m.old)
        if occurrences != 1:
            not_observed.append({
                "id": m.id, "control": m.control,
                "why": f"anchor matched {occurrences} times, expected exactly 1 — "
                       f"the mutant could not be applied, so the control was NEVER "
                       f"EXAMINED. Repair the anchor.",
            })
            continue

        path.write_text(original.replace(m.old, m.new))
        try:
            proc = run_suite(m.suite)
        except subprocess.TimeoutExpired:
            path.write_text(original)
            not_observed.append({
                "id": m.id, "control": m.control,
                "why": "suite timed out; the mutant was never judged",
            })
            continue
        finally:
            path.write_text(original)

        fails = failing_tests(proc.stdout)
        entry = {"id": m.id, "control": m.control, "failing": fails[:6],
                 "failing_count": len(fails)}

        if proc.returncode == 0:
            survived.append(entry)
        elif m.expect and not any(m.expect in f for f in fails):
            entry["why"] = (
                f"the suite went red but no test matching {m.expect!r} failed — this "
                f"mutant was killed by an UNRELATED test, so the control it targets "
                f"is not demonstrably covered"
            )
            survived.append(entry)
        else:
            killed.append(entry)

    examined = len(killed) + len(survived)
    verdict = (
        "NO_WORK_DONE" if examined == 0
        else "HOLES" if survived or not_observed
        else "ALL_KILLED"
    )

    summary = {
        "verdict": verdict,
        "totals": {
            "selected": len(selected),
            "examined": examined,
            "killed": len(killed),
            "survived": len(survived),
            "not_observed": len(not_observed),
        },
        "killed": killed,
        "survived": survived,
        "not_observed": not_observed,
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        # ONE sentence, derived FROM the verdict — never a separate judgement.
        print(f"verdict={verdict}  selected={len(selected)} examined={examined} "
              f"killed={len(killed)} survived={len(survived)} "
              f"not_observed={len(not_observed)}")
        for e in killed:
            print(f"  KILLED       {e['id']}  {e['control']}  "
                  f"({e['failing_count']} test(s) red)")
        for e in survived:
            print(f"  SURVIVED     {e['id']}  {e['control']}"
                  + (f"  — {e['why']}" if e.get("why") else ""))
        for e in not_observed:
            print(f"  NOT-OBSERVED {e['id']}  {e['control']}  — {e['why']}")
        if verdict == "NO_WORK_DONE":
            print("NOTHING WAS EXAMINED. This is a failure, not a clean run.")

    return 0 if verdict == "ALL_KILLED" else 1


if __name__ == "__main__":
    sys.exit(main())
