#!/usr/bin/env python3
"""
Mutation campaign for F7 — false-positive suppression gates.

WHY
---
Every suite in this flow was written by the same agent that wrote the fix, so "the tests
pass" is a statement about agreement, not about fault detection. This plants each defect
back, one at a time, and requires a NAMED test to notice.

WHAT IT MUTATES
---------------
Three production files and one contract file:

    proxy/detection/features.py      the gates themselves
    proxy/detection/engine.py        the marker's first carry-through
    proxy/endpoints/detect.py        the three consumer boundaries
    tests/test_suppression_surface_floor.py   the floor's own declarations

THE TIER INCLUDES EVERY FILE IT PLANTS FAULTS IN, which is the point: mutating detect.py
while running only the gate unit tests would score a hole as covered.

    proxy/tests/test_suppression_gates_adversarial.py
    proxy/tests/test_suppression_surface_parity.py
    proxy/tests/test_suppression_receipts.py
    tests/test_suppression_surface_floor.py          (stdlib floor tier)

BUCKETS — three, and NOT-OBSERVED is never folded into KILLED
-------------------------------------------------------------
    KILLED           the mutant's OWN expected killer failed, and the run is otherwise
                     accounted for against the baseline
    KILLED_BY_OTHER  the tier went red but the expected killer did not; reported
                     separately, because it means the suite noticed by accident
    SURVIVED         the tier stayed green
    NOT_OBSERVED     the anchor did not appear exactly once (unplantable), or the tier
                     could not COLLECT the mutant. A collection error makes CI red while
                     observing nothing about behaviour, so it is its own bucket — a
                     crashing mutant must never be banked as coverage.

EVERY TRIAL IS TOTALLED AGAINST THE BASELINE. The baseline set of failing node ids is
captured first and subtracted from every trial, so a mutant that takes down five
unrelated tests is visible as collateral rather than as a clean kill.

COUNTERFACTUAL
--------------
`--counterfactual` re-runs the same mutants against ONLY the suites that existed on
origin/master, answering the question that matters: could this defect have been
introduced with the whole pre-existing suite green?

USAGE
    python3.12 tools/mutate_f7_suppression.py [--counterfactual] [--only M07,M12]

Run it on the CI interpreter (3.12), not the local default.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

FEATURES = "proxy/detection/features.py"
ENGINE = "proxy/detection/engine.py"
DETECT = "proxy/endpoints/detect.py"
FLOOR = "tests/test_suppression_surface_floor.py"

TIER = [
    "proxy/tests/test_suppression_gates_adversarial.py",
    "proxy/tests/test_suppression_surface_parity.py",
    "proxy/tests/test_suppression_receipts.py",
    FLOOR,
]

#: The suites that existed on origin/master @ 3037f0c and touch this code at all.
COUNTERFACTUAL_TIER = [
    "proxy/tests/test_empty_output_gate.py",
    "proxy/tests/test_detect.py",
    "proxy/tests/test_failure_modes.py",
    "proxy/tests/test_e2e.py",
    "tests/test_detection_adapter.py",
    "tests/test_proxy_client.py",
    "tests/test_audit_floor.py",
]


@dataclasses.dataclass
class Mutant:
    id: str
    file: str
    anchor: str
    replacement: str
    killer: str          # substring of the node id that MUST fail
    note: str


M = Mutant
MUTANTS: list[Mutant] = [
    # ---- _usable_count: the validator that stops a corrupt signal buying silence ----
    M("M01", FEATURES,
      "if math.isnan(v) or math.isinf(v) or v < 0:",
      "if math.isinf(v) or v < 0:",
      "test_nan_must_not_buy_a_suppression",
      "NaN passes validation again -> every comparison False -> suppress"),
    # M02 (ROUND 1) WITHDRAWN — it was a DEFECT IN THE MUTANT, not a hole in the suite.
    # It deleted only `math.isinf(v)`, and that arm is provably redundant at both call
    # sites: -inf is already refused by `v < 0`, and +inf falls out of `ot >= 1` in the
    # empty-output gate and out of `inf < max_tokens` in the mode gate. Nothing
    # observable changes, so no test could kill it. `math.isinf` is deliberate belt-and-
    # braces (it stops being redundant the moment a caller compares in the other
    # direction). Replaced by the COMPOUND mutant below, which deletes both arms of the
    # pair and therefore plants a real, observable defect.
    M("M02", FEATURES,
      "    if math.isnan(v) or math.isinf(v) or v < 0:\n        return None\n    return v",
      "    if math.isnan(v):\n        return None\n    return v",
      "test_negative_infinity_must_not_buy_a_suppression",
      "COMPOUND (replaces the withdrawn round-1 M02): deletes BOTH the isinf and the "
      "v<0 arms, so -inf and every negative count buy a suppression again"),
    M("M03", FEATURES,
      "    if math.isnan(v) or math.isinf(v) or v < 0:\n        return None\n",
      "    if math.isnan(v) or math.isinf(v):\n        return None\n",
      "test_negative_count_must_not_buy_a_suppression",
      "a negative count buys a suppression again"),
    M("M04", FEATURES,
      "if value is None or isinstance(value, bool):",
      "if value is None:",
      "test_bool_false_must_not_buy_a_suppression",
      "bool is an int subclass -> False coerces to 0.0 -> suppress"),
    M("M05", FEATURES,
      "    except (TypeError, ValueError):\n        return None\n    if math.isnan(v)",
      "    except (TypeError, ValueError):\n        return 0.0\n    if math.isnan(v)",
      "test_unparseable_carries_on",
      "an unparseable value becomes 0.0 and suppresses"),

    # ---- _is_flag_set: truthiness was the vector ----
    M("M06", FEATURES,
      "    if value is True:\n        return True",
      "    if value:\n        return True",
      "test_truthy_non_boolean_is_function_call_must_not_buy_a_suppression",
      'the string "false" fires the function-call arm again'),
    M("M07", FEATURES,
      "    return isinstance(value, int) and not isinstance(value, bool) and value == 1",
      "    return bool(value)",
      "test_truthy_non_boolean_is_function_call_must_not_buy_a_suppression",
      "same vector via the numeric arm"),
    M("M08", FEATURES,
      'if _is_flag_set(signals.get("is_function_call")):',
      'if signals.get("is_function_call", False):',
      "test_truthy_non_boolean_is_function_call_must_not_buy_a_suppression",
      "the verbatim pre-fix call site"),

    # ---- empty-output gate ----
    M("M09", FEATURES,
      "    if ot >= 1:\n        return None",
      "    if ot > 1:\n        return None",
      "test_at_or_above_one_carries_on",
      "BOUNDARY: exactly 1 output token now suppresses"),
    M("M10", FEATURES,
      "    if ot >= 1:\n        return None\n\n    features_config",
      "    if ot >= 0:\n        return None\n\n    features_config",
      "test_zero_suppresses",
      "the gate never fires - under-suppression, the cry-wolf direction"),
    M("M11", FEATURES,
      '        "gate_action": "advise",\n        "evidence_depth_limited": True,\n'
      '        "model_detected": profile.get("model", "unknown"),\n'
      '        "detection_method": "empty_output_suppressed",',
      '        "gate_action": "block",\n        "evidence_depth_limited": True,\n'
      '        "model_detected": profile.get("model", "unknown"),\n'
      '        "detection_method": "empty_output_suppressed",',
      "test_empty_output_suppression_states_advise",
      "a suppression claims block authority"),
    M("M12", FEATURES,
      '"detection_method": "empty_output_suppressed",',
      '"detection_method": "profile_ensemble",',
      "test_every_gate_method_is_in_the_closed_set",
      "a suppression disguises itself as a scored verdict"),
    M("M13", FEATURES,
      '            "gate_reason": SUPPRESSION_REASON_EMPTY_OUTPUT,',
      '            "gate_reason": None,',
      "test_zero_suppresses",
      "LIES IN THE VALUE: key present, marker null. The static floor cannot see this."),
    M("M14", FEATURES,
      '            "computed_features": {},\n'
      '            "gate_reason": SUPPRESSION_REASON_EMPTY_OUTPUT,\n',
      '            "computed_features": {},\n',
      "test_inv1_every_gate_return_carries_the_required_keys",
      "DELETES THE KEY: the static floor sees this one, paired with M13."),

    # ---- mode gate ----
    M("M15", FEATURES,
      "        if token_count is not None and token_count < max_tokens:",
      "        if token_count is None or token_count < max_tokens:",
      "test_absent_token_count_carries_on",
      "an ABSENT token_count now suppresses - the widest over-suppression there is"),
    M("M16", FEATURES,
      "        if token_count is not None and token_count < max_tokens:",
      "        if token_count is not None and token_count <= max_tokens:",
      "test_boundary_exactly_at_threshold_is_scored_not_suppressed",
      "BOUNDARY: the threshold value itself is suppressed"),
    M("M17", FEATURES,
      '        token_count = _usable_count(signals.get("token_count"))',
      '        token_count = signals.get("token_count", float("inf"))',
      "test_inv6_no_gate_compares_a_raw_get_result",
      "the verbatim pre-fix crash shape. ROUND 1 returned KILLED_BY_OTHER: the runtime "
      "tests caught it but INV-6 did not, because INV-6 only looked at INLINE .get() "
      "operands and this mutant binds a local first. INV-6 now taints locals bound "
      "directly to a .get() result, restricted to ORDERED operators so an equality "
      "check is not a false positive."),
    M("M18", FEATURES,
      "        max_tokens = _usable_count(raw_max)",
      "        max_tokens = raw_max",
      "test_unusable_profile_threshold_must_not_crash_the_gate",
      "a malformed profile threshold crashes the classifier again"),
    M("M19", FEATURES,
      "        # See check_empty_output_gate: a suppression can never carry block "
      "authority.\n        \"gate_action\": \"advise\",",
      "        # See check_empty_output_gate: a suppression can never carry block "
      "authority.\n        \"gate_action\": \"block\",",
      "test_mode_gate_suppression_states_advise",
      "a mode-gate suppression claims block authority"),
    M("M20", FEATURES,
      '"detection_method": "tool_surface_suppressed",',
      '"detection_method": "profile_ensemble",',
      "test_every_gate_method_is_in_the_closed_set",
      "the mode gate disguises itself as a scored verdict"),
    M("M21", FEATURES,
      '    action = tool_cfg.get("action", "suppress")\n    if action != "suppress":\n'
      "        return None",
      '    action = tool_cfg.get("action", "suppress")\n    if False:\n'
      "        return None",
      "test_non_suppress_action_never_suppresses",
      "a profile that asked NOT to suppress is suppressed anyway"),
    M("M22", FEATURES,
      '    if not mode_gate.get("enabled", False):\n        return None',
      "    if False:\n        return None",
      "test_gate_disabled_never_suppresses",
      "a disabled gate fires"),

    # ---- the closed vocabulary and its predicate ----
    M("M23", FEATURES,
      "    if not isinstance(reason, str) or not reason:\n        return False",
      "    if reason is None:\n        return False",
      "test_a_non_string_is_rejected_and_does_not_raise",
      "is_suppression_reason accepts non-strings and then raises AttributeError on "
      ".startswith. ROUND 1: SURVIVED — a real hole in the suite, not in the mutant. "
      "Every case in the free-text test was a str or None, so the isinstance guard was "
      "never exercised. Closed by a parametrised non-string case."),
    M("M24", FEATURES,
      "    return bool(suffix) and _usable_count(suffix) is not None",
      "    return True",
      "test_free_text_is_not_a_suppression_reason",
      "the prefix arm accepts any suffix, so free text is a valid reason"),
    M("M25", FEATURES,
      'SUPPRESSED_DETECTION_METHODS = ("empty_output_suppressed", '
      '"tool_surface_suppressed")',
      "SUPPRESSED_DETECTION_METHODS = ()",
      "test_inv2_every_gate_method_is_in_the_declared_closed_set",
      "ATTACKS THE DERIVATION: the closed taxonomy goes quiet"),

    # ---- gate ordering ----
    M("M26", FEATURES,
      "    empty_result = check_empty_output_gate(profile, signals)\n"
      "    if empty_result is not None:\n        return empty_result",
      "    empty_result = None\n"
      "    if empty_result is not None:\n        return empty_result",
      "test_runs_before_the_mode_gate",
      "the empty-output gate is skipped entirely inside classify_with_profile"),

    # ---- engine.py: the marker's first carry-through ----
    M("M27", ENGINE,
      '            gate_reason=(result.get("metrics") or {}).get("gate_reason"),\n',
      "",
      "test_inv4_the_marker_reaches_all_six_boundaries",
      "DELETES the kwarg: the static floor sees it"),
    M("M28", ENGINE,
      '            gate_reason=(result.get("metrics") or {}).get("gate_reason"),',
      "            gate_reason=None,",
      "test_the_suppression_reason_reaches_the_caller",
      "LIES IN THE VALUE: floor stays green, only a runtime test sees it. Pairs M27."),

    # ---- detect.py: the three consumer boundaries, each as a delete/lie pair ----
    M("M29", DETECT,
      '        gate_reason=getattr(result, "gate_reason", None),\n',
      "",
      "test_inv4_the_marker_reaches_all_six_boundaries",
      "DELETES the caller-surface kwarg"),
    M("M30", DETECT,
      '        gate_reason=getattr(result, "gate_reason", None),',
      "        gate_reason=None,",
      "test_the_suppression_reason_reaches_the_caller",
      "LIES to the caller. Pairs M29."),
    M("M31", DETECT,
      '        "gate_reason": response.gate_reason,\n'
      '        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),\n'
      '        "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),\n'
      '        "response_length": len(req.response),',
      '        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),\n'
      '        "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),\n'
      '        "response_length": len(req.response),',
      "test_inv4_the_marker_reaches_all_six_boundaries",
      "DELETES the marker from the FORENSIC record"),
    M("M32", DETECT,
      '        "gate_reason": response.gate_reason,\n'
      '        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),\n'
      '        "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),\n'
      '        "response_length": len(req.response),',
      '        "gate_reason": None,\n'
      '        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),\n'
      '        "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),\n'
      '        "response_length": len(req.response),',
      "test_the_row_names_the_gate_and_the_threshold",
      "LIES on the durable rail: the record says 'screened, and clean'. Pairs M31."),
    M("M33", DETECT,
      '            "gate_reason": response.gate_reason,\n'
      '            "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),',
      '            "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),',
      "test_inv4_the_marker_reaches_all_six_boundaries",
      "DELETES the marker from the governance push"),
    M("M34", DETECT,
      '            "gate_reason": response.gate_reason,\n'
      '            "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),',
      '            "gate_reason": None,\n'
      '            "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),',
      "test_the_pushed_body_carries_the_reason",
      "LIES on the governance wire. Pairs M33."),

    # ---- attacks on the floor's own contract ----
    M("M35", FLOOR,
      "REQUIRED_GATE_KEYS = {\n"
      '    "risk", "confidence", "gate_action", "evidence_depth_limited",\n'
      '    "detection_method", "metrics",\n}',
      "REQUIRED_GATE_KEYS = set()",
      "test_inv0_the_contract_this_floor_checks_against_has_not_gone_quiet",
      "ATTACKS THE DERIVATION: INV-1 would pass over nothing"),
    M("M36", FLOOR,
      'REQUIRED_GATE_METRIC_KEYS = {"features_used", "gate_reason"}',
      "REQUIRED_GATE_METRIC_KEYS = set()",
      "test_inv0_the_contract_this_floor_checks_against_has_not_gone_quiet",
      "ATTACKS THE DERIVATION: the metrics half of INV-1 goes quiet"),
    M("M37", FLOOR,
      'GATE_NAME_RE = re.compile(r"^check_[a-z0-9_]+_gate$")',
      'GATE_NAME_RE = re.compile(r"^__never_matches__$")',
      "test_inv0",
      "ATTACKS THE DERIVATION: discovery finds no gates, so every gate invariant "
      "passes vacuously"),
]


# ---------------------------------------------------------------------------

FAIL_RE = re.compile(r"^(FAILED|ERROR) (\S+)", re.M)
SUMMARY_RE = re.compile(r"^(\d+) failed", re.M)


def run_tier(python: str, tier: list[str]) -> tuple[int, set[str], str]:
    """Return (exit_code, failing_node_ids, tail_of_output)."""
    proc = subprocess.run(
        [python, "-m", "pytest", *tier, "-q", "-p", "no:cacheprovider",
         "--timeout=120", "--no-header"],
        cwd=ROOT, capture_output=True, text=True,
        env={**__import__("os").environ,
             "JWT_SECRET": "ci-test-secret-not-for-production-use-minimum-32chars!!"},
    )
    out = proc.stdout + proc.stderr
    failing = {m.group(2) for m in FAIL_RE.finditer(out)}
    return proc.returncode, failing, out[-1500:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--counterfactual", action="store_true")
    ap.add_argument("--only", default="")
    ap.add_argument("--python", default=sys.executable)
    args = ap.parse_args()

    tier = COUNTERFACTUAL_TIER if args.counterfactual else TIER
    tier = [t for t in tier if (ROOT / t).exists()]
    selected = [m for m in MUTANTS
                if not args.only or m.id in args.only.split(",")]

    print(f"interpreter : {args.python}")
    print(f"tier        : {' '.join(tier)}")
    print(f"mutants     : {len(selected)}")

    print("\n== BASELINE ==")
    code, baseline_fail, tail = run_tier(args.python, tier)
    print(f"exit={code} failing={len(baseline_fail)}")
    if code != 0 and not args.counterfactual:
        print(tail)
        print("BASELINE IS NOT GREEN — every number below would be meaningless.")
        return 2

    originals = {f: (ROOT / f).read_text(encoding="utf-8")
                 for f in {m.file for m in selected}}
    results = []
    try:
        for m in selected:
            src = originals[m.file]
            n = src.count(m.anchor)
            if n != 1:
                results.append((m, "NOT_OBSERVED", f"anchor matched {n} times", set()))
                print(f"{m.id} NOT_OBSERVED (anchor x{n})")
                continue
            (ROOT / m.file).write_text(src.replace(m.anchor, m.replacement, 1),
                                       encoding="utf-8")
            t0 = time.time()
            code, failing, tail = run_tier(args.python, tier)
            (ROOT / m.file).write_text(src, encoding="utf-8")

            new_fail = failing - baseline_fail
            collection_error = ("error" in tail.lower() and not failing) or code == 4
            if collection_error:
                bucket = "NOT_OBSERVED"
                detail = "tier could not collect the mutant (CI red, nothing observed)"
            elif code == 0:
                bucket, detail = "SURVIVED", "tier stayed green"
            elif any(m.killer in nid for nid in new_fail):
                bucket = "KILLED"
                detail = f"{len(new_fail)} new failure(s)"
            else:
                bucket = "KILLED_BY_OTHER"
                detail = (f"expected killer {m.killer!r} did NOT fail; "
                          f"new failures: {sorted(new_fail)[:4]}")
            results.append((m, bucket, detail, new_fail))
            print(f"{m.id} {bucket:<16} {time.time()-t0:5.1f}s  {detail}")
    finally:
        for f, src in originals.items():
            (ROOT / f).write_text(src, encoding="utf-8")

    counts: dict[str, int] = {}
    for _, b, _, _ in results:
        counts[b] = counts.get(b, 0) + 1

    print("\n== TOTALS ==")
    scored = counts.get("KILLED", 0) + counts.get("KILLED_BY_OTHER", 0) + \
        counts.get("SURVIVED", 0)
    for b in ("KILLED", "KILLED_BY_OTHER", "SURVIVED", "NOT_OBSERVED"):
        print(f"  {b:<16} {counts.get(b, 0)}")
    print(f"  planted          {len(selected)}")
    print(f"  scored           {scored}   (NOT_OBSERVED is NOT a pass)")
    if counts.get("SURVIVED"):
        print("\nSURVIVORS:")
        for m, b, d, _ in results:
            if b == "SURVIVED":
                print(f"  {m.id} {m.file}: {m.note}")
    if counts.get("NOT_OBSERVED"):
        print("\nNOT OBSERVED (named, never summarised):")
        for m, b, d, _ in results:
            if b == "NOT_OBSERVED":
                print(f"  {m.id} {m.file}: {d}")

    verdict = "ALL_KILLED" if scored == len(selected) and \
        counts.get("SURVIVED", 0) == 0 and counts.get("NOT_OBSERVED", 0) == 0 \
        else "INCOMPLETE"
    summary = {
        "verdict": verdict,
        "mode": "counterfactual" if args.counterfactual else "own_tier",
        "tier": tier,
        "planted": len(selected),
        "scored": scored,
        "totals": counts,
        "survivors": [m.id for m, b, _, _ in results if b == "SURVIVED"],
        "not_observed": [m.id for m, b, _, _ in results if b == "NOT_OBSERVED"],
    }
    print("\n" + json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
