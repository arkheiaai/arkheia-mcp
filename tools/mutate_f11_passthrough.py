#!/usr/bin/env python3
"""
Mutation campaign for F11 — passthrough provider forwarding + SSRF path/header guard.

WHAT THIS ANSWERS
-----------------
The suites are green. That is a statement about the code, not about the suites.
This plants a fault the suites are *supposed* to catch and checks that they do.

FILES IT PLANTS FAULTS IN
-------------------------
    proxy/endpoints/passthrough.py          (the only one)

THE TIER MUST COVER EVERY FILE IT MUTATES. It does:

    proxy/tests/test_passthrough.py             (pre-existing)
    proxy/tests/test_passthrough_adversarial.py
    proxy/tests/test_passthrough_receipts.py
    proxy/tests/test_passthrough_wire.py
    tests/test_passthrough_ssrf_floor.py

BUCKETS — three, and only three
-------------------------------
Every trial is totalled against the baseline and lands in exactly one bucket.
"Not observed" is never folded into "killed":

  KILLED            the tier RAN and at least one test FAILED.
  KILLED_COLLECTION the tier could not import the mutated module at all. CI would
                    go red, so it is not a survivor — but no test OBSERVED the
                    behaviour, so it is reported separately and never summed into
                    KILLED.
  SURVIVED          the tier ran fully green against the fault.
  NOT_OBSERVED      the mutant could not be applied (pattern absent or ambiguous),
                    or the runner timed out. Nothing was learned. Reported by name.

An equivalent survivor is a defect in the MUTANT, not evidence about the suite:
withdraw it, replace it, and say so.

THE COUNTERFACTUAL
------------------
Each mutant is also run against the PRE-EXISTING suite alone
(``proxy/tests/test_passthrough.py``, unmodified from origin/master), so the
report can say what this branch's tests actually added rather than asserting it.

USAGE
-----
    .venv/bin/python tools/mutate_f11_passthrough.py            # full campaign
    .venv/bin/python tools/mutate_f11_passthrough.py --only M01
    .venv/bin/python tools/mutate_f11_passthrough.py --json out.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGET = REPO / "proxy" / "endpoints" / "passthrough.py"

NEW_TIER = [
    "proxy/tests/test_passthrough.py",
    "proxy/tests/test_passthrough_adversarial.py",
    "proxy/tests/test_passthrough_receipts.py",
    "proxy/tests/test_passthrough_wire.py",
    "tests/test_passthrough_ssrf_floor.py",
]
PREEXISTING_TIER = ["proxy/tests/test_passthrough.py"]

TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Mutant:
    mid: str
    what: str
    old: str
    new: str
    #: Which control this fault removes. Grouping only; never affects a verdict.
    area: str
    #: Further (old, new) pairs applied in the same trial. Used where two checks
    #: are deliberately redundant, so removing either alone is unobservable and a
    #: single-edit mutant would be equivalent.
    extra: tuple = ()


MUTANTS: list[Mutant] = [
    # -- path allowlist -----------------------------------------------------
    Mutant("M01", "restore the exact pre-fix `audio/.*` arm",
           r"|audio/(speech|transcriptions|translations)|moderations)\Z",
           r"|audio/.*|moderations)\Z", "allowlist"),
    Mutant("M02", "OpenAI allowlist end-anchor \\Z -> $",
           r'|audio/(speech|transcriptions|translations)|moderations)\Z"',
           r'|audio/(speech|transcriptions|translations)|moderations)$"', "allowlist"),
    Mutant("M03", "OpenAI allowlist start-anchor \\A -> ^",
           r'r"\A(chat/completions|completions',
           r'r"^(chat/completions|completions', "allowlist"),
    Mutant("M04", "Gemini allowlist end-anchor \\Z -> $",
           r'r"\Amodels(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?\Z"',
           r'r"\Amodels(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?$"', "allowlist"),
    Mutant("M05", "Anthropic allowlist end-anchor \\Z -> $",
           'r"\\A(messages|models)\\Z"', 'r"\\A(messages|models)$"', "allowlist"),
    # M06 WITHDRAWN — equivalent. `fullmatch` -> `match` is a no-op while every
    # pattern is \A..\Z anchored, so the mutant changes no observable behaviour
    # and a survival would say nothing about the suite. The anchoring itself is
    # what M02/M03 attack and floor INV-2 enforces. Replaced by M06R.
    Mutant("M06R", "every route screens against the OpenAI allowlist "
                   "(one shared regex widens three surfaces at once)",
           "    if not provider.path_re.fullmatch(path):",
           "    if not _OPENAI_PATH_RE.fullmatch(path):", "allowlist"),
    # M07 WITHDRAWN — equivalent by REDUNDANCY, which is a fact about the code
    # rather than the suite: the '..' marker and the raw-path segment check
    # overlap completely for every reachable input, so deleting either alone is
    # unobservable. Deliberate belt-and-braces; both are kept. M07R deletes BOTH.
    Mutant("M07R", "delete BOTH the '..' marker and the raw-path segment check",
           '_TRAVERSAL_MARKERS = ("..", "\\\\", "%2e"',
           '_TRAVERSAL_MARKERS = ("\\\\", "%2e"', "allowlist",
           extra=((
               '    if any(segment in (".", "..") for segment in path.split("/")):\n'
               "        return DENY_PATH_TRAVERSAL\n", ""),)),
    Mutant("M08", "drop percent-encoded dots from the traversal markers",
           '"%2e", "%2E", ', '', "allowlist"),
    Mutant("M09", "drop percent-encoded slashes from the traversal markers",
           '"%2f", "%2F", ', '', "allowlist"),
    # M10 WITHDRAWN — equivalent by REDUNDANCY: the backslash marker on the raw
    # path and the backslash check on the RESOLVED path overlap for every
    # reachable input. M10R deletes both.
    Mutant("M10R", "delete BOTH backslash checks (raw path and resolved path)",
           '_TRAVERSAL_MARKERS = ("..", "\\\\", ',
           '_TRAVERSAL_MARKERS = ("..", ', "allowlist",
           extra=((
               '    if "\\\\" in resolved_path:\n'
               "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", ""),)),
    Mutant("M11", "delete the '.'/'..' segment check on the raw path",
           '    if any(segment in (".", "..") for segment in path.split("/")):\n'
           '        return DENY_PATH_TRAVERSAL\n', '', "allowlist"),
    Mutant("M12", "delete the control-character check",
           "    if any(ch for ch in path if ord(ch) < 0x20 or ord(ch) == 0x7F):\n"
           "        return DENY_PATH_ILLEGAL_CHARACTER\n", "", "allowlist"),

    # -- resolved-URL post-condition ---------------------------------------
    Mutant("M13", "post-condition no longer compares the host",
           "    if parsed.host != provider.expected_host:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M14", "post-condition no longer compares the scheme",
           "    if parsed.scheme != provider.expected_scheme:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M15", "post-condition no longer compares the port",
           "    if parsed.port != provider.expected_port:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M16", "post-condition allows a smuggled query/fragment",
           "    if parsed.query or parsed.fragment:", "    if False:", "postcondition"),
    Mutant("M17", "post-condition no longer rejects decoded dot segments",
           '    if any(segment in (".", "..") for segment in resolved_path.split("/")):\n'
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M18", "post-condition no longer rejects a decoded backslash",
           '    if "\\\\" in resolved_path:\n'
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M19", "prefix test loses its trailing separator (prefix confusion)",
           'if not (resolved_path == base_path or resolved_path.startswith(base_path + "/")):',
           "if not (resolved_path == base_path or resolved_path.startswith(base_path)):",
           "postcondition"),
    Mutant("M20", "post-condition short-circuits: always resolve",
           "    candidate = f\"{provider.base}/{path}\"\n",
           "    candidate = f\"{provider.base}/{path}\"\n    return candidate, None\n",
           "postcondition"),

    # -- gate ordering and credentials -------------------------------------
    Mutant("M21", "gate no longer checks duplicate credential headers",
           "    dups = _duplicate_credential_headers(request)\n"
           "    if dups:\n"
           "        return None, DENY_DUPLICATE_CREDENTIAL\n", "", "credentials"),
    Mutant("M22", "duplicate detection needs three occurrences, not two",
           "return sorted(k for k, n in seen.items() if n > 1)",
           "return sorted(k for k, n in seen.items() if n > 2)", "credentials"),
    Mutant("M23", "no header is treated as a credential",
           '_CREDENTIAL_HEADERS = frozenset({"authorization", "x-api-key"})',
           "_CREDENTIAL_HEADERS = frozenset()", "credentials"),
    Mutant("M24", "cookie added to the upstream forward allowlist",
           '    "authorization",       # provider API key (Bearer token)\n',
           '    "authorization",       # provider API key (Bearer token)\n    "cookie",\n',
           "credentials"),
    Mutant("M25", "gate screens the path but ignores the verdict",
           "    deny = _screen_path(provider, path)\n    if deny:\n        return None, deny\n",
           "    deny = _screen_path(provider, path)\n", "credentials"),

    # -- response framing and hop-by-hop -----------------------------------
    Mutant("M26", "content-length no longer stripped (the framing desync)",
           '    "content-length",\n', "", "framing"),
    Mutant("M27", "proxy-authenticate no longer stripped",
           '    "proxy-authenticate",\n', "", "framing"),
    Mutant("M28", "upgrade no longer stripped",
           '    "upgrade",\n', "", "framing"),
    Mutant("M29", "content-encoding no longer stripped",
           '    "content-encoding",\n', "", "framing"),
    Mutant("M30", "Connection-nominated headers no longer honoured",
           "    connection_value = upstream_headers.get(\"connection\")\n"
           "    if connection_value:",
           "    connection_value = upstream_headers.get(\"connection\")\n"
           "    if False:", "framing"),
    Mutant("M31", "redirects are followed",
           "httpx.AsyncClient(timeout=60.0, follow_redirects=False)",
           "httpx.AsyncClient(timeout=60.0, follow_redirects=True)", "framing"),
    Mutant("M32", "redirect policy falls back to the library default",
           "httpx.AsyncClient(timeout=60.0, follow_redirects=False)",
           "httpx.AsyncClient(timeout=60.0)", "framing"),

    # -- receipts -----------------------------------------------------------
    Mutant("M33", "refusal receipt is never written",
           "    try:\n        await audit.write(record)\n",
           "    try:\n        pass\n", "receipts"),
    Mutant("M34", "refusal is filed as a pass",
           '"action_taken": "refuse",\n        "source": "passthrough",\n'
           '        "error": None,',
           '"action_taken": "pass",\n        "source": "passthrough",\n'
           '        "error": None,', "receipts"),
    Mutant("M35", "refusal is filed at a screened risk level",
           '"risk_level": REFUSAL_RISK_LEVEL,', '"risk_level": "LOW",', "receipts"),
    Mutant("M36", "the deny code is dropped from the record",
           '"deny_code": deny_code,\n        "attempted_path"',
           '"deny_code": None,\n        "attempted_path"', "receipts"),
    Mutant("M37", "header VALUES are recorded instead of key names",
           '"request_header_names": sorted({k.lower() for k in request.headers.keys()}),',
           '"request_header_names": sorted(set(request.headers.values())),', "receipts"),
    Mutant("M38", "the attempted path is no longer length-capped",
           '"attempted_path": attempted_path[:_MAX_RECORDED_PATH],',
           '"attempted_path": attempted_path,', "receipts"),
    Mutant("M39", "the refusal receipt is skipped entirely by _refuse",
           "    receipt_id, receipt_status = await _receipt_refusal(\n"
           "        request, provider, deny_code, attempted_path\n    )",
           '    receipt_id, receipt_status = str(uuid.uuid4()), "enqueued"',
           "receipts"),
    Mutant("M40", "the record's id field no longer matches the id handed out",
           '"detection_id": receipt_id,\n        "timestamp": datetime.now',
           '"detection_id": str(uuid.uuid4()),\n        "timestamp": datetime.now',
           "receipts"),
    Mutant("M41", "a refusal returns 200",
           "        status_code=400,\n        media_type=\"application/json\",\n"
           "        headers={\"X-Arkheia-Risk\": REFUSAL_RISK_LEVEL},",
           "        status_code=200,\n        media_type=\"application/json\",\n"
           "        headers={\"X-Arkheia-Risk\": REFUSAL_RISK_LEVEL},", "receipts"),
    Mutant("M42", "the refusal stops telling the caller what would clear it",
           '        body["allowed"] = list(provider.allowed)',
           '        body["allowed"] = []', "receipts"),
]


# ---------------------------------------------------------------------------

@dataclass
class Trial:
    mid: str
    what: str
    area: str
    bucket: str
    detail: str = ""
    failing_tests: list[str] = field(default_factory=list)
    preexisting_bucket: str = ""
    seconds: float = 0.0


def run_pytest(paths: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "-q", "-p", "no:cacheprovider",
         "--timeout=60", "--no-header", "-x" if False else "--tb=no"],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
        env=None,
    )
    return proc.returncode, proc.stdout + proc.stderr


def classify(returncode: int, output: str) -> tuple[str, list[str]]:
    failures = [ln.split(" ")[1] for ln in output.splitlines()
                if ln.startswith("FAILED ") and len(ln.split(" ")) > 1]
    if "ERROR collecting" in output or "INTERNALERROR" in output:
        return "KILLED_COLLECTION", failures
    if returncode == 0:
        return "SURVIVED", []
    if returncode == 5:
        return "NOT_OBSERVED", []
    return ("KILLED", failures) if failures else ("KILLED_COLLECTION", failures)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    original = TARGET.read_text(encoding="utf-8")

    print("=" * 78)
    print("BASELINE — the tier must be green before any fault is planted")
    print("=" * 78)
    rc, out = run_pytest(NEW_TIER)
    if rc != 0:
        print(out[-4000:])
        print("BASELINE IS NOT GREEN — aborting. Nothing below would mean anything.")
        return 2
    baseline_line = [ln for ln in out.splitlines() if " passed" in ln][-1]
    print(f"  new tier          : {baseline_line.strip()}")

    rc0, out0 = run_pytest(PREEXISTING_TIER)
    assert rc0 == 0, out0[-2000:]
    print(f"  pre-existing tier : "
          f"{[ln for ln in out0.splitlines() if ' passed' in ln][-1].strip()}")
    print()

    selected = [m for m in MUTANTS if not args.only or m.mid in args.only]
    trials: list[Trial] = []

    try:
        for mutant in selected:
            started = time.monotonic()
            pairs = ((mutant.old, mutant.new),) + tuple(mutant.extra)
            counts = [original.count(old) for old, _ in pairs]
            if any(c != 1 for c in counts):
                trials.append(Trial(
                    mutant.mid, mutant.what, mutant.area, "NOT_OBSERVED",
                    detail=f"anchors matched {counts}, each must match exactly 1 — "
                           f"the fault was never planted, so nothing was learned",
                ))
                print(f"  {mutant.mid}  NOT_OBSERVED  (anchors {counts})  {mutant.what}")
                continue

            mutated = original
            for old, new in pairs:
                mutated = mutated.replace(old, new)
            assert mutated != original
            TARGET.write_text(mutated, encoding="utf-8")
            try:
                rc, out = run_pytest(NEW_TIER)
                bucket, failures = classify(rc, out)
                rc_old, out_old = run_pytest(PREEXISTING_TIER)
                pre_bucket, _ = classify(rc_old, out_old)
            except subprocess.TimeoutExpired:
                bucket, failures, pre_bucket = "NOT_OBSERVED", [], "NOT_OBSERVED"
                out = "runner timed out"
            finally:
                TARGET.write_text(original, encoding="utf-8")

            trials.append(Trial(
                mutant.mid, mutant.what, mutant.area, bucket,
                detail="" if bucket != "SURVIVED" else "tier fully green against the fault",
                failing_tests=failures[:6],
                preexisting_bucket=pre_bucket,
                seconds=round(time.monotonic() - started, 1),
            ))
            marker = {"KILLED": "kill", "SURVIVED": "SURVIVED **",
                      "KILLED_COLLECTION": "kill(collect)",
                      "NOT_OBSERVED": "NOT_OBSERVED"}[bucket]
            print(f"  {mutant.mid}  {marker:<14} old-tier={pre_bucket:<18} {mutant.what}")
    finally:
        TARGET.write_text(original, encoding="utf-8")

    # Post-campaign baseline: prove the target was restored byte-for-byte.
    assert TARGET.read_text(encoding="utf-8") == original, "target not restored"
    rc, out = run_pytest(NEW_TIER)
    restored_green = rc == 0

    totals = {b: sum(1 for t in trials if t.bucket == b)
              for b in ("KILLED", "KILLED_COLLECTION", "SURVIVED", "NOT_OBSERVED")}
    scored = totals["KILLED"] + totals["KILLED_COLLECTION"] + totals["SURVIVED"]

    print()
    print("=" * 78)
    print("TOTALS — every trial accounted for, against the baseline")
    print("=" * 78)
    print(f"  planted           : {len(selected)}")
    print(f"  KILLED            : {totals['KILLED']}")
    print(f"  KILLED_COLLECTION : {totals['KILLED_COLLECTION']}   "
          f"(CI red, but no test observed the behaviour — NOT summed into KILLED)")
    print(f"  SURVIVED          : {totals['SURVIVED']}")
    print(f"  NOT_OBSERVED      : {totals['NOT_OBSERVED']}")
    print(f"  scored            : {scored} of {len(selected)}")
    print(f"  baseline restored green : {restored_green}")

    not_observed = [t for t in trials if t.bucket == "NOT_OBSERVED"]
    if not_observed:
        print("\n  NOT OBSERVED — named, never summarised:")
        for t in not_observed:
            print(f"    {t.mid}  {t.what}\n        {t.detail}")

    survivors = [t for t in trials if t.bucket == "SURVIVED"]
    if survivors:
        print("\n  ** SURVIVORS — each is either a hole in the suite or a defect "
              "in the mutant:")
        for t in survivors:
            print(f"    {t.mid}  {t.what}")

    print("\n  COUNTERFACTUAL — same faults against the PRE-EXISTING suite alone:")
    counter = {}
    for t in trials:
        counter[t.preexisting_bucket] = counter.get(t.preexisting_bucket, 0) + 1
    for bucket, n in sorted(counter.items()):
        print(f"    {bucket or '(not run)':<18} {n}")
    would_have_survived = [t.mid for t in trials
                           if t.preexisting_bucket == "SURVIVED"]
    print(f"    mutants the pre-existing suite would NOT have caught: "
          f"{len(would_have_survived)} — {', '.join(would_have_survived)}")

    verdict = (
        "CLEAN" if (totals["SURVIVED"] == 0 and totals["NOT_OBSERVED"] == 0
                    and scored == len(selected) and restored_green and selected)
        else "INCOMPLETE"
    )
    print(f"\n  VERDICT: {verdict}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "verdict": verdict,
            "interpreter": sys.version,
            "mutated_files": [str(TARGET.relative_to(REPO))],
            "tier": NEW_TIER,
            "preexisting_tier": PREEXISTING_TIER,
            "totals": {**totals, "planted": len(selected), "scored": scored},
            "baseline_restored_green": restored_green,
            "not_observed": [t.mid for t in not_observed],
            "survivors": [t.mid for t in survivors],
            "counterfactual_survived_preexisting": would_have_survived,
            "trials": [vars(t) for t in trials],
        }, indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")

    return 0 if verdict == "CLEAN" else 1


if __name__ == "__main__":
    sys.exit(main())
