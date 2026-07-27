#!/usr/bin/env python3
"""
Mutation campaign for F10 — /v1/* interception block/warn enforcement.

WHAT THIS ANSWERS
-----------------
The suites are green. That is a statement about the code, not about the suites.
This plants a fault the suites are *supposed* to catch and checks that they do.

FILES IT PLANTS FAULTS IN
-------------------------
    proxy/middleware/interception.py        (the only one)

THE TIER MUST COVER EVERY FILE IT MUTATES. It does:

    proxy/tests/test_interception.py             (pre-existing)
    proxy/tests/test_interception_correctness.py
    proxy/tests/test_interception_receipts.py
    proxy/tests/test_interception_wire.py
    tests/test_interception_ssrf_floor.py

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
  NOT_OBSERVED      the mutant could not be applied (anchor absent or ambiguous),
                    or the runner timed out. Nothing was learned. Named, never
                    summarised.

An equivalent survivor is a defect in the MUTANT, not evidence about the suite:
withdraw it, replace it, and say so.

THE COUNTERFACTUAL, AND THE HONEST COMPLICATION IN IT
-----------------------------------------------------
Each mutant is also run against the PRE-EXISTING suite alone — the
``proxy/tests/test_interception.py`` that sits on ``origin/master``, extracted
at runtime so the comparison is against the real prior state and not against
this branch's edited copy.

That prior suite is NOT green against this branch's module: one test
(``test_high_risk_warn_prepends_warning``) asserts the banner-prepend this
sweep deliberately removed. So its failures are diffed against a recorded
baseline, and a mutant counts as caught by the old suite only when it produces
a failure the baseline did not already have. Ignoring that would credit the old
suite with catching all fifty.

USAGE
-----
    .venv312/bin/python tools/mutate_f10_interception.py
    .venv312/bin/python tools/mutate_f10_interception.py --only M01 M02
    .venv312/bin/python tools/mutate_f10_interception.py --json out.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGET = REPO / "proxy" / "middleware" / "interception.py"

NEW_TIER = [
    "proxy/tests/test_interception.py",
    "proxy/tests/test_interception_correctness.py",
    "proxy/tests/test_interception_receipts.py",
    "proxy/tests/test_interception_wire.py",
    "tests/test_interception_ssrf_floor.py",
]

#: Materialised at runtime from origin/master so the counterfactual is against
#: the prior state, not this branch's edited copy.
PREEXISTING_SRC = "proxy/tests/test_interception.py"
PREEXISTING_TMP = REPO / "proxy" / "tests" / "test_zz_preexisting_baseline_tmp.py"

TIMEOUT_SECONDS = 420


@dataclass(frozen=True)
class Mutant:
    mid: str
    what: str
    old: str
    new: str
    #: Which control this fault removes. Grouping only; never affects a verdict.
    area: str
    #: Further (old, new) pairs applied in the same trial. Used where two checks
    #: are deliberately independent, so a single-edit mutant would be equivalent.
    extra: tuple = ()


MUTANTS: list[Mutant] = [
    # -- destination post-condition ----------------------------------------
    Mutant("M01", "_confine stops checking the scheme",
           "    if target.scheme != base.scheme:\n"
           "        raise InterceptionRefusal(\"path_escapes_prefix\", prefix=INTERCEPT_PREFIX)\n",
           "", "confine"),
    Mutant("M02", "_confine stops checking the host",
           "    if target.host != base.host:\n"
           "        raise InterceptionRefusal(\"path_escapes_prefix\", prefix=INTERCEPT_PREFIX)\n",
           "", "confine"),
    Mutant("M03", "_confine stops checking the port",
           "    if target.port != base.port:\n"
           "        raise InterceptionRefusal(\"path_escapes_prefix\", prefix=INTERCEPT_PREFIX)\n",
           "", "confine"),
    Mutant("M04", "_confine stops comparing userinfo against the configured base",
           "    if target.userinfo != base.userinfo:\n"
           "        raise InterceptionRefusal(\"path_escapes_prefix\", prefix=INTERCEPT_PREFIX)\n",
           "", "confine"),
    Mutant("M05", "prefix confinement weakened from startswith to substring",
           "    if not target.path.startswith(expected_prefix):",
           "    if expected_prefix not in target.path:", "confine"),
    Mutant("M06", "confinement ignores the configured base path",
           "    expected_prefix = base.path.rstrip(\"/\") + INTERCEPT_PREFIX",
           "    expected_prefix = INTERCEPT_PREFIX", "confine"),
    Mutant("M07", "the post-condition is never run",
           "    _confine(target, base)\n    return target",
           "    return target", "confine"),
    Mutant("M08", "file:// and gopher:// become forwardable upstreams",
           'ALLOWED_UPSTREAM_SCHEMES = frozenset({"http", "https"})',
           'ALLOWED_UPSTREAM_SCHEMES = frozenset({"http", "https", "file", "gopher"})',
           "confine"),
    Mutant("M09", "the upstream scheme is never validated",
           "    if base.scheme not in ALLOWED_UPSTREAM_SCHEMES:\n"
           "        raise InterceptionRefusal(\"upstream_scheme_not_allowed\")\n",
           "", "confine"),
    Mutant("M10", "the gate authorises on a prefix it does not enforce",
           "INTERCEPT_PREFIX = \"/v1/\"", "INTERCEPT_PREFIX = \"/\"", "confine"),

    # -- raw-path pre-condition --------------------------------------------
    Mutant("M11", "encoded slash %2f is no longer refused",
           'UNSAFE_PATH_MARKERS = ("%2f", "%5c", "%2e", "\\\\", "\\x00")',
           'UNSAFE_PATH_MARKERS = ("%5c", "%2e", "\\\\", "\\x00")', "rawpath"),
    Mutant("M12", "backslash is no longer refused",
           'UNSAFE_PATH_MARKERS = ("%2f", "%5c", "%2e", "\\\\", "\\x00")',
           'UNSAFE_PATH_MARKERS = ("%2f", "%5c", "%2e", "\\x00")', "rawpath"),
    Mutant("M13", "encoded dot %2e is no longer refused",
           'UNSAFE_PATH_MARKERS = ("%2f", "%5c", "%2e", "\\\\", "\\x00")',
           'UNSAFE_PATH_MARKERS = ("%2f", "%5c", "\\\\", "\\x00")', "rawpath"),
    Mutant("M14", "the raw-path pre-condition is never run",
           "        _check_raw_path(request.url.path)\n", "", "rawpath"),
    Mutant("M15", "marker matching becomes case-sensitive (%2F survives)",
           "    lowered = path.lower()", "    lowered = path", "rawpath"),

    # -- forward headers ----------------------------------------------------
    Mutant("M16", "hop-by-hop headers are relayed on the FORWARD leg",
           "        if lowered in HOP_BY_HOP_HEADERS:\n            continue\n"
           "        if lowered in REQUEST_OWNED_HEADERS:",
           "        if lowered in REQUEST_OWNED_HEADERS:", "headers"),
    Mutant("M17", "proxy-authenticate is relayed to the provider",
           '    "proxy-authenticate",\n    "proxy-authorization",\n'
           '    "proxy-connection",\n',
           '    "proxy-authorization",\n    "proxy-connection",\n', "headers"),
    Mutant("M18", "upgrade is relayed to the provider",
           '    "transfer-encoding",\n    "upgrade",\n', '    "transfer-encoding",\n',
           "headers"),
    Mutant("M19", "Connection-nominated headers are relayed past their hop",
           "        if lowered in REQUEST_OWNED_HEADERS:\n            continue\n"
           "        if lowered in nominated:\n            continue\n",
           "        if lowered in REQUEST_OWNED_HEADERS:\n            continue\n",
           "headers"),
    Mutant("M20", "duplicate credential headers are tolerated again",
           "            if seen_credentials[lowered] > 1:",
           "            if seen_credentials[lowered] > 99:", "headers"),
    Mutant("M21", "Authorization is dropped from the single-valued set",
           '    "authorization",\n    "proxy-authorization",\n    "x-api-key",',
           '    "proxy-authorization",\n    "x-api-key",', "headers"),
    Mutant("M22", "the exact pre-fix header build: a dict, last occurrence wins",
           "    nominated = _nominated_hop_headers(headers)",
           "    return [(k, v) for k, v in {\n"
           "        k2: v2 for k2, v2 in headers.items() if k2.lower() != 'host'\n"
           "    }.items()]\n    nominated = _nominated_hop_headers(headers)", "headers"),
    Mutant("M23", "the caller's content-length is forwarded alongside httpx's",
           'REQUEST_OWNED_HEADERS = frozenset({"host", "content-length"})',
           'REQUEST_OWNED_HEADERS = frozenset({"host"})', "headers"),

    # -- response relay / framing ------------------------------------------
    Mutant("M24", "content-length is relayed over an httpx-decoded body",
           'RESPONSE_OWNED_HEADERS = frozenset({"content-length", "content-encoding"})',
           'RESPONSE_OWNED_HEADERS = frozenset({"content-encoding"})', "framing"),
    Mutant("M25", "content-encoding is relayed over an httpx-decoded body",
           'RESPONSE_OWNED_HEADERS = frozenset({"content-length", "content-encoding"})',
           'RESPONSE_OWNED_HEADERS = frozenset({"content-length"})', "framing"),
    Mutant("M26", "hop-by-hop response headers are relayed to the caller",
           "        if lowered in HOP_BY_HOP_HEADERS:\n            continue\n"
           "        if lowered in RESPONSE_OWNED_HEADERS:\n            continue\n",
           "        if lowered in RESPONSE_OWNED_HEADERS:\n            continue\n",
           "framing"),
    Mutant("M27", "every upstream status is reported to the caller as 200",
           "    response = Response(content=body, status_code=status_code)",
           "    response = Response(content=body, status_code=200)", "framing"),
    Mutant("M28", "relayed response headers are dropped (content-type included)",
           "    extra = [(k.lower().encode(\"latin-1\"), v.encode(\"latin-1\"))\n"
           "             for k, v in relayed\n"
           "             if k.lower() not in RESPONSE_OWNED_HEADERS]",
           "    extra = []", "framing"),
    Mutant("M29", "redirects are followed",
           "httpx.AsyncClient(follow_redirects=False)",
           "httpx.AsyncClient(follow_redirects=True)", "framing"),
    Mutant("M30", "redirect policy falls back to the library default",
           "httpx.AsyncClient(follow_redirects=False)", "httpx.AsyncClient()",
           "framing"),

    # -- fail-open ----------------------------------------------------------
    Mutant("M31", "a detector crash serves an empty body",
           "            logger.exception(\"Detection failed; passing response "
           "through: %s\", exc)\n            return _build_response(\n"
           "                response_body, status_code, relayed,",
           "            logger.exception(\"Detection failed; passing response "
           "through: %s\", exc)\n            return _build_response(\n"
           "                b\"\", status_code, relayed,", "failopen"),
    Mutant("M32", "a detector crash re-enters call_next (the pre-fix recovery)",
           "            return _build_response(\n"
           "                response_body, status_code, relayed,\n"
           "                _signal_headers(\"ERROR\", \"error\"),\n            )",
           "            inner = await call_next(request)\n"
           "            chunks = [c async for c in inner.body_iterator]\n"
           "            return _build_response(\n"
           "                b\"\".join(chunks), status_code, relayed,\n"
           "                _signal_headers(\"ERROR\", \"error\"),\n            )",
           "failopen"),
    Mutant("M33", "a detector crash is reported as a clean LOW",
           '_signal_headers("ERROR", "error"),', '_signal_headers("LOW", "pass"),',
           "failopen"),
    Mutant("M34", "an absent engine is reported as a clean LOW",
           '_signal_headers("UNAVAILABLE", "unavailable"),',
           '_signal_headers("LOW", "pass"),', "failopen"),
    Mutant("M35", "an unreachable upstream is answered 200 from local routes",
           "                request, InterceptionRefusal(\"upstream_unreachable\"), prompt,\n"
           "                status_code=502,",
           "                request, InterceptionRefusal(\"upstream_unreachable\"), prompt,\n"
           "                status_code=200,", "failopen"),

    # -- block / warn -------------------------------------------------------
    Mutant("M36", "block never fires",
           "        if result.risk_level == \"HIGH\" and action == \"block\":",
           "        if False:", "enforce"),
    Mutant("M37", "block serves the flagged answer anyway",
           "            return _build_response(\n"
           "                json.dumps(payload).encode(\"utf-8\"), 200,\n"
           "                [(\"content-type\", \"application/json\")],\n"
           "                _signal_headers(\"HIGH\", \"block\", result.detection_id),\n"
           "            )",
           "            return _build_response(\n"
           "                response_body, 200,\n"
           "                [(\"content-type\", \"application/json\")],\n"
           "                _signal_headers(\"HIGH\", \"block\", result.detection_id),\n"
           "            )", "enforce"),
    # M38 WITHDRAWN — EQUIVALENT, and the equivalence is a fact about the code,
    # not a hole in the suite. Dropping the `risk_level == "HIGH"` conjunct
    # changes nothing, because `action` is only ever bound to the configured
    # policy on the HIGH branch and is the literal "pass" otherwise, so
    # `action == "block"` is already false for every non-HIGH verdict. A
    # survival would have said nothing about the tests. Replaced by M38R, which
    # attacks the binding rather than the conjunct.
    Mutant("M38R", "non-HIGH verdicts inherit the configured block policy",
           "        else:\n            action = \"pass\"",
           "        else:\n            action = getattr(detection_cfg, "
           "\"high_risk_action\", \"pass\") if detection_cfg else \"pass\"",
           "enforce"),
    Mutant("M39", "warn re-prepends the banner that corrupts the payload",
           "            return _build_response(\n"
           "                response_body, status_code, relayed,\n"
           "                _signal_headers(\"HIGH\", \"warn\", result.detection_id),\n"
           "            )",
           "            return _build_response(\n"
           "                b\"[ARKHEIA WARNING: HIGH RISK DETECTED] \" + response_body,\n"
           "                status_code, relayed,\n"
           "                _signal_headers(\"HIGH\", \"warn\", result.detection_id),\n"
           "            )", "enforce"),
    Mutant("M40", "the risk header is hardcoded LOW on the pass path",
           "            _signal_headers(result.risk_level, action, result.detection_id),",
           "            _signal_headers(\"LOW\", action, result.detection_id),", "enforce"),
    Mutant("M41", "a block is no longer attributable to a detection id",
           "                _signal_headers(\"HIGH\", \"block\", result.detection_id),",
           "                _signal_headers(\"HIGH\", \"block\", None),", "enforce"),
    Mutant("M42", "the block stops saying what would clear it",
           '                "remedy": (\n                    "re-run the request, narrow '
           'the prompt to material the "\n                    "model can ground, or ask an '
           'operator to review detection "\n                    f"id {result.detection_id} '
           'in the audit log"\n                ),',
           '                "remedy": "",', "enforce"),
    Mutant("M43", "the high-risk action falls back to block instead of warn",
           'action = getattr(detection_cfg, "high_risk_action", "warn") if detection_cfg else "warn"',
           'action = getattr(detection_cfg, "high_risk_action", "block") if detection_cfg else "block"',
           "enforce"),

    # -- receipts -----------------------------------------------------------
    Mutant("M44", "the audit rail is never written to",
           "        await audit.write(record)", "        pass", "receipts"),
    Mutant("M45", "a block is filed as a pass",
           '                action_taken="block",', '                action_taken="pass",',
           "receipts"),
    Mutant("M46", "a block is filed at a screened-clean risk level",
           '                risk_level="HIGH",\n                action_taken="block",',
           '                risk_level="LOW",\n                action_taken="block",',
           "receipts"),
    Mutant("M47", "the record's id no longer matches the id the caller was handed",
           "                detection_id=result.detection_id,\n"
           "                risk_level=\"HIGH\",\n                action_taken=\"block\",",
           "                detection_id=str(uuid.uuid4()),\n"
           "                risk_level=\"HIGH\",\n                action_taken=\"block\",",
           "receipts"),
    Mutant("M48", "a refusal leaves no record",
           "        await _emit(request, _audit_record(\n"
           "            detection_id=detection_id,\n"
           "            risk_level=\"REFUSED\",",
           "        await _noop(request, _audit_record(\n"
           "            detection_id=detection_id,\n"
           "            risk_level=\"REFUSED\",", "receipts"),
    Mutant("M49", "prompt TEXT is written to the evidence file instead of a hash",
           '"prompt_hash": hashlib.sha256(prompt.encode("utf-8", "replace")).hexdigest(),',
           '"prompt_hash": prompt,', "receipts"),
    Mutant("M50", "a warn leaves no record",
           '                action_taken="warn",', '                action_taken="pass",',
           "receipts"),
    Mutant("M51", "the receipt status overclaims: enqueued -> recorded",
           '                "receipt": "enqueued",\n            }\n'
           '            return _build_response(\n'
           '                json.dumps(payload).encode("utf-8"), 200,',
           '                "receipt": "recorded",\n            }\n'
           '            return _build_response(\n'
           '                json.dumps(payload).encode("utf-8"), 200,', "receipts"),
    Mutant("M52", "the blocked surface is dropped from the record",
           "                path=request.url.path,\n"
           "                method=request.method,\n                prompt=prompt,\n"
           "                response_body=response_body,\n"
           "                model_id=result.model_id,\n"
           "                profile_version=result.profile_version,\n"
           "                confidence=result.confidence,\n"
           "                features_triggered=list(result.features_triggered or []),\n"
           "            ))\n            payload = {",
           "                path=\"\",\n"
           "                method=request.method,\n                prompt=prompt,\n"
           "                response_body=response_body,\n"
           "                model_id=result.model_id,\n"
           "                profile_version=result.profile_version,\n"
           "                confidence=result.confidence,\n"
           "                features_triggered=list(result.features_triggered or []),\n"
           "            ))\n            payload = {", "receipts"),
    # M53 WITHDRAWN — the guard is real but its trigger is not reachable
    # without patching the rail, so the mutant cannot be scored honestly.
    # `AuditWriter.write()` catches its own QueueFull and returns; nothing on
    # the production path makes it raise. DONE.md v1.18 forbids proving a
    # fail-open path with a monkeypatched exception, so rather than
    # manufacture a fake failure this is left as UNSCORED defence-in-depth and
    # is DISCLOSED as such in the PR. Replaced by M53R, which attacks a
    # property of the refusal record that a triager actually needs.
    Mutant("M53R", "the refusal record loses its deny code",
           '            deny_code=refusal.deny_code,', '            deny_code=None,',
           "receipts"),
    Mutant("M54", "the caller's Host header is relayed to the provider",
           'REQUEST_OWNED_HEADERS = frozenset({"host", "content-length"})',
           'REQUEST_OWNED_HEADERS = frozenset({"content-length"})', "headers"),
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


def _env() -> dict:
    env = dict(os.environ)
    env.setdefault("JWT_SECRET",
                   "ci-test-secret-not-for-production-use-minimum-32chars!!")
    return env


def run_pytest(paths: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "-q", "-p", "no:cacheprovider",
         "--timeout=120", "--no-header", "--tb=no"],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
        env=_env(),
    )
    return proc.returncode, proc.stdout + proc.stderr


def failures_of(output: str) -> set[str]:
    return {ln.split(" ")[1] for ln in output.splitlines()
            if ln.startswith("FAILED ") and len(ln.split(" ")) > 1}


def classify(returncode: int, output: str) -> tuple[str, list[str]]:
    failures = sorted(failures_of(output))
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

    # Materialise origin/master's pre-existing suite for the counterfactual.
    PREEXISTING_TMP.write_text(subprocess.run(
        ["git", "show", f"origin/master:{PREEXISTING_SRC}"],
        cwd=REPO, capture_output=True, text=True, check=True,
    ).stdout, encoding="utf-8")
    pre_tier = [str(PREEXISTING_TMP.relative_to(REPO))]

    print("=" * 78)
    print("BASELINE — the tier must be green before any fault is planted")
    print("=" * 78)
    rc, out = run_pytest(NEW_TIER)
    if rc != 0:
        print(out[-4000:])
        print("BASELINE IS NOT GREEN — aborting. Nothing below would mean anything.")
        PREEXISTING_TMP.unlink(missing_ok=True)
        return 2
    print(f"  new tier          : "
          f"{[ln for ln in out.splitlines() if ' passed' in ln][-1].strip()}")

    rc0, out0 = run_pytest(pre_tier)
    pre_baseline_failures = failures_of(out0)
    print(f"  pre-existing tier : "
          f"{[ln for ln in out0.splitlines() if 'passed' in ln or 'failed' in ln][-1].strip()}")
    if pre_baseline_failures:
        print("    NOTE — origin/master's suite is not green against this branch's")
        print("    module by design (the banner-prepend was removed). These failures")
        print("    are the counterfactual BASELINE and are subtracted from every")
        print("    trial, so the old suite is not credited with catching them:")
        for name in sorted(pre_baseline_failures):
            print(f"      {name}")
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
            assert mutated != original, f"{mutant.mid} produced no textual change"
            TARGET.write_text(mutated, encoding="utf-8")
            try:
                rc, out = run_pytest(NEW_TIER)
                bucket, failures = classify(rc, out)
                rc_old, out_old = run_pytest(pre_tier)
                pre_bucket, _ = classify(rc_old, out_old)
                new_pre_failures = failures_of(out_old) - pre_baseline_failures
                if pre_bucket == "KILLED" and not new_pre_failures:
                    pre_bucket = "SURVIVED"
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
            print(f"  {mutant.mid}  {marker:<14} old-tier={pre_bucket:<10} {mutant.what}")
    finally:
        TARGET.write_text(original, encoding="utf-8")
        PREEXISTING_TMP.unlink(missing_ok=True)

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
            print(f"    {t.mid}  ({t.area})  {t.what}")

    print("\n  COUNTERFACTUAL — same faults against origin/master's suite alone,")
    print("  with its pre-recorded baseline failures subtracted:")
    counter: dict[str, int] = {}
    for t in trials:
        counter[t.preexisting_bucket] = counter.get(t.preexisting_bucket, 0) + 1
    for bucket, n in sorted(counter.items()):
        print(f"    {bucket or '(not run)':<18} {n}")
    survived_old = [t.mid for t in trials if t.preexisting_bucket == "SURVIVED"]
    print(f"    would have SURVIVED the pre-existing suite: "
          f"{len(survived_old)} of {len(trials)}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "interpreter": sys.version,
            "target": str(TARGET.relative_to(REPO)),
            "tier": NEW_TIER,
            "verdict": ("CLEAN" if totals["SURVIVED"] == 0
                        and totals["NOT_OBSERVED"] == 0 else "REVIEW"),
            "totals": {**totals, "planted": len(selected), "scored": scored},
            "baseline_restored_green": restored_green,
            "counterfactual_survived_ids": survived_old,
            "trials": [t.__dict__ for t in trials],
        }, indent=2), encoding="utf-8")
        print(f"\n  json written: {args.json}")

    return 0 if (totals["SURVIVED"] == 0 and totals["NOT_OBSERVED"] == 0
                 and restored_green) else 1


if __name__ == "__main__":
    raise SystemExit(main())
