#!/usr/bin/env python3
"""
Mutation harness for the governance detection-adapter push.

WHY THREE BUCKETS AND NOT TWO
-----------------------------
A harness that counts only `FAILED` lines scores a mutant that breaks the IMPORT
as a clean run — pytest exits with a collection error, prints no `FAILED`, and
the harness records a green pass. That is a harness reporting "no survivors" over
a suite that never executed. Two such void runs were found in this sweep, so this
one classifies into THREE buckets and treats the third as a harness fault, not a
kill:

    KILLED    exit 1 AND at least one `FAILED` line   -> a test caught it
    SURVIVED  exit 0                                  -> a real hole
    NOT_RUN   anything else (2/3/4/5, collection error, no tests ran)

`__pycache__` is cleared before every trial. A stale `.pyc` from the previous
mutant is the other way a mutation run silently lies.

Usage:  python scripts/mutate_detection_adapter.py [--python PATH]
Exit 0 only when SURVIVED == 0 and NOT_RUN == 0.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "proxy" / "detection_adapter.py"

TESTS = [
    "tests/test_detection_adapter.py",
    "tests/test_detection_adapter_push.py",
    "tests/test_detection_adapter_receipt.py",
    "tests/test_detection_adapter_endpoint_path.py",
    "tests/test_detection_adapter_target.py",
    "tests/test_governance_push_floor.py",
    "tests/test_url_composition_floor.py",
]


@dataclass
class Mutant:
    mid: str
    what: str
    find: str
    replace: str
    count: int = 1


MUTANTS: list[Mutant] = [
    # ── the wire contract ────────────────────────────────────────────────────
    Mutant("M01", "revert to the pre-fix signing string f'{ts}.{body}'",
           'signing_string = f"POST\\n{ADAPTER_PATH}\\n{ts}\\n{body_hash}"',
           'signing_string = f"{ts}.{body.decode()}"'),
    Mutant("M02", "sign the wrong path (/v1/events/onprem)",
           'signing_string = f"POST\\n{ADAPTER_PATH}\\n{ts}\\n{body_hash}"',
           'signing_string = f"POST\\n/v1/events/onprem\\n{ts}\\n{body_hash}"'),
    Mutant("M03", "drop the method from the signing string",
           'signing_string = f"POST\\n{ADAPTER_PATH}\\n{ts}\\n{body_hash}"',
           'signing_string = f"{ADAPTER_PATH}\\n{ts}\\n{body_hash}"'),
    Mutant("M04", "hash a constant instead of the body",
           "body_hash = hashlib.sha256(body).hexdigest()",
           'body_hash = hashlib.sha256(b"").hexdigest()'),
    Mutant("M05", "sign with an empty key",
           "sig = _hmac.new(secret.encode(), signing_string.encode(), hashlib.sha256).hexdigest()",
           'sig = _hmac.new(b"", signing_string.encode(), hashlib.sha256).hexdigest()'),
    Mutant("M06", "POST to the onprem endpoint (signature no longer covers the path used)",
           'ADAPTER_PATH = "/v1/events/proxy"',
           'ADAPTER_PATH = "/v1/events/onprem"'),
    Mutant("M07", "send an unsigned request (drop the headers kwarg)",
           "                headers=headers,\n", "", ),
    Mutant("M08", "freeze the timestamp (would be outside the receiver's +/-60s window)",
           'ts = timestamp if timestamp is not None else str(int(time.time()))',
           'ts = timestamp if timestamp is not None else "1700000000"'),

    # ── the body schema ──────────────────────────────────────────────────────
    Mutant("M09", "flatten tenant back to a scalar (ProxyTenant is an object)",
           '"tenant": {\n            "tenant_id": tenant_id,\n            "proxy_deployment_id": None,\n        },',
           '"tenant": tenant_id,'),
    Mutant("M10", "drop event_id (serde requires it)",
           '"event_id": event_id,\n        "emitted_at": now,',
           '"emitted_at": now,'),
    Mutant("M11", "emit a non-UUID event_id",
           "        return str(uuid.uuid5(_DETECTION_ID_NS, text))",
           "        return text"),

    # ── delivery visibility ──────────────────────────────────────────────────
    Mutant("M12", "treat 4xx as delivered (only 5xx is a rejection)",
           "if resp.status_code >= 400:", "if resp.status_code >= 500:"),
    Mutant("M13", "drop the rejection back to debug level",
           '        logger.error(\n            "%s adapter rejected event_id=%s with HTTP %s posting to %s: %s%s",',
           '        logger.debug(\n            "%s adapter rejected event_id=%s with HTTP %s posting to %s: %s%s",'),
    Mutant("M14", "drop the transport failure back to debug level",
           '        logger.error(\n            "%s transport error posting event_id=%s to %s: %s",',
           '        logger.debug(\n            "%s transport error posting event_id=%s to %s: %s",'),
    Mutant("M15", "report a rejection as DELIVERED",
           "            PushOutcome.REJECTED,", "            PushOutcome.DELIVERED,"),
    Mutant("M16", "report a transport failure as DELIVERED",
           "            PushOutcome.FAILED, error=f\"{type(exc).__name__}: {exc}\", event_id=event_id",
           "            PushOutcome.DELIVERED, error=f\"{type(exc).__name__}: {exc}\", event_id=event_id"),

    # ── no unsigned fallback ─────────────────────────────────────────────────
    Mutant("M17", "send anyway when the signing secret is absent",
           "if not url.strip() or not secret:", "if not url.strip():"),
    Mutant("M18", "ship a default signing secret",
           'os.getenv("DETECTION_ADAPTER_HMAC_SECRET", ""),',
           'os.getenv("DETECTION_ADAPTER_HMAC_SECRET", "default-dev-secret"),'),

    # ── verdict honesty ──────────────────────────────────────────────────────
    Mutant("M19", "call an unassessable verdict AUTHENTIC",
           '    # MEDIUM, UNKNOWN, and anything unrecognised.\n    return "UNCERTAIN"',
           '    # MEDIUM, UNKNOWN, and anything unrecognised.\n    return "AUTHENTIC"'),
    Mutant("M20", "coerce an unknown band to LOW on the wire",
           '"fabrication_risk": band if band in _VALID_RISK else "UNKNOWN",',
           '"fabrication_risk": band if band in _VALID_RISK else "LOW",'),

    # ── the receipt ──────────────────────────────────────────────────────────
    Mutant("M21", "never receipt a rejected push",
           "            FAILURE_MARKER, event_id, resp.status_code, target, outcome.error, hint,\n        )\n        await _receipt(audit, _record(outcome, target))",
           "            FAILURE_MARKER, event_id, resp.status_code, target, outcome.error, hint,\n        )"),
    Mutant("M22", "receipt every push as delivered",
           '            "delivery_status": outcome.status,',
           '            "delivery_status": PushOutcome.DELIVERED,'),
    Mutant("M23", "swallow a receipt-write failure",
           '        logger.error(\n            "%s could not receipt governance push event_id=%s: %s",',
           '        logger.debug(\n            "%s could not receipt governance push event_id=%s: %s",'),
    Mutant("M24", "make push_id a constant (attempts become indistinguishable)",
           '"push_id": str(uuid.uuid4()),', '"push_id": "fixed",'),
    Mutant("M25", "put the signing secret in the receipt",
           '            "key_id": key_id,', '            "key_id": secret,'),

    # ── dispatch ─────────────────────────────────────────────────────────────
    Mutant("M26", "restore the deprecated get_event_loop()",
           "        loop = asyncio.get_running_loop()", "        loop = asyncio.get_event_loop()"),
    Mutant("M27", "never dispatch from sync context",
           "        return asyncio.run(coro)", "        coro.close()\n        return None"),
    Mutant("M28", "drop the fire-and-forget done-callback",
           "        task.add_done_callback(_log_task_result)\n", ""),

    # ── the ADDRESS: the operator-supplied term of the contract ──────────────
    # M29 is the defect verbatim. The rest are the ways a later edit could
    # partially undo the fix and still look plausible in review.
    Mutant("M29", "revert to raw concatenation of the base URL (THE defect)",
           "        target = adapter_target(url)",
           '        target = f"{url}{ADAPTER_PATH}"'),
    Mutant("M30", "normalise, but leave trailing slashes on the base",
           'urllib.parse.urlunsplit((scheme, parts.netloc, parts.path.rstrip("/"), "", ""))',
           'urllib.parse.urlunsplit((scheme, parts.netloc, parts.path, "", ""))'),
    Mutant("M31", "stop stripping surrounding whitespace from the env value",
           '    text = (raw or "").strip()', '    text = raw or ""'),
    Mutant("M32", "accept any scheme and a missing host",
           "    if scheme not in _ALLOWED_SCHEMES or not parts.netloc:",
           "    if False:"),
    Mutant("M33", "fold a misconfigured URL back into the silent SKIPPED bucket",
           "            PushOutcome.MISCONFIGURED, error=str(exc), event_id=event_id",
           "            PushOutcome.SKIPPED, error=str(exc), event_id=event_id"),
    Mutant("M34", "drop the route-miss diagnosis from the 404 log",
           "        if resp.status_code in (404, 405):", "        if False:"),
    Mutant("M35", "receipt the raw base URL instead of the target actually posted to",
           '            "adapter_url": target,', '            "adapter_url": url,'),
    Mutant("M36", "startup guard warns instead of refusing to boot",
           '            raise RuntimeError(f"Cannot start: {exc}") from None',
           "            pass"),
    Mutant("M37", "stop surfacing a half-configured rail at startup",
           "    if url_set != secret_set:", "    if False:"),
    Mutant("M38", "compose the target without the endpoint path at all",
           '    return f"{base}{ADAPTER_PATH}" if base else ""',
           '    return base if base else ""'),
    # Withdrawn and replaced: the first M39 ("let a malformed URL through by
    # catching a name that is never raised") was redundant with M32 — both assert
    # the same guard — and it killed via NameError rather than via the behaviour
    # under test. A mutant that is equivalent to another, or that fails for an
    # unrelated reason, measures nothing. This one targets a guard nothing else
    # covers: silently DISCARDING an operator's query string.
    Mutant("M39", "drop the query/fragment guard (silently discards part of the value)",
           "    if parts.query or parts.fragment:", "    if False:"),
]


# ── harness self-controls ────────────────────────────────────────────────────
# "KILLED 28 / SURVIVED 0" is only believable from a harness that CAN report the
# other two buckets. A run whose success condition is an empty result must prove
# it is able to find something. These two are asserted, not scored: if the
# survivor control does not SURVIVE, or the broken-import control does not read
# as NOT_RUN, the whole run is void.
CONTROLS: list[tuple[Mutant, str]] = [
    (Mutant("CTRL-S", "semantically inert edit (a comment) — MUST survive",
            "# Namespace for deriving a UUID from a non-UUID detection id.",
            "# Namespace for deriving a UUID from a non-UUID detection id (inert)."),
     "SURVIVED"),
    (Mutant("CTRL-N", "break the module import — MUST read as NOT_RUN, never as a kill",
            "import httpx", "import httpx\nraise ImportError('control: broken import')"),
     "NOT_RUN"),
]


def clear_pycache() -> None:
    for p in ROOT.rglob("__pycache__"):
        if ".venv" in p.parts:
            continue
        shutil.rmtree(p, ignore_errors=True)


def run_suite(python: str) -> tuple[int, str]:
    env = dict(os.environ)
    env.setdefault("JWT_SECRET", "ci-test-secret-not-for-production-use-minimum-32chars!!")
    env.pop("DETECTION_ADAPTER_URL", None)
    env.pop("DETECTION_ADAPTER_HMAC_SECRET", None)
    proc = subprocess.run(
        [python, "-m", "pytest", *TESTS, "-q", "-p", "no:cacheprovider",
         "-o", 'python_files=test_*.py', "--timeout=120"],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=900,
    )
    return proc.returncode, proc.stdout + proc.stderr


def classify(rc: int, out: str) -> tuple[str, str]:
    """
    KILLED / SURVIVED / NOT_RUN.

    The NOT_RUN bucket is the whole point: a mutant that breaks collection prints
    no `FAILED` line and must never be counted as caught.
    """
    m = re.search(r"(\d+) failed", out)
    failed = int(m.group(1)) if m else 0
    collected = re.search(r"(\d+) (?:passed|failed)", out)
    if rc in (0,):
        return "SURVIVED", "suite green under mutation"
    if rc == 1 and failed > 0:
        return "KILLED", f"{failed} test(s) failed"
    if not collected:
        return "NOT_RUN", f"rc={rc}, nothing collected (import/collection error)"
    return "NOT_RUN", f"rc={rc}, no FAILED lines"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--only", default="", help="comma-separated mutant ids")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",") if s.strip()}
    original = TARGET.read_text(encoding="utf-8")

    # Baseline: the unmutated suite MUST be green, or every "kill" is meaningless.
    clear_pycache()
    rc, out = run_suite(args.python)
    if rc != 0:
        print("BASELINE IS RED — every result below would be uninterpretable.")
        print(out[-4000:])
        return 2
    base = re.search(r"(\d+) passed", out)
    assert base, "baseline reported no passing tests — the harness would measure nothing"
    print(f"baseline: green ({base.group(1)} passed)\n")

    # ── self-controls first; a void harness must not be allowed to report 0/0 ──
    control_failures = []
    try:
        for mut, expected in CONTROLS:
            assert original.count(mut.find) == 1, f"{mut.mid} pattern miss"
            TARGET.write_text(original.replace(mut.find, mut.replace, 1), encoding="utf-8")
            clear_pycache()
            rc, out = run_suite(args.python)
            verdict, detail = classify(rc, out)
            ok = verdict == expected
            print(f"{mut.mid}  {verdict:<9} (expected {expected}) {'ok' if ok else 'HARNESS FAULT'}"
                  f"  — {mut.what}")
            if not ok:
                control_failures.append((mut.mid, verdict, expected))
    finally:
        TARGET.write_text(original, encoding="utf-8")
        clear_pycache()

    if control_failures:
        print(f"\nHARNESS IS VOID — self-controls failed: {control_failures}")
        return 2
    print()

    results: list[tuple[str, str, str, str]] = []
    try:
        for mut in MUTANTS:
            if only and mut.mid not in only:
                continue
            occurrences = original.count(mut.find)
            if occurrences != mut.count:
                results.append((mut.mid, "NOT_RUN",
                                f"pattern found {occurrences}x, expected {mut.count}", mut.what))
                print(f"{mut.mid}  NOT_RUN   pattern miss — {mut.what}")
                continue

            TARGET.write_text(original.replace(mut.find, mut.replace, mut.count), encoding="utf-8")
            clear_pycache()
            rc, out = run_suite(args.python)
            verdict, detail = classify(rc, out)
            results.append((mut.mid, verdict, detail, mut.what))
            print(f"{mut.mid}  {verdict:<9} {detail:<45} {mut.what}")
    finally:
        TARGET.write_text(original, encoding="utf-8")
        clear_pycache()

    killed = sum(1 for r in results if r[1] == "KILLED")
    survived = [r for r in results if r[1] == "SURVIVED"]
    not_run = [r for r in results if r[1] == "NOT_RUN"]

    print(f"\nKILLED {killed}   SURVIVED {len(survived)}   NOT_RUN {len(not_run)}   "
          f"of {len(results)}")
    for mid, _, detail, what in survived:
        print(f"  SURVIVED {mid}: {what} — {detail}")
    for mid, _, detail, what in not_run:
        print(f"  NOT_RUN  {mid}: {what} — {detail}")

    return 0 if not survived and not not_run else 1


if __name__ == "__main__":
    sys.exit(main())
