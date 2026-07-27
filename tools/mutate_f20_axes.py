#!/usr/bin/env python3
"""
Mutation campaign for F20 — the receipted and enforced axes.

WHAT THIS ANSWERS
-----------------
The suites are green. That is a statement about the code, not about the suites.
This plants a fault the suites are *supposed* to catch and checks that they do.

FILES IT PLANTS FAULTS IN — four, and the tier covers all four
---------------------------------------------------------------
    proxy/audit/decision_journal.py
    proxy/crypto/profile_crypto.py
    proxy/router/profile_router.py
    proxy/main.py

THE TIER MUST COVER EVERY FILE IT MUTATES. It does:

    proxy/tests/test_f20_profile_key_receipts.py    (decision_journal, profile_crypto)
    proxy/tests/test_f20_profile_auth_receipts.py   (decision_journal, profile_router)
    proxy/tests/test_f20_lifespan_ordering.py       (main — the real lifespan)
    tests/test_f20_profile_key_floor.py             (main, decision_journal — static)
    tests/test_dynamic_key_startup.py               (pre-existing)
    tests/test_encrypted_profiles.py                (pre-existing)
    proxy/tests/test_router.py                      (pre-existing)

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
withdraw it, replace it, and say so. Withdrawals are recorded in place below,
with the reason, rather than deleted.

THE COUNTERFACTUAL
------------------
Each mutant is also run against the PRE-EXISTING suite alone — the three files
above that are unmodified from ``origin/master`` — so the report can state what
this branch's tests actually added rather than assert it.

USAGE
-----
    <venv>/bin/python tools/mutate_f20_axes.py
    <venv>/bin/python tools/mutate_f20_axes.py --only M01 M02
    <venv>/bin/python tools/mutate_f20_axes.py --json out.json
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

JOURNAL = "proxy/audit/decision_journal.py"
CRYPTO = "proxy/crypto/profile_crypto.py"
ROUTER = "proxy/router/profile_router.py"
MAIN = "proxy/main.py"

MUTATED_FILES = (JOURNAL, CRYPTO, ROUTER, MAIN)

NEW_TIER = [
    "proxy/tests/test_f20_profile_key_receipts.py",
    "proxy/tests/test_f20_profile_auth_receipts.py",
    "proxy/tests/test_f20_lifespan_ordering.py",
    "tests/test_f20_profile_key_floor.py",
    "tests/test_dynamic_key_startup.py",
    "tests/test_encrypted_profiles.py",
    "proxy/tests/test_router.py",
]

#: Unmodified from origin/master on this branch. This is the counterfactual.
PREEXISTING_TIER = [
    "tests/test_dynamic_key_startup.py",
    "tests/test_encrypted_profiles.py",
    "proxy/tests/test_router.py",
    "tests/test_audit_floor.py",
]

TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class Mutant:
    mid: str
    path: str
    what: str
    old: str
    new: str
    #: Which control this fault removes. Grouping only; never affects a verdict.
    area: str
    #: Further ``(path, old, new)`` triples applied in the same trial, possibly
    #: in OTHER files. Used where two paths are deliberately redundant, so
    #: removing either alone is unobservable and a single-edit mutant would be
    #: equivalent — the fault has to be planted in both to mean anything.
    extra: tuple = ()


MUTANTS: list[Mutant] = [
    # -- identifiers: the things that must not be reversible ----------------
    Mutant("M01", JOURNAL, "key_id loses its domain separation",
           'return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:16]',
           'return hashlib.sha256(key).hexdigest()[:16]', "identifiers"),
    Mutant("M02", JOURNAL, "key_id returns the key itself, hex-encoded",
           'return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:16]',
           'return key.hex()', "identifiers"),
    Mutant("M03", JOURNAL, "key_id stops truncating (full digest is an oracle)",
           'return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:16]',
           'return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()', "identifiers"),
    Mutant("M04", JOURNAL, "ciphertext_id returns the ciphertext, hex-encoded",
           'return hashlib.sha256(blob).hexdigest()', 'return blob.hex()',
           "identifiers"),
    Mutant("M05", JOURNAL, "hosted_origin reports nothing",
           '        return f"{parts.scheme}://{host}"', '        return None',
           "identifiers"),

    # -- the honesty of the status ------------------------------------------
    Mutant("M06", JOURNAL, 'receipt_status becomes "recorded" (the overclaim)',
           'RECEIPT_ENQUEUED = "enqueued"', 'RECEIPT_ENQUEUED = "recorded"',
           "status"),
    Mutant("M07", JOURNAL, "a missing writer is reported as a successful enqueue",
           "            event_label, id_label, outcome_label,\n"
           "        )\n        return RECEIPT_UNAVAILABLE",
           "            event_label, id_label, outcome_label,\n"
           "        )\n        return RECEIPT_ENQUEUED", "status"),
    Mutant("M08", JOURNAL, "a raised write error is reported as a successful enqueue",
           "            type(exc).__name__, event_label, id_label, outcome_label,\n"
           "        )\n        return RECEIPT_UNAVAILABLE",
           "            type(exc).__name__, event_label, id_label, outcome_label,\n"
           "        )\n        return RECEIPT_ENQUEUED", "status"),
    Mutant("M09", CRYPTO, "the loader assumes 'enqueued' instead of reporting it",
           "        self.last_receipt_status = (\n"
           "            RECEIPT_UNAVAILABLE if (not results or RECEIPT_UNAVAILABLE in statuses)\n"
           "            else RECEIPT_ENQUEUED\n        )",
           "        self.last_receipt_status = RECEIPT_ENQUEUED", "status"),

    # -- log-sink sanitisation (earned by CodeQL on PR #34, two HIGH) --------
    Mutant("M43", JOURNAL, "the failure log reads the outcome straight out of the record",
           "    outcome_label = _label(out.get(\"outcome\"), KEY_LOAD_OUTCOMES | PROFILE_AUTH_OUTCOMES)",
           "    outcome_label = out.get(\"outcome\")", "disclosure"),
    Mutant("M44", JOURNAL, "the failure log reads the decision id straight out of the record",
           "    id_label = _uuid_label(out.get(\"decision_id\"))",
           "    id_label = out.get(\"decision_id\")", "disclosure"),
    Mutant("M45", JOURNAL, "_label returns the record's value instead of the vocabulary member",
           "    for member in vocabulary:\n        if member == value:\n            return member\n"
           "    return UNRESOLVED_LABEL",
           "    return value", "disclosure"),

    # -- the timing gap ------------------------------------------------------
    Mutant("M10", JOURNAL, "the deferral is no longer measured",
           'out["receipt_deferred_ms"] = _deferral_ms(out.get("decided_at"), enqueued_at)',
           'out["receipt_deferred_ms"] = None', "timing"),
    Mutant("M11", JOURNAL, "decided_at is stamped at flush time, not at the decision",
           '        entry["decided_at"] = _now().isoformat()',
           "        entry.setdefault(\"decided_at\", None)", "timing"),

    # -- the journal's own not-observed bucket -------------------------------
    Mutant("M12", JOURNAL, "evicted decisions stop being counted",
           "        if len(self._entries) == self._entries.maxlen:\n"
           "            # deque silently evicts the oldest; count it rather than lose it.\n"
           "            self._dropped += 1\n", "", "journal"),
    Mutant("M13", JOURNAL, "the overflow record is never emitted",
           "    if dropped:", "    if False:", "journal"),

    # -- the closed taxonomy -------------------------------------------------
    Mutant("M14", JOURNAL, "key-load outcomes stop being checked",
           "    if outcome not in KEY_LOAD_OUTCOMES:\n"
           "        raise ValueError(f\"key-load outcome {outcome!r} is outside the closed taxonomy\")\n",
           "", "taxonomy"),
    Mutant("M15", JOURNAL, "revocation state stops being checked",
           "    if revocation_state not in REVOCATION_STATES:\n"
           "        raise ValueError(f\"revocation state {revocation_state!r} is outside the closed taxonomy\")\n",
           "", "taxonomy"),
    Mutant("M16", JOURNAL, "profile-auth outcomes stop being checked",
           "    if outcome not in PROFILE_AUTH_OUTCOMES:\n"
           "        raise ValueError(f\"profile-auth outcome {outcome!r} is outside the closed taxonomy\")\n",
           "", "taxonomy"),
    Mutant("M17", JOURNAL, "governance rows are filed at a detection risk level",
           'RISK_LEVEL = "GOVERNANCE"', 'RISK_LEVEL = "LOW"', "taxonomy"),

    # -- what may reach disk (the allow-list) --------------------------------
    Mutant("M18", JOURNAL, "the raw key is written into the key-load record",
           '        "key_id": key_id(key) if key else None,\n'
           '        "key_length_bytes": len(key) if key else None,\n'
           '        "hosted_origin"',
           '        "key_id": key_id(key) if key else None,\n'
           '        "key_length_bytes": len(key) if key else None,\n'
           '        "key_material": key,\n'
           '        "hosted_origin"', "disclosure"),
    Mutant("M19", JOURNAL, "the raw ciphertext is written into the auth record",
           '        "ciphertext_sha256": ciphertext_id(ciphertext) if ciphertext else None,',
           '        "ciphertext_sha256": ciphertext.hex() if ciphertext else None,',
           "disclosure"),
    Mutant("M20", ROUTER, "the exception MESSAGE is recorded instead of its type",
           "            error_type=type(error).__name__ if error is not None else None,",
           "            error_type=str(error) if error is not None else None,",
           "disclosure"),

    # -- D1: which key, from where -------------------------------------------
    Mutant("M21", CRYPTO, "a cached key is recorded as having been checked with the issuer",
           "                revocation_state=REVOCATION_UNKNOWN_OFFLINE,",
           "                revocation_state=REVOCATION_CHECKED,", "key_load"),
    Mutant("M22", CRYPTO, "a cached key is recorded as having come from the issuer",
           "                key_source=KEY_SOURCE_CACHE,", "                key_source=KEY_SOURCE_HOSTED,",
           "key_load"),
    Mutant("M23", CRYPTO, "the hosted branch records nothing",
           "            await self._record_key_load(\n"
           "                outcome=KEY_LOAD_FETCHED_HOSTED,\n"
           "                key_source=KEY_SOURCE_HOSTED,\n"
           "                revocation_state=REVOCATION_CHECKED,\n"
           "                key=key,\n            )\n", "", "key_load"),
    Mutant("M24", CRYPTO, "the no-key-available branch records nothing",
           "        await self._record_key_load(\n"
           "            outcome=KEY_LOAD_UNAVAILABLE,\n"
           "            key_source=KEY_SOURCE_NONE,\n"
           "            revocation_state=REVOCATION_NOT_APPLICABLE,\n        )\n",
           "", "key_load"),
    Mutant("M25", CRYPTO, "the record is built but never flushed to the rail",
           "        results = await self.flush_decisions()", "        results = []",
           "key_load"),
    Mutant("M26", CRYPTO, "the HTTP status is never captured",
           "                self.last_http_status = resp.status_code\n", "", "key_load"),
    Mutant("M27", CRYPTO, "the loader ignores the writer it was handed",
           "        self._audit_writer = audit_writer\n"
           "        self.decision_journal = journal or DecisionJournal()",
           "        self._audit_writer = None\n"
           "        self.decision_journal = journal or DecisionJournal()", "key_load"),

    # -- D2: did the profile authenticate ------------------------------------
    Mutant("M28", ROUTER, "a tamper is filed as a malformed file",
           "                    self._journal_auth(PROFILE_AUTH_FAILED, profile_name, encrypted, e)",
           "                    self._journal_auth(PROFILE_AUTH_MALFORMED, profile_name, encrypted, e)",
           "profile_auth"),
    Mutant("M29", ROUTER, "InvalidTag falls back into the generic handler (the pre-fix shape)",
           "                except InvalidTag as e:", "                except ZeroDivisionError as e:",
           "profile_auth"),
    Mutant("M30", ROUTER, "an expired licence is filed as an authentication failure",
           "                    self._journal_auth(PROFILE_AUTH_LICENSE_REJECTED, profile_name, encrypted, None)",
           "                    self._journal_auth(PROFILE_AUTH_FAILED, profile_name, encrypted, None)",
           "profile_auth"),
    Mutant("M31", ROUTER, "the ciphertext evidence is dropped from the record",
           "            ciphertext=ciphertext or None,", "            ciphertext=None,",
           "profile_auth"),
    Mutant("M32", ROUTER, "the record no longer names the key that failed to open it",
           "            key=self._decryption_key,", "            key=None,", "profile_auth"),
    Mutant("M33", ROUTER, "the skipped-no-key branch records nothing",
           "            self.decision_journal.record(build_profile_auth_record(\n"
           "                outcome=PROFILE_AUTH_SKIPPED_NO_KEY,\n"
           "                skipped_profile_names=[f.name for f in enc_files],\n            ))\n",
           "", "profile_auth"),
    Mutant("M34", ROUTER, "a successful authentication leaves no record",
           "                self._journal_auth(PROFILE_AUTH_AUTHENTICATED, profile_name, encrypted, None)",
           "                pass", "profile_auth"),
    Mutant("M35", ROUTER, "a reload no longer schedules its own drain",
           "    def _schedule_flush(self) -> None:", "    def _schedule_flush_disabled(self) -> None:",
           "profile_auth",
           extra=((ROUTER,
                   "    def _schedule_flush_disabled(self) -> None:\n        \"\"\"",
                   "    def _schedule_flush(self) -> None:\n        return None\n\n"
                   "    def _schedule_flush_disabled(self) -> None:\n        \"\"\""),)),
    Mutant("M36", ROUTER, "the router ignores the writer it was handed",
           "        self._audit_writer = audit_writer\n"
           "        self.decision_journal = journal or DecisionJournal()",
           "        self._audit_writer = None\n"
           "        self.decision_journal = journal or DecisionJournal()", "profile_auth"),

    # -- the ordering itself, in the lifespan ---------------------------------
    Mutant("M37", MAIN, "the router is no longer handed the writer at construction",
           "        audit_writer=audit_writer,\n    )\n    await profile_router.flush_decision_journal()",
           "    )\n    await profile_router.flush_decision_journal()", "ordering"),
    # M38 WITHDRAWN — equivalent by REDUNDANCY, which is a fact about the code
    # rather than the suite. Deleting main.py's explicit
    # `await profile_router.flush_decision_journal()` alone is unobservable,
    # because ProfileRouter.__init__ ALSO calls _schedule_flush(), which drains
    # via a task as soon as the lifespan yields. The redundancy is deliberate and
    # both halves are kept: the explicit await makes startup deterministic (the
    # rows are on the rail before the app serves its first request), and
    # _schedule_flush covers the reload paths where no caller is awaiting. A
    # single-edit mutant here says nothing about the tests, so M38R deletes BOTH.
    Mutant("M38R", MAIN, "BOTH startup drains removed (explicit await + the router's self-schedule)",
           "    await profile_router.flush_decision_journal()\n    logger.info(\"Loaded %d profiles from %s\",",
           "    logger.info(\"Loaded %d profiles from %s\",", "ordering",
           extra=((ROUTER, "        self.load_all()\n        self._schedule_flush()\n\n    def attach_audit_writer",
                   "        self.load_all()\n\n    def attach_audit_writer"),)),
    Mutant("M39", MAIN, "step 1b stops recording the key-load posture",
           "    await _record_key_load_posture(audit_writer, profiles_dir, profile_router)",
           "    pass", "ordering"),
    Mutant("M40", MAIN, "the writer moves back below the profile router (the original defect)",
           "    audit_writer = AuditWriter(\n"
           "        log_path=settings.audit.log_path,\n"
           "        retention_days=settings.audit.retention_days,\n"
           "    )\n    await audit_writer.start()\n",
           "", "ordering",
           extra=((MAIN,
                   "    # 2. Detection engine\n    engine = DetectionEngine(profile_router)",
                   "    audit_writer = AuditWriter(\n"
                   "        log_path=settings.audit.log_path,\n"
                   "        retention_days=settings.audit.retention_days,\n"
                   "    )\n    await audit_writer.start()\n\n"
                   "    # 2. Detection engine\n    engine = DetectionEngine(profile_router)"),)),
    Mutant("M41", MAIN, "the no-encrypted-profiles branch stops leaving a row",
           "    if not enc_files:\n        return await emit(audit_writer, build_key_load_record(",
           "    if False:\n        return await emit(audit_writer, build_key_load_record(",
           "ordering"),
    Mutant("M42", MAIN, "a preconfigured key is not distinguished from no key at all",
           "            outcome=KEY_LOAD_KEY_PRECONFIGURED,\n"
           "            key_source=KEY_SOURCE_PRECONFIGURED,",
           "            outcome=KEY_LOAD_NO_API_KEY,\n"
           "            key_source=KEY_SOURCE_NONE,", "ordering"),
]


# ---------------------------------------------------------------------------

@dataclass
class Trial:
    mid: str
    path: str
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
         "--timeout=90", "--no-header", "--tb=no"],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
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

    originals = {rel: (REPO / rel).read_text(encoding="utf-8") for rel in MUTATED_FILES}

    print("=" * 78)
    print("BASELINE — the tier must be green before any fault is planted")
    print("=" * 78)
    rc, out = run_pytest(NEW_TIER)
    if rc != 0:
        print(out[-4000:])
        print("BASELINE IS NOT GREEN — aborting. Nothing below would mean anything.")
        return 2
    print(f"  new tier          : "
          f"{[ln for ln in out.splitlines() if ' passed' in ln][-1].strip()}")

    rc0, out0 = run_pytest(PREEXISTING_TIER)
    if rc0 != 0:
        print(out0[-3000:])
        print("PRE-EXISTING TIER IS NOT GREEN — the counterfactual would be noise.")
        return 2
    print(f"  pre-existing tier : "
          f"{[ln for ln in out0.splitlines() if ' passed' in ln][-1].strip()}")
    print()

    selected = [m for m in MUTANTS if not args.only or m.mid in args.only]
    trials: list[Trial] = []

    try:
        for mutant in selected:
            started = time.monotonic()
            edits = ((mutant.path, mutant.old, mutant.new),) + tuple(mutant.extra)

            staged = {rel: originals[rel] for rel in {e[0] for e in edits}}
            counts = []
            ok = True
            for rel, old, new in edits:
                counts.append(staged[rel].count(old))
                if staged[rel].count(old) != 1:
                    ok = False
                    break
                staged[rel] = staged[rel].replace(old, new)

            if not ok or all(staged[rel] == originals[rel] for rel in staged):
                trials.append(Trial(
                    mutant.mid, mutant.path, mutant.what, mutant.area, "NOT_OBSERVED",
                    detail=f"anchors matched {counts}, each must match exactly 1 — "
                           f"the fault was never planted, so nothing was learned",
                ))
                print(f"  {mutant.mid}  NOT_OBSERVED  (anchors {counts})  {mutant.what}")
                continue

            for rel, text in staged.items():
                (REPO / rel).write_text(text, encoding="utf-8")
            try:
                rc, out = run_pytest(NEW_TIER)
                bucket, failures = classify(rc, out)
                rc_old, out_old = run_pytest(PREEXISTING_TIER)
                pre_bucket, _ = classify(rc_old, out_old)
            except subprocess.TimeoutExpired:
                bucket, failures, pre_bucket = "NOT_OBSERVED", [], "NOT_OBSERVED"
            finally:
                for rel in staged:
                    (REPO / rel).write_text(originals[rel], encoding="utf-8")

            trials.append(Trial(
                mutant.mid, mutant.path, mutant.what, mutant.area, bucket,
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
        for rel, text in originals.items():
            (REPO / rel).write_text(text, encoding="utf-8")

    for rel, text in originals.items():
        assert (REPO / rel).read_text(encoding="utf-8") == text, f"{rel} not restored"
    rc, _ = run_pytest(NEW_TIER)
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
    print(f"  files mutated     : {len(MUTATED_FILES)} — {', '.join(MUTATED_FILES)}")
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
            print(f"    {t.mid}  [{t.path}]  {t.what}")

    print("\n  COUNTERFACTUAL — same faults against the PRE-EXISTING suite alone:")
    counter: dict[str, int] = {}
    for t in trials:
        counter[t.preexisting_bucket] = counter.get(t.preexisting_bucket, 0) + 1
    for bucket, n in sorted(counter.items()):
        print(f"    {bucket or '(not run)':<18} {n}")
    would_have_survived = [t.mid for t in trials if t.preexisting_bucket == "SURVIVED"]
    print(f"    mutants the pre-existing suite would NOT have caught: "
          f"{len(would_have_survived)} of {len(trials)}")

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
            "mutated_files": list(MUTATED_FILES),
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
