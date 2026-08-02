#!/usr/bin/env python3
"""
Mutation harness for F20 — Encrypted-profile decryption (AES-256-GCM).

WHY A MUTATION RUN AND NOT A REVIEW
-----------------------------------
The `adversarial` axis for this flow was previously carried by a
`critique_security_reviewer` artifact that flagged "Secret extraction from
binary: CRITICAL" — a finding about an EMBEDDED key, in an implementation that
uses a runtime-fetched key. The artifact existed, but it had reviewed the SPEC.
This harness reviews the CODE: it breaks each security-relevant decision in
turn and requires the suite to notice.

TRAPS THIS HARNESS IS BUILT AGAINST (both cost real time on 2026-07-26)
----------------------------------------------------------------------
1. **Stale bytecode.** A same-length, same-second-mtime restore leaves Python
   serving the mutated `.pyc`. Two agents were misled — one saw a fake red
   baseline, one a mutant that was never loaded. Every trial here clears
   `__pycache__` across the whole tree, before AND after.
2. **A void run reported as clean.** DONE.md floor invariant 9: a check that
   reports a verdict must fail when it measured nothing. If zero mutants are
   generated, or any mutant fails to APPLY, this exits non-zero and names the
   units — it never prints a green line over an empty run.

A SURVIVOR IS NOT AUTOMATICALLY A DEFECT, and a KILL is not automatically
proof: the permissive-assertion class (`pytest.raises(Exception)`,
`assert x != y`) is invisible to mutation. Read the survivors, and read the
assertions.

Usage:
    python tools/mutate_f20_profile_crypto.py [--json OUT]
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CRYPTO = "proxy/crypto/profile_crypto.py"
ROUTER = "proxy/router/profile_router.py"

TEST_CMD = [
    sys.executable, "-m", "pytest",
    "tests/test_encrypted_profile_tamper.py",
    "tests/test_encrypted_profiles.py",
    "tests/test_dynamic_key_startup.py",
    "-x", "-q", "-p", "no:cacheprovider",
]


@dataclass
class Mutant:
    mid: str
    path: str
    old: str
    new: str
    intent: str
    #: A semantics-PRESERVING edit, expected to survive. It proves the harness
    #: edits a line that actually executes without claiming a hole when it does
    #: not change behaviour. Counted separately from real survivors.
    control: bool = False


MUTANTS: list[Mutant] = [
    # --- Is the tag actually verified? -------------------------------------
    Mutant(
        "M1", CRYPTO,
        "    return aesgcm.decrypt(nonce, ciphertext, profile_name.encode(\"utf-8\"))",
        "    try:\n"
        "        return aesgcm.decrypt(nonce, ciphertext, profile_name.encode(\"utf-8\"))\n"
        "    except Exception:\n"
        "        return ciphertext[:-_TAG_SIZE]",
        "swallow InvalidTag and return the raw ciphertext body — the "
        "'authenticated encryption becomes a plain cipher' collapse",
    ),
    Mutant(
        "M2", CRYPTO,
        "    ciphertext = encrypted[_NONCE_SIZE:]",
        "    ciphertext = encrypted[_NONCE_SIZE:]\n"
        "    del ciphertext  # noqa\n"
        "    ciphertext = encrypted[_NONCE_SIZE:]",
        "CONTROL (semantics-preserving): proves the harness edits a line that "
        "actually executes. Expected to SURVIVE.",
        control=True,
    ),
    Mutant(
        "M3", CRYPTO,
        "    return aesgcm.decrypt(nonce, ciphertext, profile_name.encode(\"utf-8\"))",
        "    return aesgcm.decrypt(nonce, ciphertext, b\"\")",
        "drop the AAD on decrypt — a blob then loads under ANY profile name",
    ),
    Mutant(
        "M4", CRYPTO,
        "    ciphertext = aesgcm.encrypt(nonce, plaintext, profile_name.encode(\"utf-8\"))",
        "    ciphertext = aesgcm.encrypt(nonce, plaintext, b\"\")",
        "drop the AAD on encrypt — profile-name binding gone",
    ),
    # --- Nonce discipline ---------------------------------------------------
    Mutant(
        "M5", CRYPTO,
        "    nonce = secrets.token_bytes(_NONCE_SIZE)",
        "    nonce = hashlib.sha256(plaintext).digest()[:_NONCE_SIZE]",
        "derive the nonce from the CONTENT — identical plaintexts reuse "
        "(key, nonce), which is catastrophic for GCM",
    ),
    Mutant(
        "M6", CRYPTO,
        "    nonce = secrets.token_bytes(_NONCE_SIZE)",
        "    nonce = b\"\\x00\" * _NONCE_SIZE",
        "fixed nonce — every profile encrypted under the same (key, nonce)",
    ),
    # --- Key derivation / validation ---------------------------------------
    Mutant(
        "M7", CRYPTO,
        "    master_key = _require_master_key(master_key)\n"
        "    return hashlib.sha256(master_key + profile_name.encode(\"utf-8\")).digest()",
        "    return hashlib.sha256(bytes(master_key) + profile_name.encode(\"utf-8\")).digest()",
        "restore the pre-fix behaviour: accept a master key of ANY length",
    ),
    Mutant(
        "M8", CRYPTO,
        "    return hashlib.sha256(master_key + profile_name.encode(\"utf-8\")).digest()",
        "    return hashlib.sha256(master_key).digest()",
        "drop the per-profile separation — every profile shares one key",
    ),
    Mutant(
        "M9", CRYPTO,
        "    if len(encrypted) < _NONCE_SIZE + _TAG_SIZE:  # nonce + minimum GCM tag",
        "    if False:  # nonce + minimum GCM tag",
        "remove the short-blob guard",
    ),
    # --- Key loading / cache ------------------------------------------------
    Mutant(
        "M10", CRYPTO,
        "                    if len(key) == _KEY_SIZE:",
        "                    if True:",
        "accept a key of any length from the hosted endpoint",
    ),
    Mutant(
        "M11", CRYPTO,
        "            if not hmac.compare_digest(mac, self._cache_mac(obfuscated, salt)):",
        "            if False:",
        "accept an unauthenticated / foreign / planted key cache",
    ),
    # RESTATED TWICE, and the reason is worth keeping.
    #
    # Attempt 1 changed only the mode passed to `os.open` -> SURVIVED.
    # Attempt 2 removed only the trailing `chmod`          -> SURVIVED.
    #
    # Neither was a hole. The 0600 file mode is protected by TWO redundant
    # guards, so removing either one alone leaves the observable mode correct and
    # no outcome-observing test can possibly kill it. Reporting either as a
    # survivor would have been a false finding. The mutant that actually tests
    # the property removes BOTH, and it is killed. Recorded here rather than
    # quietly dropped, because "a survivor that is really a redundancy" and "a
    # survivor that is really a gap" look identical in a summary line.
    Mutant(
        "M12", CRYPTO,
        "            fd = os.open(\n"
        "                self.CACHE_FILE,\n"
        "                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,\n"
        "                stat.S_IRUSR | stat.S_IWUSR,\n"
        "            )\n"
        "            try:\n"
        "                os.write(fd, blob)\n"
        "            finally:\n"
        "                os.close(fd)\n"
        "            try:\n"
        "                self.CACHE_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600\n"
        "            except OSError:  # pragma: no cover - platform-dependent\n"
        "                pass\n",
        "            self.CACHE_FILE.write_bytes(blob)\n",
        "restore the world-readable key cache — remove BOTH redundant 0600 "
        "guards (removing either one alone is unkillable by construction)",
    ),
    Mutant(
        "M12b", CRYPTO,
        "            try:\n"
        "                self.CACHE_DIR.chmod(stat.S_IRWXU)  # 0700\n"
        "            except OSError:  # pragma: no cover - platform-dependent (e.g. Windows)\n"
        "                pass\n",
        "",
        "remove the chmod that fixes the key-cache DIRECTORY mode at 0700",
    ),
    Mutant(
        "M13", CRYPTO,
        "    parts = (\n"
        "        os.environ.get(\"COMPUTERNAME\", \"\")\n"
        "        + os.environ.get(\"HOSTNAME\", \"\")\n"
        "        + platform.node()\n"
        "    )",
        "    parts = (\n"
        "        os.environ.get(\"COMPUTERNAME\", \"\")\n"
        "        + os.environ.get(\"HOSTNAME\", \"\")\n"
        "    )",
        "restore the salt that collapses to sha256(b'') on POSIX",
    ),
    Mutant(
        "M14", CRYPTO,
        "                    key = base64.b64decode(key_b64, validate=True)",
        "                    key = base64.b64decode(key_b64)",
        "restore silent discarding of non-base64 characters",
    ),
    # --- Router: fail-closed + honest accounting ---------------------------
    Mutant(
        "M15", ROUTER,
        "                except InvalidTag as e:\n"
        "                    # THE TAMPER SIGNAL. AES-GCM refused the tag: the bytes on\n"
        "                    # disk are not the bytes that were sealed, or this is not the\n"
        "                    # key they were sealed with. Previously this was one ERROR\n"
        "                    # line in an unchained log; it is now a row on the\n"
        "                    # hash-chained rail carrying which bytes and which key, AND a\n"
        "                    # named unit in the work-done report below -- it must never\n"
        "                    # vanish into a log line while the summary reports a clean\n"
        "                    # load. InvalidTag carries an EMPTY message, so the exception\n"
        "                    # type is named explicitly or the operator gets no reason at\n"
        "                    # all.\n"
        "                    report.encrypted_failed.append(f.name)\n"
        "                    logger.error(",
        "                except InvalidTag as e:\n"
        "                    # THE TAMPER SIGNAL. AES-GCM refused the tag: the bytes on\n"
        "                    # disk are not the bytes that were sealed, or this is not the\n"
        "                    # key they were sealed with. Previously this was one ERROR\n"
        "                    # line in an unchained log; it is now a row on the\n"
        "                    # hash-chained rail carrying which bytes and which key, AND a\n"
        "                    # named unit in the work-done report below -- it must never\n"
        "                    # vanish into a log line while the summary reports a clean\n"
        "                    # load. InvalidTag carries an EMPTY message, so the exception\n"
        "                    # type is named explicitly or the operator gets no reason at\n"
        "                    # all.\n"
        "                    logger.error(",
        "stop recording which files failed to authenticate — the failure "
        "becomes a log line only",
    ),
    Mutant(
        "M16", ROUTER,
        "        if report.encrypted_failed or report.encrypted_rejected:\n"
        "            logger.error(\"ProfileRouter: %s\", report.summary(self.profile_dir))\n"
        "        else:\n"
        "            logger.info(\"ProfileRouter: %s\", report.summary(self.profile_dir))",
        "        logger.info(\n"
        "            \"ProfileRouter: loaded %d valid profiles from %s\",\n"
        "            len(profiles),\n"
        "            self.profile_dir,\n"
        "        )",
        "restore the clean-looking success line that reads the same over zero "
        "successful decrypts",
    ),
    Mutant(
        "M17", ROUTER,
        "                    report.encrypted_failed.append(f.name)\n"
        "                    logger.error(\n"
        "                        \"AUTHENTICATION FAILED for encrypted profile %s (%s) — \"",
        "                    report.encrypted_failed.append(f.name)\n"
        "                    profiles[profile_name] = yaml.safe_load(encrypted) or {}\n"
        "                    logger.error(\n"
        "                        \"AUTHENTICATION FAILED for encrypted profile %s (%s) — \"",
        "FALL BACK TO PLAINTEXT on decrypt failure — the highest-severity "
        "outcome available to this flow",
    ),
    Mutant(
        "M18", ROUTER,
        "        if enc_files and not self._decryption_key:",
        "        if False:",
        "attempt decryption with a None key instead of skipping",
    ),
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
    return proc.returncode == 0, (proc.stdout + proc.stderr)[-1200:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    root = REPO_ROOT
    results: list[Result] = []

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
            results.append(Result(m.mid, m.intent, False, "NOT_APPLIED",
                                  "anchor text not found — the mutant never reached the interpreter"))
            print(f"  {m.mid} NOT_APPLIED  {m.intent}")
            continue
        if original.count(m.old) != 1:
            results.append(Result(m.mid, m.intent, False, "NOT_APPLIED",
                                  f"anchor is ambiguous ({original.count(m.old)} matches)"))
            print(f"  {m.mid} NOT_APPLIED  {m.intent}")
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
        results.append(
            Result(m.mid, m.intent, True, verdict, "" if passed else out[-300:], m.control)
        )
        print(f"  {m.mid} {verdict:9s} {m.intent}")

    clear_pycache(root)
    green_after, out_after = run_suite(root)

    applied = [r for r in results if r.applied]
    killed = [r for r in applied if r.verdict == "KILLED"]
    survived = [r for r in applied if r.verdict == "SURVIVED" and not r.control]
    controls_ok = [r for r in applied if r.control and r.verdict == "SURVIVED"]
    controls_bad = [r for r in applied if r.control and r.verdict == "KILLED"]
    not_applied = [r for r in results if not r.applied]

    # Floor invariant 9: name the units of work-not-done; never report only the
    # aggregate; gate the wording on work DONE, not absence-of-failure.
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

    print("\n" + "=" * 70)
    print(f"verdict            : {verdict}")
    print(f"mutants generated  : {len(MUTANTS)}")
    print(f"mutants APPLIED    : {len(applied)}   <- the work-done number")
    print(f"KILLED             : {len(killed)}")
    print(f"SURVIVED           : {len(survived)}")
    for r in survived:
        print(f"    - {r.mid}: {r.intent}")
    print(f"controls SURVIVED  : {len(controls_ok)} (expected)")
    print(f"controls KILLED    : {len(controls_bad)} (must be 0)")
    print(f"NOT APPLIED        : {len(not_applied)}")
    for r in not_applied:
        print(f"    - {r.mid}: {r.detail}")
    print(f"final baseline     : {'GREEN' if green_after else 'RED'}")
    print("=" * 70)

    if args.json:
        Path(args.json).write_text(json.dumps({
            "verdict": verdict,
            "totals": {
                "generated": len(MUTANTS),
                "applied": len(applied),
                "killed": len(killed),
                "survived": len(survived),
                "not_applied": len(not_applied),
                "controls_survived_as_expected": len(controls_ok),
                "controls_unexpectedly_killed": len(controls_bad),
            },
            "survivors": [r.mid for r in survived],
            "not_applied": [{"id": r.mid, "reason": r.detail} for r in not_applied],
            "final_baseline_green": green_after,
            "results": [r.__dict__ for r in results],
        }, indent=2))

    return 0 if verdict == "CLEAN" else 2


if __name__ == "__main__":
    sys.exit(main())
