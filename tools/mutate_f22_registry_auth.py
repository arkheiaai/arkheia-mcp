#!/usr/bin/env python3
"""
Mutation harness for flow F22 — "Registry API-key auth (fail-closed)".

Runs the adversarial suite against DELIBERATELY BROKEN copies of the auth
gate. A mutation that SURVIVES is a hole in the suite: it means the suite
would not notice that break landing on master.

Why this exists rather than a coverage number: coverage says the line ran,
not that anything would have failed had the line been wrong. Every mutation
below is a real fail-open shape — a bypass, a disabled branch, an
enumeration oracle — and each must be KILLED.

Usage:
    python tools/mutate_f22_registry_auth.py            # all mutants
    python tools/mutate_f22_registry_auth.py --list

`__pycache__` is cleared before every trial: stale bytecode silently reverts
a mutation and reports a false SURVIVED.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUTH = ROOT / "registry_server" / "auth.py"
MAIN = ROOT / "registry_server" / "main.py"
SUITE = "registry_server/tests/test_registry_auth_adversarial.py"

# (id, file, find, replace, what break this simulates)
MUTANTS: list[tuple[str, Path, str, str, str]] = [
    (
        "M1-gate-removed", AUTH,
        "    if credentials is None or not _key_is_valid(credentials.credentials, valid_keys):",
        "    if False:",
        "the refusal branch never fires — any credential is accepted",
    ),
    (
        "M2-unprovisioned-allows-all", AUTH,
        "    if not valid_keys:\n        raise HTTPException(\n            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,",
        "    if not valid_keys:\n        return \"anonymous\"\n    if False:\n        raise HTTPException(\n            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,",
        "unprovisioned server serves everyone instead of no one — the exact "
        "inversion the flow is named against",
    ),
    (
        "M3-missing-credential-allowed", AUTH,
        "    if credentials is None or not _key_is_valid(credentials.credentials, valid_keys):",
        "    if credentials is not None and not _key_is_valid(credentials.credentials, valid_keys):",
        "no Authorization header at all is treated as authorised",
    ),
    (
        "M4-prefix-match", AUTH,
        "        if secrets.compare_digest(candidate_bytes, key_bytes):",
        "        if key_bytes.startswith(candidate_bytes[:8]):",
        "the compare degrades to a prefix match — an 8-char guess is enough",
    ),
    (
        "M5-early-return-position-leak", AUTH,
        "        if secrets.compare_digest(candidate_bytes, key_bytes):\n            found = True\n    return found",
        "        if secrets.compare_digest(candidate_bytes, key_bytes):\n            return True\n    return found",
        "short-circuit on first match — leaks the matching key's position",
    ),
    (
        "M6-plain-set-membership", AUTH,
        "    candidate_bytes = candidate.encode(\"utf-8\", errors=\"surrogatepass\")\n    found = False\n    for key in valid_keys:\n        key_bytes = key.encode(\"utf-8\", errors=\"surrogatepass\")\n        if secrets.compare_digest(candidate_bytes, key_bytes):\n            found = True\n    return found",
        "    return candidate in valid_keys",
        "reverts to the pre-fix hash-table compare (timing safety becomes an "
        "implementation detail again)",
    ),
    (
        "M7-enumeration-oracle", AUTH,
        "        raise HTTPException(\n            status_code=status.HTTP_401_UNAUTHORIZED,\n            detail=\"Invalid or missing API key\",",
        "        raise HTTPException(\n            status_code=status.HTTP_401_UNAUTHORIZED,\n            detail=(\"Missing API key\" if credentials is None else \"Unknown API key\"),",
        "unknown key answers differently from absent key — the difference IS "
        "the enumeration oracle",
    ),
    (
        "M8-credential-echoed", AUTH,
        "            detail=\"Invalid or missing API key\",",
        "            detail=f\"Invalid or missing API key: {credentials.credentials if credentials else None}\",",
        "the refusal quotes the presented credential back into every log "
        "between caller and server",
    ),
    (
        "M9-caller-supplied-header-override", AUTH,
        "async def require_auth(\n    credentials: HTTPAuthorizationCredentials = Security(_bearer),\n) -> str:",
        "from fastapi import Request as _Request\n\nasync def require_auth(\n    request: _Request,\n    credentials: HTTPAuthorizationCredentials = Security(_bearer),\n) -> str:\n    if request.headers.get(\"X-API-Key\"):\n        return request.headers[\"X-API-Key\"]",
        "a caller-supplied alternate header bypasses the check — the F-detect "
        "defect shape (caller influences the check applied to the caller)",
    ),
    (
        "M10-env-kill-switch", AUTH,
        "    valid_keys = _load_valid_keys()",
        "    if os.environ.get(\"ARKHEIA_DEV_MODE\"):\n        return \"dev\"\n    valid_keys = _load_valid_keys()",
        "a guard configured off — the proxy's ARKHEIA_REQUIRE_LICENSE shape, "
        "applied to registry auth",
    ),
    (
        "M11-route-dependency-dropped", MAIN,
        "async def list_profiles(\n    since: Optional[str] = Query(",
        "async def list_profiles(\n    _unused: Optional[str] = Query(default=None, include_in_schema=False),\n    since: Optional[str] = Query(",
        "control: a benign signature change that must NOT be flagged",
    ),
    (
        "M12-auth-dep-removed-from-download", MAIN,
        "async def download_profile(\n    model_id: str,\n    api_key: str = Depends(require_auth),\n):",
        "async def download_profile(\n    model_id: str,\n):",
        "a route ships without the auth dependency — the discovering test must "
        "catch it WITHOUT this file being edited",
    ),
]

CONTROL_MUTANTS = {"M11-route-dependency-dropped"}


def clear_pycache() -> None:
    for p in ROOT.rglob("__pycache__"):
        shutil.rmtree(p, ignore_errors=True)


def run_suite() -> tuple[bool, str]:
    clear_pycache()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", SUITE, "-q", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True,
    )
    return proc.returncode == 0, proc.stdout.strip().splitlines()[-1] if proc.stdout else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        for mid, path, _, _, why in MUTANTS:
            print(f"{mid:36s} {path.name:12s} {why}")
        return 0

    print("=== BASELINE (unmutated) ===")
    ok, summary = run_suite()
    print(f"  {summary}")
    if not ok:
        print("  BASELINE IS RED — fix the suite before trusting any mutation result.")
        return 2

    killed, survived, skipped = [], [], []
    for mid, path, find, replace, why in MUTANTS:
        original = path.read_text(encoding="utf-8")
        if find not in original:
            skipped.append(mid)
            print(f"\n=== {mid} ===\n  ANCHOR NOT FOUND in {path.name} — mutation not applied "
                  f"(the code moved; update the harness rather than trusting a pass)")
            continue
        try:
            path.write_text(original.replace(find, replace, 1), encoding="utf-8")
            ok, summary = run_suite()
        finally:
            path.write_text(original, encoding="utf-8")
            clear_pycache()

        is_control = mid in CONTROL_MUTANTS
        verdict = "SURVIVED" if ok else "KILLED"
        expected = "SURVIVED" if is_control else "KILLED"
        flag = "  <-- HOLE IN THE SUITE" if verdict != expected else ""
        print(f"\n=== {mid} ===\n  {why}\n  -> {verdict} (expected {expected}){flag}\n  {summary}")
        (survived if ok else killed).append(mid)

    real = [m for m in survived if m not in CONTROL_MUTANTS]
    print("\n" + "=" * 70)
    print(f"KILLED   : {len(killed)}")
    print(f"SURVIVED : {len(survived)}  (of which {len(CONTROL_MUTANTS & set(survived))} are controls)")
    if skipped:
        print(f"NOT APPLIED: {skipped}")
    if real:
        print(f"HOLES    : {real}")
        return 1
    if skipped:
        return 1
    print("No holes: every fail-open mutation is caught, and the control survives.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
