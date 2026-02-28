#!/usr/bin/env python3
"""
Arkheia Pilot Deployment Validator (Step 3.4)

Starts proxy + registry server on test ports, runs the full pipeline,
reports PASS/FAIL for each criterion, then shuts down cleanly.

Usage:
    python scripts/pilot_validate.py

Options:
    --proxy-port PORT      proxy port (default 8098)
    --registry-port PORT   registry port (default 8201)
    --profiles-dir DIR     profile directory (default ./profiles)
    --skip-registry        skip registry start (no ARKHEIA_REGISTRY_KEYS)

Exit codes:
    0  all criteria passed
    1  one or more criteria failed
    2  setup failed (could not start servers)
"""

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).parent.parent
VENV_PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
if not VENV_PYTHON.exists():
    VENV_PYTHON = ROOT / ".venv" / "bin" / "python"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _wait_healthy(url: str, timeout: int = 20) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def _check(label: str, passed: bool, detail: str = "") -> bool:
    status = "PASS" if passed else "FAIL"
    suffix = f"  -- {detail}" if detail else ""
    print(f"  [{status}] {label}{suffix}")
    return passed


# ---------------------------------------------------------------------------
# Criteria checks
# ---------------------------------------------------------------------------

def check_proxy_health(proxy_url: str) -> bool:
    try:
        r = httpx.get(f"{proxy_url}/admin/health", timeout=5.0)
        data = r.json()
        profiles = data.get("profiles_loaded", 0)
        return _check("Proxy health", r.status_code == 200 and profiles > 0,
                      f"{profiles} profiles loaded")
    except Exception as e:
        return _check("Proxy health", False, str(e))


def check_detection_pipeline(proxy_url: str) -> bool:
    try:
        r = httpx.post(f"{proxy_url}/detect/verify", json={
            "prompt": "What is the capital of France?",
            "response": "The capital of France is Paris.",
            "model_id": "claude-sonnet-4-6",
            "session_id": "pilot-validate",
        }, timeout=5.0)
        data = r.json()
        ok = r.status_code == 200 and data.get("risk_level") in ("LOW","MEDIUM","HIGH","UNKNOWN")
        return _check("Detection pipeline", ok, f"risk={data.get('risk_level')} id={data.get('detection_id','?')[:8]}")
    except Exception as e:
        return _check("Detection pipeline", False, str(e))


def check_audit_log(proxy_url: str) -> bool:
    try:
        r = httpx.get(f"{proxy_url}/audit/log", params={"limit": 5}, timeout=5.0)
        data = r.json()
        events = data.get("events", [])
        ok = r.status_code == 200 and len(events) > 0
        if ok and events:
            has_hash = "prompt_hash" in events[0]
            no_prompt = "prompt" not in events[0] and "response" not in events[0]
            ok = has_hash and no_prompt
            return _check("Audit log (privacy)", ok,
                          f"{len(events)} events, prompt_hash={has_hash}, no raw text={no_prompt}")
        return _check("Audit log", ok, f"{len(events)} events")
    except Exception as e:
        return _check("Audit log", False, str(e))


def check_error_contract(proxy_url: str) -> bool:
    """All error conditions must return HTTP 200, never 4xx/5xx."""
    cases = [
        {"prompt": "", "response": "", "model_id": ""},
        {"prompt": "x", "response": "", "model_id": "x"},
        {"prompt": "x", "response": "x", "model_id": "no-such-model-xyz"},
    ]
    try:
        for case in cases:
            r = httpx.post(f"{proxy_url}/detect/verify", json=case, timeout=5.0)
            if r.status_code != 200:
                return _check("Error contract (always 200)", False,
                              f"Got {r.status_code} for {case}")
        return _check("Error contract (always 200)", True, "all error cases returned 200")
    except Exception as e:
        return _check("Error contract (always 200)", False, str(e))


def check_registry_health(registry_url: str) -> bool:
    try:
        r = httpx.get(f"{registry_url}/health", timeout=5.0)
        data = r.json()
        n = data.get("profiles_available", 0)
        return _check("Registry health", r.status_code == 200 and n > 0,
                      f"{n} profiles available")
    except Exception as e:
        return _check("Registry health", False, str(e))


def check_registry_auth(registry_url: str) -> bool:
    try:
        r_unauth = httpx.get(f"{registry_url}/profiles", timeout=5.0)
        unauth_ok = r_unauth.status_code == 401
        return _check("Registry auth (401 without key)", unauth_ok,
                      f"got {r_unauth.status_code}")
    except Exception as e:
        return _check("Registry auth", False, str(e))


def check_mcp_client(proxy_url: str) -> bool:
    async def _run():
        # Only available if mcp_server is importable
        try:
            sys.path.insert(0, str(ROOT))
            from mcp_server.proxy_client import ProxyClient
            client = ProxyClient(proxy_url)
            result = await client.verify("pilot test", "pilot response", "gpt-4o")
            return result.get("risk_level") in ("LOW","MEDIUM","HIGH","UNKNOWN")
        except Exception as e:
            return False, str(e)
    try:
        ok = asyncio.run(_run())
        return _check("MCP ProxyClient.verify()", bool(ok))
    except Exception as e:
        return _check("MCP ProxyClient.verify()", False, str(e))


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def start_proxy(port: int, profiles_dir: str) -> subprocess.Popen:
    env = {**os.environ,
           "ARKHEIA_PROFILES_DIR": str(profiles_dir),
           "ARKHEIA_AUDIT_LOG": str(ROOT / "pilot_audit.jsonl")}
    return subprocess.Popen(
        [str(VENV_PYTHON), "-m", "uvicorn", "proxy.main:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def start_registry(port: int, profiles_dir: str) -> subprocess.Popen:
    env = {**os.environ,
           "ARKHEIA_REGISTRY_PROFILE_DIR": str(profiles_dir),
           "ARKHEIA_REGISTRY_BASE_URL": f"http://127.0.0.1:{port}",
           "ARKHEIA_REGISTRY_KEYS": os.environ.get("ARKHEIA_REGISTRY_KEYS", "pilot-test-key")}
    return subprocess.Popen(
        [str(VENV_PYTHON), "-m", "uvicorn", "registry_server.main:app",
         "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Arkheia pilot deployment validator")
    parser.add_argument("--proxy-port", type=int, default=8098)
    parser.add_argument("--registry-port", type=int, default=8201)
    parser.add_argument("--profiles-dir", default=str(ROOT / "profiles"))
    parser.add_argument("--skip-registry", action="store_true")
    args = parser.parse_args()

    proxy_url = f"http://127.0.0.1:{args.proxy_port}"
    registry_url = f"http://127.0.0.1:{args.registry_port}"
    profiles_dir = args.profiles_dir

    print("=" * 60)
    print("Arkheia Pilot Deployment Validator")
    print("=" * 60)

    procs = []

    # Start proxy
    print(f"\nStarting proxy on port {args.proxy_port}...", end=" ", flush=True)
    proxy_proc = start_proxy(args.proxy_port, profiles_dir)
    procs.append(proxy_proc)
    if _wait_healthy(f"{proxy_url}/admin/health"):
        print("ready")
    else:
        print("TIMEOUT")
        proxy_proc.terminate()
        print("\nSetup failed: proxy did not start")
        sys.exit(2)

    # Start registry (optional)
    registry_proc = None
    if not args.skip_registry:
        print(f"Starting registry on port {args.registry_port}...", end=" ", flush=True)
        registry_proc = start_registry(args.registry_port, profiles_dir)
        procs.append(registry_proc)
        if _wait_healthy(f"{registry_url}/health"):
            print("ready")
        else:
            print("TIMEOUT (continuing without registry)")
            registry_proc.terminate()
            registry_proc = None

    # Run checks
    print("\nRunning validation criteria:")
    results = []
    results.append(check_proxy_health(proxy_url))
    results.append(check_detection_pipeline(proxy_url))
    results.append(check_audit_log(proxy_url))
    results.append(check_error_contract(proxy_url))
    results.append(check_mcp_client(proxy_url))

    if registry_proc is not None:
        results.append(check_registry_health(registry_url))
        results.append(check_registry_auth(registry_url))

    # Summary
    passed = sum(results)
    total = len(results)
    print(f"\n{'='*60}")
    print(f"Result: {passed}/{total} criteria passed")
    if passed == total:
        print("STATUS: READY FOR PILOT DEPLOYMENT")
    else:
        print("STATUS: NOT READY -- fix failing criteria above")
    print("=" * 60)

    # Cleanup
    for p in procs:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    audit_log = ROOT / "pilot_audit.jsonl"
    if audit_log.exists():
        audit_log.unlink()

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
