"""
Load testing suite for Arkheia Enterprise Proxy.

PASSING CRITERIA (must pass before Phase 3):
  1. 10,000 concurrent users can call /detect/verify
  2. p99 latency < 50ms
  3. p50 latency < 10ms
  4. Zero request failures (all return HTTP 200)
  5. Profile reload under load -- no dropped requests during atomic swap

Run with locust:
  locust -f proxy/tests/test_load.py --headless -u 10000 -r 500 \
         --host http://localhost:8099 --run-time 60s

Or for quick CI smoke test:
  locust -f proxy/tests/test_load.py --headless -u 100 -r 50 \
         --host http://localhost:8099 --run-time 10s

Unit-style async load test (no locust required):
  pytest proxy/tests/test_load.py::test_concurrent_async_load -v
"""

import asyncio
import random
import statistics
import time
from typing import List

import httpx
import pytest

try:
    from locust import HttpUser, between, task
    HAS_LOCUST = True
except ImportError:
    HAS_LOCUST = False

# ---------------------------------------------------------------------------
# Locust load test (used when locust is installed)
# ---------------------------------------------------------------------------

if HAS_LOCUST:
    MODELS = ["claude-sonnet-4-6", "gpt-4o", "grok-3-mini-fast"]
    PROMPTS = [
        ("What is the capital of France?", "The capital of France is Paris."),
        ("Summarize quantum computing.", "Quantum computing uses quantum bits."),
        ("List Python best practices.", "Use type hints, write tests, keep functions small."),
    ]

    class ArkheiaProxyUser(HttpUser):
        """
        Simulates enterprise AI traffic hitting /detect/verify.

        PASSING CRITERIA:
          - Failure rate: 0%
          - p50 response time: < 10ms
          - p99 response time: < 50ms
        """
        wait_time = between(0.001, 0.01)   # 1-10ms between requests per user

        @task(10)
        def verify_known_model(self):
            prompt, response = random.choice(PROMPTS)
            self.client.post(
                "/detect/verify",
                json={
                    "prompt": prompt,
                    "response": response,
                    "model_id": random.choice(MODELS),
                },
                name="/detect/verify [known_model]",
            )

        @task(2)
        def verify_unknown_model(self):
            """Unknown model should return UNKNOWN -- still 200."""
            self.client.post(
                "/detect/verify",
                json={
                    "prompt": "test prompt",
                    "response": "test response",
                    "model_id": "unknown-model-xyz",
                },
                name="/detect/verify [unknown_model]",
            )

        @task(1)
        def health_check(self):
            self.client.get("/admin/health", name="/admin/health")


# ---------------------------------------------------------------------------
# Async load test (pytest, no locust required)
# ---------------------------------------------------------------------------

PROXY_URL = "http://localhost:8099"
CONCURRENCY_TARGET = 10_000
LATENCY_P50_MS = 10
LATENCY_P99_MS = 50


async def _single_verify(client: httpx.AsyncClient, model: str) -> tuple[bool, float]:
    """Send one /detect/verify and return (success, latency_ms)."""
    t0 = time.monotonic()
    try:
        resp = await client.post(
            f"{PROXY_URL}/detect/verify",
            json={
                "prompt": "What is the capital of France?",
                "response": "The capital of France is Paris.",
                "model_id": model,
            },
            timeout=5.0,
        )
        latency_ms = (time.monotonic() - t0) * 1000
        success = resp.status_code == 200 and resp.json().get("risk_level") in (
            "LOW", "MEDIUM", "HIGH", "UNKNOWN"
        )
        return success, latency_ms
    except Exception:
        latency_ms = (time.monotonic() - t0) * 1000
        return False, latency_ms


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,  # Set to False to run against a live server
    reason="Requires live proxy on localhost:8099 -- run manually",
)
async def test_concurrent_async_load():
    """
    Async load test: 1000 concurrent requests (smoke; full 10k via locust).

    PASSING CRITERIA:
      1. All 1000 requests return HTTP 200
      2. p50 latency < 10ms
      3. p99 latency < 50ms
    """
    n = 1_000
    models = ["claude-sonnet-4-6", "gpt-4o", "grok-3-mini-fast"]

    async with httpx.AsyncClient() as client:
        tasks = [
            _single_verify(client, random.choice(models))
            for _ in range(n)
        ]
        results = await asyncio.gather(*tasks)

    successes = [r for r in results if r[0]]
    latencies: List[float] = [r[1] for r in results]

    failure_count = n - len(successes)
    p50 = statistics.median(latencies)
    p99 = sorted(latencies)[int(0.99 * len(latencies))]

    print(f"\nLoad test results ({n} requests):")
    print(f"  Failures:    {failure_count} / {n}")
    print(f"  p50 latency: {p50:.1f}ms  (target < {LATENCY_P50_MS}ms)")
    print(f"  p99 latency: {p99:.1f}ms  (target < {LATENCY_P99_MS}ms)")

    # CRITERION 4: Zero failures
    assert failure_count == 0, f"{failure_count} requests failed"

    # CRITERION 3: p50 < 10ms
    assert p50 < LATENCY_P50_MS, f"p50 {p50:.1f}ms exceeds target {LATENCY_P50_MS}ms"

    # CRITERION 2: p99 < 50ms
    assert p99 < LATENCY_P99_MS, f"p99 {p99:.1f}ms exceeds target {LATENCY_P99_MS}ms"


@pytest.mark.asyncio
@pytest.mark.skipif(
    True,
    reason="Requires live proxy on localhost:8099 -- run manually",
)
async def test_reload_under_load():
    """
    CRITERION 5: Profile reload under concurrent load causes zero dropped requests.

    Fires reload while 500 requests are in flight.
    All requests must still return HTTP 200.
    """
    n = 500

    async def fire_requests():
        async with httpx.AsyncClient() as client:
            tasks = [
                _single_verify(client, "claude-sonnet-4-6")
                for _ in range(n)
            ]
            return await asyncio.gather(*tasks)

    async def trigger_reload():
        await asyncio.sleep(0.01)  # start reload 10ms into the load
        async with httpx.AsyncClient() as client:
            await client.post(f"{PROXY_URL}/admin/registry/pull", timeout=5.0)

    results, _ = await asyncio.gather(fire_requests(), trigger_reload())

    failures = [r for r in results if not r[0]]
    assert len(failures) == 0, f"{len(failures)} requests failed during reload"
