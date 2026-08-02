"""
Flow F2 — "Provider inference wrappers + mandatory Arkheia screening".

The word that carries the product claim is *mandatory*: inference routed through
``run_grok`` / ``run_gemini`` / ``run_ollama`` / ``run_together`` **is** screened
for fabrication. That claim is what an InTouch-style "Screened by Arkheia
detection" footer rests on, so the only question worth asking of these four
functions is: **can a provider response reach a caller without being screened?**

At base 3037f0c these four functions had **ZERO behavioural tests anywhere in
the repository**, in CI or out. ``tests/test_smoke_e2e.py`` names them in a
``tools/list`` assertion (line 129-132) and never calls them; that suite is
itself excluded from ``unit-tests`` by ``--ignore`` and its own workflow triggers
on ``[main, staging]`` while the default branch is ``master``. So the headline
claim of the flow was carried entirely by four docstrings — the *presence is not
effect* class.

``tests/test_screening_floor.py`` enforces the STRUCTURE statically (no return
path carries provider output without the verdict). This file pins the
BEHAVIOUR: what the caller actually receives, including on every degraded path.

------------------------------------------------------------------------------
On assertion strength
------------------------------------------------------------------------------
Every verdict below is pinned POSITIVELY to an exact value. There is no
``assert risk != "HIGH"``, no ``assert result is not None``, no bare
"it did not raise": those pass against a wrong-but-not-that answer and **no
mutation can reveal them**. Where a test asserts something is ABSENT (the
provider was not called, screening did not happen), it is paired in the same
test with a positive control proving the mechanism that would have made it
present does work.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from mcp_server import server as srv
from mcp_server import tool_registry
from mcp_server.proxy_client import ProxyClient

PROMPT = "Summarise the 2019 Zhang et al. paper on quantum tunnelling in membranes."
PROVIDER_TEXT = (
    "Zhang et al. (2019) reported in Nature Physics that quantum tunnelling in lipid "
    "bilayers accounts for 42% of proton transport."
)

# (tool name, the wrapper coroutine, the provider function bound in server's
# namespace, the tool's DEFAULT model). The default matters: it is what an agent
# gets when it does not name a model, so it is the configuration actually shipped.
WRAPPERS = [
    ("run_grok", "run_grok", "call_grok", "grok-4-fast-non-reasoning"),
    ("run_gemini", "run_gemini", "call_gemini", "gemini-2.5-flash"),
    ("run_ollama", "run_ollama", "call_ollama", "phi4:14b"),
    ("run_together", "run_together", "call_together", "moonshotai/Kimi-K2.5"),
]
WRAPPER_IDS = [w[0] for w in WRAPPERS]


def _provider_ok(text: str = PROVIDER_TEXT) -> dict:
    return {
        "response": text,
        "model": "set-by-the-wrapper",
        "prompt_hash": "deadbeef",
        "error": None,
    }


def _provider_failed(error: str = "http_429") -> dict:
    """The exact shape providers.py::_err_response produces."""
    return {
        "response": f"[provider_error: {error}]",
        "model": "m",
        "prompt_hash": "deadbeef",
        "error": error,
    }


@pytest.fixture
def screening(monkeypatch):
    """Replace the module-level ProxyClient with a recording double."""
    mock = AsyncMock(spec=ProxyClient)
    monkeypatch.setattr(srv, "proxy", mock)
    return mock


@pytest.fixture
def provider(monkeypatch):
    """Bind a recording double over a named provider function in server's namespace."""
    def _bind(provider_attr: str, result: dict) -> AsyncMock:
        mock = AsyncMock(return_value=result)
        monkeypatch.setattr(srv, provider_attr, mock)
        return mock
    return _bind


def _tool(name: str):
    fn = getattr(srv, name)
    assert callable(fn), f"{name} is not callable on mcp_server.server"
    return fn


# ---------------------------------------------------------------------------
# 1. Screening happens, on the right bytes, exactly once
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_wrapper_screens_the_provider_response_verbatim(
    screening, provider, name, tool, prov, default_model
):
    """
    The load-bearing behaviour: the wrapper screens the PROVIDER'S OUTPUT — not
    the prompt, not a placeholder — under the model the provider was called
    with, exactly once.
    """
    prov_mock = provider(prov, _provider_ok())
    screening.verify.return_value = {"risk_level": "LOW", "confidence": 0.9,
                                     "features_triggered": [], "error": None}

    await _tool(tool)(prompt=PROMPT)

    prov_mock.assert_awaited_once_with(PROMPT, default_model)
    screening.verify.assert_awaited_once_with(
        prompt=PROMPT,
        response=PROVIDER_TEXT,
        model_id=default_model,
    )


@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_wrapper_screens_the_model_the_caller_asked_for(
    screening, provider, name, tool, prov, default_model
):
    """
    An explicit model must reach BOTH the provider and the screener. A wrapper
    that called the provider with model X and screened under the default would
    produce a verdict from the wrong fingerprint.
    """
    explicit = "an-explicitly-requested-model"
    prov_mock = provider(prov, _provider_ok())
    screening.verify.return_value = {"risk_level": "LOW", "confidence": 0.9,
                                     "features_triggered": [], "error": None}

    await _tool(tool)(prompt=PROMPT, model=explicit)

    prov_mock.assert_awaited_once_with(PROMPT, explicit)
    assert screening.verify.await_args.kwargs["model_id"] == explicit
    assert screening.verify.await_args.kwargs["model_id"] != default_model


# ---------------------------------------------------------------------------
# 2. The verdict reaches the caller unaltered — all four bands
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.parametrize(
    "risk,confidence",
    [("LOW", 0.91), ("MEDIUM", 0.55), ("HIGH", 0.87), ("UNKNOWN", 0.0)],
)
@pytest.mark.asyncio
async def test_wrapper_passes_the_verdict_through_unaltered(
    screening, provider, name, tool, prov, default_model, risk, confidence
):
    """
    Identity across every band, INCLUDING UNKNOWN. Per the contract a model
    without usable evidence yields an evidence-limited verdict, which is a
    couldn't-assess and not a clean bill of health — so the one thing the
    wrapper must never do is render it as anything else. Asserting all four
    bands in one parametrised set is what makes 'UNKNOWN survives' meaningful:
    a wrapper that hardcoded a single band would fail three of the four.
    """
    provider(prov, _provider_ok())
    verdict = {
        "risk_level": risk,
        "confidence": confidence,
        "features_triggered": ["reasoning_ratio"],
        "detection_id": "det-1",
        "evidence_depth_limited": risk == "UNKNOWN",
        "detection_method": "profile_ensemble",
        "profile_model_id": "some-profile",
        "source": "local",
    }
    screening.verify.return_value = verdict

    result = await _tool(tool)(prompt=PROMPT)

    assert result["arkheia"] == verdict
    assert result["arkheia"]["risk_level"] == risk
    assert result["arkheia"]["confidence"] == confidence
    # Nothing is dropped on the way through: the fields that say what the
    # verdict MEANS survive the wrapper as well as the risk band does.
    assert result["arkheia"]["evidence_depth_limited"] is (risk == "UNKNOWN")
    assert result["arkheia"]["detection_method"] == "profile_ensemble"
    assert result["arkheia"]["profile_model_id"] == "some-profile"


@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_wrapper_preserves_the_provider_payload(
    screening, provider, name, tool, prov, default_model
):
    """The response the caller acts on is the provider's, not the screener's."""
    provider(prov, _provider_ok())
    screening.verify.return_value = {"risk_level": "LOW", "confidence": 0.9,
                                     "features_triggered": [], "error": None}

    result = await _tool(tool)(prompt=PROMPT)

    assert result["response"] == PROVIDER_TEXT
    assert result["prompt_hash"] == "deadbeef"
    assert "arkheia" in result


# ---------------------------------------------------------------------------
# 3. Fail-open must not be fail-silent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.parametrize(
    "detection_error",
    ["proxy_unavailable", "proxy_timeout", "no_detection_available",
     "all_detection_paths_failed", "hosted_auth_failed", "hosted_quota_exceeded"],
)
@pytest.mark.asyncio
async def test_unscreened_response_is_never_presented_as_screened(
    screening, provider, name, tool, prov, default_model, detection_error
):
    """
    Detection is fail-open by design — inference must never be blocked. But an
    unscreened response that LOOKS screened is worse than a blocked one, so
    every reachable ProxyClient failure string must arrive at the caller as an
    explicit UNKNOWN carrying its reason, never as a band.
    """
    provider(prov, _provider_ok())
    screening.verify.return_value = {
        "risk_level": "UNKNOWN",
        "confidence": 0.0,
        "features_triggered": [],
        "error": detection_error,
    }

    result = await _tool(tool)(prompt=PROMPT)

    # The response still flows: fail-OPEN.
    assert result["response"] == PROVIDER_TEXT
    # And it is unambiguously marked unscreened: fail-open, not fail-silent.
    assert result["arkheia"]["risk_level"] == "UNKNOWN"
    assert result["arkheia"]["confidence"] == 0.0
    assert result["arkheia"]["error"] == detection_error


@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_provider_failure_is_still_screened_and_the_reason_survives(
    screening, provider, name, tool, prov, default_model
):
    """
    A failed provider call produces a synthetic marker string, and the wrapper
    screens THAT rather than skipping screening. Pinned deliberately: it means
    a verdict on a provider failure is a verdict about the marker, not about
    the model, and the caller distinguishes the two via the top-level `error`.
    """
    provider(prov, _provider_failed("http_429"))
    screening.verify.return_value = {"risk_level": "LOW", "confidence": 0.0,
                                     "features_triggered": [], "error": None}

    result = await _tool(tool)(prompt=PROMPT)

    screening.verify.assert_awaited_once_with(
        prompt=PROMPT,
        response="[provider_error: http_429]",
        model_id=default_model,
    )
    assert result["error"] == "http_429"
    assert result["response"] == "[provider_error: http_429]"


# ---------------------------------------------------------------------------
# 4. The refusal path carries no inference at all
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_policy_refusal_happens_before_any_inference(
    screening, provider, monkeypatch, name, tool, prov, default_model
):
    """
    De-registering the tool must refuse BEFORE the provider is called: no
    inference occurred, so there is nothing to screen and no unscreened output
    escapes. The 'was not called' assertions are paired with a positive control
    in the same test (re-register, call again, both mocks fire) so they cannot
    pass because the wrapper is simply broken.
    """
    prov_mock = provider(prov, _provider_ok())
    screening.verify.return_value = {"risk_level": "LOW", "confidence": 0.9,
                                     "features_triggered": [], "error": None}
    policy = tool_registry._REGISTRY[name]

    monkeypatch.delitem(tool_registry._REGISTRY, name)
    refused = await _tool(tool)(prompt=PROMPT)

    assert prov_mock.await_count == 0, "the provider was called despite a policy refusal"
    assert screening.verify.await_count == 0
    assert refused["risk_level"] == "UNKNOWN"
    assert name in refused["error"]
    assert "response" not in refused, (
        "a refusal must not carry model output — there was no inference"
    )

    # POSITIVE CONTROL: with the policy restored the same call reaches both.
    monkeypatch.setitem(tool_registry._REGISTRY, name, policy)
    allowed = await _tool(tool)(prompt=PROMPT)
    assert prov_mock.await_count == 1
    assert screening.verify.await_count == 1
    assert allowed["response"] == PROVIDER_TEXT


@pytest.mark.parametrize("name,tool,prov,default_model", WRAPPERS, ids=WRAPPER_IDS)
@pytest.mark.asyncio
async def test_refusal_and_success_shapes_are_both_pinned(
    screening, provider, monkeypatch, name, tool, prov, default_model
):
    """
    The two return shapes DIFFER, and that difference is a caller hazard worth
    pinning rather than discovering: the refusal path puts `risk_level` at the
    TOP level, while the success path nests the verdict under `arkheia` and has
    no top-level `risk_level` at all. A caller written against the refusal shape
    reads `result.get("risk_level")` as None on every successful call — None is
    not "HIGH", so it reads as benign.

    Pinned in both directions so any future harmonisation is a deliberate,
    visible change to this file rather than a silent one.
    """
    provider(prov, _provider_ok())
    screening.verify.return_value = {"risk_level": "HIGH", "confidence": 0.87,
                                     "features_triggered": [], "error": None}

    success = await _tool(tool)(prompt=PROMPT)
    assert success["arkheia"]["risk_level"] == "HIGH"
    assert "risk_level" not in success

    monkeypatch.delitem(tool_registry._REGISTRY, name)
    refusal = await _tool(tool)(prompt=PROMPT)
    assert refusal["risk_level"] == "UNKNOWN"
    assert "arkheia" not in refusal


# ---------------------------------------------------------------------------
# 5. ProxyClient's own degraded paths — the screening supply chain
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_detection_path_available_reports_unknown_with_a_reason(monkeypatch):
    """
    Local proxy refused and no hosted key configured: the honest answer is a
    named UNKNOWN, and NOT a band.
    """
    import httpx

    client = ProxyClient("http://127.0.0.1:9", api_key=None)

    class _Refusing:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Refusing())

    result = await client.verify("q", "a", "gpt-4o")

    assert result["risk_level"] == "UNKNOWN"
    assert result["confidence"] == 0.0
    assert result["error"] == "no_detection_available"


@pytest.mark.asyncio
async def test_local_outage_is_sticky_and_stays_visible(monkeypatch):
    """
    ``_local_available`` latches False after one ConnectError and, with no
    hosted key, is never retried for the lifetime of the process — so a
    transient proxy blip disables screening until restart.

    Pinned because the failure mode that matters is not the outage but the
    silence: the second call must still say UNKNOWN with a reason, and must
    demonstrably NOT have re-attempted the local proxy (attempt count stays at
    1). The count is asserted at both 1 and 1-after-two-calls, so 'no retry'
    cannot pass by the client never attempting anything at all.
    """
    import httpx

    attempts = {"n": 0}
    client = ProxyClient("http://127.0.0.1:9", api_key=None)

    class _Refusing:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, *a, **k):
            attempts["n"] += 1
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Refusing())

    first = await client.verify("q", "a", "gpt-4o")
    assert attempts["n"] == 1, "the first call must actually attempt the local proxy"
    assert first["risk_level"] == "UNKNOWN"
    assert first["error"] == "no_detection_available"

    second = await client.verify("q", "a", "gpt-4o")
    assert attempts["n"] == 1, (
        "local was re-attempted; if this behaviour is changed to retry, update "
        "this assertion deliberately"
    )
    assert second["risk_level"] == "UNKNOWN"
    assert second["error"] == "no_detection_available"
    assert client._local_available is False
