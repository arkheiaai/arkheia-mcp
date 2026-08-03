"""
F2 round 2 — the fleet's default Grok path is NOT SCREENED, and that must be impossible to miss.

Runs in the REQUIRED `unit-tests` context (.github/workflows/unit-tests.yml, job `unit`,
`pytest ... mcp_server/tests ...` on push+pull_request to master).

THE FINDING THESE CLOSE (re-confirmed by measurement before anything was changed, and
independently reproduced by a second vendor):

    run_grok/call_grok default model id: grok-4.20-non-reasoning
    ProfileRouter("profiles").get("grok-4.20-non-reasoning")            -> None
    DetectionEngine.verify(..., "grok-4.20-non-reasoning")             ->
        risk_level='UNKNOWN' confidence=0.0 error='no_profile_for_model'
        profile_version='none' gate_action='advise'

  So the id the fleet reaches for by default cannot be screened at all. The `None` is
  CORRECT and is deliberately kept: `"grok-4.20-non-reasoning".startswith("grok-4")` is
  True, so before ProfileRouter._resolve_grok existed the id silently borrowed the
  **grok-4** profile and detection returned a confident verdict computed from a different
  model's fingerprint. An honest UNKNOWN beats a borrowed fingerprint.

  What was missing is that the honest UNKNOWN was QUIET. `run_grok` returned it nested
  inside `arkheia`, next to a top-level `error: None` from the provider call, with no
  statement anywhere that the response had not been assessed. A caller skimming the result
  sees a successful tool call.

INV-1  The default id genuinely has no profile — asserted against the REAL router and the
       REAL profiles/ directory, not a fixture. This is the regression test for the finding
       itself: if a grok-4.20 profile is ever added, this test fails and must be retired
       deliberately (with the KNOWINGLY_UNPROFILED entry removed in the same change).
INV-2  A tool result for an unscreened response says so, at the TOP level, in plain English,
       naming the reason and what would clear it.
INV-3  DIFFERENTIAL: a genuinely screened response is reported as screened, with no warning.
       Without this, `arkheia_screened = False` hardcoded would pass INV-2 and destroy the
       signal — a permanent "not screened" is as useless as a permanent "fine".
INV-4  EVERY provider wrapper carries the annotation, discovered from the module rather than
       enumerated, so a fifth `run_*` tool added later cannot ship quiet.
"""

from __future__ import annotations

import ast
import inspect
import pathlib
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mcp_server import server as server_module
from mcp_server.screening import annotate_screening, is_screened, unscreened_warning
from mcp_server.tools import providers

XAI_URL = "https://api.x.ai/v1/chat/completions"
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta"
    "/models/gemini-2.5-flash:generateContent"
)


def _use_provider_key(monkeypatch, provider: str, key: str) -> None:
    monkeypatch.setattr(
        providers,
        "provider_api_key",
        lambda requested: key if requested == provider else "",
    )

# The EXACT body /detect/verify returns for the fleet default, measured against the real
# engine + real profiles/ dir on 2026-07-26 (see module docstring). Not a paraphrase.
UNPROFILED_VERDICT = {
    "risk_level": "UNKNOWN",
    "confidence": 0.0,
    "features_triggered": [],
    "model_id": "grok-4.20-non-reasoning",
    "profile_version": "none",
    "timestamp": "2026-07-26T21:00:56.708554+00:00",
    "detection_id": "95d06397-3758-4d94-9888-0003346e0bdd",
    "error": "no_profile_for_model",
    "action": "pass",
    "gate_action": "advise",
}

SCREENED_VERDICT = {
    "risk_level": "LOW",
    "confidence": 0.88,
    "features_triggered": ["unique_token_ratio", "mean_logprob"],
    "model_id": "gemini-2.5-flash",
    "profile_version": "3.0",
    "timestamp": "2026-07-26T21:00:56.708554+00:00",
    "detection_id": "11111111-2222-3333-4444-555555555555",
    "error": None,
    "action": "pass",
    "gate_action": "advise",
    "evidence_depth_limited": False,
}


# ---------------------------------------------------------------------------
# INV-1 — the finding, reproduced against real ground truth
# ---------------------------------------------------------------------------

class TestTheDefaultGrokPathCannotBeScreened:

    def test_the_run_grok_default_id_resolves_to_no_profile(self):
        from proxy.router.profile_router import ProfileRouter

        repo_root = pathlib.Path(__file__).resolve().parents[2]
        router = ProfileRouter(str(repo_root / "profiles"))

        # POSITIVE CONTROL: the router really loaded profiles, so a None below means
        # "this id is unprofiled", not "the profile directory was empty".
        assert router.loaded_count > 40, (
            f"only {router.loaded_count} profiles loaded — the router is broken, so a "
            "None result below would prove nothing"
        )
        assert router.get("gemini-2.5-flash") is not None

        default = inspect.signature(server_module.run_grok).parameters["model"].default
        assert default == "grok-4.20-non-reasoning"
        assert router.get(default) is None

    @pytest.mark.asyncio
    async def test_the_engine_reports_no_profile_for_model(self):
        from proxy.detection.engine import DetectionEngine
        from proxy.router.profile_router import ProfileRouter

        repo_root = pathlib.Path(__file__).resolve().parents[2]
        engine = DetectionEngine(ProfileRouter(str(repo_root / "profiles")))
        default = inspect.signature(server_module.run_grok).parameters["model"].default

        result = await engine.verify(
            "what is the capital of France?", "Paris is the capital. " * 40, default
        )

        assert result.risk_level == "UNKNOWN"
        assert result.error == "no_profile_for_model"
        assert result.profile_version == "none"
        assert result.features_triggered == []
        # Never authorised to hard-block on an unprofiled model.
        assert result.gate_action == "advise"


# ---------------------------------------------------------------------------
# INV-2 / INV-3 — the caller surface, both directions
# ---------------------------------------------------------------------------

class TestTheCallerIsToldItWasNotScreened:

    @respx.mock
    @pytest.mark.asyncio
    async def test_run_grok_on_its_default_says_NOT_SCREENED_at_the_top_level(self, monkeypatch):
        _use_provider_key(monkeypatch, "xai", "xai-test-key")
        respx.post(XAI_URL).mock(
            return_value=httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Paris is the capital of France."}}]},
            )
        )

        with patch.object(
            server_module.proxy, "verify", AsyncMock(return_value=dict(UNPROFILED_VERDICT))
        ):
            result = await server_module.run_grok("what is the capital of France?")

        # The nested verdict is unchanged — we add signal, we never rewrite it.
        assert result["arkheia"]["risk_level"] == "UNKNOWN"
        assert result["arkheia"]["error"] == "no_profile_for_model"

        # ... and the top level now states it, where a caller cannot miss it.
        assert result["arkheia_screened"] is False
        assert result["arkheia_unscreened_reason"] == "no_profile_for_model"

        warning = result["arkheia_warning"]
        assert "NOT SCREENED" in warning
        assert "grok-4.20-non-reasoning" in warning
        # It must not be readable as an all-clear, and must say what would clear it.
        assert "not an all-clear" in warning.lower()
        assert "characteris" in warning.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_a_screened_response_is_reported_as_screened(self, monkeypatch):
        """
        DIFFERENTIAL CONTROL for the test above, through the same code path. A hardcoded
        `arkheia_screened = False` would pass that test and be a worse defect than the one
        being fixed: a permanent warning is ignored within a day.
        """
        _use_provider_key(monkeypatch, "google", "google-test-key")
        respx.post(GEMINI_URL).mock(
            return_value=httpx.Response(
                200,
                json={"candidates": [{"content": {"parts": [{"text": "Paris."}]}}]},
            )
        )

        with patch.object(
            server_module.proxy, "verify", AsyncMock(return_value=dict(SCREENED_VERDICT))
        ):
            result = await server_module.run_gemini("what is the capital of France?")

        assert result["arkheia_screened"] is True
        assert result["arkheia_unscreened_reason"] is None
        assert result["arkheia_warning"] is None


# ---------------------------------------------------------------------------
# INV-4 — no sibling wrapper ships quiet (auto-discovered, not enumerated)
# ---------------------------------------------------------------------------

class TestEveryProviderWrapperAnnotatesScreening:

    def test_every_run_tool_calls_the_annotator(self):
        """
        Structural, so a FIFTH provider wrapper added later is covered without anyone
        remembering this file. Parses mcp_server/server.py and requires every top-level
        async `run_*` tool to call `annotate_screening`.
        """
        source_path = pathlib.Path(server_module.__file__)
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))

        tools = [
            node
            for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name.startswith("run_")
        ]

        # POSITIVE CONTROL: an empty `tools` list would make the loop below vacuous.
        assert len(tools) >= 4, (
            f"expected >=4 run_* provider tools in {source_path.name}, found {len(tools)} "
            "— the AST scan is not finding what it is supposed to check"
        )

        missing = []
        for tool in tools:
            calls = {
                n.func.id
                for n in ast.walk(tool)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            }
            if "annotate_screening" not in calls:
                missing.append(tool.name)

        assert not missing, (
            "these provider tools return a detection verdict without annotating whether it "
            f"was screened: {missing}"
        )


# ---------------------------------------------------------------------------
# The pure helper — exhaustive case table (spec medium-fit: the table is the oracle)
# ---------------------------------------------------------------------------

class TestScreeningClassification:

    @pytest.mark.parametrize(
        "verdict, expected_screened",
        [
            ({"risk_level": "LOW"}, True),
            ({"risk_level": "MEDIUM"}, True),
            ({"risk_level": "HIGH"}, True),
            ({"risk_level": "CRITICAL"}, True),
            ({"risk_level": "low"}, True),                       # case-insensitive
            ({"risk_level": "UNKNOWN"}, False),
            ({"risk_level": ""}, False),
            ({}, False),                                          # no verdict at all
            (None, False),
            ({"risk_level": "LOW", "error": "proxy_timeout"}, False),   # verdict + error
            ({"risk_level": "UNKNOWN", "error": "no_profile_for_model"}, False),
        ],
    )
    def test_is_screened_case_table(self, verdict, expected_screened):
        assert is_screened(verdict) is expected_screened

    def test_an_error_beside_a_LOW_is_not_a_clean_LOW(self):
        """
        The specific shape that must never read clean: ProxyClient._unavailable() and the
        hosted mapper both produce a risk_level with an error beside it. A detection that
        errored did not observe the thing it was meant to observe, so it is neither
        observed-good nor observed-bad — it is not-observed, and must be visible as such.
        """
        assert is_screened({"risk_level": "LOW", "error": "hosted_quota_exceeded"}) is False
        warning = unscreened_warning("gpt-4o", {"risk_level": "LOW", "error": "hosted_quota_exceeded"})
        assert "NOT SCREENED" in warning
        assert "hosted_quota_exceeded" in warning

    def test_an_explicitly_evidence_limited_verdict_is_flagged_without_being_called_unscreened(self):
        """
        A verdict that reached a band but on zero computed features is 'couldn't-assess', the
        same distinction check_signal.py draws between `✓ LOW · assessed` and
        `○ LOW · couldn't-assess`. It IS screened (a profile ran), so `arkheia_screened` stays
        True — but it carries a warning, because a LOW off zero features is not evidence.
        """
        verdict = {
            "risk_level": "LOW",
            "confidence": 0.0,
            "features_triggered": [],
            "evidence_depth_limited": True,
        }
        assert is_screened(verdict) is True
        warning = unscreened_warning("grok-4", verdict)
        assert warning is not None
        assert "couldn't-assess" in warning

    def test_absent_evidence_depth_field_is_not_treated_as_limited(self):
        """
        Fail-loud must not become cry-wolf. /detect/verify did not emit
        `evidence_depth_limited` at all until this change, and inferring 'limited' from an
        ABSENT field would put a warning on every local LOW — a floor that cries wolf gets
        switched off, and then there is no floor. Only an EXPLICIT True counts.
        """
        verdict = {"risk_level": "LOW", "confidence": 0.9, "features_triggered": ["a", "b"]}
        assert unscreened_warning("gemini-2.5-flash", verdict) is None

    def test_annotate_never_mutates_or_drops_the_original_verdict(self):
        verdict = dict(UNPROFILED_VERDICT)
        provider_result = {"response": "hi", "model": "grok-4.20-non-reasoning", "error": None}

        annotated = annotate_screening(provider_result, verdict, "grok-4.20-non-reasoning")

        assert annotated["arkheia"] == UNPROFILED_VERDICT
        assert verdict == UNPROFILED_VERDICT          # unchanged
        assert annotated["response"] == "hi"          # provider fields preserved
        assert "arkheia_screened" not in provider_result  # caller's dict untouched

    def test_the_warning_never_echoes_the_prompt_or_the_response(self):
        """
        The warning is rendered into an agent's context and into logs. It carries the model
        id and the reason code only — never content.
        """
        verdict = dict(UNPROFILED_VERDICT)
        warning = unscreened_warning("grok-4.20-non-reasoning", verdict)
        assert verdict["detection_id"] not in warning
        assert "prompt" not in warning.lower()
