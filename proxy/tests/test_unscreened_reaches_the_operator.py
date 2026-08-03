"""
F2 round 2 — an UNKNOWN / no_profile_for_model detection must reach the OPERATOR as
"couldn't assess", never as a clean LOW.

Runs in the REQUIRED `unit-tests` context (.github/workflows/unit-tests.yml, job `unit`,
`pytest proxy/tests ...` on push+pull_request to master).

THE DEFECT THESE CLOSE, measured before the fix by driving the real endpoint with the real
engine and the real profiles/ directory and capturing the outbound governance push:

    POST /detect/verify {"model_id": "grok-4.20-non-reasoning", ...}   -> HTTP 200
      body:      risk_level="UNKNOWN"  error="no_profile_for_model"  profile_version="none"
      headers:   x-arkheia-risk: UNKNOWN
      schedule_push(risk_level=...) == 'LOW'        <-- THE LIE
      schedule_push(payload)        has no `error` key at all

  So the two surfaces disagreed. The response body was honest; the governance/analytics
  envelope — the one an operator actually looks at, aggregates and alerts on — recorded the
  fleet's unscreened default path as a clean LOW, and dropped the reason entirely. A
  detection that never ran was indistinguishable in the governance record from one that ran
  and found nothing wrong.

  `proxy/endpoints/detect.py` did this on purpose-looking code:
      risk_level=response.risk_level if response.risk_level in
                 ("LOW","MEDIUM","HIGH","CRITICAL") else "LOW"
  i.e. an unrecognised band was defaulted to the SAFEST-SOUNDING value. The honest default
  for "we do not recognise this" is UNKNOWN, never LOW.

INV-1  An unscreened detection is pushed to the governance surface as UNKNOWN, with its
       reason, never as LOW.
INV-2  DIFFERENTIAL: a genuinely LOW detection is still pushed as LOW. Without this,
       `risk_level="UNKNOWN"` hardcoded would pass INV-1 and destroy the signal.
INV-3  An unrecognised band is coerced to UNKNOWN (fail-loud), not to LOW (fail-clean).
INV-4  `evidence_depth_limited`, which the engine computes, actually reaches the caller —
       it was being dropped at the VerifyResponse boundary, so `LOW off zero features` was
       indistinguishable from a well-evidenced LOW.
INV-5  The operator DASHBOARD renders the reason for an adverse/unassessable verdict, not a
       bare badge. A badge with the reason swallowed is, for a trust product,
       indistinguishable from fabrication (DONE.md Gate-9 legibility criterion, v1.12).
"""

from __future__ import annotations

import pathlib
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.detection.engine import DetectionEngine
from proxy.endpoints.admin import router as admin_router
from proxy.endpoints.detect import router as detect_router
from proxy.router.profile_router import ProfileRouter

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE_DIR = str(REPO_ROOT / "profiles")

# Long enough that structural features are computable — a short response would be rejected
# by the empty-output gate and we would be measuring the wrong thing.
PROSE = (
    "The capital of France is Paris, a city on the river Seine with a population of "
    "roughly two million people inside the city limits. "
) * 6


@pytest.fixture
def client_and_pushes():
    """Real engine + real profiles, with the outbound governance push captured."""
    app = FastAPI()
    app.include_router(detect_router)
    router = ProfileRouter(PROFILE_DIR)
    # POSITIVE CONTROL: the profile dir really loaded, so a "no profile" result below means
    # the model is unprofiled and not that we pointed at an empty directory.
    assert router.loaded_count > 40, f"only {router.loaded_count} profiles loaded"
    app.state.engine = DetectionEngine(router)
    app.state.audit_writer = None
    app.state.settings = None

    pushes: list[dict] = []
    with patch("proxy.endpoints.detect.schedule_push", lambda **kw: pushes.append(kw)):
        yield TestClient(app), pushes


def _verify(client, model_id: str, response_text: str = PROSE):
    return client.post(
        "/detect/verify",
        json={"prompt": "what is the capital of France?", "response": response_text,
              "model_id": model_id},
    )


# ---------------------------------------------------------------------------
# INV-1 / INV-2 — the governance envelope, both directions
# ---------------------------------------------------------------------------

class TestTheGovernanceEnvelopeDoesNotSayLOW:

    def test_an_unprofiled_model_is_pushed_as_UNKNOWN_with_its_reason(self, client_and_pushes):
        client, pushes = client_and_pushes

        r = _verify(client, "grok-4.20-non-reasoning")

        assert r.status_code == 200
        body = r.json()
        assert body["risk_level"] == "UNKNOWN"
        assert body["error"] == "no_profile_for_model"

        assert len(pushes) == 1
        push = pushes[0]
        assert push["risk_level"] == "UNKNOWN", (
            "the governance envelope recorded the fleet's unscreened default as "
            f"{push['risk_level']!r}"
        )
        assert push["risk_level"] != "LOW"
        # The reason must travel with it: a bare UNKNOWN band with no reason is the
        # "computer says no with the evidence swallowed" failure.
        assert push["payload"]["error"] == "no_profile_for_model"
        assert push["payload"]["risk_level"] == "UNKNOWN"
        assert push["payload"]["profile_version"] == "none"

    def test_a_genuinely_low_detection_is_still_pushed_as_LOW(self, client_and_pushes):
        """
        DIFFERENTIAL CONTROL for the test above, through the same code path. phi4:14b has a
        real profile whose features are computable from text alone, so this is a REAL LOW
        from the real engine, not a stub. Without this row, `risk_level="UNKNOWN"` hardcoded
        would pass INV-1 while making every band meaningless.
        """
        client, pushes = client_and_pushes

        r = _verify(client, "phi4:14b")

        assert r.status_code == 200
        assert r.json()["risk_level"] == "LOW"
        assert r.json()["error"] is None
        assert pushes[0]["risk_level"] == "LOW"
        assert pushes[0]["payload"]["error"] is None
        assert pushes[0]["payload"]["features_triggered"], (
            "expected real features to have fired — otherwise this is not a screened LOW "
            "and the control row proves nothing"
        )

    def test_an_unrecognised_band_defaults_to_UNKNOWN_not_LOW(self, client_and_pushes):
        """
        INV-3. The rule under test is the DEFAULT direction: whatever we do not recognise
        must land on the loud value. The previous code defaulted to the quietest one.
        """
        client, pushes = client_and_pushes

        class _Weird:
            risk_level = "SOMETHING_NEW"
            confidence = 0.5
            features_triggered: list[str] = []
            model_id = "phi4:14b"
            profile_version = "9.9"
            timestamp = "2026-07-26T00:00:00+00:00"
            detection_id = "d"
            error = None
            gate_action = "advise"
            evidence_depth_limited = True

        class _Engine:
            async def verify(self, *a, **k):
                return _Weird()

        client.app.state.engine = _Engine()
        _verify(client, "phi4:14b")

        assert pushes[0]["risk_level"] == "UNKNOWN"
        assert pushes[0]["risk_level"] != "LOW"


# ---------------------------------------------------------------------------
# INV-4 — the evidence-depth flag reaches the caller
# ---------------------------------------------------------------------------

class TestEvidenceDepthReachesTheCaller:

    def test_evidence_depth_limited_is_returned(self, client_and_pushes):
        """
        The engine computes `evidence_depth_limited` and VerifyResponse dropped it, so a
        caller could not tell `✓ LOW · assessed` from `○ LOW · couldn't-assess`. phi4:14b
        fires three real features, so this is the well-evidenced direction.
        """
        client, _ = client_and_pushes
        body = _verify(client, "phi4:14b").json()
        assert body["evidence_depth_limited"] is False

    def test_a_LOW_off_zero_features_is_reported_as_evidence_limited(self, client_and_pushes):
        """
        DIFFERENTIAL. claude-sonnet-4-6 returns LOW with ZERO features fired on this
        text-only path — the exact shape that must not read as a clean assessment. Measured,
        not assumed; if the profile changes so features do fire, this test fails loudly
        rather than silently asserting nothing.
        """
        client, _ = client_and_pushes
        body = _verify(client, "claude-sonnet-4-6").json()
        assert body["risk_level"] == "LOW"
        assert body["features_triggered"] == []
        assert body["evidence_depth_limited"] is True


# ---------------------------------------------------------------------------
# INV-5 — the operator dashboard shows the reason, not a bare badge
# ---------------------------------------------------------------------------

class TestTheDashboardShowsWhyItCouldNotAssess:
    """
    Fetches the ADVERTISED operator surface over HTTP (GET /ui) rather than asserting on the
    module constant, so a route that stops serving the template fails this too.

    HONEST LIMITATION, stated so a pass is not over-read: the dashboard is a static template
    with client-side rendering, so this checks that the reason fields are WIRED INTO the
    template. It does not execute the JavaScript, so it does not prove the rendered DOM. A
    browser-level assertion belongs in the Playwright tier (Gate 7) and is NOT covered here.
    """

    @pytest.fixture
    def ui(self):
        from proxy.auth import COOKIE_NAME, create_jwt

        app = FastAPI()
        app.include_router(admin_router)
        client = TestClient(app)
        client.cookies.set(COOKIE_NAME, create_jwt("operator@arkheia.ai"))
        return client.get("/admin/ui")

    def test_the_ui_is_served(self, ui):
        """
        POSITIVE CONTROL for every assertion below: without a real 200 the substring checks
        would pass or fail on the text of a redirect, proving nothing about the dashboard.
        """
        assert ui.status_code == 200, (
            f"expected the dashboard, got {ui.status_code} — the assertions below would be "
            "measuring the wrong document"
        )
        assert "arkheia" in ui.text.lower()

    def test_the_expand_panel_renders_the_detection_reason(self, ui):
        assert "Detection reason" in ui.text
        assert "e.error" in ui.text

    def test_the_expand_panel_renders_the_profile_version(self, ui):
        assert "Profile version" in ui.text
        assert "e.profile_version" in ui.text

    def test_an_unassessed_row_states_what_would_clear_it(self, ui):
        """
        DONE.md Gate-9 v1.12: an adverse verdict must state what would clear it. For UNKNOWN
        that is a characterisation run for the model id.
        """
        assert "What would clear it" in ui.text
        assert "couldn't assess" in ui.text or "couldn't-assess" in ui.text

    def test_unknown_is_never_styled_as_the_low_band(self, ui):
        """
        The badge helper maps anything outside HIGH/MEDIUM/LOW to the UNKNOWN class. Pinned
        because a 'tidy-up' that folded the default into LOW would repaint every unscreened
        detection green.
        """
        assert ".badge-UNKNOWN" in ui.text
        assert "['HIGH','MEDIUM','LOW'].includes(l) ? l : 'UNKNOWN'" in ui.text
