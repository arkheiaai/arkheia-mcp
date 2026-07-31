"""UNKNOWN must reach the governance envelope as UNKNOWN, never as LOW.

The envelope band was ``risk_level if risk_level in ("LOW","MEDIUM","HIGH","CRITICAL") else "LOW"``.
UNKNOWN is absent from that tuple, so every unassessable verdict -- no profile for the model, no
computable features, a suppression gate firing with features_used == 0 -- was recorded as the
QUIETEST possible band. An unscreened response and a measured-clean one became indistinguishable in
the governance record.

That is the failure detection exists to catch, one layer below the response body: a check that
reports clean when it measured nothing. A response that was never scored has not been found safe.
"""

from __future__ import annotations

import pytest

from proxy.endpoints.detect import _ENVELOPE_RISK_BANDS, _envelope_risk_band


@pytest.mark.parametrize("band", ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"])
def test_every_real_band_survives_verbatim(band):
    """A recognised band is recorded as itself — the fix must not rewrite real verdicts."""
    assert _envelope_risk_band(band) == band


def test_unknown_is_not_recorded_as_low():
    """The defect, stated directly."""
    assert _envelope_risk_band("UNKNOWN") == "UNKNOWN", (
        "an unassessable verdict was recorded on the governance envelope as LOW — a response that "
        "was never scored is not a response that was found safe"
    )


@pytest.mark.parametrize("weird", ["", "   ", "bogus", "low-ish", None])
def test_anything_unrecognised_falls_to_unknown_not_low(weird):
    """Unrecognised input must fail LOUD (UNKNOWN), not quiet (LOW).

    This is the direction that matters. Defaulting an unparseable band to LOW manufactures a clean
    result out of an error; defaulting it to UNKNOWN says truthfully that we do not know.
    """
    assert _envelope_risk_band(weird) == "UNKNOWN"


def test_case_and_whitespace_do_not_silently_downgrade_a_real_band():
    """A band that only differs by case/padding must not be treated as unrecognised."""
    assert _envelope_risk_band(" high ") == "HIGH"
    assert _envelope_risk_band("critical") == "CRITICAL"


def test_unknown_is_a_declared_envelope_band():
    """UNKNOWN belongs in the band vocabulary, not outside it.

    _determine_action already branches on UNKNOWN (settings.detection.unknown_action), so the
    endpoint already treats it as a first-class outcome; only the envelope was collapsing it.
    """
    assert "UNKNOWN" in _ENVELOPE_RISK_BANDS


# ---------------------------------------------------------------------------
# The CALL SITE. The helper tests above are necessary and NOT sufficient: reverting the call site
# to the old inline expression leaves every one of them green, because they never drive the
# endpoint. A pin that cannot see the defect it was written for is decorative. This drives the real
# app and reads the bytes that actually reach the governance wire.
# ---------------------------------------------------------------------------

import json          # noqa: E402
import threading     # noqa: E402
from pathlib import Path          # noqa: E402
from unittest.mock import MagicMock, patch          # noqa: E402

import httpx         # noqa: E402
from fastapi.testclient import TestClient          # noqa: E402

from proxy.main import create_app          # noqa: E402

_REPO_ROOT = Path(__file__).resolve().parents[2]

#: No profile ships for this id, so the engine returns UNKNOWN / no_profile_for_model.
UNPROFILED_MODEL = "definitely-not-a-real-model-9000"


class _Wire:
    """Captures the serialized bytes the governance push puts on the wire."""

    def __init__(self) -> None:
        self.bodies: list[bytes] = []
        self.arrived = threading.Event()

    async def send(self, request, *args, **kwargs):  # noqa: ANN001
        self.bodies.append(request.content)
        self.arrived.set()
        return httpx.Response(200, request=request, json={"ok": True})

    def await_one(self, timeout: float = 5.0) -> dict:
        if not self.arrived.wait(timeout):
            raise AssertionError(
                "no governance push reached the wire — this test would be vacuous"
            )
        assert len(self.bodies) == 1, f"expected one push, got {len(self.bodies)}"
        return json.loads(self.bodies[0].decode())


@pytest.fixture
def wire(monkeypatch):
    w = _Wire()
    monkeypatch.setattr("proxy.detection_adapter.DETECTION_ADAPTER_URL", "http://adapter.test")
    monkeypatch.setattr("proxy.detection_adapter.DETECTION_ADAPTER_HMAC_SECRET", "test-secret")
    monkeypatch.setattr(httpx.AsyncClient, "send", w.send)
    return w


@pytest.fixture
def app_client(tmp_path):
    with patch("proxy.main.settings") as s:
        s.detection.profile_dir = str(_REPO_ROOT / "profiles")
        s.detection.high_risk_action = "warn"
        s.detection.unknown_action = "pass"
        s.proxy.log_level = "WARNING"
        s.audit.log_path = str(tmp_path / "audit.jsonl")
        s.audit.retention_days = 90
        s.registry.url = ""
        from pydantic import SecretStr
        s.arkheia_api_key = SecretStr("")
        s.synesis = MagicMock()
        s.synesis.enabled = False
        app = create_app()
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c


def test_an_unprofiled_model_reaches_the_governance_wire_as_UNKNOWN(app_client, wire):
    """THE REGRESSION TEST. Reverting detect.py's call site turns this RED.

    The endpoint returns UNKNOWN / no_profile_for_model for a model with no profile. What the
    governance plane RECORDS must say the same thing. Before the fix it recorded LOW.
    """
    r = app_client.post("/detect/verify", json={
        "prompt": "What is the capital of France?",
        "response": "Paris is the capital of France.",
        "model_id": UNPROFILED_MODEL,
    })
    assert r.status_code == 200
    body = r.json()
    assert body["risk_level"] == "UNKNOWN", (
        f"premise failed — the endpoint did not return UNKNOWN for {UNPROFILED_MODEL!r}, "
        f"so this test would be vacuous: {body}"
    )

    pushed = wire.await_one()
    assert pushed["risk_level"] == "UNKNOWN", (
        "the governance envelope recorded an UNSCREENED response as "
        f"{pushed['risk_level']!r}. A response that was never scored has not been found safe. "
        "This is the defect: UNKNOWN fell outside the accepted band tuple and defaulted to LOW."
    )
