"""
Screening transparency at the /detect/verify boundary — the flow-F2 question:
can a response reach a caller LOOKING screened when it was not?

Un-mocked: the real ``ProfileRouter`` over the real shipped ``profiles/``
directory and the real ``DetectionEngine``. Mocked fixtures would be claims
about what the endpoint returns; these are measurements of what it returns.

------------------------------------------------------------------------------
The defect these tests were written red against (arkheia-mcp @ 3037f0c)
------------------------------------------------------------------------------
``DetectionEngine.verify()`` computes, and ``classify_with_profile()`` returns,
three facts that decide what a verdict MEANS:

  * ``evidence_depth_limited`` — whether anything was actually measured
  * ``detection_method``      — including ``tool_surface_suppressed`` /
                                ``empty_output_suppressed``, i.e. "a gate fired
                                and NO feature was scored"
  * the identity of the profile that scored it (``model_detected``) — which is
    NOT always the model the caller asked about, because ProfileRouter falls
    back through prefix and family matching

``VerifyResponse`` in ``proxy/endpoints/detect.py`` dropped **all three**, so
what reached the caller was ``{risk_level, confidence, features_triggered, ...}``
and nothing else. Measured on the shipped profiles, that made these three
responses byte-indistinguishable from a real verdict:

  gemini-2.5-flash  ->  LOW  conf 0.00   mode gate fired, features_used = 0,
                                          evidence_depth_limited = True
  grok-3            ->  HIGH conf 1.00   scored by profile `grok-3-mini-fast`,
                                          a DIFFERENT model, 1 feature
  deepseek-coder:33b-instruct -> LOW conf 1.00  scored by the cloud profile
                                          `deepseek-ai/DeepSeek-V4-Pro`

The first is the one that matters most: ``gemini-2.5-flash`` is ``run_gemini``'s
DEFAULT model, and any response under the profile's 80-token mode gate returns a
LOW that scored nothing at all. The global contract is explicit that an
evidence-limited verdict must surface as a visible couldn't-assess and NEVER as
a green LOW. On this path it surfaced as a green LOW.

The hosted fallback in ``mcp_server/proxy_client.py::_verify_hosted`` already
maps ``evidence_depth_limited`` and ``detection_method`` from the hosted API. So
the same ``ProxyClient.verify()`` call returned a DIFFERENT field set depending
on which detection path served it — see
``test_local_field_set_covers_what_the_hosted_path_promises``.

Every assertion below pins a value positively. There is deliberately no
``assert risk != "HIGH"`` / ``assert x is not None`` here: those pass against a
wrong-but-not-that answer and no mutation can reveal them.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.detection.engine import DetectionEngine
from proxy.endpoints.detect import router as detect_router
from proxy.router.profile_router import ProfileRouter

ROOT = Path(__file__).resolve().parents[2]
PROFILES_DIR = ROOT / "profiles"

PROMPT = "Summarise the 2019 Zhang et al. paper on quantum tunnelling in membranes."

# ~35 words. Deliberately BELOW the 80-token mode gate carried by the Gemini
# profiles, so the suppression path is the one under test.
SHORT_FABRICATION = (
    "Zhang et al. (2019) demonstrated in Nature Physics that quantum tunnelling in "
    "lipid bilayers accounts for 42% of proton transport, using a novel cryo-EM "
    "protocol at 1.8 angstrom resolution, later replicated by Okafor's group at ETH."
)

# ── Models chosen for what each one PROVES, measured against shipped profiles ──
# A profile that scores this text on its own features (no gate, 3 features used).
MODEL_FULLY_SCORED = "phi4:14b"
# run_gemini's DEFAULT model: mode gate fires, features_used = 0.
MODEL_GATE_SUPPRESSED = "gemini-2.5-flash"
# Resolves, via ProfileRouter prefix matching, to a DIFFERENT model's profile.
MODEL_SUBSTITUTED = "grok-3"
PROFILE_OF_SUBSTITUTED = "grok-3-mini-fast"
# No profile at any match tier.
MODEL_UNPROFILED = "no-such-vendor-no-such-model-9x"


# ---------------------------------------------------------------------------
# Fixtures — real router, real engine, real profiles
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def real_router() -> ProfileRouter:
    assert PROFILES_DIR.is_dir(), f"shipped profiles dir missing: {PROFILES_DIR}"
    router = ProfileRouter(str(PROFILES_DIR))
    assert router.loaded_count > 0, (
        "ZERO profiles loaded — every assertion below would then be measuring an "
        "empty detector rather than the shipped one. Refusing to report on nothing."
    )
    return router


@pytest.fixture(scope="module")
def client(real_router: ProfileRouter) -> TestClient:
    app = FastAPI()
    app.include_router(detect_router)
    app.state.engine = DetectionEngine(real_router)
    app.state.audit_writer = None
    app.state.settings = None
    return TestClient(app)


@pytest.fixture
def engineless_client() -> TestClient:
    """A proxy whose detection engine failed to come up: the fail-open path."""
    app = FastAPI()
    app.include_router(detect_router)
    app.state.engine = None
    app.state.audit_writer = None
    app.state.settings = None
    return TestClient(app)


def _verify(client: TestClient, model_id: str, response: str = SHORT_FABRICATION):
    http = client.post(
        "/detect/verify",
        json={"prompt": PROMPT, "response": response, "model_id": model_id},
    )
    assert http.status_code == 200, http.text
    return http, http.json()


# ---------------------------------------------------------------------------
# Guard: the fixtures really do exercise the branches the tests claim.
# If ProfileRouter's matching changes, these fail LOUDLY instead of quietly
# turning the tests below into assertions about a different code path.
# ---------------------------------------------------------------------------

def test_fixture_models_select_the_branches_under_test(real_router: ProfileRouter) -> None:
    fully = real_router.get(MODEL_FULLY_SCORED)
    assert fully is not None and fully["model"] == MODEL_FULLY_SCORED, (
        f"{MODEL_FULLY_SCORED} must resolve to its OWN profile for the "
        "positive-control tests to mean anything."
    )

    gated = real_router.get(MODEL_GATE_SUPPRESSED)
    assert gated is not None and gated["model"] == MODEL_GATE_SUPPRESSED
    assert gated.get("mode_gate", {}).get("enabled") is True, (
        f"{MODEL_GATE_SUPPRESSED} no longer carries an enabled mode_gate, so the "
        "suppression tests below are no longer testing suppression."
    )

    subbed = real_router.get(MODEL_SUBSTITUTED)
    assert subbed is not None and subbed["model"] == PROFILE_OF_SUBSTITUTED, (
        f"{MODEL_SUBSTITUTED} is expected to resolve to the DIFFERENT profile "
        f"{PROFILE_OF_SUBSTITUTED} (that substitution is the thing under test); "
        f"it resolved to {subbed['model']!r}."
    )

    assert real_router.get(MODEL_UNPROFILED) is None


# ---------------------------------------------------------------------------
# 1. A verdict that measured NOTHING must say so
# ---------------------------------------------------------------------------

def test_gate_suppressed_low_is_marked_evidence_limited(client: TestClient) -> None:
    """
    The headline defect. A mode-gate suppression scores ZERO features and the
    engine flags it evidence-limited; the caller must be able to see that.
    """
    _http, body = _verify(client, MODEL_GATE_SUPPRESSED)

    # The verdict as banded — pinned exactly, so a change of banding is visible.
    assert body["risk_level"] == "LOW"
    assert body["confidence"] == 0.0

    # ...and the two fields that stop it reading as a clean bill of health.
    assert body["evidence_depth_limited"] is True, (
        "A LOW at confidence 0.00 produced by a mode gate that scored ZERO "
        "features reached the caller with no evidence-depth marker. "
        f"body keys = {sorted(body)}"
    )
    assert body["detection_method"] == "tool_surface_suppressed", (
        "The caller cannot distinguish a suppressed non-verdict from a scored "
        f"LOW. detection_method = {body.get('detection_method')!r}"
    )


def test_fully_scored_verdict_is_not_marked_evidence_limited(client: TestClient) -> None:
    """
    POSITIVE CONTROL for the test above. Without this, `is True` and
    `== "tool_surface_suppressed"` would both pass against an endpoint that
    hardcoded them — which is the same bug in a different place.
    """
    _http, body = _verify(client, MODEL_FULLY_SCORED)

    assert body["risk_level"] == "HIGH"
    assert body["confidence"] == 1.0
    assert body["evidence_depth_limited"] is False, (
        "evidence_depth_limited must be DERIVED, not stamped True: a verdict that "
        "scored features on its own profile is not evidence-limited."
    )
    assert body["detection_method"] == "profile_multi_feature"


# ---------------------------------------------------------------------------
# 2. A verdict must name the profile that actually produced it
# ---------------------------------------------------------------------------

def test_profile_substitution_is_named_to_the_caller(client: TestClient) -> None:
    """
    ProfileRouter resolved `grok-3` to the `grok-3-mini-fast` fingerprint. The
    response echoed `model_id: grok-3` and named the substituted profile
    nowhere, so a HIGH at confidence 1.00 measured against another model's
    behavioural baseline was presented as a verdict on the model asked about.
    """
    _http, body = _verify(client, MODEL_SUBSTITUTED)

    assert body["model_id"] == MODEL_SUBSTITUTED
    assert body["profile_model_id"] == PROFILE_OF_SUBSTITUTED, (
        "The caller cannot tell that a DIFFERENT model's profile scored this "
        f"response. profile_model_id = {body.get('profile_model_id')!r}"
    )
    assert body["profile_model_id"] != body["model_id"]


def test_exact_profile_match_reports_itself(client: TestClient) -> None:
    """
    POSITIVE CONTROL for the test above: `profile_model_id` must equal
    `model_id` on an exact match, so the field cannot be passing merely by
    always differing (or by echoing a constant).
    """
    _http, body = _verify(client, MODEL_FULLY_SCORED)
    assert body["model_id"] == MODEL_FULLY_SCORED
    assert body["profile_model_id"] == MODEL_FULLY_SCORED


# ---------------------------------------------------------------------------
# 3. Couldn't-assess must never render as a clean bill of health
# ---------------------------------------------------------------------------

def test_unprofiled_model_is_unknown_and_names_no_profile(client: TestClient) -> None:
    _http, body = _verify(client, MODEL_UNPROFILED)

    assert body["risk_level"] == "UNKNOWN"
    assert body["confidence"] == 0.0
    assert body["error"] == "no_profile_for_model"
    assert body["evidence_depth_limited"] is True
    assert body["profile_model_id"] is None, (
        "An unprofiled model must not name a profile. A borrowed profile id here "
        "would be a wrong-model verdict wearing the right label."
    )
    assert body["detection_method"] is None


def test_engine_unavailable_is_evidence_limited_not_clean(
    engineless_client: TestClient,
) -> None:
    """
    The fail-open path. Detection must never block inference — but a response
    that was not screened may not be presentable as one that was.
    """
    _http, body = _verify(engineless_client, MODEL_FULLY_SCORED)

    assert body["risk_level"] == "UNKNOWN"
    assert body["confidence"] == 0.0
    assert body["error"] == "engine_unavailable"
    assert body["evidence_depth_limited"] is True, (
        "Fail-open must not be fail-silent: an unscreened response defaulting to "
        "evidence_depth_limited=False would read as a full-evidence verdict."
    )
    assert body["profile_model_id"] is None


@pytest.mark.parametrize(
    "bad_field,expected_error",
    [("model_id", "model_id_missing"), ("response", "response_empty")],
)
def test_input_validation_paths_are_evidence_limited(
    client: TestClient, bad_field: str, expected_error: str
) -> None:
    payload = {"prompt": PROMPT, "response": SHORT_FABRICATION, "model_id": MODEL_FULLY_SCORED}
    payload[bad_field] = ""
    http = client.post("/detect/verify", json=payload)
    assert http.status_code == 200
    body = http.json()
    assert body["risk_level"] == "UNKNOWN"
    assert body["error"] == expected_error
    assert body["evidence_depth_limited"] is True
    assert body["profile_model_id"] is None


# ---------------------------------------------------------------------------
# 4. Headers mirror the body (the transport-layer / operator-hook surface)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "model_id,expected_risk,expected_limited",
    [
        (MODEL_FULLY_SCORED, "HIGH", "false"),
        (MODEL_GATE_SUPPRESSED, "LOW", "true"),
        (MODEL_UNPROFILED, "UNKNOWN", "true"),
    ],
)
def test_evidence_limitation_header_mirrors_the_body(
    client: TestClient, model_id: str, expected_risk: str, expected_limited: str
) -> None:
    """
    A consumer that reads headers (the interception path, the operator hook)
    must reach the same conclusion as one that parses the body. Where a check
    makes the verdict AND the rendered signal two independent decisions, they
    eventually disagree.
    """
    http, body = _verify(client, model_id)

    assert http.headers["X-Arkheia-Risk"] == expected_risk
    assert body["risk_level"] == expected_risk

    assert http.headers["X-Arkheia-Evidence-Limited"] == expected_limited
    assert body["evidence_depth_limited"] is (expected_limited == "true")


def test_profile_header_names_the_scoring_profile(client: TestClient) -> None:
    http, body = _verify(client, MODEL_SUBSTITUTED)
    assert http.headers["X-Arkheia-Profile"] == PROFILE_OF_SUBSTITUTED
    assert body["profile_model_id"] == PROFILE_OF_SUBSTITUTED

    # Positive control: no profile => the header says so explicitly rather than
    # being absent, because an absent header is indistinguishable from an old
    # proxy that never sets it.
    http, body = _verify(client, MODEL_UNPROFILED)
    assert http.headers["X-Arkheia-Profile"] == "none"
    assert body["profile_model_id"] is None


# ---------------------------------------------------------------------------
# 5. Differential: the two detection paths must not disagree on field set
# ---------------------------------------------------------------------------

def test_local_field_set_covers_what_the_hosted_path_promises(client: TestClient) -> None:
    """
    ``ProxyClient.verify()`` serves callers from the local proxy OR the hosted
    API, and the caller cannot choose which. The hosted mapping in
    ``_verify_hosted`` promises a specific field set; the local path must not
    return a smaller one, or the meaning of a verdict silently depends on which
    path happened to answer.

    Asserted as a DIFFERENTIAL against the runtime mapping itself (parsed from
    the source) rather than a hand-copied list, so the two cannot drift apart.
    """
    import ast
    import inspect

    from mcp_server.proxy_client import ProxyClient

    source = inspect.getsource(ProxyClient._verify_hosted)
    tree = ast.parse(source.strip())
    hosted_keys = {
        k.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Dict)
        for k in node.keys
        if isinstance(k, ast.Constant) and isinstance(k.value, str)
    }
    # `source` is the hosted path's own marker for provenance; the local path
    # carries its own value, asserted separately below.
    hosted_keys.discard("model")   # request payload key, not a response field
    hosted_keys.discard("prompt")
    hosted_keys.discard("response")

    assert hosted_keys, (
        "Parsed ZERO response keys out of ProxyClient._verify_hosted — this "
        "differential would then be comparing against nothing."
    )

    _http, body = _verify(client, MODEL_FULLY_SCORED)
    missing = sorted(hosted_keys - set(body))
    assert missing == [], (
        "The LOCAL detection path returns a smaller field set than the HOSTED "
        f"path promises. Missing: {missing}. A caller of ProxyClient.verify() "
        "gets a different contract depending on which path served it."
    )


def test_local_path_declares_its_provenance(client: TestClient) -> None:
    """The hosted mapping stamps source='hosted'; local must stamp its own."""
    _http, body = _verify(client, MODEL_FULLY_SCORED)
    assert body["source"] == "local"
