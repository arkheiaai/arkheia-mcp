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
  grok-3            ->  HIGH conf 1.00   scored by a `grok-3-mini*` profile,
                                          a DIFFERENT model, 1 feature — and
                                          WHICH one is filesystem-order
                                          dependent (see MODEL_SUBSTITUTED)
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
#
# Which one is NOT DETERMINISTIC, and that is itself a finding. Two shipped
# profiles prefix-match "grok-3" -- `grok-3-mini` and `grok-3-mini-fast` -- and
# ProfileRouter.get() returns the FIRST match in dict-insertion order, which comes
# from `Path.glob` i.e. unordered `os.scandir`. Measured: macOS/APFS yields
# grok-3-mini-fast, Linux/ext4 (CI) yields grok-3-mini. So which model's
# fingerprint scores a response depends on filesystem directory-listing order, and
# two identical installs can return different verdicts for the same
# (prompt, response, model) triple.
#
# Not fixed here: proxy/router/profile_router.py is owned by open PR #13. So the
# shipped-profile test below asserts what is actually TRUE and STABLE -- that the
# candidate set is ambiguous and that whichever wins is NAMED to the caller -- and
# a separate hermetic test pins the substitution mechanism exactly, over a
# purpose-built profile dir where no ambiguity can arise.
MODEL_SUBSTITUTED = "grok-3"
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


def _prefix_candidates(router: ProfileRouter, model_id: str) -> set[str]:
    """
    Every loaded profile ProfileRouter's prefix tier could legitimately return
    for model_id. More than one member means the choice is ambiguous and, because
    the winner is taken from unordered `Path.glob` insertion order, unstable
    across filesystems.
    """
    m = model_id.lower()
    return {k for k in router.profile_ids if k.startswith(m) or m.startswith(k)}


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

    candidates = _prefix_candidates(real_router, MODEL_SUBSTITUTED)
    assert len(candidates) > 1, (
        f"{MODEL_SUBSTITUTED} no longer has AMBIGUOUS prefix candidates in the "
        f"shipped profile set (found {sorted(candidates)}), so the "
        "order-dependence finding this fixture exists to demonstrate no longer "
        "reproduces. Re-derive it or drop these tests deliberately."
    )
    subbed = real_router.get(MODEL_SUBSTITUTED)
    assert subbed is not None
    assert subbed["model"] in candidates
    assert subbed["model"] != MODEL_SUBSTITUTED, (
        f"{MODEL_SUBSTITUTED} must resolve to a DIFFERENT model's profile — that "
        "substitution is the thing under test."
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

def test_profile_substitution_is_named_to_the_caller(
    client: TestClient, real_router: ProfileRouter
) -> None:
    """
    ProfileRouter resolves `grok-3` to one of the `grok-3-mini*` fingerprints.
    The response echoed `model_id: grok-3` and named the substituted profile
    nowhere, so a HIGH at confidence 1.00 measured against another model's
    behavioural baseline was presented as a verdict on the model asked about.

    Which candidate wins is filesystem-order dependent (see the module header),
    so the assertion is on the invariant that is actually true and stable: the
    substitution is NAMED, and named as one of the real candidates rather than
    echoing the request. `test_substitution_is_named_exactly` pins the mechanism
    to a single exact value over a hermetic profile dir.
    """
    _http, body = _verify(client, MODEL_SUBSTITUTED)
    candidates = _prefix_candidates(real_router, MODEL_SUBSTITUTED)

    assert body["model_id"] == MODEL_SUBSTITUTED
    assert body["profile_model_id"] != body["model_id"], (
        "The caller cannot tell that a DIFFERENT model's profile scored this "
        f"response. profile_model_id = {body.get('profile_model_id')!r}"
    )
    assert body["profile_model_id"] in candidates, (
        "profile_model_id must name a profile that could really have scored "
        f"this: {body.get('profile_model_id')!r} not in {sorted(candidates)}"
    )


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


def test_profile_header_names_the_scoring_profile(
    client: TestClient, real_router: ProfileRouter
) -> None:
    http, body = _verify(client, MODEL_SUBSTITUTED)
    # Header and body must agree with each other exactly, whichever candidate the
    # filesystem happened to order first: two decision sites, one verdict.
    assert http.headers["X-Arkheia-Profile"] == body["profile_model_id"]
    assert body["profile_model_id"] in _prefix_candidates(real_router, MODEL_SUBSTITUTED)

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

    # Only the dict the SUCCESS path RETURNS — not the request payload and not the
    # request headers, which are also dict literals in that function.
    hosted_keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            hosted_keys |= {
                k.value
                for k in node.value.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }

    assert hosted_keys, (
        "Parsed ZERO returned response keys out of ProxyClient._verify_hosted — "
        "this differential would then be comparing against nothing."
    )
    # Guard the parse itself: if it silently started matching the request payload
    # or headers instead of the response mapping, this differential would be
    # asserting the wrong contract.
    assert {"risk_level", "evidence_depth_limited", "detection_method", "source"} <= hosted_keys, (
        "The hosted mapping no longer returns the fields this differential exists "
        f"to compare. Parsed: {sorted(hosted_keys)}"
    )
    assert "X-Arkheia-Key" not in hosted_keys, "parsed the request headers, not the response"

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


# ---------------------------------------------------------------------------
# 6. The OPERATOR surface — the audit record must not be blinder than the
#    response. An audit trail recording a bare "LOW" for a verdict that scored
#    nothing is a forensic record of a screening that did not happen.
# ---------------------------------------------------------------------------

class _RecordingAudit:
    """Captures exactly what detect.py hands the audit layer."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    async def write(self, record: dict) -> None:
        self.records.append(record)


@pytest.fixture
def audited(real_router: ProfileRouter):
    app = FastAPI()
    app.include_router(detect_router)
    app.state.engine = DetectionEngine(real_router)
    audit = _RecordingAudit()
    app.state.audit_writer = audit
    app.state.settings = None
    return TestClient(app), audit


@pytest.mark.parametrize(
    "model_id,expected_limited,expected_method,expected_profile",
    [
        (MODEL_FULLY_SCORED, False, "profile_multi_feature", MODEL_FULLY_SCORED),
        (MODEL_GATE_SUPPRESSED, True, "tool_surface_suppressed", MODEL_GATE_SUPPRESSED),
        (MODEL_UNPROFILED, True, None, None),
    ],
)
def test_audit_record_carries_the_screening_context(
    audited, model_id, expected_limited, expected_method, expected_profile
) -> None:
    """
    The audit log is the compliance artefact and the operator's after-the-fact
    view. It recorded risk_level / confidence / features_triggered and NOT
    whether anything was measured or which profile measured it — so a
    suppressed non-verdict and a fully-scored verdict were the same audit row.

    Parametrised so the four rows are mutually distinguishing: any
    implementation that hardcoded one of these values fails at least two rows.
    """
    client, audit = audited
    _verify(client, model_id)

    assert len(audit.records) == 1, (
        f"expected exactly one audit record, got {len(audit.records)} — with zero "
        "records every assertion below would pass vacuously"
    )
    rec = audit.records[0]

    assert rec["model_id"] == model_id
    assert rec["evidence_depth_limited"] is expected_limited
    assert rec["detection_method"] == expected_method
    assert rec["profile_model_id"] == expected_profile


def test_audit_record_and_response_cannot_disagree(audited) -> None:
    """
    The response and the audit row are two independent decision sites reading
    the same verdict; where that happens they eventually disagree. Asserted as
    equality on the transparency fields rather than as two separate expected
    values, so drift in either one fails.
    """
    client, audit = audited
    for model_id in (MODEL_FULLY_SCORED, MODEL_GATE_SUPPRESSED, MODEL_UNPROFILED):
        audit.records.clear()
        _http, body = _verify(client, model_id)
        rec = audit.records[0]
        for field in ("risk_level", "confidence", "evidence_depth_limited",
                      "detection_method", "profile_model_id"):
            assert rec[field] == body[field], (
                f"audit row and response disagree on {field!r} for {model_id}: "
                f"{rec[field]!r} vs {body[field]!r}"
            )


# ---------------------------------------------------------------------------
# 7. The substitution MECHANISM, pinned exactly — hermetic profile dir
#
# The shipped-profile tests above cannot pin profile_model_id to one value,
# because the shipped set is ambiguous for `grok-3` and the winner comes from
# unordered Path.glob insertion order. This test removes the ambiguity by
# construction: a temp profile dir with exactly ONE profile that can match, so
# the value IS determinable and is asserted exactly. Without it, every
# substitution assertion in this file would be a set-membership check.
# ---------------------------------------------------------------------------

def _write_profile(directory: Path, model: str, version: str = "1.0") -> None:
    """A minimal profile that scores on one always-computable structural feature."""
    (directory / f"{model.replace('/', '_').replace(':', '_')}.yaml").write_text(
        f'model: "{model}"\n'
        f'version: "{version}"\n'
        "detection:\n"
        "  strategy: multi_feature\n"
        "  min_required_features: 1\n"
        "  features:\n"
        "    unique_word_ratio:\n"
        "      weight: 1.0\n"
        "      polarity: positive\n"
        "      threshold_low: 0.10\n"
        "      threshold_medium: 0.20\n"
        "      truth_mean: 0.10\n"
        "      fab_mean: 0.90\n",
        encoding="utf-8",
    )


def test_substitution_is_named_exactly(tmp_path: Path) -> None:
    """
    One requested model, one candidate profile that prefix-matches it, no
    ambiguity: `profile_model_id` must be that profile's id EXACTLY, and must
    not echo the requested model.
    """
    _write_profile(tmp_path, "borrowed-surface-v9")
    router = ProfileRouter(str(tmp_path))
    assert router.loaded_count == 1, router.profile_ids

    app = FastAPI()
    app.include_router(detect_router)
    app.state.engine = DetectionEngine(router)
    app.state.audit_writer = None
    app.state.settings = None
    client = TestClient(app)

    requested = "borrowed-surface-v9-turbo-2026"
    _http, body = _verify(client, requested)

    assert body["model_id"] == requested
    assert body["profile_model_id"] == "borrowed-surface-v9"
    assert body["profile_model_id"] != requested


def test_exact_request_is_not_reported_as_a_substitution(tmp_path: Path) -> None:
    """
    POSITIVE CONTROL for the test above. On an exact match the two must be
    EQUAL, so `profile_model_id` cannot be passing by always differing from
    `model_id` — which a naive implementation (e.g. reporting the filename) could.
    """
    _write_profile(tmp_path, "borrowed-surface-v9")
    router = ProfileRouter(str(tmp_path))

    app = FastAPI()
    app.include_router(detect_router)
    app.state.engine = DetectionEngine(router)
    app.state.audit_writer = None
    app.state.settings = None
    client = TestClient(app)

    _http, body = _verify(client, "borrowed-surface-v9")

    assert body["model_id"] == "borrowed-surface-v9"
    assert body["profile_model_id"] == "borrowed-surface-v9"
