"""
F7 — adversarial contract for the two false-positive suppression gates.

WHY THIS FILE EXISTS
--------------------
`check_empty_output_gate` and `check_mode_gate` turn a would-be finding into LOW. That
makes them the only two functions in the detector that can DESTROY a finding, and the
direction of danger is asymmetric:

  * OVER-suppression is silent. A HIGH that becomes a LOW produces no error, no log line
    a customer sees, and a verdict that reads as a clean bill of health.
  * UNDER-suppression is loud. It is cry-wolf, and the operator switches the detector off.

So every case below is written as a PAIR: what MUST buy a suppression, and what must NOT.
The second half is the half that protects detection, and it is the half that was missing.

RED RUN (DONE.md v1.15) — executed against origin/master @ 3037f0c on python 3.12.13,
BEFORE the fix landed:

    48 failed, 75 passed

and the file DISCRIMINATED rather than being uniformly red — the 75 that passed pre-fix
are the control rows (the gates still firing when they should), the boundary pins, the
reachability statement and the two PINNED-not-fixed classes. The 48 that failed group as:

  * 12  a corrupt `output_tokens` bought a suppression
        (NaN, "nan"/"NaN"/"-nan", -inf/"-inf"/"-Infinity", -1/-1.0/-1e9/"-1", False)
  * 10  a corrupt `token_count` bought one, or CRASHED the gate
        (None/"80"/""/[]/{}/object() -> TypeError; -1/-1000/False/True -> suppressed)
  *  4  a malformed profile `token_count_max` crashed the gate
  *  8  a truthy NON-boolean `is_function_call` — including the string "false" —
        suppressed a 9999-token generative response
  *  7  `classify_with_profile` raised on a corrupt signal instead of returning
  *  2  a suppression carried no `gate_action`, so containment relied on a caller default
  *  5  the closed suppression taxonomy did not exist

Everything here drives the REAL functions with a REAL shipped profile where the
behaviour is profile-dependent; assertions pin exact values, never `is not None`.
"""
from __future__ import annotations

import math
from pathlib import Path

import pytest
import yaml

from proxy.detection import features as F
from proxy.detection.features import (
    check_empty_output_gate,
    check_mode_gate,
    classify_with_profile,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _shipped_profile(name: str) -> dict:
    """A REAL profile off disk, so the contract is the one that ships."""
    with open(_REPO_ROOT / "profiles" / f"{name}.yaml") as fh:
        return yaml.safe_load(fh)


@pytest.fixture(scope="module")
def gated_profile() -> dict:
    """gpt-5.3-codex ships mode_gate.enabled=true, token_count_max=80, action=suppress."""
    p = _shipped_profile("gpt-5.3-codex")
    # Premise check: if the shipped profile ever stops carrying the gate, every
    # suppression case below would pass vacuously. Fail loudly instead.
    assert p["mode_gate"]["enabled"] is True
    assert p["mode_gate"]["tool_surface"]["action"] == "suppress"
    assert p["mode_gate"]["tool_surface"]["triggers"]["token_count_max"] == 80
    return p


#: A profile with NO mode_gate at all — used to prove the empty-output gate is
#: independent of the mode gate, and as the control for mode-gate cases.
UNGATED_PROFILE = {
    "model": "test-model",
    "version": "9.9",
    "detection": {
        "features": {
            "reasoning_ratio": {
                "enabled": True, "weight": 2.0, "polarity": "positive",
                "threshold_low": 0.4, "threshold_medium": 0.4,
            },
        }
    },
}


# ===========================================================================
# 1. THE EMPTY-OUTPUT GATE — what can BUY a suppression
# ===========================================================================

class TestEmptyOutputGateSuppressionDomain:
    """`output_tokens` is provider-supplied usage metadata. Anything that reaches this
    field and is not a real count must NOT be able to purchase silence."""

    def test_zero_suppresses(self):
        """CONTROL ROW THAT PASSES (DONE.md v1.15 cl.5): the gate must still fire."""
        r = check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": 0})
        assert r is not None
        assert r["risk"] == "LOW"
        assert r["confidence"] == 0.0
        assert r["detection_method"] == "empty_output_suppressed"
        assert r["metrics"]["gate_reason"] == "output_tokens_below_1"
        assert r["metrics"]["features_used"] == 0

    def test_string_zero_still_suppresses(self):
        """Pre-existing coercion behaviour is preserved, not collateral damage."""
        r = check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": "0"})
        assert r is not None and r["risk"] == "LOW"

    @pytest.mark.parametrize("value", [0, 0.0, 0.5, 0.999])
    def test_below_one_suppresses(self, value):
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is not None

    @pytest.mark.parametrize("value", [1, 1.0, 2, 512, "512"])
    def test_at_or_above_one_carries_on(self, value):
        """BOUNDARY. The threshold is `>= 1`; 1 itself must be scored, not suppressed."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is None

    def test_absent_carries_on(self):
        """No usage metadata means we cannot confirm zero — keep detecting."""
        assert check_empty_output_gate(UNGATED_PROFILE, {}) is None

    def test_explicit_none_carries_on(self):
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": None}) is None

    @pytest.mark.parametrize("value", ["", "abc", [], {}, [0]])
    def test_unparseable_carries_on(self, value):
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is None

    def test_positive_infinity_carries_on(self):
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": float("inf")}) is None

    # ---- the half that was missing: corrupt values that BOUGHT a suppression ----

    def test_nan_must_not_buy_a_suppression(self):
        """NaN is not a count. Every comparison against NaN is False, so `ot >= 1`
        is False and the pre-fix gate fell straight through to SUPPRESS. A provider
        (or anything upstream of it) that emits `usage.output_tokens: NaN` could
        silence the detector for that response."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": float("nan")}) is None

    @pytest.mark.parametrize("value", ["nan", "NaN", "-nan"])
    def test_nan_as_a_string_must_not_buy_a_suppression(self, value):
        """`float("nan")` parses. JSON has no NaN literal, so a NaN arrives as a STRING —
        which is exactly the reachable form of the vector above."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is None

    @pytest.mark.parametrize("value", [float("-inf"), "-inf", "-Infinity"])
    def test_negative_infinity_must_not_buy_a_suppression(self, value):
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is None

    @pytest.mark.parametrize("value", [-1, -1.0, -1e9, "-1"])
    def test_negative_count_must_not_buy_a_suppression(self, value):
        """A negative token count is corrupt data. Corrupt data must not be able to
        purchase silence — the gate's premise ('nothing was emitted') is not
        established by a number that cannot be a count."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": value}) is None

    def test_bool_false_must_not_buy_a_suppression(self):
        """`bool` is a subclass of `int`, so `False` coerced to 0.0 and suppressed.
        A JSON `false` in the usage block is a malformed count, not zero tokens."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": False}) is None

    def test_bool_true_carries_on(self):
        """The mirror control: `True` must not be read as '1 token' either."""
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": True}) is None


class TestEmptyOutputGateIgnoresContradictingEvidence:
    """PINNED CURRENT BEHAVIOUR — NOT A FIX. Reported for adjudication.

    The gate's stated premise is 'a response that emitted zero output tokens has no
    generative surface to score'. It consults `output_tokens` and nothing else, so a
    signals dict that CONTRADICTS itself — zero output tokens alongside five thousand
    words of text — still suppresses. Whether the gate should refuse a self-contradicting
    signal set is a product call about what the detector trusts, so it is pinned here
    rather than changed. This test goes red the moment the behaviour moves in either
    direction.
    """

    def test_zero_output_tokens_suppresses_despite_five_thousand_words(self):
        signals = {"output_tokens": 0, "word_count": 5000, "char_count": 30000,
                   "sentence_count": 300}
        r = check_empty_output_gate(UNGATED_PROFILE, signals)
        assert r is not None
        assert r["risk"] == "LOW"
        assert r["metrics"]["gate_reason"] == "output_tokens_below_1"


class TestEmptyOutputGateIsUnconditionalOnTheProfile:
    def test_fires_for_a_profile_with_no_mode_gate(self):
        """Documented ordering: the empty-output gate is not conditioned on mode_gate."""
        assert "mode_gate" not in UNGATED_PROFILE
        assert check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": 0}) is not None

    def test_runs_before_the_mode_gate(self, gated_profile):
        """Both gates would fire; the empty-output reason is the one that survives."""
        r = classify_with_profile(gated_profile, {"output_tokens": 0, "token_count": 5})
        assert r["metrics"]["gate_reason"] == "output_tokens_below_1"
        assert r["detection_method"] == "empty_output_suppressed"


# ===========================================================================
# 2. THE MODE GATE — what can BUY a suppression
# ===========================================================================

class TestModeGateSuppressionDomain:

    def test_short_response_suppresses(self, gated_profile):
        """CONTROL ROW THAT PASSES."""
        r = check_mode_gate(gated_profile, {"token_count": 79})
        assert r is not None
        assert r["risk"] == "LOW"
        assert r["confidence"] == 0.0
        assert r["detection_method"] == "tool_surface_suppressed"
        assert r["metrics"]["gate_reason"] == "token_count_below_80"

    def test_boundary_exactly_at_threshold_is_scored_not_suppressed(self, gated_profile):
        """BOUNDARY. The comparison is strict `<`, so 80 is scored."""
        assert check_mode_gate(gated_profile, {"token_count": 80}) is None

    def test_boundary_one_below_threshold_suppresses(self, gated_profile):
        assert check_mode_gate(gated_profile, {"token_count": 79}) is not None

    def test_absent_token_count_carries_on(self, gated_profile):
        assert check_mode_gate(gated_profile, {}) is None

    def test_gate_disabled_never_suppresses(self):
        p = {"mode_gate": {"enabled": False,
                           "tool_surface": {"action": "suppress",
                                            "triggers": {"token_count_max": 80}}}}
        assert check_mode_gate(p, {"token_count": 1, "is_function_call": True}) is None

    def test_no_mode_gate_key_never_suppresses(self):
        assert check_mode_gate(UNGATED_PROFILE, {"token_count": 1}) is None

    def test_non_suppress_action_never_suppresses(self):
        p = {"mode_gate": {"enabled": True,
                           "tool_surface": {"action": "advise",
                                            "triggers": {"token_count_max": 80}}}}
        assert check_mode_gate(p, {"token_count": 1}) is None

    def test_function_call_true_suppresses(self, gated_profile):
        r = check_mode_gate(gated_profile, {"token_count": 9999, "is_function_call": True})
        assert r is not None
        assert r["metrics"]["gate_reason"] == "function_call_part"

    # ---- the half that was missing ----

    @pytest.mark.parametrize("value", [None, "80", "", [], {}, object()])
    def test_unusable_token_count_must_not_crash_the_gate(self, gated_profile, value):
        """PRE-FIX: `signals.get("token_count", inf) < max_tokens` raises TypeError for
        every one of these. The raise escapes `classify_with_profile`, is caught by
        `DetectionEngine.verify`'s blanket handler, and is reported to the caller as
        `error="no_computable_features"` — a determinate, benign-sounding cause for
        what was actually a crash. An unusable count must simply mean 'cannot confirm
        shortness', i.e. keep detecting."""
        assert check_mode_gate(gated_profile, {"token_count": value}) is None

    def test_nan_token_count_does_not_suppress(self, gated_profile):
        """Already correct by accident (every NaN comparison is False). Pinned so a
        future refactor to `not (tc >= max)` cannot invert it."""
        assert check_mode_gate(gated_profile, {"token_count": float("nan")}) is None

    @pytest.mark.parametrize("value", [-1, -1000, False, True])
    def test_corrupt_token_count_must_not_buy_a_suppression(self, gated_profile, value):
        """A negative count cannot be a count; `bool` is an `int` subclass and
        `True < 80` suppressed. Neither establishes 'this response is short'."""
        assert check_mode_gate(gated_profile, {"token_count": value}) is None

    @pytest.mark.parametrize("bad_max", [None, "eighty", [], float("nan")])
    def test_unusable_profile_threshold_must_not_crash_the_gate(self, bad_max):
        """A malformed `token_count_max` in a profile raised TypeError from inside the
        gate, taking the whole classification with it. It must fall back to the coded
        default and keep working."""
        p = {"model": "m", "version": "1",
             "mode_gate": {"enabled": True,
                           "tool_surface": {"action": "suppress",
                                            "triggers": {"token_count_max": bad_max}}}}
        r = check_mode_gate(p, {"token_count": 5})
        assert r is not None
        assert r["metrics"]["gate_reason"] == "token_count_below_80"

    @pytest.mark.parametrize("value", ["false", "no", "0", [0], {"a": 1}, 2, -1, 0.5])
    def test_truthy_non_boolean_is_function_call_must_not_buy_a_suppression(
        self, gated_profile, value
    ):
        """PRE-FIX the gate read `signals.get("is_function_call", False)` for TRUTHINESS,
        so the STRING "false" — and any other non-empty string — suppressed a 9999-token
        generative response outright. `is_function_call` is a boolean signal; only a
        boolean (or the int 1) may stand for it."""
        assert check_mode_gate(
            gated_profile, {"token_count": 9999, "is_function_call": value}
        ) is None

    @pytest.mark.parametrize("value", [False, 0, None, "", []])
    def test_falsy_is_function_call_falls_through_to_the_token_arm(self, gated_profile, value):
        """CONTROL: a false flag must not short-circuit; the token arm still applies."""
        assert check_mode_gate(
            gated_profile, {"token_count": 9999, "is_function_call": value}
        ) is None
        assert check_mode_gate(
            gated_profile, {"token_count": 5, "is_function_call": value}
        ) is not None


class TestNoCorruptSignalCanCrashTheClassifier:
    """The classifier is on a path contracted never to crash the pipeline it monitors.
    A gate that RAISES does not fail open OR closed — it is converted by the engine's
    blanket `except` into a mislabelled `no_computable_features` UNKNOWN."""

    CORRUPT = [None, "", "abc", "80", [], {}, object(), float("nan"),
               float("inf"), float("-inf"), -1, True, False]

    @pytest.mark.parametrize("value", CORRUPT)
    @pytest.mark.parametrize("key", ["token_count", "output_tokens", "is_function_call"])
    def test_classify_never_raises(self, gated_profile, key, value):
        classify_with_profile(gated_profile, {key: value})


# ===========================================================================
# 3. COMPOSITION WITH THE ADVISORY CAP
# ===========================================================================

class TestASuppressionCanNeverAuthorizeABlock:
    """`resolve_gate_action` is the earned-authority cap: a consumer hard-blocks ONLY on
    `gate_action == "block"`. Both gates return BEFORE the cap is ever resolved, so
    pre-fix a suppression dict carried no `gate_action` key at all and the value a
    consumer saw came from a downstream `.get(..., "advise")` default. Relying on a
    caller's default for a containment property is how the property gets dropped by the
    next caller. The gate states it."""

    BLOCK_EARNED = {
        "model": "earned", "version": "2.0",
        "gate_action": "block",
        "performance": {"precision": 0.99, "f1": 0.98, "false_positive_rate": 0.01},
        "mode_gate": {"enabled": True,
                      "tool_surface": {"action": "suppress",
                                       "triggers": {"token_count_max": 80}}},
        "detection": {"features": {}},
    }

    def test_the_profile_really_has_earned_block(self):
        """Premise check — otherwise the two tests below pass vacuously."""
        assert F.resolve_gate_action(self.BLOCK_EARNED) == "block"

    def test_mode_gate_suppression_states_advise(self):
        r = check_mode_gate(self.BLOCK_EARNED, {"token_count": 5})
        assert r["gate_action"] == "advise"

    def test_empty_output_suppression_states_advise(self):
        r = check_empty_output_gate(self.BLOCK_EARNED, {"output_tokens": 0})
        assert r["gate_action"] == "advise"

    def test_a_scored_verdict_still_reports_the_earned_block(self):
        """CONTROL: the cap is not disabled by this change — a scored verdict on the
        same profile still reports the authority the profile earned."""
        p = dict(self.BLOCK_EARNED)
        p["detection"] = {"features": {
            "word_count": {"enabled": True, "weight": 1.0, "polarity": "positive",
                           "threshold_low": 10, "threshold_medium": 20},
        }}
        r = classify_with_profile(p, {"word_count": 500, "token_count": 500})
        assert r["gate_action"] == "block"
        assert r["risk"] == "HIGH"


# ===========================================================================
# 4. THE SUPPRESSION TAXONOMY IS CLOSED
# ===========================================================================

class TestSuppressionTaxonomyIsClosed:
    """A suppression reason is switched on by consumers and lands in the audit record.
    It must come from a fixed vocabulary (PR #31 pattern), never free text, and it must
    never collide with a value a SCORED verdict can produce."""

    def test_declared_taxonomies_are_non_empty(self):
        assert len(F.SUPPRESSED_DETECTION_METHODS) >= 2
        assert len(F.SUPPRESSION_REASONS) >= 3

    def test_every_gate_method_is_in_the_closed_set(self, gated_profile):
        for r in (check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": 0}),
                  check_mode_gate(gated_profile, {"token_count": 5}),
                  check_mode_gate(gated_profile, {"token_count": 9, "is_function_call": True})):
            assert r["detection_method"] in F.SUPPRESSED_DETECTION_METHODS

    def test_every_gate_reason_is_in_the_closed_set(self, gated_profile):
        for r in (check_empty_output_gate(UNGATED_PROFILE, {"output_tokens": 0}),
                  check_mode_gate(gated_profile, {"token_count": 5}),
                  check_mode_gate(gated_profile, {"token_count": 9, "is_function_call": True})):
            assert F.is_suppression_reason(r["metrics"]["gate_reason"])

    def test_a_scored_verdict_carries_no_gate_reason(self, gated_profile):
        """THE MARKER MUST DISCRIMINATE. If a scored verdict could carry a gate_reason,
        the field stops distinguishing 'not scored' from 'scored clean'."""
        r = classify_with_profile(gated_profile, {"token_count": 500, "word_count": 400,
                                                  "char_count": 2400,
                                                  "unique_word_ratio": 0.6,
                                                  "avg_word_length": 6.0,
                                                  "sentence_count": 20})
        assert r is not None
        assert "gate_reason" not in r["metrics"]
        assert r["detection_method"] not in F.SUPPRESSED_DETECTION_METHODS
        assert r["metrics"]["features_used"] >= 1

    def test_free_text_is_not_a_suppression_reason(self):
        for junk in ["", None, "because", "token_count_below_", "TOKEN_COUNT_BELOW_80",
                     "output_tokens_below_2", "token_count_below_eighty",
                     "token_count_below_-1", " token_count_below_80"]:
            assert F.is_suppression_reason(junk) is False, junk

    @pytest.mark.parametrize("junk", [123, 0, 1, True, False, [], {}, object(), 3.5,
                                      b"token_count_below_80"])
    def test_a_non_string_is_rejected_and_does_not_raise(self, junk):
        """FOUND BY MUTATION M23. `is_suppression_reason` is the one place a consumer
        asks "was this verdict suppressed?", so it is called on whatever an audit row
        or a decoded push body happens to hold. Replacing the `isinstance(reason, str)`
        guard with `reason is None` left every string case passing while a non-string
        reached `.startswith` and raised AttributeError — inside the predicate a
        consumer uses to decide whether a LOW is trustworthy."""
        assert F.is_suppression_reason(junk) is False


# ===========================================================================
# 5. THE UNIT DIVERGENCE — pinned, not fixed
# ===========================================================================

class TestTokenCountIsActuallyAWordCount:
    """PINNED CURRENT BEHAVIOUR — NOT A FIX. Reported for adjudication.

    `DetectionEngine.verify` builds the mode gate's input as
    `signals.setdefault("token_count", len(response.split()))` — a WORD count — and the
    profile threshold it is compared against is named `token_count_max`. English runs at
    roughly 1.3 tokens per word, so the gate configured to suppress below 80 TOKENS
    actually suppresses up to roughly 105 tokens: about 30% wider than the profile
    declares, in the over-suppression direction.

    Correcting it means choosing a words->tokens conversion, which is a threshold
    decision and therefore a product call under this sweep's rules. Pinned so the
    divergence is a recorded decision rather than an unnoticed one.
    """

    def test_the_engine_feeds_word_count_into_the_token_count_signal(self):
        import inspect
        from proxy.detection.engine import DetectionEngine
        src = inspect.getsource(DetectionEngine.verify)
        assert 'signals.setdefault("token_count", len(words))' in src
        assert "words = response.split()" in src

    def test_a_seventy_nine_word_response_is_suppressed(self, gated_profile):
        """79 words is ~103 tokens by the usual ratio, and is still suppressed."""
        response = " ".join(["word"] * 79)
        assert len(response.split()) == 79
        assert check_mode_gate(gated_profile, {"token_count": len(response.split())}) is not None


# ===========================================================================
# 6. WHAT NEITHER GATE CAN REACH TODAY
# ===========================================================================

class TestExplicitMetadataMakesTheGateReachable:
    """HONEST SCOPE. `output_tokens` is now reachable through explicit request/provider
    metadata only. The detector still must not infer it from response text, because
    "empty string" and "provider usage says zero output tokens" are different facts."""

    @pytest.mark.asyncio
    async def test_engine_uses_explicit_zero_output_metadata(self):
        from proxy.detection.engine import DetectionEngine

        class Router:
            def get(self, _model):
                return UNGATED_PROFILE

        result = await DetectionEngine(Router()).verify(
            "prompt",
            "",
            "test-model",
            output_tokens=0,
        )
        assert result.risk_level == "LOW"
        assert result.detection_method == "empty_output_suppressed"
        assert result.gate_reason == "output_tokens_below_1"

    def test_response_text_extraction_still_produces_neither_metadata_signal(self):
        from proxy.detection.features import extract_structural_features
        f = extract_structural_features("a b c d e", token_count=5)
        assert "output_tokens" not in f
        assert "is_function_call" not in f

    def test_only_ingress_paths_populate_output_tokens_or_is_function_call(self):
        import re
        offenders = []
        for path in sorted(_REPO_ROOT.rglob("*.py")):
            rel = path.relative_to(_REPO_ROOT).as_posix()
            if rel.startswith((".venv", "tests/", "proxy/tests/", "mcp_server/tests/",
                               "registry_server/tests/", "tools/")):
                continue
            if rel == "proxy/detection/features.py":
                continue
            if rel in {
                "proxy/detection/engine.py",
                "proxy/endpoints/detect.py",
                "proxy/endpoints/passthrough.py",
                "proxy/middleware/interception.py",
                "mcp_server/proxy_client.py",
            }:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for key in ("output_tokens", "is_function_call"):
                # An ASSIGNMENT into a signals-shaped mapping, not a read.
                if re.search(rf'''\[["']{key}["']\]\s*=''', text) or \
                   re.search(rf'''setdefault\(\s*["']{key}["']''', text) or \
                   re.search(rf'''["']{key}["']\s*:''', text):
                    offenders.append(f"{rel}:{key}")
        assert offenders == [], (
            "A new path now populates suppression metadata. Either route it through the "
            "explicit /detect/verify metadata contract, or update this floor with a "
            f"new reviewed ingress: {offenders}"
        )
