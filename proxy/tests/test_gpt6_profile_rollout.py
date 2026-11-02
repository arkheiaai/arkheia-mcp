"""GPT-6 / GPT-6.1 bundled-profile rollout contracts."""

from pathlib import Path

from proxy.detection.features import classify_with_profile
from proxy.router.profile_router import ProfileRouter


PROFILE_DIR = Path(__file__).resolve().parents[2] / "profiles"
BASE = {
    "tokens": ["word"] * 20,
    "token_count": 20,
    "word_count": 20,
    "char_count": 100,
    "output_tokens": 100,
    "visible_tokens": 100,
    "total_generated": 100,
}


def test_every_named_gpt6_variant_loads_its_own_bundled_profile():
    router = ProfileRouter(str(PROFILE_DIR))
    for model in (
        "gpt-6-astra", "gpt-6-sol", "gpt-6-luna",
        "gpt-6.1-sol", "gpt-6.1-terra",
    ):
        profile = router.get(model)
        assert profile is not None
        assert profile["model"] == model

    # Prefix resolution permits a dated snapshot only within the same variant.
    assert router.get("gpt-6.1-sol-2026-11-01")["model"] == "gpt-6.1-sol"
    assert router.get("gpt-6.1-luna") is None


def test_presence_threshold_profiles_do_not_flag_zero_reasoning():
    router = ProfileRouter(str(PROFILE_DIR))
    for model in ("gpt-6-astra", "gpt-6.1-sol", "gpt-6.1-terra"):
        result = classify_with_profile(
            router.get(model), {**BASE, "reasoning_tokens": 0}
        )
        assert result is not None and result["risk"] == "LOW", model


def test_luna_calibration_profile_observes_without_claiming_low():
    router = ProfileRouter(str(PROFILE_DIR))
    result = classify_with_profile(
        router.get("gpt-6-luna"),
        {**BASE, "reasoning_tokens": 0, "reasoning_ratio": 0.0,
         "unique_word_ratio": 0.7},
    )
    assert result is not None
    assert result["detection_method"] == "calibration_suppressed"
    assert result["confidence"] == 0.0
    assert result["evidence_depth_limited"] is True
    assert result["metrics"]["features_used"] == 0
    assert result["metrics"]["computed_features"]
