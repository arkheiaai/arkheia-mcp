"""Provenance travelling with an MCP detection verdict.

A profile tells the engine how to score; it says nothing about how well that
scoring was shown to work or when it was last confirmed. Without the manifest, a
model measured last week at 98% and one measured in March at 62% produce results
of identical shape and a caller cannot tell them apart.

The MCP server also serves encrypted profiles to customer installations, so the
same rule applies with more force: annotation must never be able to break
scoring, and a model we have never measured must say so rather than guess.
"""
import json

import pytest

from proxy.router.profile_router import ProfileRouter


MANIFEST = {
    "as_of": "2026-08-27",
    "caveat": "measured on a false-premise corpus",
    "models": {
        "grok-4.5": {"model": "grok-4.5", "domains": {
            "code": {"domain": "code", "capability": "LIMITED", "currency": "CURRENT",
                     "measured_on": "2026-08-26", "held_out_recall": 0.984,
                     "held_out_fpr": 0.256, "auc": 0.977, "auc_ci_95": [0.945, 0.993],
                     "primary_feature": "reasoning_tokens", "risk_grade": "WATCH",
                     "limiting_dimension": ["detection_strength"], "statement": "x"},
            "prose": {"domain": "prose", "capability": "LIMITED", "currency": "CURRENT",
                      "measured_on": "2026-08-26", "held_out_recall": 0.929,
                      "held_out_fpr": 0.268, "auc": 0.9, "auc_ci_95": [0.85, 0.94],
                      "primary_feature": "reasoning_ratio", "risk_grade": "WATCH",
                      "limiting_dimension": [], "statement": "x"},
        }},
    },
}


@pytest.fixture
def router(tmp_path):
    (tmp_path / ProfileRouter.MANIFEST_FILE).write_text(json.dumps(MANIFEST),
                                                        encoding="utf-8")
    return ProfileRouter(str(tmp_path))


class TestProvenance:
    def test_returns_the_requested_domain(self, router):
        assert router.get_detection_provenance("grok-4.5", "code")["held_out_recall"] == 0.984

    def test_no_domain_returns_the_weakest_measurement(self, router):
        """A caller who does not say where they are gets the conservative figure."""
        assert router.get_detection_provenance("grok-4.5")["held_out_recall"] == 0.929

    def test_unknown_domain_falls_back_conservatively(self, router):
        assert router.get_detection_provenance("grok-4.5", "poetry")["held_out_recall"] == 0.929

    def test_uncharacterised_model_returns_none(self, router):
        assert router.get_detection_provenance("never-measured") is None

    def test_lookup_is_case_insensitive(self, router):
        assert router.get_detection_provenance("GROK-4.5", "code") is not None

    def test_recall_never_travels_without_its_fpr(self, router):
        p = router.get_detection_provenance("grok-4.5", "code")
        assert p["held_out_recall"] is not None and p["held_out_fpr"] is not None
        assert p["measured_on"] and p["currency"] and p["auc_ci_95"]


class TestAnnotationCannotBreakScoring:
    def test_missing_manifest_is_not_an_error(self, tmp_path):
        assert ProfileRouter(str(tmp_path)).get_detection_provenance("grok-4.5") is None

    def test_corrupt_manifest_is_not_an_error(self, tmp_path):
        (tmp_path / ProfileRouter.MANIFEST_FILE).write_text("{not json", encoding="utf-8")
        assert ProfileRouter(str(tmp_path)).get_detection_provenance("grok-4.5") is None

    def test_manifest_is_not_mistaken_for_a_profile(self, tmp_path):
        """It is .json and the loader globs .yaml — but assert it, because a
        manifest silently loaded as a profile would be a scoring defect."""
        (tmp_path / ProfileRouter.MANIFEST_FILE).write_text(json.dumps(MANIFEST),
                                                            encoding="utf-8")
        assert ProfileRouter(str(tmp_path))._loaded_count == 0


def test_the_shipped_manifest_is_wellformed():
    """Guards the real artefact, not a stub."""
    from pathlib import Path
    path = Path(__file__).resolve().parents[1] / "profiles" / ProfileRouter.MANIFEST_FILE
    if not path.exists():
        pytest.skip("no manifest exported into this checkout")
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m.get("as_of") and m.get("caveat") and m["models"]
    for name, rec in m["models"].items():
        for dom, d in (rec.get("domains") or {}).items():
            assert (d.get("held_out_recall") is None) == (d.get("held_out_fpr") is None), \
                "%s/%s quotes recall without its false positive rate" % (name, dom)
            assert d.get("measured_on"), "%s/%s has no measurement date" % (name, dom)
