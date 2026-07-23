"""MCP parity: empty-output gate (output_tokens<1 -> LOW; else carry on)."""
from proxy.detection.features import check_empty_output_gate, classify_with_profile

PROFILE = {
    "model": "gpt-5.6-sol", "version": "1.0",
    "detection": {"features": {
        "reasoning_ratio": {"enabled": True, "weight": 2.0, "polarity": "positive",
                            "threshold_low": 0.4, "threshold_medium": 0.4},
    }},
}

def test_zero_output_gates_low():
    r = check_empty_output_gate(PROFILE, {"output_tokens": 0, "reasoning_ratio": 9.9})
    assert r is not None and r["risk"] == "LOW"
    assert r["metrics"]["gate_reason"] == "output_tokens_below_1"

def test_zero_output_short_circuits_classify():
    r = classify_with_profile(PROFILE, {"output_tokens": 0, "reasoning_ratio": 9.9})
    assert r["risk"] == "LOW" and r["metrics"]["gate_reason"] == "output_tokens_below_1"

def test_positive_output_carries_on():
    assert check_empty_output_gate(PROFILE, {"output_tokens": 512}) is None

def test_missing_output_metadata_carries_on():
    assert check_empty_output_gate(PROFILE, {"reasoning_ratio": 9.9}) is None

def test_string_zero_coerced_and_gated():
    r = check_empty_output_gate(PROFILE, {"output_tokens": "0"})
    assert r is not None and r["risk"] == "LOW"
