"""
Feature extraction for Arkheia fabrication detection.

Pure computation -- no I/O, no profile loading, no side effects.
Adapted from arkheia-proxy app/services/detection.py and app/routers/proxy.py.

DO NOT replace this with reimplemented logic. These functions are the validated
detection engine. Extend only.
"""

import math
import statistics
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Structural feature extraction (from response text)
# ---------------------------------------------------------------------------

def extract_structural_features(text: str, token_count: int = 0) -> dict:
    """
    Extract structural features from response text.

    These are available without logprobs or timing data.
    Used when only the response text is provided (e.g. /detect/verify endpoint).
    """
    if not text:
        return {}
    words = text.split()
    if not words:
        return {}
    sentences = [s.strip() for s in text.split(".") if s.strip()]
    features = {
        "word_count": len(words),
        "char_count": len(text),
        "unique_word_ratio": len(set(w.lower() for w in words)) / len(words),
        "avg_word_length": sum(len(w) for w in words) / len(words),
        "sentence_count": len(sentences),
    }
    if token_count > 0:
        features["words_per_token"] = len(words) / token_count
        features["chars_per_token"] = len(text) / token_count
        features["token_density"] = token_count / len(text)
    return features


# ---------------------------------------------------------------------------
# Logprob feature extraction
# ---------------------------------------------------------------------------

def compute_token_entropies(raw_logprobs: list) -> List[float]:
    """Compute per-token entropy from full logprob data (with top alternatives)."""
    entropies = []
    for item in raw_logprobs:
        if not isinstance(item, dict):
            continue
        top_lps = item.get("top_logprobs", [])
        if top_lps:
            entropy = 0.0
            for alt in top_lps:
                lp = alt.get("logprob", 0)
                p = math.exp(max(lp, -50.0))   # clamp to prevent overflow
                if p > 0:
                    entropy -= p * lp
            entropies.append(entropy)
        else:
            lp = item.get("logprob")
            if lp is not None:
                p = math.exp(max(lp, -50.0))
                entropies.append(-p * lp if p > 0 else 0)
    return entropies


def compute_feature(feature_name: str, signals: dict) -> Optional[float]:
    """
    Compute a single named feature value from a signals dict.

    signals keys:
        logprobs, raw_logprobs, tokens, token_count, total_time_s,
        word_count, char_count, unique_word_ratio, avg_word_length,
        sentence_count, output_tokens, reasoning_tokens, visible_tokens,
        reasoning_ratio, thinking_token_count, is_function_call
    """
    logprobs = signals.get("logprobs", [])
    raw_logprobs = signals.get("raw_logprobs", [])
    tokens = signals.get("tokens", [])
    token_count = signals.get("token_count", 0)
    total_time_s = signals.get("total_time_s", 0)

    # --- Logprob features ---
    if feature_name == "entropy_mean":
        entropies = compute_token_entropies(raw_logprobs)
        return statistics.mean(entropies) if entropies else None

    if feature_name == "entropy_std":
        entropies = compute_token_entropies(raw_logprobs)
        return statistics.stdev(entropies) if len(entropies) >= 2 else None

    if feature_name == "top1_confidence_mean":
        confs = [math.exp(lp["logprob"]) for lp in logprobs
                 if isinstance(lp, dict) and "logprob" in lp]
        return statistics.mean(confs) if confs else None

    if feature_name == "top1_confidence_std":
        confs = [math.exp(lp["logprob"]) for lp in logprobs
                 if isinstance(lp, dict) and "logprob" in lp]
        return statistics.stdev(confs) if len(confs) >= 2 else None

    if feature_name == "median_logprob":
        vals = [lp["logprob"] for lp in logprobs
                if isinstance(lp, dict) and "logprob" in lp]
        return statistics.median(vals) if vals else None

    if feature_name == "mean_logprob":
        vals = [lp["logprob"] for lp in logprobs
                if isinstance(lp, dict) and "logprob" in lp]
        return statistics.mean(vals) if vals else None

    if feature_name == "logprob_iqr":
        vals = sorted(lp["logprob"] for lp in logprobs
                      if isinstance(lp, dict) and "logprob" in lp)
        if len(vals) < 4:
            return None
        return vals[3 * len(vals) // 4] - vals[len(vals) // 4]

    if feature_name == "logprob_q25":
        vals = sorted(lp["logprob"] for lp in logprobs
                      if isinstance(lp, dict) and "logprob" in lp)
        return vals[len(vals) // 4] if len(vals) >= 4 else None

    # --- Token / timing features ---
    if feature_name == "token_count":
        tc = token_count or len(tokens)
        return float(tc) if tc else None

    if feature_name == "unique_token_ratio":
        return len(set(tokens)) / len(tokens) if tokens else None

    if feature_name == "tokens_per_second":
        tc = signals.get("output_tokens") or token_count or len(tokens)
        if not tc or not total_time_s or total_time_s <= 0:
            return None
        return tc / total_time_s

    if feature_name == "total_time_s":
        return total_time_s if total_time_s and total_time_s > 0 else None

    # --- Reasoning model features ---
    if feature_name == "reasoning_tokens":
        rt = signals.get("reasoning_tokens")
        return float(rt) if rt is not None else None

    if feature_name == "visible_tokens":
        vt = signals.get("visible_tokens")
        return float(vt) if vt is not None else None

    if feature_name == "reasoning_ratio":
        rr = signals.get("reasoning_ratio")
        return float(rr) if rr is not None else None

    if feature_name == "output_tokens":
        ot = signals.get("output_tokens")
        return float(ot) if ot is not None else None

    if feature_name == "thinking_token_count":
        ttc = signals.get("thinking_token_count")
        return float(ttc) if ttc is not None else None

    if feature_name == "thinking_per_second":
        ttc = signals.get("thinking_token_count")
        tts = signals.get("total_time_s")
        if ttc is not None and tts and tts > 0:
            return float(ttc) / tts
        return None

    # --- Structural features ---
    if feature_name == "word_count":
        wc = signals.get("word_count")
        return float(wc) if wc else None

    if feature_name == "char_count":
        cc = signals.get("char_count")
        return float(cc) if cc else None

    if feature_name == "unique_word_ratio":
        return signals.get("unique_word_ratio")

    if feature_name == "avg_word_length":
        return signals.get("avg_word_length")

    if feature_name == "sentence_count":
        sc = signals.get("sentence_count")
        return float(sc) if sc else None

    if feature_name == "words_per_token":
        return signals.get("words_per_token")

    if feature_name == "token_density":
        return signals.get("token_density")

    if feature_name == "chars_per_token":
        return signals.get("chars_per_token")

    return None


# ---------------------------------------------------------------------------
# Mode gate: suppress generative scoring for tool/short responses
# ---------------------------------------------------------------------------

def check_mode_gate(profile: dict, signals: dict) -> Optional[Dict[str, Any]]:
    """
    Mode gate: suppress generative scoring for tool-call or very short responses.

    Returns a suppression result dict if gate fires, None if scoring should proceed.
    """
    mode_gate = profile.get("mode_gate", {})
    if not mode_gate.get("enabled", False):
        return None

    tool_cfg = mode_gate.get("tool_surface", {})
    triggers = tool_cfg.get("triggers", {})

    gate_reason = None
    if signals.get("is_function_call", False):
        gate_reason = "function_call_part"
    else:
        max_tokens = triggers.get("token_count_max", 80)
        if signals.get("token_count", float("inf")) < max_tokens:
            gate_reason = f"token_count_below_{max_tokens}"

    if gate_reason is None:
        return None

    action = tool_cfg.get("action", "suppress")
    if action != "suppress":
        return None

    features_config = profile.get("detection", {}).get("features", {})
    logger.debug("mode_gate fired: reason=%s", gate_reason)
    return {
        "risk": "LOW",
        "confidence": 0.0,
        "evidence_depth_limited": True,
        "model_detected": profile.get("model", "unknown"),
        "detection_method": "tool_surface_suppressed",
        "profile_version": profile.get("version", "unknown"),
        "metrics": {
            "features_used": 0,
            "features_total": len(features_config),
            "computed_features": {},
            "gate_reason": gate_reason,
        },
    }


# ---------------------------------------------------------------------------
# Profile-based classification
# ---------------------------------------------------------------------------

def classify_with_profile(profile: dict, signals: dict) -> Optional[Dict[str, Any]]:
    """
    Classify fabrication risk using a YAML model profile.

    Returns None if no features could be computed (caller should treat as UNKNOWN).
    """
    # Mode gate check first
    gate_result = check_mode_gate(profile, signals)
    if gate_result is not None:
        return gate_result

    detection_cfg = profile.get("detection", {})
    features_config = detection_cfg.get("features", {})

    risk_weights: Dict[str, float] = {"LOW": 0.0, "MEDIUM": 0.0, "HIGH": 0.0}
    computed_features: Dict[str, float] = {}
    features_used = 0

    for feat_name, feat_cfg in features_config.items():
        if not feat_cfg.get("enabled", True):
            continue

        value = compute_feature(feat_name, signals)
        if value is None:
            continue

        computed_features[feat_name] = value
        features_used += 1

        weight = abs(feat_cfg.get("weight", 1.0))
        polarity = feat_cfg.get("polarity", "positive")
        thresh_low = feat_cfg.get("threshold_low")
        thresh_medium = feat_cfg.get("threshold_medium")

        if thresh_low is None or thresh_medium is None:
            continue

        if polarity == "positive":
            if value < thresh_low:
                feat_risk = "LOW"
            elif value < thresh_medium:
                feat_risk = "MEDIUM"
            else:
                feat_risk = "HIGH"
        else:
            if value > thresh_low:
                feat_risk = "LOW"
            elif value > thresh_medium:
                feat_risk = "MEDIUM"
            else:
                feat_risk = "HIGH"

        logger.debug(
            "%s: value=%.4f polarity=%s low=%s med=%s -> %s (w=%.3f)",
            feat_name, value, polarity, thresh_low, thresh_medium, feat_risk, weight,
        )
        risk_weights[feat_risk] += weight

    if features_used == 0:
        return None

    risk = max(risk_weights, key=risk_weights.get)
    total_weight = sum(risk_weights.values())
    confidence = round(risk_weights[risk] / total_weight, 2) if total_weight > 0 else 0.5

    # Evidence depth assessment
    min_features = detection_cfg.get("min_required_features", 3)
    min_contribution = detection_cfg.get("min_contribution_threshold", 0.0)

    if features_used < min_features:
        evidence_limited = True
    elif total_weight < min_contribution:
        evidence_limited = True
    else:
        separation_achieved = False
        for feat_name, value in computed_features.items():
            feat_cfg = features_config[feat_name]
            truth_mean = feat_cfg.get("truth_mean")
            fab_mean = feat_cfg.get("fab_mean")
            if truth_mean is None or fab_mean is None:
                continue
            basin_low = min(truth_mean, fab_mean)
            basin_high = max(truth_mean, fab_mean)
            if value < basin_low or value > basin_high:
                separation_achieved = True
                break
        evidence_limited = not separation_achieved

    # Profile-level override
    if detection_cfg.get("evidence_depth_limited", False):
        evidence_limited = True

    return {
        "risk": risk,
        "confidence": confidence,
        "evidence_depth_limited": evidence_limited,
        "model_detected": profile.get("model", "unknown"),
        "detection_method": "profile_" + detection_cfg.get("strategy", "ensemble"),
        "profile_version": profile.get("version", "unknown"),
        "features_triggered": [k for k, v in computed_features.items()],
        "metrics": {
            "features_used": features_used,
            "features_total": len(features_config),
            "computed_features": {k: round(v, 4) for k, v in computed_features.items()},
        },
    }
