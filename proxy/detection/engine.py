"""
Arkheia Detection Engine -- thin orchestration wrapper.

Receives (prompt, response, model_id), builds signals from text,
delegates to classify_with_profile() from features.py.

Does NOT re-implement feature extraction. Does NOT replace the existing
detection logic -- wraps it.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from proxy.detection.features import classify_with_profile, extract_structural_features

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    risk_level: str          # LOW | MEDIUM | HIGH | UNKNOWN
    confidence: float        # 0.0 to 1.0
    features_triggered: list[str]
    model_id: str
    profile_version: str
    timestamp: str           # ISO8601
    detection_id: str        # UUID
    error: Optional[str] = None
    evidence_depth_limited: bool = True
    # How the verdict was reached. "profile_<strategy>" when features were scored;
    # "tool_surface_suppressed" / "empty_output_suppressed" when a GATE fired and NO
    # feature was scored. A suppressed LOW is a couldn't-assess, not a clean bill of
    # health, so a consumer that cannot see this cannot tell the two apart.
    detection_method: Optional[str] = None
    # The model_id of the profile that ACTUALLY scored this response, which is not
    # always model_id: ProfileRouter falls back through prefix and family matching, so
    # e.g. "grok-3" resolves to the "grok-3-mini-fast" fingerprint. None when no
    # profile matched. Compare against model_id to detect a substitution.
    profile_model_id: Optional[str] = None
    # WHICH false-positive suppression gate fired, and against WHICH threshold — a value
    # from the closed vocabulary in proxy/detection/features.py (SUPPRESSION_REASONS),
    # or None when the verdict was actually SCORED.
    #
    # A suppression is a decision NOT to report something, so it is the decision whose
    # evidence trail matters most; before this field existed the reason died inside
    # features.py and no consumer — caller, audit record or governance push — could say
    # why a LOW was a LOW. Non-None is the positive marker for "nothing was measured";
    # None is the marker for "measured, and clean". It must never be set on a scored
    # verdict or it stops discriminating.
    gate_reason: Optional[str] = None
    # Gate eligibility (2026-06-28 containment). Consumers MUST only hard-block when this
    # is "block"; default "advise" so an unvalidated/UNKNOWN profile can never block.
    gate_action: str = "advise"
    metrics: dict = field(default_factory=dict)


class DetectionEngine:
    """
    Orchestrates detection for a (prompt, response, model_id) triple.

    The engine:
      1. Extracts structural signals from response text
      2. Looks up profile via ProfileRouter
      3. Calls classify_with_profile() if profile found
      4. Returns UNKNOWN if no profile (not an error -- surfaced as information)
    """

    def __init__(self, profile_router):
        self.router = profile_router

    async def verify(
        self,
        prompt: str,
        response: str,
        model_id: str,
        output_tokens: Any = None,
        is_function_call: Any = None,
    ) -> DetectionResult:
        detection_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        profile = self.router.get(model_id)

        if profile is None:
            logger.debug("No profile for model=%s -> UNKNOWN", model_id)
            return DetectionResult(
                risk_level="UNKNOWN",
                confidence=0.0,
                features_triggered=[],
                model_id=model_id,
                profile_version="none",
                timestamp=timestamp,
                detection_id=detection_id,
                error="no_profile_for_model",
            )

        # Identify the profile that will actually score this response. ProfileRouter
        # resolves through exact -> prefix -> family, so this is NOT necessarily
        # model_id, and the difference changes what the verdict means.
        profile_model_id = (
            profile.get("model")
            or profile.get("metadata", {}).get("model_id")
            or None
        )

        # Build signals from response text plus explicit provider metadata.
        # Never infer output_tokens from response text: zero output is a
        # server-side usage fact, not a string-shape fact.
        signals = extract_structural_features(response)
        # Add token-level approximation from word count
        words = response.split() if response else []
        signals.setdefault("tokens", words)
        signals.setdefault("token_count", len(words))
        if output_tokens is not None:
            signals["output_tokens"] = output_tokens
        if is_function_call is not None:
            signals["is_function_call"] = is_function_call

        try:
            result = classify_with_profile(profile, signals)
        except Exception as e:
            logger.error("classify_with_profile failed for model=%s: %s", model_id, e)
            result = None

        if result is None:
            # Profile found but no features computable (e.g. profile requires logprobs)
            return DetectionResult(
                risk_level="UNKNOWN",
                confidence=0.0,
                features_triggered=[],
                model_id=model_id,
                profile_version=str(
                    profile.get("version")
                    or profile.get("metadata", {}).get("version", "unknown")
                ),
                timestamp=timestamp,
                detection_id=detection_id,
                error="no_computable_features",
                profile_model_id=profile_model_id,
            )

        profile_version = str(
            profile.get("version")
            or profile.get("metadata", {}).get("version", "unknown")
        )

        return DetectionResult(
            risk_level=result.get("risk", "UNKNOWN"),
            confidence=result.get("confidence", 0.0),
            features_triggered=result.get("features_triggered", []),
            model_id=model_id,
            profile_version=profile_version,
            timestamp=timestamp,
            detection_id=detection_id,
            evidence_depth_limited=result.get("evidence_depth_limited", True),
            detection_method=result.get("detection_method"),
            profile_model_id=profile_model_id,
            gate_reason=(result.get("metrics") or {}).get("gate_reason"),
            gate_action=result.get("gate_action", "advise"),
            metrics=result.get("metrics", {}),
        )
