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
from typing import Optional

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

        # Build signals from response text
        # For /detect/verify we only have text -- no logprobs or timing
        signals = extract_structural_features(response)
        # Add token-level approximation from word count
        words = response.split() if response else []
        signals.setdefault("tokens", words)
        signals.setdefault("token_count", len(words))

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
            metrics=result.get("metrics", {}),
        )
