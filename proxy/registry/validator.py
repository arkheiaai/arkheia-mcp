"""
Profile registry validator.

Validates a downloaded profile YAML before it is applied:
  1. Checksum verification (sha256)
  2. Schema validation (required fields present)
  3. Smoke test (known prompt/response pair produces expected risk level)

If any step fails, the profile is rejected. The existing profile is retained.
"""

import hashlib
import logging
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Required top-level keys in a profile (supports both real format and spec format)
_REQUIRED_REAL_FORMAT = {"model", "version", "detection"}
_REQUIRED_SPEC_FORMAT = {"metadata", "thresholds", "features"}


class ProfileValidator:

    def verify_checksum(self, content: bytes, expected_sha256: str) -> bool:
        """Return True if sha256(content) matches expected."""
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected_sha256:
            logger.error(
                "Checksum mismatch: expected=%s actual=%s", expected_sha256, actual
            )
            return False
        return True

    def validate_schema(self, data: dict) -> tuple[bool, str]:
        """
        Validate profile YAML structure.

        Returns (is_valid, error_message).
        Accepts both real profile format (model/version/detection)
        and spec schema format (metadata/thresholds/features).
        """
        if not isinstance(data, dict):
            return False, "profile must be a YAML mapping"

        # Real format check
        missing_real = _REQUIRED_REAL_FORMAT - set(data.keys())
        if not missing_real:
            # Validate detection section
            detection = data.get("detection", {})
            if not isinstance(detection, dict):
                return False, "detection must be a mapping"
            if "features" not in detection:
                return False, "detection.features is required"
            return True, ""

        # Spec schema format check
        missing_spec = _REQUIRED_SPEC_FORMAT - set(data.keys())
        if not missing_spec:
            meta = data.get("metadata", {})
            if not meta.get("model_id"):
                return False, "metadata.model_id is required"
            return True, ""

        return (
            False,
            f"profile missing required keys (real format needs {_REQUIRED_REAL_FORMAT}, "
            f"spec format needs {_REQUIRED_SPEC_FORMAT})",
        )

    def run_smoke_test(self, profile: dict) -> tuple[bool, str]:
        """
        Run the profile's built-in smoke test (if defined).

        The smoke test provides a known prompt/response pair and an expected
        risk level. If the profile produces a different risk level, reject it.

        Returns (passed, reason).
        """
        smoke = profile.get("smoke_test")
        if not smoke:
            # No smoke test defined -- pass by default
            return True, "no smoke test defined"

        prompt = smoke.get("prompt", "")
        response = smoke.get("response", "")
        expected_risk = smoke.get("expected_risk", "")

        if not response or not expected_risk:
            return True, "smoke test incomplete -- skipped"

        try:
            from proxy.detection.features import classify_with_profile, extract_structural_features

            signals = extract_structural_features(response)
            words = response.split()
            signals.setdefault("tokens", words)
            signals.setdefault("token_count", len(words))

            result = classify_with_profile(profile, signals)
            if result is None:
                # No features computable -- smoke test inconclusive
                return True, "smoke test inconclusive (no features computed)"

            actual_risk = result.get("risk", "UNKNOWN")
            if actual_risk != expected_risk:
                return (
                    False,
                    f"smoke test FAILED: expected={expected_risk} actual={actual_risk}",
                )
            return True, f"smoke test passed: {actual_risk}"

        except Exception as e:
            logger.error("Smoke test error: %s", e)
            return False, f"smoke test raised exception: {e}"

    def validate(self, content: bytes) -> dict:
        """
        Parse and fully validate a profile from raw YAML bytes.

        Returns the parsed profile dict if valid.
        Raises ValueError if any validation step fails.
        """
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"YAML parse error: {e}")

        is_valid, error = self.validate_schema(data)
        if not is_valid:
            raise ValueError(f"Schema validation failed: {error}")

        passed, reason = self.run_smoke_test(data)
        if not passed:
            raise ValueError(f"Smoke test failed: {reason}")

        return data
