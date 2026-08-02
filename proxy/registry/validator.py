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

import yaml

logger = logging.getLogger(__name__)

# Required top-level keys in a profile (supports both real format and spec format)
_REQUIRED_REAL_FORMAT = {"model", "version", "detection"}
_REQUIRED_SPEC_FORMAT = {"metadata", "thresholds", "features"}


class ProfileValidator:

    def require_checksum(self, expected_sha256: str) -> str:
        """
        Return a normalised SHA-256 checksum or raise ValueError.

        Registry-delivered profiles must be content-addressed. Treating an
        absent checksum as "nothing to verify, so pass" is the same vacuous
        success shape as an empty manifest or absent smoke test.
        """
        if not isinstance(expected_sha256, str) or not expected_sha256.strip():
            raise ValueError("checksum is required for registry-delivered profiles")
        normalised = expected_sha256.strip().lower()
        if len(normalised) != 64 or any(c not in "0123456789abcdef" for c in normalised):
            raise ValueError("checksum must be a 64-character SHA-256 hex digest")
        return normalised

    def verify_checksum(self, content: bytes, expected_sha256: str) -> bool:
        """Return True if sha256(content) matches expected."""
        expected = self.require_checksum(expected_sha256)
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            logger.error(
                "Checksum mismatch: expected=%s actual=%s", expected, actual
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
            # A delivered profile is NOT re-proved here, and a smoke test is not what proves it.
            # Detection profiles are built and validated in the model lab against a labelled
            # corpus -- the `characterization` block records that run (date, prompt count,
            # features, methodology; e.g. "200 total, 50 TRUTH + 50 FAB per domain"). A single
            # canned prompt/response pair asserted at DELIVERY time is strictly weaker evidence
            # than the run that already happened, and demanding it would gate the stronger
            # evidence sitting in the same file.
            #
            # What delivery is responsible for is that the bytes arrived intact and from the
            # right place -- that is the checksum, which IS mandatory (require_checksum) and IS
            # satisfiable, because registry metadata carries one.
            #
            # This briefly returned False, which rejected ALL 60 shipped profiles: none carries a
            # smoke_test, so registry delivery failed universally. The reasoning behind that change
            # was sound for a property nothing establishes elsewhere; it is not sound for one the
            # lab already established.
            return True, "no smoke test defined"

        prompt = smoke.get("prompt", "")
        response = smoke.get("response", "")
        expected_risk = smoke.get("expected_risk", "")

        if not response or not expected_risk:
            # The smoke_test block was DECLARED (unlike the `not smoke` branch
            # above, where the key is absent entirely) but is missing fields
            # profiles/schema.yaml requires together. This is a malformed
            # declared check, not the absence of one -- `return True` here was
            # the `if not items: return True` vacuous-truth shape: nothing to
            # compare, so it defaulted to "passed". Reject instead, same as any
            # other schema violation.
            return False, (
                "smoke test declared but incomplete (missing response and/or "
                "expected_risk) -- an incomplete smoke test is evidence of a "
                "malformed profile, not evidence that it passed"
            )

        try:
            from proxy.detection.features import classify_with_profile, extract_structural_features

            signals = extract_structural_features(response)
            words = response.split()
            signals.setdefault("tokens", words)
            signals.setdefault("token_count", len(words))

            result = classify_with_profile(profile, signals)
            if result is None:
                # No features computable: classify_with_profile already refused
                # to guess (it returns None rather than defaulting to a risk
                # level). Absence of evidence is not evidence of a pass, so the
                # smoke test must not certify the profile either.
                return False, (
                    "smoke test inconclusive: no features computable for the "
                    "given response, so nothing was actually verified"
                )

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
