"""
Multi-profile router with atomic reload and license enforcement.

Loads all YAML profiles at startup. Supports exact, prefix, and family matching.
Reload is copy-and-swap -- zero dropped requests during update.

License verification:
  - Profiles with a 'license:' block are checked for expiry and HMAC signature.
  - ARKHEIA_LICENSE_KEY   — HMAC-SHA256 secret; if unset, signature check is skipped (dev mode)
  - ARKHEIA_REQUIRE_LICENSE — if true, profiles without a license block are rejected
  - Expired / tampered profiles are silently skipped; other profiles are unaffected.
"""

import asyncio
import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import sys
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# Read once at import time; NSSM AppEnvironmentExtra sets these per installation.
_LICENSE_KEY: str = os.getenv("ARKHEIA_LICENSE_KEY", "")
_REQUIRE_LICENSE: bool = os.getenv("ARKHEIA_REQUIRE_LICENSE", "false").lower() in (
    "true", "1", "yes"
)


def _canonical_profile(profile: dict) -> str:
    """Deterministic JSON serialization of profile content, excluding the license block."""
    content = {k: v for k, v in profile.items() if k != "license"}
    return json.dumps(content, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _verify_profile_license(profile: dict, filename: str) -> bool:
    """
    Verify the license block in a profile. Returns True if the profile may be loaded.

    Rules:
      - No license block + REQUIRE_LICENSE=false  → allowed (open / dev mode)
      - No license block + REQUIRE_LICENSE=true   → rejected, warning logged
      - Expired date                               → rejected, warning logged
      - HMAC mismatch                              → rejected, error logged
      - No LICENSE_KEY configured                  → HMAC check skipped (dev mode)
    """
    block = profile.get("license")

    if not block:
        if _REQUIRE_LICENSE:
            logger.warning(
                "Profile %s has no license block and ARKHEIA_REQUIRE_LICENSE=true — skipping",
                filename,
            )
            return False
        return True  # open mode: no license required

    valid_until_str = str(block.get("valid_until", ""))
    try:
        expiry = date.fromisoformat(valid_until_str)
    except ValueError:
        logger.error(
            "Profile %s has invalid valid_until %r — skipping", filename, valid_until_str
        )
        return False

    if expiry < date.today():
        logger.warning(
            "Profile %s license expired on %s — skipping (model returns UNKNOWN)",
            filename,
            valid_until_str,
        )
        return False

    if _LICENSE_KEY:
        customer_id = str(block.get("customer_id", ""))
        message = f"{_canonical_profile(profile)}|{customer_id}|{valid_until_str}"
        expected = _hmac_mod.new(
            _LICENSE_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        actual = str(block.get("signature", ""))
        if not _hmac_mod.compare_digest(expected, actual):
            logger.error(
                "Profile %s license signature mismatch — skipping (possible tampering)",
                filename,
            )
            return False

    return True


class ProfileRouter:
    """
    Thread-safe (asyncio-safe) profile dispatch table.

    Lookup priority:
      1. Exact model_id match
      2. Prefix match (e.g. "claude-sonnet" matches "claude-sonnet-4-6")
      3. Family match (e.g. "claude" matches any Claude profile, uses latest version)
      4. No match -> None (caller returns UNKNOWN)
    """

    def __init__(self, profile_dir: str):
        self._profiles: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.profile_dir = profile_dir
        self._loaded_count = 0
        self.load_all()

    def load_all(self) -> None:
        """Load all YAML profiles from profile_dir. Called at startup."""
        profiles: dict[str, dict] = {}
        path = Path(self.profile_dir).resolve()
        if not path.exists():
            logger.warning("Profiles directory not found: %s", self.profile_dir)
            self._profiles = profiles
            self._loaded_count = 0
            return

        for f in path.glob("*.yaml"):
            # Guard: only load files within the profile directory (no symlink escape)
            if not f.resolve().parent == path:  # aikido-ignore
                logger.warning("Skipping file outside profile dir: %s", f)
                continue
            if f.name == "schema.yaml":
                continue
            try:
                with open(f, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if not data:
                    continue
                if not _verify_profile_license(data, f.name):
                    continue
                # Support both real profile format (top-level "model" key)
                # and spec schema format (metadata.model_id)
                model_id = (
                    data.get("model")
                    or data.get("metadata", {}).get("model_id")
                )
                if not model_id:
                    logger.warning("Profile %s has no model_id, skipping", f.name)
                    continue
                profiles[model_id] = data
                logger.debug("Loaded profile: %s -> %s", f.name, model_id)
            except Exception as e:
                logger.error("Failed to load profile %s: %s", f.name, e)

        self._profiles = profiles
        self._loaded_count = len(profiles)
        logger.info(
            "ProfileRouter: loaded %d valid profiles from %s",
            len(profiles),
            self.profile_dir,
        )

    def get(self, model_id: str) -> Optional[dict]:
        """Return profile for model_id, or None if no match."""
        if not model_id:
            return None

        model_lower = model_id.lower()

        # 1. Exact match
        if model_lower in self._profiles:
            return self._profiles[model_lower]

        # Also try exact match against values (profiles may store mixed-case)
        for key, profile in self._profiles.items():
            stored_id = (
                profile.get("model")
                or profile.get("metadata", {}).get("model_id", "")
            ).lower()
            if stored_id == model_lower:
                return profile

        # 2. Prefix match (either direction)
        for key in self._profiles:
            if key.startswith(model_lower) or model_lower.startswith(key):
                logger.debug("Profile prefix match: %s -> %s", model_lower, key)
                return self._profiles[key]

        # 3. Family match (first token of model_id)
        family = model_lower.split("-")[0]
        candidates = []
        for key, profile in self._profiles.items():
            stored_family = (
                profile.get("metadata", {}).get("model_family", "")
                or key.split("-")[0]
            ).lower()
            if stored_family == family:
                candidates.append(profile)

        if candidates:
            # Use highest version
            def _version_key(p: dict) -> str:
                return str(
                    p.get("version")
                    or p.get("metadata", {}).get("version", "0.0")
                )
            best = sorted(candidates, key=_version_key, reverse=True)[0]
            logger.debug("Profile family match: %s -> family=%s", model_lower, family)
            return best

        logger.debug("No profile match for model: %s", model_id)
        return None

    async def reload(self, profile_dir: Optional[str] = None) -> None:
        """
        Atomic reload -- build new profiles dict then swap.
        Requests in flight complete against old profiles.
        """
        target = profile_dir or self.profile_dir
        new_profiles: dict[str, dict] = {}
        path = Path(target).resolve()
        for f in path.glob("*.yaml"):
            # Guard: only load files within the profile directory (no symlink escape)
            if not f.resolve().parent == path:  # aikido-ignore
                logger.warning("Skipping file outside profile dir: %s", f)
                continue
            if f.name == "schema.yaml":
                continue
            try:
                with open(f, encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                if not data:
                    continue
                if not _verify_profile_license(data, f.name):
                    continue
                model_id = (
                    data.get("model")
                    or data.get("metadata", {}).get("model_id")
                )
                if not model_id:
                    continue
                new_profiles[model_id] = data
            except Exception as e:
                logger.error("Reload: failed to parse %s: %s", f.name, e)

        async with self._lock:
            self._profiles = new_profiles
            self._loaded_count = len(new_profiles)

        logger.info("ProfileRouter reloaded: %d valid profiles", len(new_profiles))

    @property
    def loaded_count(self) -> int:
        return self._loaded_count

    @property
    def profile_ids(self) -> list[str]:
        return list(self._profiles.keys())
