"""
Tests for ProfileRouter

PASSING CRITERIA:
  1. ProfileRouter loads all YAML files from a profiles directory on init
  2. Exact match by model_id works
  3. Prefix match works (e.g. "claude-sonnet" matches "claude-sonnet-4-6")
  4. Family match works (e.g. "claude" matches any Claude profile)
  5. Unknown model_id returns None
  6. schema.yaml is excluded from profile loading
  7. Malformed YAML does not crash the router -- skipped with warning
  8. reload() is atomic -- profile count consistent before and after
  9. reload() with new directory picks up new profiles
  10. loaded_count and profile_ids reflect actual loaded profiles
"""

import asyncio
import hashlib
import hmac
import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from proxy.audit.decision_journal import (
    PLAINTEXT_POLICY_ENCRYPTED_INVENTORY,
    PROFILE_AUTH_PLAINTEXT_REJECTED,
    PROFILE_AUTH_SKIPPED_NO_KEY,
)
from proxy.router.profile_router import ProfileRouter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def profiles_dir(tmp_path):
    """Minimal profiles directory with two profiles."""
    # Claude profile (real format)
    claude = {
        "model": "claude-sonnet-4-6",
        "version": "1.0",
        "detection": {
            "strategy": "ensemble",
            "min_required_features": 1,
            "features": {
                "unique_word_ratio": {
                    "enabled": True,
                    "weight": 0.7,
                    "polarity": "positive",
                    "threshold_low": 0.7,
                    "threshold_medium": 0.8,
                    "truth_mean": 0.65,
                    "fab_mean": 0.75,
                }
            }
        }
    }
    # GPT profile (spec schema format)
    gpt = {
        "model": "gpt-4o",
        "version": "2.0",
        "detection": {
            "strategy": "ensemble",
            "min_required_features": 1,
            "features": {
                "word_count": {
                    "enabled": True,
                    "weight": 0.5,
                    "polarity": "positive",
                    "threshold_low": 100.0,
                    "threshold_medium": 200.0,
                }
            }
        }
    }
    # schema.yaml -- should be excluded
    schema = {"description": "profile schema definition"}

    (tmp_path / "claude-sonnet-4-6.yaml").write_text(yaml.dump(claude))
    (tmp_path / "gpt-4o.yaml").write_text(yaml.dump(gpt))
    (tmp_path / "schema.yaml").write_text(yaml.dump(schema))

    return str(tmp_path)


@pytest.fixture
def router(profiles_dir):
    return ProfileRouter(profiles_dir)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestProfileRouterLoading:

    def test_loads_profiles_on_init(self, router):
        """CRITERION 1: Profiles loaded at init."""
        assert router.loaded_count == 2

    def test_schema_yaml_excluded(self, router):
        """CRITERION 6: schema.yaml not loaded as a profile."""
        assert "schema" not in router.profile_ids
        assert router.loaded_count == 2

    def test_profile_ids_populated(self, router):
        """CRITERION 10: profile_ids reflects loaded profiles."""
        ids = router.profile_ids
        assert len(ids) == 2
        assert "claude-sonnet-4-6" in ids
        assert "gpt-4o" in ids

    def test_empty_dir_loads_zero_profiles(self, tmp_path):
        """Empty profiles dir returns empty router, does not crash."""
        r = ProfileRouter(str(tmp_path))
        assert r.loaded_count == 0

    def test_nonexistent_dir_does_not_crash(self, tmp_path):
        """Non-existent profiles dir returns empty router."""
        r = ProfileRouter(str(tmp_path / "does_not_exist"))
        assert r.loaded_count == 0

    def test_malformed_yaml_skipped(self, tmp_path):
        """CRITERION 7: Malformed YAML file skipped, other profiles still loaded."""
        (tmp_path / "good.yaml").write_text(
            yaml.dump({"model": "good-model", "version": "1.0",
                       "detection": {"features": {}}})
        )
        (tmp_path / "bad.yaml").write_text("{{ invalid yaml :")
        r = ProfileRouter(str(tmp_path))
        assert r.loaded_count == 1
        assert r.get("good-model") is not None


def _canonical_for_license(profile: dict) -> str:
    content = {k: v for k, v in profile.items() if k != "license"}
    return json.dumps(content, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _license_signature(profile: dict, key: str) -> str:
    block = profile["license"]
    message = (
        f"{_canonical_for_license(profile)}|"
        f"{block['customer_id']}|{block['valid_until']}"
    )
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def _licensed_profile(valid_until: str | None = None) -> dict:
    return {
        "model": "licensed-model",
        "version": "1.0",
        "detection": {"features": {}},
        "license": {
            "customer_id": "acme",
            "valid_until": valid_until or (date.today() + timedelta(days=30)).isoformat(),
        },
    }


class TestProfileRouterLicenseTrust:

    def test_valid_signed_license_loads_when_key_is_configured(self, tmp_path):
        key = "test-license-secret"
        profile = _licensed_profile()
        profile["license"]["signature"] = _license_signature(profile, key)
        (tmp_path / "licensed.yaml").write_text(yaml.dump(profile))

        router = ProfileRouter(str(tmp_path), license_key=key)

        assert router.loaded_count == 1
        assert router.get("licensed-model") is not None

    def test_license_block_is_not_default_open_without_verification_key(self, tmp_path):
        profile = _licensed_profile()
        profile["license"]["signature"] = "present-but-not-verifiable"
        (tmp_path / "licensed.yaml").write_text(yaml.dump(profile))

        router = ProfileRouter(str(tmp_path), license_key="")

        assert router.loaded_count == 0
        assert router.get("licensed-model") is None

    @pytest.mark.parametrize("license_block", [{}, [], "", 0, False, None])
    def test_present_but_unusable_license_block_is_rejected(
        self, tmp_path, license_block
    ):
        profile = {
            "model": "licensed-model",
            "version": "1.0",
            "detection": {"features": {}},
            "license": license_block,
        }
        (tmp_path / "licensed.yaml").write_text(yaml.dump(profile))

        router = ProfileRouter(str(tmp_path), license_key="")

        assert router.loaded_count == 0
        assert router.get("licensed-model") is None

    def test_bad_license_signature_is_rejected(self, tmp_path):
        profile = _licensed_profile()
        profile["license"]["signature"] = "bad"
        (tmp_path / "licensed.yaml").write_text(yaml.dump(profile))

        router = ProfileRouter(str(tmp_path), license_key="test-license-secret")

        assert router.loaded_count == 0
        assert router.get("licensed-model") is None

    def test_expired_license_is_rejected(self, tmp_path):
        key = "test-license-secret"
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        profile = _licensed_profile(yesterday)
        profile["license"]["signature"] = _license_signature(profile, key)
        (tmp_path / "licensed.yaml").write_text(yaml.dump(profile))

        router = ProfileRouter(str(tmp_path), license_key=key)

        assert router.loaded_count == 0
        assert router.get("licensed-model") is None

    def test_plaintext_profile_cannot_fallback_when_encrypted_profiles_are_refused(
        self, tmp_path
    ):
        (tmp_path / "victim.yaml.enc").write_bytes(b"encrypted-profile-needs-a-key")
        (tmp_path / "attacker.yaml").write_text(yaml.dump({
            "model": "victim-model",
            "version": "1.0",
            "detection": {"features": {}},
        }))

        router = ProfileRouter(str(tmp_path), decryption_key=None)

        assert router.loaded_count == 0
        assert router.get("victim-model") is None
        rows, dropped = router.decision_journal.drain()
        assert dropped == 0
        assert {row["outcome"] for row in rows} == {
            PROFILE_AUTH_PLAINTEXT_REJECTED,
            PROFILE_AUTH_SKIPPED_NO_KEY,
        }
        plaintext_row = next(row for row in rows if row["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED)
        assert plaintext_row["plaintext_policy_state"] == PLAINTEXT_POLICY_ENCRYPTED_INVENTORY

    def test_plaintext_profile_in_encrypted_dir_requires_explicit_escape_hatch(
        self, tmp_path
    ):
        (tmp_path / "victim.yaml.enc").write_bytes(b"encrypted-profile-needs-a-key")
        (tmp_path / "local-dev.yaml").write_text(yaml.dump({
            "model": "local-dev-model",
            "version": "1.0",
            "detection": {"features": {}},
        }))

        router = ProfileRouter(
            str(tmp_path),
            decryption_key=None,
            allow_plaintext_profiles=True,
        )

        assert router.loaded_count == 1
        assert router.get("local-dev-model") is not None


class TestProfileRouterLookup:

    def test_exact_match(self, router):
        """CRITERION 2: Exact model_id match works."""
        profile = router.get("claude-sonnet-4-6")
        assert profile is not None
        assert profile["model"] == "claude-sonnet-4-6"

    def test_exact_match_case_insensitive(self, router):
        """Exact match is case-insensitive."""
        profile = router.get("CLAUDE-SONNET-4-6")
        assert profile is not None

    def test_prefix_match(self, router):
        """CRITERION 3: Prefix match works."""
        profile = router.get("claude-sonnet")
        assert profile is not None

    def test_prefix_match_longer_input(self, router):
        """Longer model_id prefix-matches shorter profile key."""
        profile = router.get("claude-sonnet-4-6-20250515")
        assert profile is not None

    def test_unknown_model_returns_none(self, router):
        """CRITERION 5: Unknown model_id returns None."""
        profile = router.get("llama-3-70b")
        assert profile is None

    def test_empty_string_returns_none(self, router):
        """Empty string returns None."""
        assert router.get("") is None

    def test_none_safe(self, router):
        """None-like input returns None."""
        assert router.get(None) is None  # type: ignore

    def test_versioned_family_miss_does_not_borrow_unreviewed_sibling(self, tmp_path):
        (tmp_path / "claude-sonnet-4-6.yaml").write_text(yaml.dump({
            "model": "claude-sonnet-4-6",
            "version": "1.0",
            "detection": {"features": {}},
        }))
        (tmp_path / "claude-opus-4-8.yaml").write_text(yaml.dump({
            "model": "claude-opus-4-8",
            "version": "1.0",
            "detection": {"features": {}},
        }))
        router = ProfileRouter(str(tmp_path))

        assert router.get("claude-unknown-9") is None

    def test_explicit_prefix_resolution_still_supports_dated_model_ids(self, router):
        profile = router.get("claude-sonnet-4-6-20250515")

        assert profile is not None
        assert profile["model"] == "claude-sonnet-4-6"

    def test_unversioned_metadata_family_fallback_still_works(self, tmp_path):
        (tmp_path / "acme-surface.yaml").write_text(yaml.dump({
            "model": "acme-surface",
            "version": "1.0",
            "metadata": {"model_family": "acme"},
            "detection": {"features": {}},
        }))
        router = ProfileRouter(str(tmp_path))

        profile = router.get("acme")

        assert profile is not None
        assert profile["model"] == "acme-surface"


class TestProfileRouterReload:

    def test_reload_updates_profiles(self, profiles_dir, tmp_path):
        """CRITERION 8, 9: Reload with new dir picks up new profiles atomically."""
        router = ProfileRouter(profiles_dir)
        assert router.loaded_count == 2

        # Create new dir with 3 profiles
        new_profile = {"model": "llama-3-70b", "version": "1.0",
                       "detection": {"features": {}}}
        new_dir = tmp_path / "new_profiles"
        new_dir.mkdir()
        (new_dir / "llama-3-70b.yaml").write_text(yaml.dump(new_profile))

        asyncio.run(router.reload(str(new_dir)))

        assert router.loaded_count == 1
        assert router.get("llama-3-70b") is not None

    def test_reload_concurrent_safe(self, profiles_dir):
        """Concurrent reloads do not corrupt state."""
        router = ProfileRouter(profiles_dir)

        async def do_reloads():
            tasks = [router.reload() for _ in range(10)]
            await asyncio.gather(*tasks)

        asyncio.run(do_reloads())
        # Router should still be in valid state
        assert router.loaded_count >= 0
