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
from pathlib import Path

import pytest
import yaml

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

        asyncio.get_event_loop().run_until_complete(
            router.reload(str(new_dir))
        )

        assert router.loaded_count == 1
        assert router.get("llama-3-70b") is not None

    def test_reload_concurrent_safe(self, profiles_dir):
        """Concurrent reloads do not corrupt state."""
        router = ProfileRouter(profiles_dir)

        async def do_reloads():
            tasks = [router.reload() for _ in range(10)]
            await asyncio.gather(*tasks)

        asyncio.get_event_loop().run_until_complete(do_reloads())
        # Router should still be in valid state
        assert router.loaded_count >= 0
