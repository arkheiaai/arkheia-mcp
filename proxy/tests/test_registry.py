"""
Tests for RegistryClient and ProfileValidator

PASSING CRITERIA (RegistryClient):
  1. pull() makes GET /profiles with correct Authorization: Bearer header
  2. Checksum mismatch raises ValueError -- old profile retained
  3. Successful pull triggers router.reload()
  4. Registry unreachable (ConnectError) is caught -- returns error dict, no crash
  5. Registry pull timeout is caught -- returns error dict, no crash
  6. Empty API key skips pull gracefully (no request made)
  7. Profile written to profile_dir after successful pull

PASSING CRITERIA (ProfileValidator):
  8. Valid profile YAML passes schema validation
  9. Missing required keys fails schema validation
  10. Checksum mismatch returns False
  11. Smoke test failure raises ValueError
  12. Malformed YAML raises ValueError
"""

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest
import yaml
from pydantic import SecretStr

from proxy.registry.client import RegistryClient
from proxy.registry.validator import ProfileValidator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_PROFILE = {
    "model": "llama-3-70b",
    "version": "2.0",
    "detection": {
        "strategy": "ensemble",
        "min_required_features": 1,
        "features": {
            "word_count": {
                "enabled": True,
                "weight": 0.5,
                "polarity": "positive",
                "threshold_low": 50.0,
                "threshold_medium": 100.0,
            }
        }
    }
}

VALID_YAML = yaml.dump(VALID_PROFILE).encode("utf-8")
VALID_CHECKSUM = hashlib.sha256(VALID_YAML).hexdigest()


def _authority(url: str) -> tuple[str, str, int | None]:
    parsed = urlparse(url)
    port = parsed.port
    if port is None and parsed.scheme == "http":
        port = 80
    elif port is None and parsed.scheme == "https":
        port = 443
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), port


@pytest.fixture
def validator():
    return ProfileValidator()


@pytest.fixture
def mock_router():
    router = AsyncMock()
    router.reload = AsyncMock()
    return router


@pytest.fixture
def registry_client(tmp_path, mock_router):
    return RegistryClient(
        base_url="https://registry.arkheia.ai",
        api_key=SecretStr("test-api-key"),
        profile_dir=str(tmp_path),
        router=mock_router,
        validator=ProfileValidator(),
    )


# ---------------------------------------------------------------------------
# ProfileValidator tests
# ---------------------------------------------------------------------------

class TestProfileValidator:

    def test_valid_profile_passes(self, validator):
        """CRITERION 8: Valid profile passes schema validation."""
        result = validator.validate(VALID_YAML)
        assert result["model"] == "llama-3-70b"

    def test_missing_detection_fails(self, validator):
        """CRITERION 9: Missing required keys fails validation."""
        bad = yaml.dump({"model": "x", "version": "1.0"}).encode()
        with pytest.raises(ValueError, match="Schema validation failed"):
            validator.validate(bad)

    def test_malformed_yaml_raises(self, validator):
        """CRITERION 12: Malformed YAML raises ValueError."""
        with pytest.raises(ValueError, match="YAML parse error"):
            validator.validate(b"{{ not valid yaml :")

    def test_checksum_match(self, validator):
        """CRITERION 10 (positive): Correct checksum returns True."""
        assert validator.verify_checksum(VALID_YAML, VALID_CHECKSUM) is True

    def test_checksum_mismatch(self, validator):
        """CRITERION 10: Wrong checksum returns False."""
        assert validator.verify_checksum(VALID_YAML, "deadbeef" * 8) is False

    def test_smoke_test_pass(self, validator):
        """Smoke test with expected LOW result passes."""
        profile_with_smoke = dict(VALID_PROFILE)
        profile_with_smoke["smoke_test"] = {
            "prompt": "What is 2+2?",
            "response": "Four.",
            "expected_risk": "LOW",  # short text, no logprobs -- will be LOW or UNKNOWN
        }
        passed, reason = validator.run_smoke_test(profile_with_smoke)
        # Either passes or is inconclusive (no features computable for "Four.")
        assert passed or "inconclusive" in reason

    def test_no_smoke_test_passes(self, validator):
        """Profile without smoke_test passes by default."""
        passed, reason = validator.run_smoke_test(VALID_PROFILE)
        assert passed is True
        assert "no smoke test" in reason

    def test_smoke_test_incomplete_does_not_pass(self, validator):
        """
        RED (sibling of the integrity.py empty-manifest defect, 2026-07-27): a
        smoke_test block that DECLARES itself (unlike test_no_smoke_test_passes,
        where the key is absent entirely) but is missing response/expected_risk
        must not read as a pass. profiles/schema.yaml requires all three fields
        together -- a smoke_test present with fields missing is a malformed
        declared check, not the absence of one, and
        `if not response or not expected_risk: return True` was exactly the
        `if not items: return True` vacuous-truth shape: nothing to compare, so
        it defaulted to "passed".
        """
        profile = dict(VALID_PROFILE)
        profile["smoke_test"] = {"prompt": "What is 2+2?"}  # no response/expected_risk
        passed, reason = validator.run_smoke_test(profile)
        assert passed is False, reason

    def test_smoke_test_inconclusive_does_not_pass(self, validator):
        """
        RED, sibling framing: a smoke test that ran but for which
        classify_with_profile computed ZERO features (features_used == 0, so it
        returns None) must not silently read as a pass either. "Could not
        determine" is absence of evidence, not evidence of a pass.
        """
        profile = dict(VALID_PROFILE)
        profile["detection"] = {"features": {}}  # no features configured -> None
        profile["smoke_test"] = {
            "prompt": "What is 2+2?",
            "response": "Four.",
            "expected_risk": "LOW",
        }
        passed, reason = validator.run_smoke_test(profile)
        assert passed is False, reason


# ---------------------------------------------------------------------------
# RegistryClient tests
# ---------------------------------------------------------------------------

class TestRegistryClient:

    @pytest.mark.asyncio
    async def test_pull_sends_auth_header(self, registry_client, tmp_path):
        """CRITERION 1: pull() sends Authorization: Bearer header."""
        registry_response = {
            "profiles": [],
            "pull_timestamp": "2026-02-28T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_resp = MagicMock()
            mock_resp.json.return_value = registry_response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp

            await registry_client.pull()

            call_kwargs = mock_client.get.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert "Authorization" in headers
            assert headers["Authorization"].startswith("Bearer ")

    @pytest.mark.asyncio
    async def test_empty_api_key_skips_pull(self, tmp_path, mock_router):
        """CRITERION 6: Empty API key skips pull -- no network call made."""
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr(""),
            profile_dir=str(tmp_path),
            router=mock_router,
        )
        with patch("httpx.AsyncClient") as mock_client_cls:
            result = await client.pull()
            assert "api_key_not_set" in result["errors"]
            mock_client_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_error_handled_gracefully(self, registry_client):
        """CRITERION 4: ConnectError caught -- no crash, returns error info."""
        import httpx as _httpx
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = _httpx.ConnectError("refused")

            result = await registry_client.pull()

        assert len(result["errors"]) > 0

    @pytest.mark.asyncio
    async def test_timeout_handled_gracefully(self, registry_client):
        """CRITERION 5: TimeoutException caught -- no crash."""
        import httpx as _httpx
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = _httpx.TimeoutException("timeout")

            result = await registry_client.pull()

        assert "timeout" in result["errors"]

    @pytest.mark.asyncio
    async def test_checksum_mismatch_retains_old_profile(
        self, registry_client, tmp_path, mock_router
    ):
        """CRITERION 2: Checksum mismatch -- old profile not overwritten."""
        # Write an existing profile
        profile_path = tmp_path / "llama-3-70b.yaml"
        profile_path.write_bytes(b"original content")

        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.1",
                "checksum": "wrongchecksum" * 4,
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
            "pull_timestamp": "2026-02-28T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()

            download_resp = MagicMock()
            download_resp.content = VALID_YAML
            download_resp.raise_for_status = MagicMock()

            mock_client.get.side_effect = [list_resp, download_resp]

            result = await registry_client.pull()

        # Checksum wrong -> profile not applied -> router.reload not called
        mock_router.reload.assert_not_called()
        # Old content retained
        assert profile_path.read_bytes() == b"original content"

    @pytest.mark.asyncio
    async def test_successful_pull_triggers_reload(
        self, registry_client, tmp_path, mock_router
    ):
        """CRITERION 3: Successful pull triggers router.reload()."""
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": VALID_CHECKSUM,
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
            "pull_timestamp": "2026-02-28T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()

            download_resp = MagicMock()
            download_resp.content = VALID_YAML
            download_resp.raise_for_status = MagicMock()

            mock_client.get.side_effect = [list_resp, download_resp]

            result = await registry_client.pull()

        mock_router.reload.assert_called_once()
        assert "llama-3-70b" in result["updated"]

    @pytest.mark.asyncio
    async def test_profile_written_to_dir(
        self, registry_client, tmp_path, mock_router
    ):
        """CRITERION 7: Profile file written to profile_dir after successful pull."""
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": VALID_CHECKSUM,
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
            "pull_timestamp": "2026-02-28T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()

            download_resp = MagicMock()
            download_resp.content = VALID_YAML
            download_resp.raise_for_status = MagicMock()

            mock_client.get.side_effect = [list_resp, download_resp]

            await registry_client.pull()

        assert (tmp_path / "llama-3-70b.yaml").exists()

    @pytest.mark.asyncio
    async def test_pull_rejects_foreign_download_url_before_authorized_download(
        self, registry_client, mock_router
    ):
        """
        Registry metadata must not choose a second authority for bearer downloads.

        The list call is authorized for the configured registry. If a profile
        advertises a foreign download_url, the client must reject it before the
        second authorized GET is made.
        """
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": VALID_CHECKSUM,
                "download_url": "https://evil.example/profiles/llama-3-70b.yaml",
            }],
            "pull_timestamp": "2026-02-28T00:00:00Z",
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client

            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()

            download_resp = MagicMock()
            download_resp.content = VALID_YAML
            download_resp.raise_for_status = MagicMock()

            mock_client.get.side_effect = [list_resp, download_resp]

            result = await registry_client.pull()

        assert result["updated"] == []
        assert result["skipped"] == []
        assert len(result["errors"]) == 1
        assert "authority does not match" in result["errors"][0]
        mock_router.reload.assert_not_called()
        assert mock_client.get.call_count == 1
        assert mock_client.get.call_args.args[0] == "https://registry.arkheia.ai/profiles"

    @pytest.mark.parametrize(
        ("base_url", "download_url"),
        [
            ("https://registry.arkheia.ai", "/profiles/gpt.yaml"),
            ("https://registry.arkheia.ai", "profiles/gpt.yaml"),
            ("https://registry.arkheia.ai", "https://REGISTRY.ARKHEIA.AI/profiles/gpt.yaml"),
            ("https://registry.arkheia.ai", "https://registry.arkheia.ai:443/profiles/gpt.yaml"),
            ("http://registry.arkheia.ai", "http://registry.arkheia.ai:80/profiles/gpt.yaml"),
            ("http://127.0.0.1:8200", "http://127.0.0.1:8200/profiles/gpt.yaml"),
            ("http://[::1]:8200", "http://[::1]:8200/profiles/gpt.yaml"),
        ],
    )
    def test_same_origin_download_url_accepts_only_exact_authority_equivalence(
        self, base_url, download_url, tmp_path, mock_router
    ):
        client = RegistryClient(
            base_url=base_url,
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path),
            router=mock_router,
        )

        resolved = client._same_origin_download_url(download_url)

        assert _authority(resolved) == _authority(base_url)

    @pytest.mark.parametrize(
        ("base_url", "download_url", "message"),
        [
            (
                "https://registry.arkheia.ai",
                "http://registry.arkheia.ai/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "https://registry.arkheia.ai",
                "https://registry.arkheia.ai:444/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "https://registry.arkheia.ai",
                "//evil.example/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "https://registry.arkheia.ai",
                "https://registry.arkheia.ai.evil.example/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "https://registry.arkheia.ai",
                "https://registry.arkheia.ai@evil.example/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "https://registry.arkheia.ai",
                "https://user@registry.arkheia.ai/profiles/gpt.yaml",
                "must not include userinfo",
            ),
            (
                "https://registry.arkheia.ai",
                "https://user:pw@registry.arkheia.ai/profiles/gpt.yaml",
                "must not include userinfo",
            ),
            (
                "http://127.0.0.1:8200",
                "http://127.0.0.2:8200/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "http://127.0.0.1:8200",
                "http://127.0.0.1.nip.io:8200/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "http://127.0.0.1.nip.io:8200",
                "http://127.0.0.1:8200/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "http://[::1]:8200",
                "http://[::2]:8200/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "http://localhost:8200",
                "http://127.0.0.1:8200/profiles/gpt.yaml",
                "authority does not match",
            ),
            (
                "http://registry.arkheia.ai",
                "http://registry.arkheia.ai:81/profiles/gpt.yaml",
                "authority does not match",
            ),
        ],
    )
    def test_same_origin_download_url_rejects_confusing_or_foreign_authorities(
        self, base_url, download_url, message, tmp_path, mock_router
    ):
        client = RegistryClient(
            base_url=base_url,
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path),
            router=mock_router,
        )

        with pytest.raises(ValueError, match=message):
            client._same_origin_download_url(download_url)
