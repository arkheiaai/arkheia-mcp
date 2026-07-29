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
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr

from proxy.auth import require_auth
from proxy.audit.decision_journal import RECEIPT_ENQUEUED, RECEIPT_UNAVAILABLE
from proxy.audit.writer import AuditWriter
from proxy.endpoints.admin import router as admin_router
from proxy.registry.client import RegistryClient
from proxy.registry.receipts import (
    EVENT_REGISTRY_PROFILE_PULL,
    OUTCOME_PROFILE_APPLIED,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING,
    OUTCOME_PROFILE_REJECTED_VALIDATION,
    OUTCOME_PULL_SKIPPED_NO_API_KEY,
)
from proxy.registry.validator import ProfileValidator
from proxy.tests._receipt_probe import ReceiptProbe


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
    },
    "smoke_test": {
        "prompt": "What is 2+2?",
        "response": "Four simple words here.",
        "expected_risk": "LOW",
    },
}

VALID_YAML = yaml.dump(VALID_PROFILE).encode("utf-8")
VALID_CHECKSUM = hashlib.sha256(VALID_YAML).hexdigest()


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


def admin_pull_app(registry_client, writer=None):
    lifespan = None
    if writer is not None:
        @asynccontextmanager
        async def lifespan(app):
            await writer.start()
            try:
                yield
            finally:
                await writer.stop()

    app = FastAPI(lifespan=lifespan)
    app.include_router(admin_router)
    app.state.registry_client = registry_client
    app.dependency_overrides[require_auth] = lambda: "registry-test@example.com"
    return app


class BlackholeWriter:
    """A rail that accepts writes but leaves the durable log empty."""

    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.records = []

    async def write(self, record):
        self.records.append(record)


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
        passed, reason = validator.run_smoke_test(VALID_PROFILE)
        assert passed is True, reason

    def test_no_smoke_test_does_not_pass(self, validator):
        """Profile without smoke_test is not validated by default."""
        profile = dict(VALID_PROFILE)
        profile.pop("smoke_test", None)
        passed, reason = validator.run_smoke_test(profile)
        assert passed is False
        assert "required" in reason

    def test_validate_rejects_absent_smoke_test(self, validator):
        """
        F19 adversarial: registry validation must not certify a profile that
        never declared the smoke test the schema says should prove it.
        """
        profile = dict(VALID_PROFILE)
        profile.pop("smoke_test", None)
        with pytest.raises(ValueError, match="Smoke test failed: .*required"):
            validator.validate(yaml.dump(profile).encode("utf-8"))

    def test_missing_checksum_is_not_a_verification_pass(self, validator):
        """
        F19 adversarial: an absent checksum is not "nothing to compare"; it is a
        missing precondition for registry-delivered bytes.
        """
        with pytest.raises(ValueError, match="checksum is required"):
            validator.require_checksum("")

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
    async def test_missing_checksum_rejects_without_download_and_is_receipted(
        self, tmp_path, mock_router
    ):
        """
        F19 adversarial: metadata without a checksum must not download, write,
        or reload, and the refusal must be readable from the real audit rail by
        the decision id returned to the caller.
        """
        probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
        await probe.start()
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path / "profiles"),
            router=mock_router,
            validator=ProfileValidator(),
            audit_writer=probe.writer,
        )
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = list_resp

            result = await client.pull()

        await probe.stop()
        assert mock_client.get.call_count == 1, "missing checksum should stop before download"
        mock_router.reload.assert_not_called()
        assert not (tmp_path / "profiles" / "llama-3-70b.yaml").exists()
        receipt = result["receipts"][0]
        assert receipt["outcome"] == OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING
        row = probe.require(receipt["decision_id"])
        assert row["event_type"] == EVENT_REGISTRY_PROFILE_PULL
        assert row["outcome"] == OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING
        assert row["model_id"] == "llama-3-70b"
        assert row["checksum_present"] is False
        assert row["receipt_status"] == "enqueued"

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
    async def test_no_smoke_test_download_is_rejected_receipted_and_not_applied(
        self, tmp_path, mock_router
    ):
        """
        F19 adversarial: a downloaded profile with a valid checksum but no
        smoke_test must not be applied, and the validation refusal must land on
        the audit rail.
        """
        probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
        await probe.start()
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path / "profiles"),
            router=mock_router,
            validator=ProfileValidator(),
            audit_writer=probe.writer,
        )
        profile_without_smoke = dict(VALID_PROFILE)
        profile_without_smoke.pop("smoke_test", None)
        content = yaml.dump(profile_without_smoke).encode("utf-8")
        checksum = hashlib.sha256(content).hexdigest()
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": checksum,
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()
            download_resp = MagicMock()
            download_resp.content = content
            download_resp.raise_for_status = MagicMock()
            mock_client.get.side_effect = [list_resp, download_resp]

            result = await client.pull()

        await probe.stop()
        mock_router.reload.assert_not_called()
        assert not (tmp_path / "profiles" / "llama-3-70b.yaml").exists()
        assert "llama-3-70b" not in result["updated"]
        receipt = result["receipts"][0]
        assert receipt["outcome"] == OUTCOME_PROFILE_REJECTED_VALIDATION
        row = probe.require(receipt["decision_id"])
        assert row["event_type"] == EVENT_REGISTRY_PROFILE_PULL
        assert row["outcome"] == OUTCOME_PROFILE_REJECTED_VALIDATION
        assert row["checksum_present"] is True
        assert row["checksum_expected"] == f"sha256:{checksum}"
        assert row["receipt_status"] == "enqueued"

    @pytest.mark.asyncio
    async def test_successful_pull_is_receipted_by_decision_id(
        self, tmp_path, mock_router
    ):
        """F19 positive control: a successful apply emits the same receipt shape."""
        probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
        await probe.start()
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path / "profiles"),
            router=mock_router,
            validator=ProfileValidator(),
            audit_writer=probe.writer,
        )
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": VALID_CHECKSUM,
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
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

            result = await client.pull()

        await probe.stop()
        receipt = result["receipts"][0]
        assert receipt["outcome"] == OUTCOME_PROFILE_APPLIED
        row = probe.require(receipt["decision_id"])
        assert row["event_type"] == EVENT_REGISTRY_PROFILE_PULL
        assert row["outcome"] == OUTCOME_PROFILE_APPLIED
        assert row["model_id"] == "llama-3-70b"
        assert row["receipt_status"] == "enqueued"

    def test_manual_pull_http_response_surfaces_receipt_identity_and_status(
        self, tmp_path, mock_router
    ):
        """
        The caller-visible admin API must carry the receipt identity and status.
        Returning only "Registry pull completed" leaves the receipt proof
        unreachable from every HTTP surface.
        """
        log_path = tmp_path / "audit.jsonl"
        writer = AuditWriter(str(log_path))
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr("test-api-key"),
            profile_dir=str(tmp_path / "profiles"),
            router=mock_router,
            validator=ProfileValidator(),
            audit_writer=writer,
        )
        app = admin_pull_app(client, writer=writer)
        registry_response = {
            "profiles": [{
                "model_id": "llama-3-70b",
                "version": "2.0",
                "download_url": "https://registry.arkheia.ai/profiles/llama-3-70b.yaml",
            }],
        }

        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__.return_value = mock_client
            list_resp = MagicMock()
            list_resp.json.return_value = registry_response
            list_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = list_resp

            with TestClient(app) as http:
                response = http.post("/admin/registry/pull")

        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "ok"
        assert payload["updated"] == []
        assert payload["skipped"] == []
        assert payload["errors"], "missing-checksum refusal should be caller-visible"
        receipts = payload["receipts"]
        assert len(receipts) == 1

        receipt = receipts[0]
        assert str(uuid.UUID(receipt["decision_id"])) == receipt["decision_id"]
        assert receipt["receipt_status"] == RECEIPT_ENQUEUED
        assert receipt["outcome"] == OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING
        assert receipt["model_id"] == "llama-3-70b"

        probe = ReceiptProbe(log_path, id_field="decision_id")
        row = probe.require(receipt["decision_id"])
        assert row["event_type"] == EVENT_REGISTRY_PROFILE_PULL
        assert row["outcome"] == receipt["outcome"]
        assert row["model_id"] == receipt["model_id"]
        assert row["receipt_status"] == receipt["receipt_status"]
        assert len(probe.raw_bytes()) > 0

    def test_manual_pull_http_response_does_not_claim_enqueued_for_empty_log(
        self, tmp_path, mock_router
    ):
        """
        Mutation guard: a rail that accepts the write call but leaves zero
        durable bytes must surface `unavailable`, not hard-coded `enqueued`.
        """
        log_path = tmp_path / "audit.jsonl"
        writer = BlackholeWriter(log_path)
        client = RegistryClient(
            base_url="https://registry.arkheia.ai",
            api_key=SecretStr(""),
            profile_dir=str(tmp_path / "profiles"),
            router=mock_router,
            validator=ProfileValidator(),
            audit_writer=writer,
        )
        app = admin_pull_app(client)

        with TestClient(app) as http:
            response = http.post("/admin/registry/pull")

        assert response.status_code == 200
        payload = response.json()
        receipts = payload["receipts"]
        assert len(receipts) == 1
        receipt = receipts[0]
        assert str(uuid.UUID(receipt["decision_id"])) == receipt["decision_id"]
        assert receipt["outcome"] == OUTCOME_PULL_SKIPPED_NO_API_KEY
        assert receipt["receipt_status"] == RECEIPT_UNAVAILABLE
        assert ReceiptProbe(log_path, id_field="decision_id").find(
            receipt["decision_id"]
        ) is None
        assert not log_path.exists() or log_path.read_bytes() == b""
