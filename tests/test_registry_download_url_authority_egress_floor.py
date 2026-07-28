"""
Floor candidate: mcp.registry_download_url_authority_egress.

The profile list is authenticated registry metadata. Its ``download_url`` field
must not be an egress gadget that causes the proxy to send the registry bearer
token to a foreign authority.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import pytest
import yaml
from pydantic import SecretStr

from proxy.registry.client import RegistryClient
from proxy.registry.validator import ProfileValidator
from registry_server.storage import ProfileStorage


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
        },
    },
}
VALID_YAML = yaml.dump(VALID_PROFILE).encode("utf-8")
VALID_CHECKSUM = hashlib.sha256(VALID_YAML).hexdigest()


@pytest.fixture
def mock_router():
    router = AsyncMock()
    router.reload = AsyncMock()
    return router


def _client(tmp_path: Path, mock_router) -> RegistryClient:
    return RegistryClient(
        base_url="https://registry.arkheia.ai",
        api_key=SecretStr("test-api-key"),
        profile_dir=str(tmp_path),
        router=mock_router,
        validator=ProfileValidator(),
    )


def _list_response(download_url: str) -> MagicMock:
    response = MagicMock()
    response.json.return_value = {
        "profiles": [
            {
                "model_id": "llama-3-70b",
                "version": "2.0",
                "checksum": VALID_CHECKSUM,
                "download_url": download_url,
            }
        ],
    }
    response.raise_for_status = MagicMock()
    return response


def _download_response() -> MagicMock:
    response = MagicMock()
    response.content = VALID_YAML
    response.raise_for_status = MagicMock()
    return response


@pytest.mark.asyncio
async def test_relative_download_url_is_bound_to_registry_base_before_auth(
    tmp_path, mock_router
):
    client = _client(tmp_path, mock_router)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = [
            _list_response("/profiles/llama-3-70b/download"),
            _download_response(),
        ]

        result = await client.pull()

    assert result["updated"] == ["llama-3-70b"]
    download_call = mock_client.get.call_args_list[1]
    assert download_call.args[0] == (
        "https://registry.arkheia.ai/profiles/llama-3-70b/download"
    )
    assert download_call.kwargs["headers"] == {"Authorization": "Bearer test-api-key"}


@pytest.mark.asyncio
async def test_foreign_download_url_is_rejected_before_authorization_leaves(
    tmp_path, mock_router
):
    client = _client(tmp_path, mock_router)

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.get.side_effect = [
            _list_response("https://downloads.example.invalid/profile.yaml"),
        ]

        result = await client.pull()

    assert result["updated"] == []
    assert result["skipped"] == []
    assert len(result["errors"]) == 1
    assert "authority" in result["errors"][0]
    assert mock_client.get.call_count == 1, (
        "the profile list request is expected, but no credentialed download "
        "request may be sent to a foreign download_url authority"
    )
    mock_router.reload.assert_not_called()


def test_registry_storage_advertises_downloads_under_configured_base(tmp_path):
    (tmp_path / "llama-3-70b.yaml").write_bytes(VALID_YAML)
    storage = ProfileStorage(profile_dir=str(tmp_path), base_url="http://registry:8200")

    profiles = storage.list_profiles()

    assert len(profiles) == 1
    parsed = urlparse(profiles[0]["download_url"])
    assert parsed.scheme == "http"
    assert parsed.netloc == "registry:8200"
    assert parsed.path == "/profiles/llama-3-70b/download"
