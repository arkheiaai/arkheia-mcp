"""Unit tests for the shared proxy WRITE-path traversal guard (F23 sibling).

`proxy/pathsafe.py` is the WRITE-side twin of `registry_server/storage.py`'s READ
hardening (the two live in disjoint Docker images and mirror each other). These
tests lock the charset to the shipped profiles (floor) and prove the containment
rejects traversal / absolute / symlink escapes fail-closed. The client-side
sibling (`RegistryClient._download_and_apply`) is covered here too.
"""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import yaml
from pydantic import SecretStr

from proxy.pathsafe import is_safe_model_id, safe_profile_write_path
from proxy.registry.client import RegistryClient

# Same battery the registry-server READ tests use — kept in sync deliberately.
TRAVERSAL_MODEL_IDS = [
    "../SECRET_outside",
    "../../SECRET_outside",
    "..%2fSECRET_outside",
    "%2e%2e%2fSECRET_outside",
    "..\\SECRET_outside",
    "/etc/passwd",
    "/tmp/anything",  # nosec B108 — a traversal TEST VECTOR (string), not a tmp path
    "..",
    ".",
    "foo/../../SECRET_outside",
    "sub/child",
    "a\x00b",
    ".hidden",
    "-rf",
    "",
]


# --- charset allow-list -----------------------------------------------------

def test_pathsafe_accepts_all_shipped_profiles():
    """FLOOR: every profile id shipped in profiles/ passes the write allow-list.

    Mirrors the registry server's floor test so the two allow-lists cannot
    silently drift — a future profile id the proxy would reject on write fails
    here, not in production.
    """
    profiles_dir = Path(__file__).resolve().parents[2] / "profiles"
    if not profiles_dir.is_dir():
        pytest.skip("profiles/ directory not present in this checkout")
    stems = [p.stem for p in profiles_dir.glob("*.yaml") if p.name != "schema.yaml"]
    assert stems, "expected at least one shipped profile"
    bad = [s for s in stems if not is_safe_model_id(s)]
    assert bad == [], f"shipped profile ids rejected by write allow-list: {bad}"


@pytest.mark.parametrize("mid", TRAVERSAL_MODEL_IDS)
def test_is_safe_model_id_rejects_traversal(mid):
    assert is_safe_model_id(mid) is False


@pytest.mark.parametrize("mid", ["claude-opus-4-8", "deepseek-v3.1", "gpt-5.2-codex", "a"])
def test_is_safe_model_id_accepts_legit(mid):
    assert is_safe_model_id(mid) is True


# --- write-path containment -------------------------------------------------

@pytest.mark.parametrize("mid", TRAVERSAL_MODEL_IDS)
def test_write_path_rejects_traversal(tmp_path, mid):
    """No traversal id ever yields a write path (fail-closed None)."""
    assert safe_profile_write_path(str(tmp_path), mid) is None


def test_write_path_legit_is_contained(tmp_path):
    out = safe_profile_write_path(str(tmp_path), "claude-opus-4-8")
    assert out is not None
    assert out == (tmp_path / "claude-opus-4-8.yaml").resolve()
    out.relative_to(tmp_path.resolve())  # stays within root


def test_write_path_absolute_id_rejected(tmp_path):
    """An absolute model_id (which Path '/' would let escape the root) is
    rejected by the charset before any path is built."""
    assert safe_profile_write_path(str(tmp_path), str(tmp_path / "evil")) is None


def test_write_path_symlinked_root_still_contained(tmp_path):
    """CONTAINMENT BACKSTOP: even if profiles/ is reached via a symlink, a legit
    id resolves to a path within the real root; a bad id is still rejected."""
    real = tmp_path / "real_profiles"
    real.mkdir()
    link = tmp_path / "profiles_link"
    link.symlink_to(real, target_is_directory=True)
    out = safe_profile_write_path(str(link), "claude-opus-4-8")
    assert out is not None
    assert out == (real / "claude-opus-4-8.yaml").resolve()


# --- client-side sibling: RegistryClient._download_and_apply ----------------

@pytest.mark.asyncio
async def test_client_download_rejects_traversal_model_id(tmp_path):
    """A registry-supplied (untrusted) traversing model_id must NOT write a
    profile outside the profiles root: `_download_and_apply` raises (caller
    retains current profiles) and nothing lands outside the root."""
    root = tmp_path / "profiles"
    root.mkdir()
    outside_canary = tmp_path / "pwned.yaml"  # <root>/../pwned.yaml

    valid_yaml = yaml.dump(
        {
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
    ).encode("utf-8")

    router = AsyncMock()
    router.reload = AsyncMock()
    client = RegistryClient(
        base_url="https://registry.arkheia.ai",
        api_key=SecretStr("test-api-key"),
        profile_dir=str(root),
        router=router,
        validator=None,
    )
    meta = {
        "model_id": "../pwned",
        "checksum": "",  # skip checksum gate; exercise the write-path guard
        "download_url": "https://registry.arkheia.ai/profiles/x.yaml",
        "version": "2.0",
    }

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        download_resp = MagicMock()
        download_resp.content = valid_yaml
        download_resp.raise_for_status = MagicMock()
        mock_client.get.side_effect = [download_resp]

        with pytest.raises(ValueError):
            await client._download_and_apply(meta)

    assert not outside_canary.exists(), "traversal WROTE profile outside root"
    router.reload.assert_not_called()
