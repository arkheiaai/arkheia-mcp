"""
Tests for the Arkheia Registry Server.

Passing criteria:
  1. GET /health returns 200, no auth required
  2. GET /profiles without auth returns 401
  3. GET /profiles with valid key returns 200 and a profiles list
  4. GET /profiles with invalid key returns 401
  5. GET /profiles response has correct structure (model_id, version, checksum, download_url)
  6. GET /profiles/{model_id}/download with valid key returns YAML bytes
  7. GET /profiles/{model_id}/download for unknown model returns 404
  8. GET /profiles?since=future_date returns empty profiles list
  9. No keys configured (ARKHEIA_REGISTRY_KEYS empty) returns 503 on protected endpoints
 10. generate_key() returns a string starting with "ak_live_"
"""

import os
import hashlib
from datetime import datetime, timezone, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

from registry_server.auth import generate_key
from registry_server.main import app
from registry_server.storage import ProfileStorage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_KEY = "test-fixture-not-a-real-key-00000"

REAL_FORMAT_YAML = """\
model: test-model
version: "1.0"
detection:
  thresholds:
    high_risk: 0.85
"""

SPEC_FORMAT_YAML = """\
metadata:
  model_id: test-model-2
  version: "1.0"
thresholds:
  high_risk: 0.85
"""


@pytest.fixture()
def profile_dir(tmp_path):
    """Create a temp directory with two profile YAML files."""
    (tmp_path / "test-model.yaml").write_text(REAL_FORMAT_YAML, encoding="utf-8")
    (tmp_path / "test-model-2.yaml").write_text(SPEC_FORMAT_YAML, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def client(monkeypatch, profile_dir):
    """TestClient with auth configured and storage pointed at temp profile_dir."""
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")

    with TestClient(app) as c:
        yield c


@pytest.fixture()
def client_no_keys(monkeypatch, profile_dir):
    """TestClient with NO keys configured (unprovisioned server)."""
    monkeypatch.delenv("ARKHEIA_REGISTRY_KEYS", raising=False)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")

    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health_no_auth(client):
    """1. GET /health returns 200, no auth required."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "profiles_available" in data
    assert isinstance(data["profiles_available"], int)


def test_profiles_no_auth_returns_401(client):
    """2. GET /profiles without auth returns 401."""
    resp = client.get("/profiles")
    assert resp.status_code == 401


def test_profiles_valid_key_returns_200(client):
    """3. GET /profiles with valid key returns 200 and a profiles list."""
    resp = client.get(
        "/profiles",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "profiles" in data
    assert "count" in data
    assert isinstance(data["profiles"], list)
    assert data["count"] == len(data["profiles"])


def test_profiles_invalid_key_returns_401(client):
    """4. GET /profiles with invalid key returns 401."""
    resp = client.get(
        "/profiles",
        headers={"Authorization": "Bearer ak_live_wrongkey"},  # noqa: test fixture, not a real key  # aikido-ignore
    )
    assert resp.status_code == 401


def test_profiles_correct_structure(client):
    """5. GET /profiles response has correct structure."""
    resp = client.get(
        "/profiles",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    profiles = resp.json()["profiles"]
    assert len(profiles) >= 1

    for profile in profiles:
        assert "model_id" in profile, f"Missing model_id in {profile}"
        assert "version" in profile, f"Missing version in {profile}"
        assert "checksum" in profile, f"Missing checksum in {profile}"
        assert "download_url" in profile, f"Missing download_url in {profile}"
        # checksum should be a 64-char hex string (SHA-256)
        assert len(profile["checksum"]) == 64
        assert all(c in "0123456789abcdef" for c in profile["checksum"])
        # download_url should contain the model_id
        assert profile["model_id"] in profile["download_url"]


def test_download_profile_valid_key(client, profile_dir):
    """6. GET /profiles/{model_id}/download with valid key returns YAML bytes."""
    resp = client.get(
        "/profiles/test-model/download",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"] in (
        "application/yaml",
        "application/yaml; charset=utf-8",
    )
    # Content should be valid YAML matching the original file
    content = resp.content
    data = yaml.safe_load(content)
    assert data["model"] == "test-model"

    # Verify checksum matches what list_profiles reported
    expected_checksum = hashlib.sha256(
        (profile_dir / "test-model.yaml").read_bytes()
    ).hexdigest()
    list_resp = client.get(
        "/profiles",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    profiles = {p["model_id"]: p for p in list_resp.json()["profiles"]}
    assert profiles["test-model"]["checksum"] == expected_checksum


def test_download_profile_unknown_returns_404(client):
    """7. GET /profiles/{model_id}/download for unknown model returns 404."""
    resp = client.get(
        "/profiles/nonexistent-model-xyz/download",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 404


def test_profiles_since_future_returns_empty(client):
    """8. GET /profiles?since=future_date returns empty profiles list."""
    future = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
    resp = client.get(
        "/profiles",
        params={"since": future},
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["profiles"] == []
    assert data["count"] == 0


def test_no_keys_configured_returns_503(client_no_keys):
    """9. No keys configured (ARKHEIA_REGISTRY_KEYS empty) returns 503 on protected endpoints."""
    resp = client_no_keys.get(
        "/profiles",
        headers={"Authorization": "Bearer ak_live_anything"},
    )
    assert resp.status_code == 503

    resp2 = client_no_keys.get(
        "/profiles/test-model/download",
        headers={"Authorization": "Bearer ak_live_anything"},
    )
    assert resp2.status_code == 503


def test_generate_key_format():
    """10. generate_key() returns a string starting with 'ak_live_'."""
    key = generate_key()
    assert isinstance(key, str)
    assert key.startswith("ak_live_")
    # Should be ak_live_ + 32 hex chars
    suffix = key[len("ak_live_"):]
    assert len(suffix) == 32
    assert all(c in "0123456789abcdef" for c in suffix)


def test_generate_key_custom_prefix():
    """generate_key() respects custom prefix."""
    key = generate_key(prefix="ak_test")
    assert key.startswith("ak_test_")


def test_health_reports_correct_count(client, profile_dir):
    """GET /health profiles_available matches actual profile count."""
    resp = client.get("/health")
    assert resp.status_code == 200
    count = resp.json()["profiles_available"]
    # We created 2 profiles in the fixture
    assert count == 2


def test_spec_format_profile_downloadable(client):
    """Spec-format profile (metadata.model_id) is accessible via download endpoint."""
    resp = client.get(
        "/profiles/test-model-2/download",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    data = yaml.safe_load(resp.content)
    assert data["metadata"]["model_id"] == "test-model-2"


def test_root_endpoint(client):
    """GET / returns service info without auth."""
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["service"] == "arkheia-registry"
    assert "endpoints" in data


def test_profiles_since_past_returns_profiles(client):
    """GET /profiles?since=past_date returns all profiles (all are newer)."""
    past = (datetime.now(timezone.utc) - timedelta(days=365)).isoformat()
    resp = client.get(
        "/profiles",
        params={"since": past},
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 2


def test_profiles_since_invalid_format_returns_422(client):
    """GET /profiles?since=invalid returns 422."""
    resp = client.get(
        "/profiles",
        params={"since": "not-a-date"},
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code == 422
