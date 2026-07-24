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
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from registry_server.auth import generate_key
from registry_server.main import app
from registry_server.storage import ProfileStorage, _is_safe_model_id


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


# ---------------------------------------------------------------------------
# Path-traversal hardening (adversarial ledger F23)
#
# `get_profile_bytes` builds a filesystem path from an untrusted `model_id`.
# A crafted value must never read a file outside the profiles root. These
# tests are RED on the pre-fix code (traversal reads outside files) and GREEN
# after: strict allow-list + realpath containment, fail-closed.
# ---------------------------------------------------------------------------

# Absolute path, relative parent, bare "..", separators (fwd/back), null byte,
# leading dot/dash, encoded-separator literals, and dir-escape via "..".
TRAVERSAL_MODEL_IDS = [
    "../SECRET_outside",
    "../../SECRET_outside",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/tmp/anything",
    "..",
    ".",
    "..\\SECRET_outside",
    "foo/../../SECRET_outside",
    "sub/child",
    "a\x00b",
    "..%2fSECRET_outside",      # literal (already-decoded form) — has no sep but "%" is illegal
    "%2e%2e%2fSECRET_outside",
    ".hidden",
    "-rf",
    "",
]


@pytest.fixture()
def storage_with_secret(tmp_path):
    """A ProfileStorage whose profiles root has one legit profile, with a
    secret *.yaml planted OUTSIDE the root (sibling) and one at an absolute
    path — the files a traversal would try to reach."""
    root = tmp_path / "profiles"
    root.mkdir()
    (root / "claude-opus-4-8.yaml").write_text(
        "model: claude-opus-4-8\nversion: '1.0'\n", encoding="utf-8"
    )
    # secret sibling of the profiles root (reached via ../)
    (tmp_path / "SECRET_outside.yaml").write_text(
        "api_key: SUPER_SECRET\n", encoding="utf-8"
    )
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "creds.yaml").write_text("db_password: SUPER_SECRET\n", encoding="utf-8")
    storage = ProfileStorage(profile_dir=str(root), base_url="http://x")
    return storage, tmp_path, vault


def test_is_safe_model_id_accepts_all_shipped_profiles():
    """FLOOR: every profile id shipped in profiles/ passes the allow-list.

    Ties the charset to reality — a future profile whose id the allow-list
    would reject fails here instead of silently 404ing in production.
    """
    profiles_dir = Path(__file__).resolve().parents[2] / "profiles"
    if not profiles_dir.is_dir():
        pytest.skip("profiles/ directory not present in this checkout")
    stems = [p.stem for p in profiles_dir.glob("*.yaml") if p.name != "schema.yaml"]
    assert stems, "expected at least one shipped profile"
    bad = [s for s in stems if not _is_safe_model_id(s)]
    assert bad == [], f"shipped profile ids rejected by allow-list: {bad}"


@pytest.mark.parametrize("mid", TRAVERSAL_MODEL_IDS)
def test_is_safe_model_id_rejects_traversal(mid):
    """Every traversal / malformed id is rejected by the allow-list."""
    assert _is_safe_model_id(mid) is False


@pytest.mark.parametrize("mid", TRAVERSAL_MODEL_IDS)
def test_storage_traversal_returns_none(storage_with_secret, mid):
    """CONTAINMENT: no traversal id ever yields bytes from get_profile_bytes."""
    storage, _root, _vault = storage_with_secret
    assert storage.get_profile_bytes(mid) is None


def test_storage_absolute_path_returns_none(storage_with_secret):
    """An absolute path to a real *.yaml secret must not be served."""
    storage, _root, vault = storage_with_secret
    abs_id = str(vault / "creds")  # -> <vault>/creds.yaml exists on disk
    assert storage.get_profile_bytes(abs_id) is None


def test_storage_symlink_escape_returns_none(storage_with_secret):
    """CONTAINMENT BACKSTOP: a charset-valid id whose file is a symlink
    pointing OUTSIDE the root must not be read (realpath containment), and it
    must not surface in list_profiles either."""
    storage, tmp_path, _vault = storage_with_secret
    secret = tmp_path / "SECRET_outside.yaml"
    link = Path(storage.profile_dir) / "evillink.yaml"
    link.symlink_to(secret)
    # id passes the charset gate, but the resolved path escapes the root:
    assert _is_safe_model_id("evillink") is True
    assert storage.get_profile_bytes("evillink") is None
    listed = {p["model_id"] for p in storage.list_profiles()}
    assert "api_key" not in listed  # secret content never parsed into listing
    # only the legit profile is listed
    assert listed == {"claude-opus-4-8"}


def test_storage_legit_still_served(storage_with_secret):
    """A legitimate model_id is still served after hardening."""
    storage, _root, _vault = storage_with_secret
    out = storage.get_profile_bytes("claude-opus-4-8")
    assert out is not None
    assert yaml.safe_load(out)["model"] == "claude-opus-4-8"


@pytest.fixture()
def client_ext_secret(monkeypatch, tmp_path):
    """TestClient whose profiles root has a secret *.yaml planted OUTSIDE it
    (sibling of the root) — so a working traversal WOULD leak `SUPER_SECRET`."""
    root = tmp_path / "profiles"
    root.mkdir()
    (root / "claude-opus-4-8.yaml").write_text(
        "model: claude-opus-4-8\nversion: '1.0'\n", encoding="utf-8"
    )
    (tmp_path / "SECRET_outside.yaml").write_text(
        "api_key: SUPER_SECRET\n", encoding="utf-8"
    )
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(root))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")
    with TestClient(app) as c:
        yield c


@pytest.mark.parametrize(
    "vector",
    [
        "..%2f..%2fSECRET_outside",
        "..%2fSECRET_outside",
        "../../SECRET_outside",
        "%2e%2e%2fSECRET_outside",
        "..\\SECRET_outside",
        "/etc/passwd",
    ],
)
def test_download_traversal_never_leaks(client_ext_secret, vector):
    """HTTP defense-in-depth: traversal vectors on the download route never
    return 200 and never leak the planted secret's content."""
    resp = client_ext_secret.get(
        f"/profiles/{vector}/download",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code != 200
    # `SUPER_SECRET` only appears in the out-of-root secret file's *content*,
    # never in a vector string, so this catches an actual leak precisely.
    assert "SUPER_SECRET" not in resp.text
    assert "root:" not in resp.text  # /etc/passwd marker
