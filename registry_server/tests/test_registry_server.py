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
# Path-traversal hardening + registry-id round-trip (adversarial ledger F23)
#
# `get_profile_bytes` resolves an untrusted `model_id` two ways: an exact
# filename `<profiles>/<model_id>.yaml` (gated by realpath containment) and a
# fallback SCAN that matches the id against each profile's own `model:` value.
# The public id is a REGISTRY identifier that MAY contain `:` or `/` (ollama
# `qwen3:8b`, HF `deepseek-ai/DeepSeek-V3.1`, `zoecohn4/Ouro:latest`) — so BOTH
# properties must hold TOGETHER:
#   CONTRACT  — every id `list_profiles()` emits is downloadable by that id, and
#   SECURITY  — no id (traversal / absolute / encoded / symlink / NUL) ever reads
#               a file outside the profiles root.
# The CONTRACT regressed when an over-strict charset 404'd the 21 `:`/`/` ids
# (38/59 downloadable); the CONTRACT tests below are RED on that head and GREEN
# after the realpath-containment redesign. The SECURITY tests were RED on the
# ORIGINAL vulnerable storage (traversal read out-of-root files) and stay GREEN.
# ---------------------------------------------------------------------------

# ESCAPING ids: they carry a `..` token / NUL / backslash / are empty, or are an
# absolute path — each either fails the syntactic pre-filter or is caught by
# realpath containment. None may ever yield bytes.
ESCAPING_MODEL_IDS = [
    "../SECRET_outside",
    "../../SECRET_outside",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "/tmp/anything",
    "..",
    "..\\SECRET_outside",
    "foo/../../SECRET_outside",
    "..%2fSECRET_outside",      # contains a literal ".." token
    "a\x00b",
    "",
]

# CONTAINED-but-nonexistent ids: no `..`, no escape — they resolve to a literal
# filename INSIDE the root that names no real profile (encoded `%2e%2e`, a hidden
# / dash name, an in-root subpath, a bare dot). NOT security escapes; they simply
# are not found. Kept distinct so the redesign is honest: containment, not a
# charset, is what makes these safe.
CONTAINED_NONEXISTENT_MODEL_IDS = [
    "%2e%2e%2fSECRET_outside",
    ".hidden",
    "-rf",
    "sub/child",
    ".",
]

ALL_TRAVERSAL_VECTORS = ESCAPING_MODEL_IDS + CONTAINED_NONEXISTENT_MODEL_IDS


def _shipped_storage_and_emitted_ids():
    """(ProfileStorage over the REAL profiles/, list of emitted model ids), or
    (None, []) if profiles/ is absent in this checkout."""
    profiles_dir = Path(__file__).resolve().parents[2] / "profiles"
    if not profiles_dir.is_dir():
        return None, []
    storage = ProfileStorage(profile_dir=str(profiles_dir), base_url="http://x")
    return storage, [m["model_id"] for m in storage.list_profiles()]


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


def test_storage_all_emitted_ids_downloadable():
    """CONTRACT round-trip (RED on the over-strict-charset head): every id the
    registry EMITS is downloadable by that id via get_profile_bytes — all of
    them, including the 21 that contain `:` or `/` (qwen3:8b,
    deepseek-ai/DeepSeek-V3.1)."""
    storage, ids = _shipped_storage_and_emitted_ids()
    if storage is None:
        pytest.skip("profiles/ directory not present in this checkout")
    assert ids, "expected shipped profiles to emit ids"
    undownloadable = [i for i in ids if storage.get_profile_bytes(i) is None]
    assert undownloadable == [], (
        f"emitted ids NOT downloadable by their own id: {undownloadable}"
    )


@pytest.mark.parametrize(
    "mid",
    ["qwen3:8b", "gemma4:latest", "granite4.1:30b",
     "deepseek-ai/DeepSeek-V3.1", "zoecohn4/Ouro:latest"],
)
def test_storage_colon_and_slash_ids_downloadable(mid):
    """Explicit witnesses for the regression: `:`/`/` registry ids resolve via
    the scan branch (RED on the over-strict-charset head, GREEN after)."""
    storage, ids = _shipped_storage_and_emitted_ids()
    if storage is None:
        pytest.skip("profiles/ directory not present in this checkout")
    if mid not in ids:
        pytest.skip(f"{mid} not shipped in this checkout")
    assert storage.get_profile_bytes(mid) is not None


def test_is_safe_model_id_accepts_all_emitted_ids():
    """CONTRACT: the syntactic pre-filter accepts every EMITTED registry id (the
    `model:` values, not filename stems) so no legit id is dropped before
    resolution. RED on the over-strict-charset head (it rejected `:`/`/`)."""
    _storage, ids = _shipped_storage_and_emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    bad = [i for i in ids if not _is_safe_model_id(i)]
    assert bad == [], f"emitted registry ids rejected by pre-filter: {bad}"


@pytest.mark.parametrize(
    "mid",
    ["qwen3:8b", "deepseek-ai/DeepSeek-V3.1", "zoecohn4/Ouro:latest",
     "claude-opus-4-8", "gpt-5.2-codex"],
)
def test_is_safe_model_id_accepts_registry_ids(mid):
    """The pre-filter ACCEPTS real registry ids, including `:`/`/` forms —
    containment, not a charset, is what confines them."""
    assert _is_safe_model_id(mid) is True


@pytest.mark.parametrize(
    "mid", ["../x", "..", "a/../../b", "..%2fx", "x\x00y", "back\\slash", ""]
)
def test_is_safe_model_id_rejects_dangerous_tokens(mid):
    """The pre-filter drops ids that can never name a legitimate profile: a `..`
    traversal token, a NUL byte, a backslash, or empty."""
    assert _is_safe_model_id(mid) is False


@pytest.mark.parametrize("mid", ALL_TRAVERSAL_VECTORS)
def test_storage_traversal_returns_none(storage_with_secret, mid):
    """SECURITY: no traversal / absolute / encoded / in-root-junk id ever yields
    bytes — an escape (the planted out-of-root secret) is contained away, and an
    in-root non-existent filename is simply not found. Either way: None."""
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
    # id passes the syntactic pre-filter, but the resolved path escapes the root:
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


# NOTE (honesty): the download route now uses the `{model_id:path}` converter
# (so a legitimate `/` id — deepseek-ai/DeepSeek-V3.1 — whose advertised
# download_url the single-segment `[^/]+` route used to 404 now resolves). That
# makes THIS test load-bearing: with `:path`, Starlette decodes `%2f`/`%2e`
# BEFORE the handler, so `..%2f..%2fX` reaches storage as `../../X` and a literal
# `/etc/passwd` reaches it verbatim — i.e. the traversal vectors now DO hit
# `get_profile_bytes`, and it is storage containment (the `..` pre-filter +
# realpath) that must reject them. `:path` is safe ONLY because that containment
# holds; this test is the surface guard that proves it (any regression that let a
# vector through would 200 / leak here). The storage fix is ALSO exercised
# directly, genuinely RED on base, by `test_storage_*` above and
# `test_storage_download_never_leaks_secret` below.
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
def test_download_route_rejects_url_traversal(client_ext_secret, vector):
    """HTTP SURFACE guard (route matcher, not the storage fix): the download
    route never returns 200 for URL-shaped traversal vectors and never echoes
    the planted secret. See the note above for why this does not, by itself,
    exercise the storage containment."""
    resp = client_ext_secret.get(
        f"/profiles/{vector}/download",
        headers={"Authorization": f"Bearer {VALID_KEY}"},
    )
    assert resp.status_code != 200
    # `SUPER_SECRET` only appears in the out-of-root secret file's *content*,
    # never in a vector string, so this catches an actual leak precisely.
    assert "SUPER_SECRET" not in resp.text
    assert "root:" not in resp.text  # /etc/passwd marker


@pytest.mark.parametrize(
    "vector",
    [
        "../SECRET_outside",      # relative parent -> sibling of the root
        "../../SECRET_outside",
        "..\\SECRET_outside",     # backslash separator variant
    ],
)
def test_storage_download_never_leaks_secret(storage_with_secret, vector):
    """STORAGE containment (genuinely RED on base): the actual fix locus.

    Drives `get_profile_bytes` directly — the method the download route calls —
    with vectors that DO escape the profiles root on the unpatched storage
    (base reads the planted `SUPER_SECRET`). Post-fix each returns None and the
    out-of-root secret's *content* is never surfaced. Unlike the HTTP test above
    this bypasses Starlette's `[^/]+` matcher, so it fails on pre-fix storage."""
    storage, _root, _vault = storage_with_secret
    out = storage.get_profile_bytes(vector)
    assert out is None
    # Belt-and-braces: even if a future regression returned bytes, they must
    # never be the planted secret's content.
    assert out is None or b"SUPER_SECRET" not in out
