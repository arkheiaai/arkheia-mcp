"""END-TO-END registry contract (unit tier — needs fastapi/httpx/yaml).

The per-layer checks that shipped in this PR each passed while the FULL contract
still broke (Codex HIGH #1 + #2): the registry storage READ resolved slash ids,
and the proxy write path stayed "within root" — yet the advertised download_url
404'd for slash ids (single-segment route) AND the proxy cached them into a
SUBDIR the router's top-level glob never loaded. within-root != downloadable !=
loadable.

This module asserts the one contract those missed, over EVERY id the registry
emits (all 59, incl. the 6 `/` ids and 16 `:` ids):

    list_profiles() ─▶ advertised download_url GET 200 (+bytes)
                    ─▶ proxy _download_and_apply CACHES it (top-level, no subdir)
                    ─▶ ProfileRouter LOADS it (loaded_count increments)
                    ─▶ router.get(model_id) returns the profile

and that traversal ids are still rejected end-to-end (route 404 + write path None
+ a malicious registry meta cannot write outside the profiles root).

RED on head (cebf77a): slash ids 404 on their advertised URL and, once cached,
never load (`router.get` → None). GREEN after the `:path` route + single-component
encode fix.
"""
import hashlib
from pathlib import Path
from urllib.parse import urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from proxy.pathsafe import safe_profile_write_path
from proxy.registry.client import RegistryClient
from proxy.registry.validator import ProfileValidator
from proxy.router.profile_router import ProfileRouter
from registry_server.main import app
from registry_server.storage import ProfileStorage

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PROFILES_DIR = _REPO_ROOT / "profiles"
_KEY = "test-fixture-not-a-real-key-00000"
_AUTH = {"Authorization": f"Bearer {_KEY}"}
_BASE = "http://testserver"

# Witnesses for the two Codex HIGHs (a `/` id creates a subdir + 404s the route).
_SLASH_IDS = [
    "deepseek-ai/DeepSeek-V3.1", "deepseek-ai/DeepSeek-V4-Pro",
    "moonshotai/Kimi-K2.5", "moonshotai/Kimi-K2.6",
    "zai-org/GLM-5.2", "zoecohn4/Ouro:latest",
]

# Traversal battery — none may ever download (200) or yield a write path.
_TRAVERSAL_VECTORS = [
    "../../SECRET_outside", "..%2f..%2fSECRET_outside", "%2e%2e%2fSECRET_outside",
    "..\\SECRET_outside", "/etc/passwd", "..",
]
_ESCAPING_WRITE_IDS = [
    "../SECRET_outside", "../../SECRET_outside", "..%2fSECRET_outside",
    "..\\SECRET_outside", "/etc/passwd", "/tmp/x", "..", "foo/../../x", "a\x00b", "",
]


def _skip_if_no_profiles():
    if not _PROFILES_DIR.is_dir():
        pytest.skip("profiles/ directory not present in this checkout")


@pytest.fixture()
def registry_client_env(monkeypatch):
    """Configure the shared registry app: valid key + storage over shipped
    profiles/, so both the HTTP route and ASGITransport-driven pulls resolve."""
    _skip_if_no_profiles()
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", _KEY)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(_PROFILES_DIR))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", _BASE)
    # ASGITransport does not run lifespan; set state the way lifespan would.
    app.state.storage = ProfileStorage(profile_dir=str(_PROFILES_DIR), base_url=_BASE)
    return app


def _route_pull_through_app(monkeypatch, registry_app):
    """Make every httpx.AsyncClient built by RegistryClient dispatch to the real
    registry ASGI app (real `/profiles` list + real `:path` download route)."""
    real_cls = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs.setdefault("transport", httpx.ASGITransport(app=registry_app))
        return real_cls(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


def _subdirs(cache: Path):
    return [p for p in cache.rglob("*") if p.is_dir()]


# ---------------------------------------------------------------------------
# Full contract over all 59 ids
# ---------------------------------------------------------------------------

def test_e2e_every_advertised_url_downloads_and_caches_top_level(tmp_path, monkeypatch):
    """CONTRACT (RED on head): for EVERY emitted id the advertised download_url
    GETs 200 with the bytes, caches to a TOP-LEVEL single-component file, and the
    router then LOADS it and resolves get(model_id). Exercises both HIGHs together.

    NOTE: a pre-existing profile-DATA defect (unrelated to this path fix) ships
    `model: gpt-5-codex` in BOTH gpt-5-codex.yaml and gpt-5.2-codex.yaml, so the
    listing has one duplicate model_id (59 rows / 58 distinct). This test tolerates
    THAT known collision precisely — a checksum is allowed to match ANY of the
    checksums listed for a duplicated id — while still asserting an exact match for
    every uniquely-listed id. It does not paper over any other mismatch."""
    _skip_if_no_profiles()
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", _KEY)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(_PROFILES_DIR))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", _BASE)

    cache = tmp_path
    root = cache.resolve()
    with TestClient(app) as c:
        listing = c.get("/profiles", headers=_AUTH).json()
        profiles = listing["profiles"]
        assert listing["count"] == len(profiles) >= 59, "expected >=59 shipped profiles"

        # checksums listed per model_id (a set > 1 == the known duplicate anomaly)
        listed_sums: dict[str, set] = {}
        for p in profiles:
            listed_sums.setdefault(p["model_id"], set()).add(p["checksum"])
        distinct_ids = sorted(listed_sums)

        http_404, checksum_bad, not_top_level = [], [], []
        for p in profiles:
            mid = p["model_id"]
            url_path = urlparse(p["download_url"]).path  # advertised, verbatim
            resp = c.get(url_path, headers=_AUTH)
            if resp.status_code != 200:
                http_404.append((mid, resp.status_code))
                continue
            # 200 "with the bytes": the served digest must be one the listing
            # advertised for this id (exact for unique ids; either for the dup).
            if hashlib.sha256(resp.content).hexdigest() not in listed_sums[mid]:
                checksum_bad.append(mid)
            wp = safe_profile_write_path(str(cache), mid)
            if wp is None or wp.parent != root or "/" in wp.name:
                not_top_level.append((mid, str(wp)))
                continue
            wp.write_bytes(resp.content)

    assert http_404 == [], f"advertised download_url did NOT return 200 (HIGH #1): {http_404}"
    assert checksum_bad == [], f"served bytes matched no advertised checksum: {checksum_bad}"
    assert not_top_level == [], f"cached NOT as top-level single-component file (HIGH #2): {not_top_level}"
    assert _subdirs(cache) == [], f"cache created SUBDIRS (HIGH #2): {_subdirs(cache)}"

    router = ProfileRouter(profile_dir=str(cache))
    assert router.loaded_count == len(distinct_ids), (
        f"router loaded {router.loaded_count} of {len(distinct_ids)} distinct cached profiles"
    )
    unresolved = [mid for mid in distinct_ids if router.get(mid) is None]
    assert unresolved == [], f"router.get returned None for cached ids: {unresolved}"


@pytest.mark.asyncio
async def test_e2e_registry_pull_caches_and_router_loads_all(tmp_path, monkeypatch, registry_client_env):
    """FAITHFUL end-to-end through the REAL RegistryClient.pull(): real `/profiles`
    list → real advertised `:path` download → validate → cache → router.reload →
    get. Every emitted id must end up loaded and resolvable. RED on head."""
    _route_pull_through_app(monkeypatch, registry_client_env)
    cache = tmp_path
    router = ProfileRouter(profile_dir=str(cache))
    assert router.loaded_count == 0

    client = RegistryClient(
        base_url=_BASE, api_key=SecretStr(_KEY), profile_dir=str(cache),
        router=router, validator=ProfileValidator(),
    )
    result = await client.pull()

    listing = registry_client_env.state.storage.list_profiles()
    from collections import Counter
    counts = Counter(m["model_id"] for m in listing)
    distinct_ids = sorted(counts)
    dup_ids = {mid for mid, n in counts.items() if n > 1}  # known data anomaly

    # Any pull error is tolerated ONLY when it belongs to a duplicate-listed id
    # (the pre-existing gpt-5-codex checksum collision); any other error fails.
    unexpected = [e for e in result["errors"] if not any(e.startswith(d) for d in dup_ids)]
    assert unexpected == [], f"pull reported UNEXPECTED errors: {unexpected}"
    # Every DISTINCT id was applied at least once and is now loaded + resolvable.
    assert set(result["updated"]) == set(distinct_ids), "not every distinct id applied"
    assert router.loaded_count == len(distinct_ids), (
        f"router loaded {router.loaded_count} of {len(distinct_ids)} distinct profiles"
    )
    unresolved = [mid for mid in distinct_ids if router.get(mid) is None]
    assert unresolved == [], f"router.get None after pull for: {unresolved}"
    assert _subdirs(cache) == [], f"pull created SUBDIRS (HIGH #2): {_subdirs(cache)}"


@pytest.mark.asyncio
@pytest.mark.parametrize("slash_id", _SLASH_IDS)
async def test_e2e_download_and_apply_slash_id_loads(tmp_path, monkeypatch, registry_client_env, slash_id):
    """RED-first witness (HIGH #2): `_download_and_apply(slash-id)` → router.get is
    None on head (cached into a subdir the glob skips); returns the profile after
    the single-component encode fix."""
    storage = registry_client_env.state.storage
    if slash_id not in [m["model_id"] for m in storage.list_profiles()]:
        pytest.skip(f"{slash_id} not shipped in this checkout")
    _route_pull_through_app(monkeypatch, registry_client_env)

    cache = tmp_path
    router = ProfileRouter(profile_dir=str(cache))
    client = RegistryClient(
        base_url=_BASE, api_key=SecretStr(_KEY), profile_dir=str(cache),
        router=router, validator=ProfileValidator(),
    )
    meta = next(m for m in storage.list_profiles() if m["model_id"] == slash_id)

    applied = await client._download_and_apply(meta)
    assert applied is True
    assert router.get(slash_id) is not None, f"router.get({slash_id!r}) is None — written but not loaded"
    assert _subdirs(cache) == [], f"slash id created a SUBDIR: {_subdirs(cache)}"


# ---------------------------------------------------------------------------
# Traversal must still be rejected end-to-end
# ---------------------------------------------------------------------------

def test_e2e_download_route_rejects_traversal(registry_client_env):
    """SECURITY: the `:path` download route never returns 200 for a traversal
    vector — Starlette decodes `%2f`/`%2e` before the handler, and storage
    containment (pre-filter + realpath) rejects whatever reaches it."""
    with TestClient(app) as c:
        leaked = []
        for v in _TRAVERSAL_VECTORS:
            resp = c.get(f"/profiles/{v}/download", headers=_AUTH)
            if resp.status_code == 200 or "SUPER_SECRET" in resp.text or "root:" in resp.text:
                leaked.append((v, resp.status_code))
        assert leaked == [], f"traversal vectors reached content (200/leak): {leaked}"
        # control: a legitimate slash id DOES resolve on the same route
        assert c.get("/profiles/deepseek-ai/DeepSeek-V3.1/download", headers=_AUTH).status_code == 200


def test_e2e_write_path_rejects_traversal(tmp_path):
    """SECURITY: no escaping id yields a proxy write path (fail-closed None)."""
    escaped = [v for v in _ESCAPING_WRITE_IDS if safe_profile_write_path(str(tmp_path), v) is not None]
    assert escaped == [], f"escaping ids were NOT rejected on write: {escaped!r}"


@pytest.mark.asyncio
async def test_e2e_download_and_apply_rejects_malicious_meta(tmp_path, monkeypatch, registry_client_env):
    """SECURITY: a compromised registry advertising a traversal model_id (with a
    VALID profile body, so checksum+schema pass) cannot write outside the root —
    `_download_and_apply` fails closed (ValueError) at the write-path guard, and
    no file lands outside the cache."""
    storage = registry_client_env.state.storage
    good = next(m for m in storage.list_profiles() if "/" not in m["model_id"] and ":" not in m["model_id"])
    _route_pull_through_app(monkeypatch, registry_client_env)

    cache = tmp_path / "cache"
    cache.mkdir()
    router = ProfileRouter(profile_dir=str(cache))
    client = RegistryClient(
        base_url=_BASE, api_key=SecretStr(_KEY), profile_dir=str(cache),
        router=router, validator=ProfileValidator(),
    )
    # Serve a real, valid profile body but under a traversal model_id.
    evil_meta = {
        "model_id": "../../evil",
        "checksum": good["checksum"],
        "download_url": good["download_url"],
        "version": "1.0",
    }
    with pytest.raises(ValueError, match="[Uu]nsafe model_id"):
        await client._download_and_apply(evil_meta)
    assert not (tmp_path / "evil.yaml").exists()
    assert not (cache.parent / "evil.yaml").exists()
