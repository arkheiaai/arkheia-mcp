"""Unit tests for the shared proxy WRITE-path traversal guard (F23 sibling).

`proxy/pathsafe.py` is the WRITE-side twin of `registry_server/storage.py`'s READ
hardening (the two live in disjoint Docker images and mirror each other). The
public `model_id` is a REGISTRY identifier that MAY contain `:` or `/` (ollama
`qwen3:8b`, HF `deepseek-ai/DeepSeek-V3.1`, `zoecohn4/Ouro:latest`), so BOTH
properties must hold together:

  CONTRACT  — every emitted id is CACHEABLE as a TOP-LEVEL SINGLE-COMPONENT file:
              `safe_profile_write_path` ENCODES the id (`/`→`%2F`, `:`→`%3A`) so a
              slash id is one top-level file the router's top-level glob loads —
              never a subdir (written-but-never-loaded), and
  SECURITY  — no id (traversal / absolute / encoded / symlink / NUL) ever yields a
              write path OUTSIDE the profiles root.

The CONTRACT regressed twice: first an over-strict charset rejected the 21 `:`/`/`
ids on write; then the containment-only redesign accepted them but let a `/` id
land in a within-root SUBDIR the loader skips. The single-component encode closes
both. The client-side sibling (`RegistryClient._download_and_apply`) is covered too.
"""
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import hashlib
import pytest
import yaml
from pydantic import SecretStr

from proxy.pathsafe import encode_model_id, is_safe_model_id, safe_profile_write_path
from proxy.registry.client import RegistryClient

# Same batteries the registry-server READ tests use — kept in sync deliberately.
# ESCAPING ids: a `..` token / NUL / backslash / empty, or an absolute path.
# Each must yield NO write path (fail-closed None).
ESCAPING_MODEL_IDS = [
    "../SECRET_outside",
    "../../SECRET_outside",
    "..%2fSECRET_outside",          # contains a literal ".." token
    "..\\SECRET_outside",
    "/etc/passwd",
    "/tmp/anything",  # nosec B108 — a traversal TEST VECTOR (string), not a tmp path
    "..",
    "foo/../../SECRET_outside",
    "a\x00b",
    "",
]

# CONTAINED-but-nonexistent ids: no `..`, no escape — they resolve to a literal
# filename INSIDE the root. NOT escapes; containment (realpath) keeps them in.
CONTAINED_NONEXISTENT_MODEL_IDS = [
    "%2e%2e%2fSECRET_outside",
    ".hidden",
    "-rf",
    "sub/child",
    ".",
]

ALL_TRAVERSAL_VECTORS = ESCAPING_MODEL_IDS + CONTAINED_NONEXISTENT_MODEL_IDS


def _shipped_emitted_ids():
    """The model ids the registry actually EMITS for the shipped profiles (the
    `model:` value, mirroring registry_server.storage._profile_meta), or []."""
    profiles_dir = Path(__file__).resolve().parents[2] / "profiles"
    if not profiles_dir.is_dir():
        return []
    ids = []
    for p in sorted(profiles_dir.glob("*.yaml")):
        if p.name == "schema.yaml":
            continue
        data = yaml.safe_load(p.read_bytes()) or {}
        mid = data.get("model") or data.get("metadata", {}).get("model_id") or p.stem
        ids.append(mid)
    return ids


# --- syntactic pre-filter ---------------------------------------------------

@pytest.mark.parametrize(
    "mid",
    ["qwen3:8b", "deepseek-ai/DeepSeek-V3.1", "zoecohn4/Ouro:latest",
     "claude-opus-4-8", "deepseek-v3.1", "gpt-5.2-codex", "a"],
)
def test_is_safe_model_id_accepts_registry_ids(mid):
    """The pre-filter ACCEPTS real registry ids, including `:`/`/` forms —
    containment, not a charset, is what confines them."""
    assert is_safe_model_id(mid) is True


@pytest.mark.parametrize(
    "mid", ["../x", "..", "a/../../b", "..%2fx", "x\x00y", "back\\slash", ""]
)
def test_is_safe_model_id_rejects_dangerous_tokens(mid):
    """The pre-filter drops only ids that can never name a legitimate profile:
    a `..` traversal token, a NUL byte, a backslash, or empty."""
    assert is_safe_model_id(mid) is False


# --- write-path CONTRACT (cacheability round-trip) --------------------------

def test_write_path_accepts_all_emitted_ids(tmp_path):
    """CONTRACT (RED on the over-strict-charset head): every emitted registry id
    is cacheable by the proxy — safe_profile_write_path returns a within-root
    path, including every `:`/`/` id (qwen3:8b, deepseek-ai/DeepSeek-V3.1)."""
    ids = _shipped_emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    root = tmp_path.resolve()
    bad = []
    for mid in ids:
        out = safe_profile_write_path(str(tmp_path), mid)
        if out is None:
            bad.append(mid)
            continue
        try:
            out.relative_to(root)
        except ValueError:
            bad.append(mid)
    assert bad == [], f"emitted ids NOT cacheable (within-root write path): {bad}"


@pytest.mark.parametrize(
    "mid", ["claude-opus-4-8", "qwen3:8b", "deepseek-ai/DeepSeek-V3.1"]
)
def test_write_path_legit_is_contained(tmp_path, mid):
    """A legit id resolves to a TOP-LEVEL single-component file under the ENCODED
    stem — never a subdir (so a `/` id is loadable by the top-level glob)."""
    root = tmp_path.resolve()
    out = safe_profile_write_path(str(tmp_path), mid)
    assert out is not None
    assert out == (tmp_path / f"{encode_model_id(mid)}.yaml").resolve()
    assert out.parent == root          # direct child of root (no subdir)
    assert "/" not in out.name         # single component
    out.relative_to(root)              # stays within root


# --- write-path SECURITY (containment) --------------------------------------

@pytest.mark.parametrize("mid", ALL_TRAVERSAL_VECTORS)
def test_write_path_never_escapes_root(tmp_path, mid):
    """SECURITY INVARIANT: a write path is either rejected (None) or stays
    strictly WITHIN the profiles root — no vector ever yields an out-of-root
    write target."""
    out = safe_profile_write_path(str(tmp_path), mid)
    if out is not None:
        out.relative_to(tmp_path.resolve())  # raises if it escaped


@pytest.mark.parametrize("mid", ESCAPING_MODEL_IDS)
def test_write_path_rejects_escaping(tmp_path, mid):
    """Escaping ids (`..` token, absolute, backslash, NUL, empty) yield no write
    path (fail-closed None)."""
    assert safe_profile_write_path(str(tmp_path), mid) is None


@pytest.mark.parametrize("mid", CONTAINED_NONEXISTENT_MODEL_IDS)
def test_write_path_contained_junk_stays_in_root(tmp_path, mid):
    """In-root junk ids (encoded `%2e%2e`, hidden/dash, an in-root subpath, a
    bare dot) are NOT escapes: they resolve to a path WITHIN the root, so
    containment returns a contained path rather than rejecting."""
    out = safe_profile_write_path(str(tmp_path), mid)
    assert out is not None
    out.relative_to(tmp_path.resolve())  # within root


def test_write_path_absolute_id_rejected(tmp_path):
    """An absolute model_id (which Path '/' lets escape the root) is rejected by
    realpath containment — the resolved path is outside the profiles root."""
    assert safe_profile_write_path(str(tmp_path), str(tmp_path.parent / "evil")) is None


def test_write_path_symlinked_root_still_contained(tmp_path):
    """CONTAINMENT BACKSTOP: even if profiles/ is reached via a symlink, a legit
    id resolves to a path within the real root."""
    real = tmp_path / "real_profiles"
    real.mkdir()
    link = tmp_path / "profiles_link"
    link.symlink_to(real, target_is_directory=True)
    out = safe_profile_write_path(str(link), "claude-opus-4-8")
    assert out is not None
    assert out == (real / "claude-opus-4-8.yaml").resolve()


# --- client-side sibling: RegistryClient._download_and_apply ----------------

def _valid_profile(model_id: str = "llama-3-70b", version: str = "2.0") -> dict:
    return {
        "model": model_id,
        "version": version,
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


def _valid_profile_yaml(model_id: str = "llama-3-70b", version: str = "2.0") -> bytes:
    return yaml.dump(_valid_profile(model_id, version)).encode("utf-8")


_VALID_PROFILE_YAML = _valid_profile_yaml()


def _make_client(root: Path, active_profile: dict | None = None):
    """RegistryClient over `root`.

    MERGE NOTE (master): `_download_and_apply` now (a) requires the downloaded
    body's own `model:`/`version:` to match the registry metadata and (b) asserts
    through `router.get(model_id)` that the exact profile went live. The fake
    router therefore has to answer `get` with the profile that was applied —
    otherwise the apply is (correctly) rolled back. Nothing about the path guard
    under test is relaxed by this.
    """
    router = AsyncMock()
    router.reload = AsyncMock()
    router.get = MagicMock(return_value=active_profile or _valid_profile())
    client = RegistryClient(
        base_url="https://registry.arkheia.ai",
        api_key=SecretStr("test-api-key"),
        profile_dir=str(root),
        router=router,
        validator=None,
    )
    return client, router


@pytest.mark.asyncio
async def test_client_download_rejects_traversal_model_id(tmp_path):
    """A registry-supplied (untrusted) traversing model_id must NOT write a
    profile outside the profiles root: `_download_and_apply` raises (caller
    retains current profiles) and nothing lands outside the root."""
    root = tmp_path / "profiles"
    root.mkdir()
    outside_canary = tmp_path / "pwned.yaml"  # <root>/../pwned.yaml

    client, router = _make_client(root)
    meta = {
        "model_id": "../pwned",
        # A REAL checksum, deliberately: this test's subject is the TRAVERSAL guard, so the refusal
        # must come from the path check and NOT from the checksum gate. An empty checksum would make
        # it pass for the wrong reason under master's mandatory-checksum rule.
        "checksum": hashlib.sha256(_valid_profile_yaml("../pwned")).hexdigest(),
        "download_url": "https://registry.arkheia.ai/profiles/x.yaml",
        "version": "2.0",
    }

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        download_resp = MagicMock()
        download_resp.content = _VALID_PROFILE_YAML
        download_resp.raise_for_status = MagicMock()
        mock_client.get.side_effect = [download_resp]

        with pytest.raises(ValueError):
            await client._download_and_apply(meta)

    assert not outside_canary.exists(), "traversal WROTE profile outside root"
    router.reload.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("mid", ["qwen3:8b", "deepseek-ai/DeepSeek-V3.1"])
async def test_client_download_caches_separator_id_top_level(tmp_path, mid):
    """CONTRACT (client round-trip): a registry id with a `:` OR `/` downloads and
    caches as a TOP-LEVEL SINGLE-COMPONENT file under the ENCODED stem
    (`qwen3%3A8b.yaml`, `deepseek-ai%2FDeepSeek-V3.1.yaml`) — NO subdir is created,
    so the router's top-level glob loads it (Codex HIGH #2). Router reloads, no
    raise, no escape."""
    root = tmp_path / "profiles"
    root.mkdir()

    client, router = _make_client(root, active_profile=_valid_profile(mid))
    meta = {
        "model_id": mid,
        # A REAL checksum — see the note above; master requires one.
        "checksum": hashlib.sha256(_valid_profile_yaml(mid)).hexdigest(),
        "download_url": f"https://registry.arkheia.ai/profiles/{mid}/download",
        "version": "2.0",
    }

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_client
        download_resp = MagicMock()
        download_resp.content = _valid_profile_yaml(mid)
        download_resp.raise_for_status = MagicMock()
        mock_client.get.side_effect = [download_resp]

        applied = await client._download_and_apply(meta)

    cached = root / f"{encode_model_id(mid)}.yaml"
    assert cached.exists(), f"{mid} was not cached as a top-level encoded file"
    assert cached.parent == root.resolve()  # top-level, no subdir
    assert [p for p in root.rglob("*") if p.is_dir()] == [], "a subdir was created"
    cached.resolve().relative_to(root.resolve())  # stays within root
    assert applied is True
    router.reload.assert_awaited()
