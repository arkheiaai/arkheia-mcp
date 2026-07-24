"""FLOOR (stdlib + pytest only): registry model-id round-trip + traversal safety.

Deterministic, ZERO project deps — runs in the floor tier (floor-invariants.yml),
which installs ONLY pytest. It imports the WRITE-side guard `proxy/pathsafe.py`
(stdlib-only) and reads the shipped profiles' emitted ids WITHOUT PyYAML (a
`^model:` regex), then locks the F23 contract AND security property together, in
one floor:

  CONTRACT  — every id the registry emits (the `model:` value, which MAY contain
              `:` or `/` — ollama `qwen3:8b`, HF `deepseek-ai/DeepSeek-V3.1`,
              `zoecohn4/Ouro:latest`) is CACHEABLE: it passes the syntactic
              pre-filter AND yields a within-root write path. RED on the
              over-strict-charset head that rejected the 21 `:`/`/` ids
              (38/59 cacheable), GREEN after the realpath-containment redesign.
  SECURITY  — no traversal / absolute / encoded / NUL id ever yields a write path
              OUTSIDE the profiles root (../, absolute, `..%2f`, `%2e%2e`, NUL).

Companion (unit tier, needs PyYAML): the READ round-trip through
`registry_server.storage.get_profile_bytes` (59/59 downloadable) is locked in
registry_server/tests/test_registry_server.py; the two guards mirror each other
across their disjoint Docker images.
"""
import os
import re
from pathlib import Path

import pytest

from proxy.pathsafe import is_safe_model_id, safe_profile_write_path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PROFILES_DIR = _REPO_ROOT / "profiles"

_MODEL_LINE = re.compile(r"^model:\s*(.+?)\s*$", re.MULTILINE)


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _emitted_ids():
    """Emitted registry ids for the shipped profiles, parsed STDLIB-ONLY (mirrors
    registry_server.storage._profile_meta precedence: `model:` value, else stem).
    Returns [] if profiles/ is absent in this checkout."""
    if not _PROFILES_DIR.is_dir():
        return []
    ids = []
    for path in sorted(_PROFILES_DIR.glob("*.yaml")):
        if path.name == "schema.yaml":
            continue
        match = _MODEL_LINE.search(path.read_text(encoding="utf-8"))
        ids.append(_strip_quotes(match.group(1)) if match else path.stem)
    return ids


# Traversal battery (mirrors the unit-tier READ/WRITE tests, kept in sync).
_ESCAPING = [
    "../SECRET_outside", "../../SECRET_outside", "..%2fSECRET_outside",
    "..\\SECRET_outside", "/etc/passwd", "/tmp/anything", "..",
    "foo/../../SECRET_outside", "a\x00b", "",
]
_CONTAINED_JUNK = ["%2e%2e%2fSECRET_outside", ".hidden", "-rf", "sub/child", "."]


def test_floor_profiles_exercise_colon_and_slash_ids():
    """Guard the guard: the shipped set actually contains `:` and `/` ids, so the
    round-trip assertion below is not vacuous."""
    ids = _emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    assert any(":" in i for i in ids), "expected at least one `:` registry id"
    assert any("/" in i for i in ids), "expected at least one `/` registry id"


def test_floor_every_emitted_id_is_cacheable(tmp_path):
    """CONTRACT: every emitted registry id passes the pre-filter AND yields a
    within-root write path (cacheable by the proxy). RED on the over-strict head
    that rejected `:`/`/` ids."""
    ids = _emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    root = tmp_path.resolve()

    rejected = [i for i in ids if not is_safe_model_id(i)]
    assert rejected == [], f"pre-filter rejected emitted registry ids: {rejected}"

    not_cacheable = []
    for mid in ids:
        out = safe_profile_write_path(str(tmp_path), mid)
        if out is None:
            not_cacheable.append(mid)
            continue
        try:
            out.relative_to(root)
        except ValueError:
            not_cacheable.append(mid)
    assert not_cacheable == [], (
        f"emitted ids NOT cacheable (within-root write path): {not_cacheable}"
    )


def test_floor_escaping_ids_are_rejected(tmp_path):
    """SECURITY: every escaping id (../, absolute, `..%2f`, backslash, NUL, empty)
    yields NO write path (fail-closed None)."""
    escaped = [
        v for v in _ESCAPING if safe_profile_write_path(str(tmp_path), v) is not None
    ]
    assert escaped == [], f"escaping ids were NOT rejected: {escaped!r}"


def test_floor_no_vector_ever_escapes_root(tmp_path):
    """SECURITY INVARIANT: across the whole traversal battery a write path is
    either None or strictly within the profiles root — never outside it."""
    root = tmp_path.resolve()
    outside = []
    for v in _ESCAPING + _CONTAINED_JUNK:
        out = safe_profile_write_path(str(tmp_path), v)
        if out is None:
            continue
        try:
            out.relative_to(root)
        except ValueError:
            outside.append(v)
    assert outside == [], f"vectors produced OUT-OF-ROOT write paths: {outside!r}"


def test_floor_every_emitted_id_writes_top_level_single_component(tmp_path):
    """CONTRACT (the property the within-root floor MISSED): every emitted id's
    cache path is a TOP-LEVEL SINGLE-COMPONENT file — a direct child of the root
    whose name carries no path separator.

    within-root is NOT enough: a `/` id resolves to a within-root SUBDIR
    (`deepseek-ai/DeepSeek-V3.1.yaml` under `deepseek-ai/`), which the router's
    top-level `*.yaml` glob NEVER loads (written-but-never-loaded, Codex HIGH #2).
    RED on the containment-only head (6 slash ids land in subdirs → parent !=
    root); GREEN once the write path encodes to a single component.
    """
    ids = _emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    root = tmp_path.resolve()
    not_top_level = []
    for mid in ids:
        out = safe_profile_write_path(str(tmp_path), mid)
        if out is None or out.parent != root or os.sep in out.name or "/" in out.name:
            not_top_level.append((mid, str(out)))
    assert not_top_level == [], (
        f"emitted ids NOT cached as a TOP-LEVEL single-component file "
        f"(a subdir the top-level glob won't load): {not_top_level}"
    )


def test_floor_encode_decode_round_trips_every_emitted_id():
    """CONTRACT: the public model_id ↔ on-disk stem map is reversible and
    single-component for every emitted id, so the encoded filename decodes back
    to the exact id the router serves. (Imported lazily: the encode/decode pair
    does not exist on the pre-fix head — this test is RED there.)"""
    from proxy.pathsafe import decode_model_id, encode_model_id

    ids = _emitted_ids()
    if not ids:
        pytest.skip("profiles/ directory not present in this checkout")
    broken = []
    for mid in ids:
        enc = encode_model_id(mid)
        if decode_model_id(enc) != mid or "/" in enc or ":" in enc or os.sep in enc:
            broken.append((mid, enc))
    assert broken == [], f"ids that do not round-trip to a single component: {broken}"
