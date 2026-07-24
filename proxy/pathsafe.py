"""Path-traversal hardening for proxy profile WRITES (adversarial ledger F23).

`model_id` reaches a filesystem path on the proxy WRITE side from two callers:

  * ``proxy/endpoints/admin.py::rollback_profile`` — ``model_id`` from an
    authenticated (but otherwise untrusted) HTTP caller
    (``POST /admin/profiles/{model_id}/rollback``), and
  * ``proxy/registry/client.py::_download_and_apply`` — ``model_id`` from
    registry-server-supplied metadata.

Both build ``<profile_dir>/<model_id>.yaml`` and ``write_bytes`` to it. Without
validation a crafted ``model_id`` ("../pwned", an absolute path, encoded
separators, a null byte) escapes the profiles root and WRITES a file OUTSIDE it
(also a file-existence oracle + reload trigger).

This is the WRITE-side twin of the registry server's READ hardening in
``registry_server/storage.py``. ``proxy/`` and ``registry_server/`` are copied
into DISJOINT Docker images (see their Dockerfiles), so the registry helper
cannot be imported here across the deployable boundary — the containment logic
is intentionally MIRRORED. Keep the two in sync.

The public ``model_id`` is a REGISTRY identifier, not a filesystem stem: real
ids legitimately contain ``:`` and ``/`` (ollama ``qwen3:8b``, HF
``deepseek-ai/DeepSeek-V3.1``, ``zoecohn4/Ouro:latest``). A ``/`` in the id would
make ``<dir>/<model_id>.yaml`` a SUBDIRECTORY path — and a cached profile in a
subdir is NEVER loaded by the router (its ``load_all`` globs only TOP-LEVEL
``*.yaml``), so ``deepseek-ai/DeepSeek-V3.1`` would be written-but-never-loaded.
The fix is a reversible **encoding**: the public id is mapped to a SAFE
SINGLE-COMPONENT on-disk stem (percent-encoding via ``encode_model_id`` — ``/`` →
``%2F``, ``:`` → ``%3A``) so every cached profile is exactly ONE top-level file
the glob finds. ``decode_model_id`` is the inverse (used by the router as a
filename→id fallback), so the mapping is round-trippable at every layer.

Security requirement: the RESOLVED write path must stay inside the profiles root
AND be a direct child of it (single component, never a subdir). Enforcement is a
syntactic pre-filter (rejects a literal ``..`` traversal token, a NUL byte, a
backslash, empty/oversized ids) THEN realpath containment on the RAW id (so an
absolute path or otherwise-escaping id is *rejected*, not silently encoded into a
contained name) THEN encoding to a single top-level component (with a
parent==root backstop). The pre-filter deliberately does NOT reject ``:`` or
``/`` — those are encoded, not banned. The shipped-profile floor test
(``tests/test_registry_roundtrip_floor.py``) asserts every emitted id round-trips
through this guard to a TOP-LEVEL single-component path while traversal ids are
rejected/contained.

Fail-closed: an unsafe id or an escaping resolved path yields ``None``; callers
surface HTTP 400/404 and perform no write and no reload.
"""

import logging
from pathlib import Path
from typing import Optional, Union
from urllib.parse import quote, unquote

logger = logging.getLogger(__name__)

# Mirror of registry_server.storage's syntactic pre-filter (keep in sync).
_MAX_MODEL_ID_LEN = 128


def is_safe_model_id(model_id: str) -> bool:
    """True iff ``model_id`` is free of syntactic tokens that can never name a
    legitimate profile (a ``..`` traversal token, a NUL byte, a backslash) and is
    a non-empty, bounded string.

    Pre-filter ONLY: it intentionally ACCEPTS ``:`` and ``/`` (present in real
    registry ids). Realpath containment in ``safe_profile_write_path`` is what
    actually prevents any write outside the profiles root. Encoded separators
    (``%2f``, ``%2e%2e``) are literal here; ``%2e%2e`` (no real ``..``) resolves
    to a filename *inside* the root, so it is contained, not an escape.
    """
    if not isinstance(model_id, str) or not model_id:
        return False
    if len(model_id) > _MAX_MODEL_ID_LEN:
        return False
    if ".." in model_id or "\x00" in model_id or "\\" in model_id:
        return False
    return True


def encode_model_id(model_id: str) -> str:
    """Map a public ``model_id`` to a SAFE SINGLE-COMPONENT on-disk stem.

    Percent-encodes every char outside the unreserved set (``safe=""``), so the
    path separators that would otherwise create subdirectories or break routing
    never survive: ``/`` → ``%2F``, ``:`` → ``%3A``. The result contains no
    ``/``, ``:``, ``\\`` or NUL — it is exactly one filesystem component. Inverse:
    :func:`decode_model_id`. Reversible for every id (``unquote(quote(x))==x``),
    so the on-disk filename and the public id map 1:1 with no collisions.
    """
    return quote(model_id, safe="")


def decode_model_id(stem: str) -> str:
    """Inverse of :func:`encode_model_id`: recover the public ``model_id`` from a
    (percent-encoded) on-disk stem. Used as a filename→id fallback when a cached
    profile's CONTENTS carry no ``model:``/``metadata.model_id``."""
    return unquote(stem)


def safe_profile_write_path(
    profile_dir: Union[str, Path], model_id: str
) -> Optional[Path]:
    """Resolve the WRITE path for ``model_id`` as a SAFE SINGLE-COMPONENT
    top-level file ``<profile_dir>/<encode_model_id(model_id)>.yaml`` and return
    it ONLY if the id is safe and the path stays a direct child of ``profile_dir``.

    Layers (fail-closed at each — any failure returns ``None``):
      1. syntactic pre-filter (``is_safe_model_id``): drop ``..``/NUL/backslash/
         empty/oversized ids;
      2. realpath containment on the RAW id: an absolute path or otherwise
         escaping id (``/etc/passwd``, a symlinked subpath) is REJECTED here — it
         is never silently encoded into a contained name;
      3. encode to a single-component stem so a ``/`` id (e.g.
         ``deepseek-ai/DeepSeek-V3.1``) becomes ONE top-level file the router's
         top-level glob actually loads — NEVER a subdir; and
      4. a ``parent == root`` backstop + containment recheck on the encoded path.

    Unlike the read helper this does NOT require the target to already exist (a
    write may create it). The single containment chokepoint for proxy profile
    writes (registry pull cache + admin rollback).
    """
    if not is_safe_model_id(model_id):
        logger.warning("Rejected unsafe model_id for profile write: %r", model_id)
        return None
    base = Path(profile_dir)
    # (2) Containment on the RAW id: reject absolute/escaping ids up front so
    # they fail closed (None) rather than being encoded into a contained file.
    try:
        root = base.resolve()
        raw_candidate = (base / f"{model_id}.yaml").resolve()
    except (OSError, ValueError) as e:
        logger.warning("Rejected model_id (unresolvable write path) %r: %s", model_id, e)
        return None
    try:
        raw_candidate.relative_to(root)
    except ValueError:
        logger.warning("Rejected model_id (escapes profiles root on write): %r", model_id)
        return None
    # (3) Encode to a single top-level component (no subdirs, no separators).
    stem = encode_model_id(model_id)
    try:
        candidate = (base / f"{stem}.yaml").resolve()
    except (OSError, ValueError) as e:
        logger.warning("Rejected model_id (unresolvable encoded path) %r: %s", model_id, e)
        return None
    # (4) Backstop: the encoded name has no separators, so the path MUST be a
    # direct child of root. Enforce it (single-component + containment).
    if candidate.parent != root:
        logger.warning("Rejected model_id (encoded path not top-level) %r", model_id)
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        logger.warning("Rejected model_id (encoded path escapes root) %r", model_id)
        return None
    return candidate
