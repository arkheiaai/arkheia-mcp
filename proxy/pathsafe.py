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
``deepseek-ai/DeepSeek-V3.1``, ``zoecohn4/Ouro:latest``). So the security
requirement is NOT "the id has no separators" — it is "the RESOLVED write path
stays inside the profiles root". Enforcement is realpath containment
(``safe_profile_write_path``), with a thin syntactic pre-filter that rejects only
tokens that can never name a legitimate id (a literal ``..`` traversal token, a
NUL byte, a backslash) plus empty/oversized ids. It deliberately does NOT reject
``:`` or ``/``; the shipped-profile floor test
(``tests/test_registry_roundtrip_floor.py``) asserts every emitted id round-trips
through this guard while traversal ids are rejected/contained.

Fail-closed: an unsafe id or an escaping resolved path yields ``None``; callers
surface HTTP 400/404 and perform no write and no reload.
"""

import logging
from pathlib import Path
from typing import Optional, Union

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


def safe_profile_write_path(
    profile_dir: Union[str, Path], model_id: str
) -> Optional[Path]:
    """Resolve ``<profile_dir>/<model_id>.yaml`` for a WRITE and return it ONLY
    if ``model_id`` is safe AND the resolved path stays within ``profile_dir``.

    Unlike the read helper this does NOT require the target to already exist (a
    write may create it), but it applies the same syntactic pre-filter and
    realpath containment so no write can land outside the profiles root — which
    also defeats a symlinked profiles subpath pointing outside. An id with a
    ``/`` may resolve to a contained SUBPATH (e.g. ``deepseek-ai/DeepSeek-V3.1``,
    whose parent dir the caller creates); only paths that ESCAPE the root are
    rejected.

    Returns ``None`` (fail-closed) for any unsafe id or any resolved path that
    escapes the root. The single containment chokepoint for proxy profile
    writes.
    """
    if not is_safe_model_id(model_id):
        logger.warning("Rejected unsafe model_id for profile write: %r", model_id)
        return None
    base = Path(profile_dir)
    try:
        root = base.resolve()
        candidate = (base / f"{model_id}.yaml").resolve()
    except (OSError, ValueError) as e:
        logger.warning("Rejected model_id (unresolvable write path) %r: %s", model_id, e)
        return None
    try:
        candidate.relative_to(root)
    except ValueError:
        logger.warning("Rejected model_id (escapes profiles root on write): %r", model_id)
        return None
    return candidate
