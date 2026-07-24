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
cannot be imported here across the deployable boundary — the allow-list charset
and realpath-containment logic are intentionally MIRRORED. Keep the two in sync;
the shipped-profile floor test (``test_pathsafe_accepts_all_shipped_profiles``)
ties this charset to the same reality the registry floor test does.

Fail-closed: an unsafe id or an escaping resolved path yields ``None``; callers
surface HTTP 400/404 and perform no write and no reload.
"""

import logging
import re
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

# Mirror of registry_server.storage's allow-list (keep in sync).
_MAX_MODEL_ID_LEN = 128
# First char alphanumeric; remainder [A-Za-z0-9._-]. Every shipped profile id
# (e.g. "claude-opus-4-8", "deepseek-v3.1", "gpt-5.2-codex") matches this.
_MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def is_safe_model_id(model_id: str) -> bool:
    """True iff ``model_id`` is a syntactically safe profile identifier.

    Rejects empty/oversized ids, path separators, ``..`` traversal, null bytes,
    a leading dot or dash, and any character outside the allow-list. Encoded
    separators (``%2f``, ``%2e%2e``) are decoded to their literal form by the
    HTTP layer before reaching here, so they fail the charset check too.
    """
    if not isinstance(model_id, str) or not model_id:
        return False
    if len(model_id) > _MAX_MODEL_ID_LEN:
        return False
    if ".." in model_id or "\x00" in model_id:
        return False
    return _MODEL_ID_RE.fullmatch(model_id) is not None


def safe_profile_write_path(
    profile_dir: Union[str, Path], model_id: str
) -> Optional[Path]:
    """Resolve ``<profile_dir>/<model_id>.yaml`` for a WRITE and return it ONLY
    if ``model_id`` is safe AND the resolved path stays within ``profile_dir``.

    Unlike the read helper this does NOT require the target to already exist (a
    write may create it), but it applies the same charset allow-list and
    realpath containment so no write can land outside the profiles root — which
    also defeats a symlinked profiles subpath pointing outside.

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
