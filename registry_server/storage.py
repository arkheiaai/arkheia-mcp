"""
Profile storage backend for the Arkheia Registry Server.

Reads profiles from a directory, computes checksums, returns metadata.
Profiles use either:
  - Real format: top-level "model" + "version" keys
  - Spec format: metadata.model_id + metadata.version keys
Both are handled transparently.
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

# --- Path-traversal hardening (adversarial ledger F23) ---------------------
# `model_id` arrives from untrusted callers and is used to build a filesystem
# path (`<profiles>/<model_id>.yaml`). Without validation, a crafted value
# ("../secret", "/etc/config", encoded separators, null byte, a symlink) escapes
# the profiles root and reads arbitrary *.yaml files. Defence in depth:
#   1. strict allow-list charset (rejects separators / traversal / encoded /
#      null-byte / leading dot or dash), and
#   2. realpath containment: the resolved path MUST stay within the profiles
#      root before any read.
# Fail-closed: anything suspicious -> None (surfaced by the HTTP layer as 404).
_MAX_MODEL_ID_LEN = 128
# First char alphanumeric; remainder [A-Za-z0-9._-]. All 60 shipped profile
# ids (e.g. "claude-opus-4-8", "deepseek-v3.1", "gpt-5.2-codex") match this.
_MODEL_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def _is_safe_model_id(model_id: str) -> bool:
    """True iff `model_id` is a syntactically safe profile identifier.

    Rejects empty/oversized ids, path separators, `..` traversal, null bytes,
    and any character outside the allow-list. Encoded separators (e.g. ``%2f``,
    ``%2e%2e``) are decoded to their literal form by the HTTP layer before
    reaching here, so they fail the charset check too.
    """
    if not isinstance(model_id, str) or not model_id:
        return False
    if len(model_id) > _MAX_MODEL_ID_LEN:
        return False
    if ".." in model_id or "\x00" in model_id:
        return False
    return _MODEL_ID_RE.fullmatch(model_id) is not None


class ProfileStorage:
    def __init__(self, profile_dir: str, base_url: str):
        self.profile_dir = Path(profile_dir)
        self.base_url = base_url.rstrip("/")

    def _iter_profile_files(self):
        """Yield *.yaml profile paths that are contained within the profiles
        root.

        Skips ``schema.yaml`` and any entry whose realpath escapes the root
        (e.g. a symlink planted to point outside) so no code path reads a file
        outside the profiles directory (path-traversal hardening, F23).
        """
        try:
            root = self.profile_dir.resolve()
        except (OSError, ValueError):
            return
        for path in sorted(self.profile_dir.glob("*.yaml")):
            if path.name == "schema.yaml":
                continue
            try:
                path.resolve().relative_to(root)
            except (OSError, ValueError):
                logger.warning("Skipping profile escaping root: %s", path.name)
                continue
            yield path

    def list_profiles(self, since: Optional[datetime] = None) -> list[dict]:
        """
        Return metadata for all available profiles.
        If `since` is provided, only return profiles modified after that time.
        """
        profiles = []
        for path in self._iter_profile_files():
            try:
                meta = self._profile_meta(path, since)
                if meta:
                    profiles.append(meta)
            except Exception as e:
                logger.warning("Skipping %s: %s", path.name, e)
        return profiles

    def _safe_profile_path(self, model_id: str) -> Optional[Path]:
        """Resolve ``<profiles>/<model_id>.yaml`` and return it ONLY if it is a
        regular file contained within the profiles root.

        Returns None for any unsafe id or any resolved path that escapes the
        root (realpath containment — also defeats symlinks that point outside).
        This is the single containment chokepoint for filesystem reads.
        """
        if not _is_safe_model_id(model_id):
            return None
        try:
            root = self.profile_dir.resolve()
            candidate = (self.profile_dir / f"{model_id}.yaml").resolve()
        except (OSError, ValueError) as e:
            logger.warning("Rejected model_id (unresolvable path) %r: %s", model_id, e)
            return None
        try:
            candidate.relative_to(root)
        except ValueError:
            logger.warning("Rejected model_id (escapes profiles root): %r", model_id)
            return None
        if not candidate.is_file():
            return None
        return candidate

    def get_profile_bytes(self, model_id: str) -> Optional[bytes]:
        """Return raw YAML bytes for the given model_id, or None if not found.

        `model_id` is validated against a strict allow-list and the resolved
        path is asserted to stay within the profiles root before any read
        (path-traversal hardening, adversarial ledger F23).
        """
        # Reject traversal / absolute / encoded / null-byte ids up front:
        # no filesystem read and no scan for anything that fails the allow-list.
        if not _is_safe_model_id(model_id):
            logger.warning("Rejected unsafe model_id: %r", model_id)
            return None
        # Exact filename match, gated by realpath containment.
        path = self._safe_profile_path(model_id)
        if path is not None:
            return path.read_bytes()
        # Fall back to scanning profiles for a matching internal model_id.
        # Bounded to contained files only; model_id already allow-listed.
        for path in self._iter_profile_files():
            try:
                data = yaml.safe_load(path.read_bytes())
                pid = data.get("model") or data.get("metadata", {}).get("model_id", "")
                if pid == model_id:
                    return path.read_bytes()
            except Exception:
                continue
        return None

    def _profile_meta(self, path: Path, since: Optional[datetime]) -> Optional[dict]:
        """Build metadata dict for one profile file."""
        content = path.read_bytes()
        data = yaml.safe_load(content)

        # Extract model_id and version from either format
        model_id = (
            data.get("model")
            or data.get("metadata", {}).get("model_id")
            or path.stem
        )
        version = str(
            data.get("version")
            or data.get("metadata", {}).get("version", "1.0")
        )

        # Check mtime for incremental pulls
        if since is not None:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            if mtime <= since:
                return None

        checksum = hashlib.sha256(content).hexdigest()
        download_url = f"{self.base_url}/profiles/{model_id}/download"

        return {
            "model_id": model_id,
            "version": version,
            "checksum": checksum,
            "download_url": download_url,
            "updated_at": datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
        }
