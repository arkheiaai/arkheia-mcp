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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlencode

import yaml

logger = logging.getLogger(__name__)

# --- Path-traversal hardening (adversarial ledger F23) ---------------------
# `model_id` arrives from untrusted callers. On the EXACT-filename branch it is
# used to build a filesystem path (`<profiles>/<model_id>.yaml`); on the fallback
# SCAN branch it is only compared (string equality) against a profile's own
# `model:` value and never touches the filesystem.
#
# The public model_id is a REGISTRY identifier, not a filesystem stem: real ids
# legitimately contain `:` and `/` (ollama `qwen3:8b`, HF `deepseek-ai/DeepSeek-
# V3.1`, `zoecohn4/Ouro:latest`). So the security requirement is NOT "the id has
# no separators" — it is "the RESOLVED path stays inside the profiles root".
# Enforcement is realpath containment (`_safe_profile_path`), with a thin
# syntactic pre-filter that rejects only tokens that can never name a legitimate
# id and that `realpath` would otherwise normalise away:
#   * a literal `..` parent-traversal token,
#   * a NUL byte or a backslash (Windows separator), and
#   * empty / oversized ids.
# It deliberately does NOT reject `:` or `/`. Fail-closed: the containment check
# turns any escaping path into None (surfaced by the HTTP layer as 404).
_MAX_MODEL_ID_LEN = 128


def _is_safe_model_id(model_id: str) -> bool:
    """True iff `model_id` is free of syntactic tokens that can never name a
    legitimate profile (a `..` traversal token, a NUL byte, a backslash) and is a
    non-empty, bounded string.

    Pre-filter ONLY: it intentionally ACCEPTS `:` and `/` (present in real
    registry ids). Containment against the profiles root — realpath, in
    `_safe_profile_path` — is what actually prevents any read outside the root.
    Encoded separators (`%2f`, `%2e%2e`) are literal here; `%2e%2e` (no real
    `..`) resolves to a filename inside the root, so it is contained, not an
    escape (and matches no profile on the scan branch -> not found).
    """
    if not isinstance(model_id, str) or not model_id:
        return False
    if len(model_id) > _MAX_MODEL_ID_LEN:
        return False
    if ".." in model_id or "\x00" in model_id or "\\" in model_id:
        return False
    return True


PUBLIC_PROFILE_METADATA_KEYS = (
    "model_id",
    "version",
    "checksum",
    "download_url",
    "updated_at",
)


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

        A `model_id` may be a REGISTRY id containing `:` or `/` (e.g. `qwen3:8b`,
        `deepseek-ai/DeepSeek-V3.1`). Resolution is two-branch:
          1. exact filename `<profiles>/<model_id>.yaml`, gated by realpath
             containment so it can never read outside the profiles root; then
          2. a fallback SCAN that matches the id against each contained profile's
             own `model:` value (string compare only — no path is built from the
             id here), which is how the `:`/`/` ids resolve.
        The syntactic pre-filter drops only `..`/NUL/backslash/empty/oversized
        ids up front (path-traversal hardening, adversarial ledger F23).
        """
        # Drop ids that can never name a legitimate profile before any work.
        if not _is_safe_model_id(model_id):
            logger.warning("Rejected unsafe model_id: %r", model_id)
            return None
        # 1. Exact filename match, gated by realpath containment.
        path = self._safe_profile_path(model_id)
        if path is not None:
            return path.read_bytes()
        # 2. Fallback: scan contained profiles for a matching internal model_id.
        #    String compare only; `model_id` never builds a path on this branch,
        #    so `:`/`/` registry ids resolve safely and no id escapes the root.
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
        # A profile's OWN `model:` value is untrusted input too - it is authored
        # in a YAML file, not validated on the way in, and it is what the listing
        # advertises as a download id. If it cannot name a legitimate profile,
        # refuse to publish an entry rather than advertise an id every download
        # route will then reject (PR #66 floor; pinned by
        # test_profile_storage_skips_unsafe_model_ids_in_listing). Raising here is
        # caught by `list_profiles`, which logs and skips the file.
        if not _is_safe_model_id(model_id):
            raise ValueError(f"unsafe model_id: {model_id!r}")
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
        # Carry the id in the QUERY, not in the path. `model_id` is a REGISTRY identifier, not a URL
        # token: it may contain `#` (truncates the URL client-side), `?` (starts a query string), `/`,
        # `:` — and even a literal `%`. So it must be escaped into whichever slot carries it, and the
        # PATH is the wrong slot: percent-escaping there is only correct if the path is unescaped
        # EXACTLY ONCE between advertising the URL and the handler reading it, and the number of
        # unescapes is not ours to control. Both counts exist in THIS stack (measured, not assumed):
        #   * uvicorn — the shipping server — decodes ONCE (h11_impl.py: `unquote(raw_path)`), so
        #     `/profiles/model%2523/download` reaches the handler as `model%23`: correct.
        #   * starlette's TestClient decodes TWICE (testclient.py:262 `"path": unquote(path)` where
        #     `path = httpx.URL.path` is ALREADY decoded), so the same URL arrives as `model#`: 404.
        #     That is Codex's exact failing set — ids holding a VALID escape (`model%23`, `model%2e`,
        #     `model%2f`, `model%3f`, `model%41`) break, while a bare `%` or an invalid escape
        #     (`model%`, `model%zz`) survives, because `%25`->`%`->(nothing left to decode).
        # Path-normalising reverse proxies/CDNs do the same second decode in production, and no
        # path-based escaping can be safe under an unknown decode count: "try the raw value, then the
        # decoded one" would silently serve `model#`'s profile for a request for `model%23`.
        # A `?model_id=` query is decoded EXACTLY ONCE by both (TestClient forwards `query_string`
        # verbatim; uvicorn never touches it) — so the advertised URL is decode-invariant: its path
        # holds no escape at all. `urlencode` escapes `#`, `?`, `/`, `:`, `%`, `+` and space into the
        # query, so nothing leaks into another URL component, and the id stays human-readable (the raw
        # id is also still returned in `model_id` for display).
        # The legacy `/profiles/{model_id:path}/download` route is KEPT as an alias — it resolves every
        # id wherever the path is decoded exactly once, slash ids included; it is simply no longer what
        # we advertise, because it cannot express a `%` id robustly (Codex #13 LOW).
        download_url = (
            f"{self.base_url}/profiles/download?{urlencode({'model_id': model_id})}"
        )

        meta = {
            "model_id": model_id,
            "version": version,
            "checksum": checksum,
            "download_url": download_url,
            "updated_at": datetime.fromtimestamp(
                path.stat().st_mtime, tz=timezone.utc
            ).isoformat(),
            "provider": data.get("api", {}).get("provider"),
        }
        return {key: meta[key] for key in PUBLIC_PROFILE_METADATA_KEYS}
