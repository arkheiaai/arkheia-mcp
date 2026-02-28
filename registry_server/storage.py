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

import yaml

logger = logging.getLogger(__name__)


class ProfileStorage:
    def __init__(self, profile_dir: str, base_url: str):
        self.profile_dir = Path(profile_dir)
        self.base_url = base_url.rstrip("/")

    def list_profiles(self, since: Optional[datetime] = None) -> list[dict]:
        """
        Return metadata for all available profiles.
        If `since` is provided, only return profiles modified after that time.
        """
        profiles = []
        for path in sorted(self.profile_dir.glob("*.yaml")):
            if path.name == "schema.yaml":
                continue
            try:
                meta = self._profile_meta(path, since)
                if meta:
                    profiles.append(meta)
            except Exception as e:
                logger.warning("Skipping %s: %s", path.name, e)
        return profiles

    def get_profile_bytes(self, model_id: str) -> Optional[bytes]:
        """Return raw YAML bytes for the given model_id, or None if not found."""
        # Try exact filename match first
        path = self.profile_dir / f"{model_id}.yaml"
        if path.exists():
            return path.read_bytes()
        # Try scanning all profiles for a matching model_id inside the YAML
        for path in self.profile_dir.glob("*.yaml"):
            if path.name == "schema.yaml":
                continue
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
