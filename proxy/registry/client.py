"""
Profile registry pull client.

Enterprise proxy instances PULL profile updates from the Arkheia-hosted
registry. No push -- the customer controls when updates are applied.

Pull cadence: configurable (default: on startup + every 24 hours).
Customer can trigger manual pull via POST /admin/registry/pull.

On failure: retain current profiles, log error, continue serving.
"""

import asyncio
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
from pydantic import SecretStr

from proxy.registry.validator import ProfileValidator

logger = logging.getLogger(__name__)


class RegistryClient:
    """
    Pulls profile updates from the Arkheia profile registry.

    Validates each profile (checksum + schema + smoke test) before applying.
    Keeps a .bak of the previous version for rollback.
    Performs atomic swap in the ProfileRouter after successful download.
    """

    def __init__(
        self,
        base_url: str,
        api_key: SecretStr,
        profile_dir: str,
        router,
        validator: Optional[ProfileValidator] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.profile_dir = profile_dir
        self.router = router
        self.validator = validator or ProfileValidator()
        self.last_pull: Optional[datetime] = None
        self._pull_task: Optional[asyncio.Task] = None

    async def pull(self) -> dict:
        """
        Pull profile updates from the registry.

        Returns summary: {"updated": [...], "skipped": [...], "errors": [...]}
        """
        params = {}
        if self.last_pull:
            params["since"] = self.last_pull.isoformat()

        key_value = self.api_key.get_secret_value()
        if not key_value:
            logger.info("ARKHEIA_API_KEY not set -- registry pull skipped")
            return {"updated": [], "skipped": [], "errors": ["api_key_not_set"]}

        updated = []
        skipped = []
        errors = []

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self.base_url}/profiles",
                    params=params,
                    headers={"Authorization": f"Bearer {key_value}"},
                )
                resp.raise_for_status()
                data = resp.json()

            for profile_meta in data.get("profiles", []):
                model_id = profile_meta.get("model_id", "unknown")
                try:
                    applied = await self._download_and_apply(profile_meta)
                    if applied:
                        updated.append(model_id)
                    else:
                        skipped.append(model_id)
                except Exception as e:
                    logger.error("Failed to apply profile %s: %s", model_id, e)
                    errors.append(f"{model_id}: {e}")

            self.last_pull = datetime.now(timezone.utc)
            logger.info(
                "Registry pull complete: updated=%s skipped=%s errors=%s",
                updated, skipped, errors,
            )

        except httpx.TimeoutException:
            logger.error("Registry pull timed out after 30s -- retaining current profiles")
            errors.append("timeout")
        except httpx.HTTPStatusError as e:
            logger.error("Registry pull HTTP error: %s -- retaining current profiles", e)
            errors.append(str(e))
        except Exception as e:
            logger.error("Registry pull failed: %s -- retaining current profiles", e)
            errors.append(str(e))

        return {"updated": updated, "skipped": skipped, "errors": errors}

    async def _download_and_apply(self, meta: dict) -> bool:
        """
        Download, validate, and apply a single profile.

        Returns True if applied, False if skipped (already up to date).
        Raises on validation failure -- caller retains old profile.
        """
        model_id = meta["model_id"]
        checksum = meta.get("checksum", "")
        download_url = meta["download_url"]
        key_value = self.api_key.get_secret_value()

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                download_url,
                headers={"Authorization": f"Bearer {key_value}"},
            )
            resp.raise_for_status()
            content = resp.content

        # 1. Verify checksum
        if checksum and not self.validator.verify_checksum(content, checksum):
            raise ValueError(f"Checksum mismatch for {model_id}")

        # 2. Validate schema + smoke test
        profile_data = self.validator.validate(content)

        # 3. Write to profile dir (keep .bak for rollback)
        path = Path(self.profile_dir) / f"{model_id}.yaml"
        if path.exists():
            bak_path = Path(str(path) + ".bak")
            bak_path.write_bytes(path.read_bytes())

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

        # 4. Atomic swap in router
        await self.router.reload()

        logger.info("Applied profile update: %s v%s", model_id, meta.get("version", "?"))
        return True

    async def start_scheduled_pull(self, interval_hours: int) -> None:
        """
        Start background pull task. Runs on startup then every interval_hours.
        Failures are logged but do not crash -- current profiles continue serving.
        """
        self._pull_task = asyncio.create_task(
            self._pull_loop(interval_hours), name="registry-pull"
        )

    async def stop(self) -> None:
        if self._pull_task:
            self._pull_task.cancel()
            try:
                await self._pull_task
            except asyncio.CancelledError:
                pass

    async def _pull_loop(self, interval_hours: int) -> None:
        while True:
            await asyncio.sleep(interval_hours * 3600)
            try:
                await self.pull()
            except Exception as e:
                logger.error("Scheduled registry pull error: %s", e)
