"""
Profile registry pull client.

Enterprise proxy instances PULL profile updates from the Arkheia-hosted
registry. No push -- the customer controls when updates are applied.

Pull cadence: configurable (default: on startup + every 24 hours).
Customer can trigger manual pull via POST /admin/registry/pull.

On failure: retain current profiles, log error, continue serving.
"""

import asyncio
import inspect
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

import httpx
from pydantic import SecretStr

from arkheia_common.egress import egress_async_client
from proxy.registry.receipts import (
    OUTCOME_PROFILE_APPLIED,
    OUTCOME_PROFILE_APPLY_FAILED,
    OUTCOME_PROFILE_SKIPPED,
    OUTCOME_PROFILE_DOWNLOAD_FAILED,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_INVALID,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_MISMATCH,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING,
    OUTCOME_PROFILE_REJECTED_VALIDATION,
    OUTCOME_PULL_FAILED,
    OUTCOME_PULL_SKIPPED_NO_API_KEY,
    emit_registry_pull,
)
from proxy.registry.validator import ProfileValidator

logger = logging.getLogger(__name__)


class RegistryApplyError(ValueError):
    """A profile was refused before apply; ``outcome`` says which refusal."""

    def __init__(self, outcome: str, message: str):
        super().__init__(message)
        self.outcome = outcome


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
        audit_writer: Optional[object] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.profile_dir = profile_dir
        self.router = router
        self.validator = validator or ProfileValidator()
        self.audit_writer = audit_writer
        self.last_pull: Optional[datetime] = None
        self.last_pull_receipts: list[dict] = []
        self._pull_task: Optional[asyncio.Task] = None

    async def _receipt(
        self,
        outcome: str,
        meta: Optional[dict] = None,
        *,
        error: Optional[BaseException] = None,
        error_reason: Optional[str] = None,
    ) -> dict:
        meta = meta or {}
        receipt = await emit_registry_pull(
            self.audit_writer,
            outcome=outcome,
            registry_url=self.base_url,
            model_id=meta.get("model_id"),
            profile_version=meta.get("version"),
            download_url=meta.get("download_url"),
            checksum=meta.get("checksum"),
            error_type=type(error).__name__ if error is not None else None,
            error_reason=error_reason,
        )
        self.last_pull_receipts.append(receipt)
        return receipt

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
            self.last_pull_receipts = []
            await self._receipt(
                OUTCOME_PULL_SKIPPED_NO_API_KEY,
                error_reason="api_key_not_set",
            )
            return {
                "updated": [],
                "skipped": [],
                "errors": ["api_key_not_set"],
                "receipts": self.last_pull_receipts,
            }

        updated = []
        skipped = []
        errors = []
        self.last_pull_receipts = []

        try:
            async with egress_async_client(timeout=30.0) as client:
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
                    outcome = self._outcome_for_error(e)
                    await self._receipt(
                        outcome,
                        profile_meta,
                        error=e,
                        error_reason=str(e),
                    )
                else:
                    await self._receipt(
                        OUTCOME_PROFILE_APPLIED if applied else OUTCOME_PROFILE_SKIPPED,
                        profile_meta,
                    )

            self.last_pull = datetime.now(timezone.utc)
            logger.info(
                "Registry pull complete: updated=%s skipped=%s errors=%s",
                updated, skipped, errors,
            )

        except httpx.TimeoutException:
            logger.error("Registry pull timed out after 30s -- retaining current profiles")
            errors.append("timeout")
            await self._receipt(
                OUTCOME_PULL_FAILED,
                error_reason="timeout",
            )
        except httpx.HTTPStatusError as e:
            logger.error("Registry pull HTTP error: %s -- retaining current profiles", e)
            errors.append(str(e))
            await self._receipt(
                OUTCOME_PULL_FAILED,
                error=e,
                error_reason="http_status_error",
            )
        except Exception as e:
            logger.error("Registry pull failed: %s -- retaining current profiles", e)
            errors.append(str(e))
            await self._receipt(
                OUTCOME_PULL_FAILED,
                error=e,
                error_reason="pull_exception",
            )

        return {
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "receipts": self.last_pull_receipts,
        }

    @staticmethod
    def _outcome_for_error(exc: BaseException) -> str:
        if isinstance(exc, RegistryApplyError):
            return exc.outcome
        if isinstance(exc, httpx.HTTPError):
            return OUTCOME_PROFILE_DOWNLOAD_FAILED
        return OUTCOME_PROFILE_APPLY_FAILED

    async def _download_and_apply(self, meta: dict) -> bool:
        """
        Download, validate, and apply a single profile.

        Returns True if applied, False if skipped (already up to date).
        Raises on validation failure -- caller retains old profile.
        """
        try:
            model_id = self._validate_registry_profile_id(meta.get("model_id"))
        except ValueError as exc:
            raise RegistryApplyError(OUTCOME_PROFILE_APPLY_FAILED, str(exc)) from exc
        try:
            checksum = self.validator.require_checksum(meta.get("checksum", ""))
        except ValueError as exc:
            outcome = (
                OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING
                if "required" in str(exc)
                else OUTCOME_PROFILE_REJECTED_CHECKSUM_INVALID
            )
            raise RegistryApplyError(outcome, str(exc)) from exc
        download_url = meta.get("download_url")
        if not download_url:
            raise RegistryApplyError(
                OUTCOME_PROFILE_APPLY_FAILED,
                f"registry profile metadata missing download_url for {model_id}",
            )
        key_value = self.api_key.get_secret_value()

        async with egress_async_client(timeout=30.0) as client:
            resp = await client.get(
                download_url,
                headers={"Authorization": f"Bearer {key_value}"},
            )
            resp.raise_for_status()
            content = resp.content

        # 1. Verify checksum
        if not self.validator.verify_checksum(content, checksum):
            raise RegistryApplyError(
                OUTCOME_PROFILE_REJECTED_CHECKSUM_MISMATCH,
                f"Checksum mismatch for {model_id}",
            )

        # 2. Validate schema + smoke test
        try:
            profile_data = self.validator.validate(content)
        except ValueError as exc:
            raise RegistryApplyError(
                OUTCOME_PROFILE_REJECTED_VALIDATION,
                str(exc),
            ) from exc
        content_model_id = self._profile_model_id(profile_data)
        if content_model_id != model_id:
            raise ValueError(
                "Profile identity mismatch: "
                f"registry metadata model_id={model_id!r} "
                f"but profile content model_id={content_model_id!r}"
            )

        content_version = self._profile_version(profile_data)
        metadata_version = meta.get("version")
        if metadata_version is not None and str(metadata_version) != content_version:
            raise ValueError(
                "Profile version mismatch: "
                f"registry metadata version={metadata_version!r} "
                f"but profile content version={content_version!r}"
            )

        # 3. Write to profile dir via a temp file in the same directory.
        profile_dir, path, temp_path, bak_path = self._profile_paths(model_id)
        profile_dir.mkdir(parents=True, exist_ok=True)

        old_content = path.read_bytes() if path.exists() else None
        bak_existed = bak_path.exists()
        old_bak_content = bak_path.read_bytes() if bak_existed else None

        try:
            temp_path.write_bytes(content)
            if old_content is not None:
                bak_path.write_bytes(old_content)
            temp_path.replace(path)

            # 4. Atomic swap in router, then assert the exact profile became active.
            await self.router.reload()
            await self._assert_active_profile(model_id, content_version)
        except Exception:
            await self._restore_profile(
                path=path,
                bak_path=bak_path,
                old_content=old_content,
                bak_existed=bak_existed,
                old_bak_content=old_bak_content,
            )
            raise
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                logger.warning("Failed to remove temporary profile file: %s", temp_path)

        logger.info("Applied profile update: %s v%s", model_id, content_version)
        return True

    @staticmethod
    def _validate_registry_profile_id(raw_model_id: object) -> str:
        """Registry profile IDs are used as filenames and must be one segment."""
        if not isinstance(raw_model_id, str):
            raise ValueError(
                f"invalid registry profile id {raw_model_id!r}: must be a string"
            )

        model_id = raw_model_id.strip()
        if model_id != raw_model_id or not model_id:
            raise ValueError(
                f"invalid registry profile id {raw_model_id!r}: must be non-empty "
                "with no leading or trailing whitespace"
            )
        if (
            model_id in {".", ".."}
            or "/" in model_id
            or "\\" in model_id
            or "\x00" in model_id
        ):
            raise ValueError(
                f"invalid registry profile id {model_id!r}: must be a single filename segment"
            )
        return model_id

    @staticmethod
    def _profile_model_id(profile_data: dict) -> str:
        model_id = (
            profile_data.get("model")
            or profile_data.get("metadata", {}).get("model_id")
            or ""
        )
        return str(model_id)

    @staticmethod
    def _profile_version(profile_data: dict) -> str:
        version = (
            profile_data.get("version")
            or profile_data.get("metadata", {}).get("version")
            or ""
        )
        return str(version)

    def _profile_paths(self, model_id: str) -> tuple[Path, Path, Path, Path]:
        profile_dir = Path(self.profile_dir).expanduser().resolve()
        path = (profile_dir / f"{model_id}.yaml").resolve(strict=False)
        temp_path = (profile_dir / f".{model_id}.{uuid4().hex}.tmp").resolve(strict=False)
        bak_path = (profile_dir / f"{model_id}.yaml.bak").resolve(strict=False)
        for candidate in (path, temp_path, bak_path):
            self._assert_path_under_profile_dir(candidate, profile_dir)
            if candidate.parent != profile_dir:
                raise ValueError(f"profile path escaped profile_dir: {candidate}")
        return profile_dir, path, temp_path, bak_path

    @staticmethod
    def _assert_path_under_profile_dir(path: Path, profile_dir: Path) -> None:
        try:
            path.relative_to(profile_dir)
        except ValueError:
            raise ValueError(f"profile path escaped profile_dir: {path}")

    async def _assert_active_profile(self, model_id: str, expected_version: str) -> None:
        get_profile = getattr(self.router, "get", None)
        if not callable(get_profile):
            raise ValueError(
                "Profile router does not expose get(); cannot verify applied profile"
            )

        active = get_profile(model_id)
        if inspect.isawaitable(active):
            active = await active
        if not isinstance(active, dict):
            raise ValueError(f"Applied profile {model_id!r} did not activate")

        active_model_id = self._profile_model_id(active)
        active_version = self._profile_version(active)
        if active_model_id != model_id:
            raise ValueError(
                f"Applied profile {model_id!r} did not activate; "
                f"router returned {active_model_id!r}"
            )
        if active_version != expected_version:
            raise ValueError(
                f"Applied profile {model_id!r} activated version {active_version!r}, "
                f"expected {expected_version!r}"
            )

    async def _restore_profile(
        self,
        path: Path,
        bak_path: Path,
        old_content: bytes | None,
        bak_existed: bool,
        old_bak_content: bytes | None,
    ) -> None:
        try:
            if old_content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(old_content)

            if bak_existed:
                bak_path.write_bytes(old_bak_content or b"")
            else:
                bak_path.unlink(missing_ok=True)
        except Exception as restore_error:
            logger.error("Profile rollback disk restore failed: %s", restore_error)
            return

        try:
            await self.router.reload()
        except Exception as restore_error:
            logger.error(
                "Profile rollback reload failed after registry apply error: %s",
                restore_error,
            )

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
