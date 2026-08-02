"""
Receipts for registry pull -> validate -> apply decisions.

The registry client decides whether downloaded profile bytes are allowed to
replace the local profile set. Those decisions need the same hash-chained audit
rail as detection/profile-auth decisions, especially the refusal cases: missing
checksums, mismatched checksums, and smoke-test failures.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any, Optional

from proxy.audit.decision_journal import (
    RISK_LEVEL,
    RECEIPT_ENQUEUED,
    RECEIPT_UNAVAILABLE,
    emit,
    hosted_origin,
)

logger = logging.getLogger(__name__)

EVENT_REGISTRY_PROFILE_PULL = "registry.profile_pull"

OUTCOME_PULL_SKIPPED_NO_API_KEY = "pull_skipped_no_api_key"
OUTCOME_PULL_FAILED = "pull_failed"
OUTCOME_PROFILE_APPLIED = "profile_applied"
OUTCOME_PROFILE_SKIPPED = "profile_skipped"
OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING = "profile_rejected_checksum_missing"
OUTCOME_PROFILE_REJECTED_CHECKSUM_INVALID = "profile_rejected_checksum_invalid"
OUTCOME_PROFILE_REJECTED_CHECKSUM_MISMATCH = "profile_rejected_checksum_mismatch"
OUTCOME_PROFILE_REJECTED_VALIDATION = "profile_rejected_validation"
OUTCOME_PROFILE_DOWNLOAD_FAILED = "profile_download_failed"
OUTCOME_PROFILE_APPLY_FAILED = "profile_apply_failed"

# Registry pull is exposed through an operator-triggered HTTP endpoint. Unlike
# the hot detection path, this surface can afford to wait briefly and must not
# hand a caller an "enqueued" identity that has no matching durable row.
DURABLE_RECEIPT_TIMEOUT_SECONDS = 5.0
DURABLE_RECEIPT_POLL_SECONDS = 0.01

REGISTRY_PROFILE_PULL_OUTCOMES = frozenset({
    OUTCOME_PULL_SKIPPED_NO_API_KEY,
    OUTCOME_PULL_FAILED,
    OUTCOME_PROFILE_APPLIED,
    OUTCOME_PROFILE_SKIPPED,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_MISSING,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_INVALID,
    OUTCOME_PROFILE_REJECTED_CHECKSUM_MISMATCH,
    OUTCOME_PROFILE_REJECTED_VALIDATION,
    OUTCOME_PROFILE_DOWNLOAD_FAILED,
    OUTCOME_PROFILE_APPLY_FAILED,
})


def build_registry_pull_record(
    *,
    outcome: str,
    registry_url: str,
    model_id: Optional[str] = None,
    profile_version: Optional[str] = None,
    download_url: Optional[str] = None,
    checksum: Optional[str] = None,
    error_type: Optional[str] = None,
    error_reason: Optional[str] = None,
) -> dict:
    """Build one governance row for a registry pull/apply decision."""
    if outcome not in REGISTRY_PROFILE_PULL_OUTCOMES:
        raise ValueError(
            f"registry pull outcome {outcome!r} is outside the closed taxonomy"
        )
    checksum_present = bool(checksum)
    return {
        "event_type": EVENT_REGISTRY_PROFILE_PULL,
        "risk_level": RISK_LEVEL,
        "source": "registry_client",
        "outcome": outcome,
        "model_id": model_id,
        "profile_version": str(profile_version) if profile_version is not None else None,
        "registry_origin": hosted_origin(registry_url),
        "download_origin": hosted_origin(download_url) if download_url else None,
        "checksum_present": checksum_present,
        "checksum_algorithm": "sha256" if checksum_present else None,
        "checksum_expected": f"sha256:{checksum.lower()}" if checksum_present else None,
        "error_type": error_type,
        "error_reason": error_reason,
    }


def _receipt_log_path(writer: Any) -> Optional[Path]:
    log_path = getattr(writer, "log_path", None)
    if log_path is None:
        return None
    try:
        return Path(log_path)
    except TypeError:
        return None


def _receipt_landed(log_path: Path, decision_id: str) -> bool:
    try:
        raw = log_path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, OSError):
        return False

    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("decision_id") == decision_id:
            return True
    return False


async def _durable_receipt_status(
    writer: Any,
    *,
    decision_id: str,
    receipt_status: str,
) -> str:
    if receipt_status != RECEIPT_ENQUEUED:
        return receipt_status

    log_path = _receipt_log_path(writer)
    if log_path is None:
        logger.error(
            "Registry pull receipt cannot be verified durable: no log_path on "
            "audit writer for decision_id=%s",
            decision_id,
        )
        return RECEIPT_UNAVAILABLE

    if _receipt_landed(log_path, decision_id):
        return RECEIPT_ENQUEUED

    queue = getattr(writer, "_queue", None)
    if queue is None:
        logger.error(
            "Registry pull receipt did not land durably: decision_id=%s "
            "log_path=%s",
            decision_id, log_path,
        )
        return RECEIPT_UNAVAILABLE
    queue_full = getattr(queue, "full", None)
    if callable(queue_full) and queue_full():
        logger.error(
            "Registry pull receipt did not enqueue: audit queue full for "
            "decision_id=%s log_path=%s",
            decision_id, log_path,
        )
        return RECEIPT_UNAVAILABLE
    queue_join = getattr(queue, "join", None)
    if not callable(queue_join):
        logger.error(
            "Registry pull receipt cannot be verified durable: audit queue has "
            "no join() for decision_id=%s log_path=%s",
            decision_id, log_path,
        )
        return RECEIPT_UNAVAILABLE

    loop = asyncio.get_running_loop()
    deadline = loop.time() + DURABLE_RECEIPT_TIMEOUT_SECONDS
    join_task = asyncio.create_task(queue_join())
    while loop.time() < deadline:
        await asyncio.sleep(DURABLE_RECEIPT_POLL_SECONDS)
        if _receipt_landed(log_path, decision_id):
            join_task.cancel()
            with suppress(asyncio.CancelledError):
                await join_task
            return RECEIPT_ENQUEUED
        if join_task.done():
            break

    if not join_task.done():
        join_task.cancel()
        with suppress(asyncio.CancelledError):
            await join_task
        logger.error(
            "Registry pull receipt did not land before response: decision_id=%s "
            "log_path=%s",
            decision_id, log_path,
        )
        return RECEIPT_UNAVAILABLE

    if _receipt_landed(log_path, decision_id):
        return RECEIPT_ENQUEUED

    logger.error(
        "Registry pull receipt did not land durably: decision_id=%s "
        "log_path=%s",
        decision_id, log_path,
    )
    return RECEIPT_UNAVAILABLE


async def emit_registry_pull(
    writer: Any,
    *,
    outcome: str,
    registry_url: str,
    model_id: Optional[str] = None,
    profile_version: Optional[str] = None,
    download_url: Optional[str] = None,
    checksum: Optional[str] = None,
    error_type: Optional[str] = None,
    error_reason: Optional[str] = None,
) -> dict:
    """
    Emit one registry governance receipt and return the caller-visible identity.

    ``emit`` never raises; a missing or failing rail is surfaced as
    ``receipt_status`` so the pull decision does not get relabelled as success.
    """
    decision_id = str(uuid.uuid4())
    record = build_registry_pull_record(
        outcome=outcome,
        registry_url=registry_url,
        model_id=model_id,
        profile_version=profile_version,
        download_url=download_url,
        checksum=checksum,
        error_type=error_type,
        error_reason=error_reason,
    )
    record["decision_id"] = decision_id
    receipt_status = await emit(writer, record)
    receipt_status = await _durable_receipt_status(
        writer,
        decision_id=decision_id,
        receipt_status=receipt_status,
    )
    return {
        "decision_id": decision_id,
        "receipt_status": receipt_status,
        "outcome": outcome,
        "model_id": model_id,
    }
