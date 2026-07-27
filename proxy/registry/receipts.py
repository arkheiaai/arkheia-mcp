"""
Receipts for registry pull -> validate -> apply decisions.

The registry client decides whether downloaded profile bytes are allowed to
replace the local profile set. Those decisions need the same hash-chained audit
rail as detection/profile-auth decisions, especially the refusal cases: missing
checksums, mismatched checksums, and smoke-test failures.
"""
from __future__ import annotations

import uuid
from typing import Any, Optional

from proxy.audit.decision_journal import RISK_LEVEL, emit, hosted_origin

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
    return {
        "decision_id": decision_id,
        "receipt_status": receipt_status,
        "outcome": outcome,
        "model_id": model_id,
    }
