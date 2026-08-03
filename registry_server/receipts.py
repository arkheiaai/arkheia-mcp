"""
Auth-decision receipts for the Arkheia Registry Server.

WHY
---
``require_auth`` makes three distinct decisions per request — accept this API
key, reject it (401), or refuse to serve at all because the server is
unprovisioned (503, the fail-closed branch the flow is named for). Before this
module, ``registry_server`` contained no logger at all: not one of those
decisions left a record anywhere.

For a server whose job is distributing detection profiles to customers, "which
key pulled what, when, and which keys were rejected" is exactly what a customer
or an auditor asks for. And a REFUSAL is the record that matters most: a denied
request nobody can see later is indistinguishable from one that never happened
— there is no way to tell a credential-stuffing run from a quiet afternoon.

WHAT IS RECORDED, AND WHAT IS NOT
---------------------------------
Never the key. The record carries a ``key_fingerprint``: the first 12 hex
characters of the SHA-256 of the presented credential. That is enough to
correlate "these 400 rejections were all the same wrong key" or "this customer
key pulled these profiles" across records, and it is not reversible — the key
space is 2^128.

Redaction is belt AND braces: ``AuditWriter._writer_loop`` runs every record
through ``proxy.audit.redactor.redact`` before anything touches disk, so even a
future field that accidentally carried a raw ``ak_live_…`` key would be
redacted on the way out. (Gap, NOT fixed here because
``proxy/audit/redactor.py`` belongs to PR #16: the redactor's pattern is
``ak_live_[a-f0-9]{20,}`` only, so a key minted with ``generate_key("ak_test")``
— a shape this module's own docstring advertises — would NOT be redacted by
that second layer. The first layer never emits a raw key either way.)

FAILURE POSTURE
---------------
Fail-open on the RECEIPT, never on the DECISION. A receipt that cannot be
written must not turn a refusal into an acceptance, and must not turn one into
a 500 either — the standing ruling is that a receipt failure may not block the
halt. So every write is wrapped, and a failure is LOGGED at error level rather
than swallowed: fail-open, never fail-silent.

The writer itself is non-blocking (``AuditWriter`` enqueues and returns), so a
receipt costs the request nothing on the hot path.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from proxy.audit.writer import (
    AUDIT_WRITE_ENQUEUED,
    AUDIT_WRITE_QUEUE_FULL,
    AuditWriter,
)

logger = logging.getLogger(__name__)

EVENT_TYPE = "registry_auth_decision"

#: Header carrying the receipt id back to the caller. A denied caller can quote
#: this to support; an auditor can use it to find the exact row. The id is a
#: fresh uuid4 per request and is derived from nothing about the credential, so
#: surfacing it to an unauthenticated caller discloses nothing.
RECEIPT_HEADER = "X-Arkheia-Receipt"

DECISION_ACCEPTED = "accepted"
DECISION_REJECTED = "rejected"
DECISION_UNPROVISIONED = "unprovisioned"

_writer: Optional[AuditWriter] = None


def default_log_path() -> str:
    """
    Repo-relative default, mirroring ``proxy.config._AuditSettings.log_path``.

    Deliberately a real path rather than ``None``: receipts are ON by default.
    A guard whose default is off is not a guard, and this fleet has shipped
    that exact defect before (``ARKHEIA_REQUIRE_LICENSE`` defaults false).
    """
    return os.environ.get(
        "ARKHEIA_REGISTRY_AUDIT_LOG",
        str(Path(__file__).parent.parent / "registry_audit.jsonl"),
    )


def key_fingerprint(credential: Optional[str]) -> Optional[str]:
    """Stable, non-reversible identifier for a presented credential."""
    if not credential:
        return None
    return "sha256:" + hashlib.sha256(credential.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]


def build_record(
    *,
    receipt_id: str,
    decision: str,
    outcome_status: int,
    method: str,
    path: str,
    client_ip: Optional[str],
    credential: Optional[str],
    keys_configured: int,
) -> dict:
    """The decision record. Pure — no I/O — so it can be asserted directly."""
    if decision not in (DECISION_ACCEPTED, DECISION_REJECTED, DECISION_UNPROVISIONED):
        raise ValueError(f"unknown auth decision: {decision!r}")
    return {
        "event_type": EVENT_TYPE,
        "receipt_id": receipt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "outcome_status": outcome_status,
        "method": method,
        "path": path,
        "client_ip": client_ip,
        "credential_presented": credential is not None,
        "key_fingerprint": key_fingerprint(credential),
        "keys_configured": keys_configured,
    }


async def start(log_path: Optional[str] = None) -> AuditWriter:
    """Start the receipt writer. Called from the app lifespan."""
    global _writer
    writer = AuditWriter(log_path=log_path or default_log_path())
    await writer.start()
    _writer = writer
    logger.info("Registry auth receipts -> %s", writer.log_path)
    return writer


async def stop() -> None:
    """Flush and stop the receipt writer. Called from the app lifespan."""
    global _writer
    if _writer is not None:
        await _writer.stop()
        _writer = None


def get_writer() -> Optional[AuditWriter]:
    return _writer


async def emit(record: dict) -> None:
    """
    Write one decision record.

    Never raises: the caller is on the auth path and the decision must stand
    whatever happens here. Never silent either — an unwritten receipt is
    logged at error level, because "no record" and "no request" must not look
    the same in the operator's logs any more than they do in the audit file.
    """
    writer = _writer
    if writer is None:
        logger.error(
            "Registry auth receipt NOT written (writer not started): %s %s decision=%s "
            "receipt_id=%s — this decision is UNRECORDED",
            record.get("method"), record.get("path"),
            record.get("decision"), record.get("receipt_id"),
        )
        return
    try:
        write_outcome = await writer.write(record)
    except Exception as exc:  # pragma: no cover — defensive; write() is itself guarded
        logger.error(
            "Registry auth receipt FAILED to enqueue (%s): decision=%s receipt_id=%s "
            "— this decision is UNRECORDED",
            exc, record.get("decision"), record.get("receipt_id"),
        )
        return
    write_status = getattr(write_outcome, "receipt", write_outcome)
    if write_status == AUDIT_WRITE_QUEUE_FULL:
        logger.error(
            "Registry auth receipt DROPPED (audit queue full): decision=%s receipt_id=%s "
            "— this decision is UNRECORDED",
            record.get("decision"), record.get("receipt_id"),
        )
    elif write_status not in (None, AUDIT_WRITE_ENQUEUED):
        logger.error(
            "Registry auth receipt returned unknown audit write status %s: "
            "decision=%s receipt_id=%s — this decision is UNRECORDED",
            write_status, record.get("decision"), record.get("receipt_id"),
        )


def new_receipt_id() -> str:
    return uuid.uuid4().hex
