"""
Decision journal — the ordering fix for F20's two unreceipted decisions.

THE PROBLEM THIS EXISTS TO SOLVE
--------------------------------
Two governed decisions are taken on the encrypted-profile path:

  D1  **which key was loaded, and from where** — hosted endpoint, on-disk cache
      (whose revocation state is unknown by construction), or nothing at all;
  D2  **whether a profile authenticated** — the AES-256-GCM tag either verified
      or it did not, and "it did not" is a tamper signal.

Neither left a record. The root cause was *ordering*, not a forgotten call site:
``proxy/main.py`` built the ``AuditWriter`` at step 3, after the profile router
(step 1) and the key load (step 1b), so no writer existed at the moment either
decision was taken. You cannot receipt a decision against a writer that does not
exist yet.

THE FIX, AND WHAT IT DOES *NOT* CLAIM
-------------------------------------
The structural half is in ``proxy/main.py``: the ``AuditWriter`` is constructed
and started at **step 0**, before anything that decides. That is the real fix —
a writer now exists at decision time, and it is passed into ``ProfileRouter``
and ``DynamicKeyLoader`` at construction.

There is a residual gap and this module refuses to hide it. ``ProfileRouter.
load_all()`` is **synchronous** (it is called from ``__init__``) while
``AuditWriter.write()`` is a coroutine, so a per-profile authentication decision
cannot be handed to the rail at the instant it is taken. It is journalled here —
stamped with ``decided_at`` at the true moment of decision — and flushed as soon
as the caller is back in async context. Every record therefore carries:

    decision_id           which decision this row describes
    decided_at            when the decision was actually taken
    decided_at_source     whether that timestamp is the decision or the write
    receipt_enqueued_at   when it was handed to the rail
    receipt_deferred_ms   the gap, in milliseconds, as a number

so a reader can see the deferral rather than being told it did not happen. A
record written late and *labelled* late is honest; a record written late and
presented as timely is the thing this codebase exists to refuse.

IDENTITY IS STAMPED ON THE PATH, NOT BY THE CALLER
--------------------------------------------------
The first version of this module stamped ``decision_id``/``decided_at`` only in
``DecisionJournal.record``. ``proxy/main.py`` has four posture branches that
emit **directly** — they never touch a journal — so in production every one of
them wrote a hash-chained row with no decision identity and
``receipt_deferred_ms: null``: the deferral mechanism existed and the production
path never reached it. Codex reproduced this on PR #34, inside the branch built
to fix it, and the covering test could not see it because it asserted row
existence, outcome and count.

``stamp_decision`` now runs inside ``emit`` — the single door to the rail — so a
fifth branch cannot get it wrong whether it journals, emits directly, uses a
builder or hands over an inline dict. ``tests/test_f20_profile_key_floor.py``
INV-9/INV-10 fail the build if a record reaches a writer by any other route.

``receipt_status`` is ``"enqueued"``, never ``"recorded"``
---------------------------------------------------------
``AuditWriter`` is fire-and-forget: ``write()`` returns as soon as the record is
queued and drops silently when the queue is full, and its background
``_writer_loop`` catches and logs *every* exception raised while redacting,
chaining, serialising or appending. So this module can honestly say a record was
HANDED to the rail. It cannot say the record LANDED. That gap is proved against a
real filesystem failure — not a monkeypatch — in
``proxy/tests/test_f20_profile_key_receipts.py::test_disclosed_rail_gap_*``.

CLOSED TAXONOMIES
-----------------
Every ``event_type``, ``key_source`` and ``outcome`` below is a member of a
frozen set, and the record builders assert membership. An open-vocabulary string
field is how a governance stream drifts into unqueryability one caller at a time;
``tests/test_f20_profile_key_floor.py`` (floor tier) fails the build if a
production call site emits a literal outside these sets.

NEVER IN A RECORD
-----------------
No key bytes, no plaintext profile, no ciphertext. A key appears only as
``key_id()`` — a domain-separated, truncated SHA-256 that correlates two records
as "same key" without being the key. Ciphertext appears only as a full SHA-256,
which is what makes a tamper record evidence. The floor test enforces this with
an **allow-list** of permitted value expressions in the record builders (DONE.md
v1.22 clause 5: name what may pass, never what may not — a deny-list lets the
next field anyone adds sail through).
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed taxonomies
# ---------------------------------------------------------------------------

#: D1 — the key-load decision.
EVENT_KEY_LOAD = "profile_key.load"
#: D2 — the per-profile authentication decision.
EVENT_PROFILE_AUTH = "profile.authentication"
#: Decisions the journal could not hold. Its own bucket, never silence.
EVENT_JOURNAL_OVERFLOW = "profile.decision_journal_overflow"

EVENT_TYPES = frozenset({
    EVENT_KEY_LOAD, EVENT_PROFILE_AUTH, EVENT_JOURNAL_OVERFLOW,
})

#: Where the key came from. ``none`` is a real answer, not an absence.
KEY_SOURCE_HOSTED = "hosted_endpoint"
KEY_SOURCE_CACHE = "local_cache"
KEY_SOURCE_PRECONFIGURED = "preconfigured"
KEY_SOURCE_NONE = "none"

KEY_SOURCES = frozenset({
    KEY_SOURCE_HOSTED, KEY_SOURCE_CACHE, KEY_SOURCE_PRECONFIGURED, KEY_SOURCE_NONE,
})

#: What the key load concluded.
KEY_LOAD_NO_ENCRYPTED_PROFILES = "no_encrypted_profiles"
KEY_LOAD_KEY_PRECONFIGURED = "key_preconfigured"
KEY_LOAD_NO_API_KEY = "no_api_key"
KEY_LOAD_FETCHED_HOSTED = "fetched_from_hosted"
KEY_LOAD_FETCHED_CACHE = "fetched_from_cache"
KEY_LOAD_UNAVAILABLE = "unavailable"
KEY_LOAD_LOADER_ERROR = "loader_error"

KEY_LOAD_OUTCOMES = frozenset({
    KEY_LOAD_NO_ENCRYPTED_PROFILES, KEY_LOAD_KEY_PRECONFIGURED, KEY_LOAD_NO_API_KEY,
    KEY_LOAD_FETCHED_HOSTED, KEY_LOAD_FETCHED_CACHE, KEY_LOAD_UNAVAILABLE,
    KEY_LOAD_LOADER_ERROR,
})

#: Whether the key we are about to trust has been checked against its issuer in
#: this process. A cached key is served precisely when the issuer was
#: unreachable, so nothing revoked it *to us*: the honest value is "unknown".
REVOCATION_CHECKED = "checked_with_issuer"
REVOCATION_UNKNOWN_OFFLINE = "unknown_offline_cache"
REVOCATION_NOT_APPLICABLE = "not_applicable"

REVOCATION_STATES = frozenset({
    REVOCATION_CHECKED, REVOCATION_UNKNOWN_OFFLINE, REVOCATION_NOT_APPLICABLE,
})

#: What the GCM tag said about one profile.
PROFILE_AUTH_AUTHENTICATED = "authenticated"
PROFILE_AUTH_FAILED = "authentication_failed"
PROFILE_AUTH_MALFORMED = "malformed_ciphertext"
PROFILE_AUTH_NOT_YAML = "decrypted_not_yaml"
PROFILE_AUTH_EMPTY = "decrypted_empty"
PROFILE_AUTH_LICENSE_REJECTED = "license_rejected"
PROFILE_AUTH_NO_MODEL_ID = "no_model_id"
PROFILE_AUTH_SKIPPED_NO_KEY = "skipped_no_key"
PROFILE_AUTH_PLAINTEXT_REJECTED = "plaintext_rejected_by_policy"
PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN = "plaintext_allowed_explicit_opt_in"

PROFILE_AUTH_OUTCOMES = frozenset({
    PROFILE_AUTH_AUTHENTICATED, PROFILE_AUTH_FAILED, PROFILE_AUTH_MALFORMED,
    PROFILE_AUTH_NOT_YAML, PROFILE_AUTH_EMPTY, PROFILE_AUTH_LICENSE_REJECTED,
    PROFILE_AUTH_NO_MODEL_ID, PROFILE_AUTH_SKIPPED_NO_KEY,
    PROFILE_AUTH_PLAINTEXT_REJECTED, PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
})

#: Why plaintext YAML required an explicit opt-in. ``development_plaintext`` is
#: the one posture where plaintext does not require an opt-in.
PLAINTEXT_POLICY_DEVELOPMENT = "development_plaintext"
PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY = "encrypted_profile_policy"
PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY = "trusted_decryption_key"
PLAINTEXT_POLICY_ENCRYPTED_INVENTORY = "encrypted_profile_inventory"

PLAINTEXT_POLICY_STATES = frozenset({
    PLAINTEXT_POLICY_DEVELOPMENT, PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY,
    PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY, PLAINTEXT_POLICY_ENCRYPTED_INVENTORY,
})

#: risk_level carried by these rows. Deliberately NOT one of LOW/MEDIUM/HIGH/
#: UNKNOWN: a governance decision must never be countable as a detection verdict
#: by ``AuditWriter.read_recent``'s summary.
RISK_LEVEL = "GOVERNANCE"

#: What we can honestly say about a handed-off record. See the module docstring.
RECEIPT_ENQUEUED = "enqueued"
RECEIPT_UNAVAILABLE = "unavailable"

#: Where a record's ``decided_at`` came from. A timestamp with no provenance
#: claims to be the moment of decision while possibly being the moment of
#: writing, and those are different facts.
DECIDED_AT_JOURNALLED = "journalled_at_decision"
DECIDED_AT_AT_EMIT = "stamped_at_emit"
#: The record arrived already carrying a ``decided_at`` that nobody labelled.
#: Its own bucket, never folded into either of the two above (DONE.md v1.19
#: clause (d): an outcome that observed nothing is not a success).
DECIDED_AT_UNLABELLED = "decided_at_unlabelled"

DECIDED_AT_SOURCES = frozenset({
    DECIDED_AT_JOURNALLED, DECIDED_AT_AT_EMIT, DECIDED_AT_UNLABELLED,
})


# ---------------------------------------------------------------------------
# Non-reversible identifiers
# ---------------------------------------------------------------------------

#: Domain separation, so a profile-key id can never collide with, or be replayed
#: as, a digest computed over the same bytes anywhere else in the estate.
_KEY_ID_DOMAIN = b"arkheia.profile-key-id.v1|"


def key_id(key: bytes) -> str:
    """
    A correlation handle for a key — **not** the key, and not reversible to it.

    Truncated to 16 hex characters (64 bits): enough to say "these two records
    describe the same key", far too little to be a verification oracle for one.
    """
    return hashlib.sha256(_KEY_ID_DOMAIN + key).hexdigest()[:16]


def ciphertext_id(blob: bytes) -> str:
    """
    Full SHA-256 of a profile's ciphertext.

    This is the evidence in a tamper record: it pins exactly which bytes failed
    to authenticate, so a later investigator can compare the file on disk against
    what the proxy actually read. A hash of ciphertext discloses nothing — the
    ciphertext itself is never recorded.
    """
    return hashlib.sha256(blob).hexdigest()


def hosted_origin(url: str) -> Optional[str]:
    """
    Scheme + host of the key endpoint, with any userinfo, path, query and
    fragment dropped.

    The origin is the fact worth auditing ("which issuer did we trust?"); the
    rest of a URL is where a credential would hide if one were ever embedded.
    """
    if not url:
        return None
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if not parts.scheme or not parts.hostname:
            return None
        host = parts.hostname
        if parts.port:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://{host}"
    except Exception:
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


#: Emitted in place of a field that does not resolve to a known label. Two
#: distinct sentinels, because "the record said something we do not recognise"
#: and "the record said nothing" are different faults.
UNRESOLVED_LABEL = "<outside-taxonomy>"
UNRESOLVED_ID = "<non-uuid>"


def _label(value: Any, vocabulary: frozenset) -> str:
    """
    Resolve a record field to **the vocabulary member it equals**, returning this
    module's own constant rather than the string that was read from the record.

    This is a real sanitiser, not a formality, and it exists for a specific
    reason. A decision record is built from arguments that include key material
    (as ``key_id(key)``), so every field read out of one carries that lineage.
    Handing any of them to a log sink means a future edit that adds a
    less-careful field is one line from writing it to stdout — and static
    analysis is right to refuse to distinguish the safe fields from the unsafe
    ones inside a single dict. (CodeQL ``py/clear-text-logging-sensitive-data``
    flagged exactly this on ``proxy/audit/decision_journal.py`` at PR #34, two
    HIGH.)

    Resolving through the vocabulary makes the guarantee structural: what reaches
    the log is a module-level literal that was compiled into this file, or a
    sentinel. No value from the record itself can be logged, whatever anyone
    later adds to it.
    """
    for member in vocabulary:
        if member == value:
            return member
    return UNRESOLVED_LABEL


def _uuid_label(value: Any) -> str:
    """
    Re-render a decision id from its parsed 128 bits.

    Same discipline as ``_label`` for a field with no fixed vocabulary: the
    string that reaches the log is produced by ``uuid.UUID.__str__`` from the
    integer it parsed, so it is a canonical UUID or the sentinel — never the
    bytes that were in the record.
    """
    try:
        return str(uuid.UUID(hex=str(value)))
    except (AttributeError, TypeError, ValueError):
        return UNRESOLVED_ID


# ---------------------------------------------------------------------------
# Decision identity — minted in ONE place, on the ONE path to the rail
# ---------------------------------------------------------------------------

def stamp_decision(record: dict, *, source: str) -> dict:
    """
    Give a record the identity of the decision it describes: ``decision_id``,
    ``decided_at``, and the provenance of that timestamp. Returns a new dict and
    never mutates the caller's.

    WHY THIS IS A FUNCTION AND NOT FOUR CALL SITES
    ----------------------------------------------
    ``DecisionJournal.record`` used to be the only code that stamped a record, so
    every branch that emitted **directly** — and ``proxy/main.py`` has four —
    wrote a hash-chained row with no ``decision_id``, no ``decided_at`` and
    ``receipt_deferred_ms: null``. That is worse than no row: it looks like
    evidence, it counts, and it cannot be tied to the decision it describes.
    (Reproduced by Codex on PR #34, inside the very branch built to fix it.)

    Adding a fifth call site would have fixed the four branches that exist and
    nothing about the fifth. So the guarantee is placed on the **chokepoint**:
    ``emit()`` is the only door to the rail (``tests/test_f20_profile_key_floor.py``
    INV-9/INV-10 fail the build if a record reaches a writer any other way), and
    ``emit()`` stamps. A future branch may journal or emit directly, may build its
    record with a builder or as an inline dict — the row lands stamped either way,
    because the stamping is on the path rather than in the caller.

    ``source`` says which. A record stamped by the journal carries the true moment
    of decision; one stamped at emit was decided and handed over in the same
    breath. A record that arrives with a ``decided_at`` nobody labelled is marked
    unlabelled rather than being assigned either claim.
    """
    if source not in DECIDED_AT_SOURCES:
        raise ValueError(f"decided_at source {source!r} is outside the closed taxonomy")
    out = dict(record)
    if not out.get("decision_id"):
        out["decision_id"] = str(uuid.uuid4())
    if not out.get("decided_at"):
        out["decided_at"] = _now().isoformat()
        out["decided_at_source"] = source
    elif not out.get("decided_at_source"):
        out["decided_at_source"] = DECIDED_AT_UNLABELLED
    return out


# ---------------------------------------------------------------------------
# The journal
# ---------------------------------------------------------------------------

class DecisionJournal:
    """
    A bounded, in-memory hold for decisions taken where ``await`` is not
    available, drained to the audit rail at the first opportunity.

    Bounded on purpose: an unbounded buffer on a startup path is a memory bug
    waiting for a directory with a hundred thousand files in it. Bounded means
    entries *can* be lost — so the loss is counted and emitted as its own record
    (``EVENT_JOURNAL_OVERFLOW``) rather than folded into the successes. A
    decision nobody observed is its own bucket, never a pass.
    """

    DEFAULT_CAPACITY = 512

    def __init__(self, capacity: int = DEFAULT_CAPACITY):
        if capacity < 1:
            raise ValueError("DecisionJournal capacity must be >= 1")
        self._entries: deque[dict] = deque(maxlen=capacity)
        self._dropped = 0

    @property
    def capacity(self) -> int:
        return self._entries.maxlen or 0

    @property
    def pending(self) -> int:
        return len(self._entries)

    @property
    def dropped(self) -> int:
        return self._dropped

    def record(self, record: dict) -> str:
        """
        Journal a decision, stamping ``decided_at`` at the true moment it was
        taken. Returns the ``decision_id`` the caller can quote.
        """
        entry = stamp_decision(record, source=DECIDED_AT_JOURNALLED)
        if len(self._entries) == self._entries.maxlen:
            # deque silently evicts the oldest; count it rather than lose it.
            self._dropped += 1
        self._entries.append(entry)
        return entry["decision_id"]

    def drain(self) -> tuple[list[dict], int]:
        """Take everything held, plus the count of anything evicted. Resets both."""
        entries = list(self._entries)
        self._entries.clear()
        dropped, self._dropped = self._dropped, 0
        return entries, dropped


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

async def emit(writer: Any, record: dict) -> str:
    """
    Hand one journalled record to the audit rail.

    Stamps the deferral so the timing gap is *in the record*, then returns
    ``"enqueued"`` or ``"unavailable"``. Never raises: a receipt failure must not
    turn a successful startup into a crashed one, and must not turn a detected
    tamper into an exception that hides it. It is never silent either — an
    unavailable rail is logged at ERROR naming the decision that went unrecorded.
    """
    # The chokepoint. A record that never passed through a journal is stamped
    # HERE, so no path to the rail — present or future — can write a row without
    # the identity of the decision it describes.
    out = stamp_decision(record, source=DECIDED_AT_AT_EMIT)
    enqueued_at = _now()
    out["receipt_enqueued_at"] = enqueued_at.isoformat()
    out["receipt_deferred_ms"] = _deferral_ms(out.get("decided_at"), enqueued_at)
    out["receipt_status"] = RECEIPT_ENQUEUED

    # Log labels are RESOLVED THROUGH THE TAXONOMY, never read straight out of
    # the record — see _label()/_uuid_label(). A record can carry a key-derived
    # field, so nothing read from it goes to a log sink unresolved.
    event_label = _label(out.get("event_type"), EVENT_TYPES)
    outcome_label = _label(out.get("outcome"), KEY_LOAD_OUTCOMES | PROFILE_AUTH_OUTCOMES)
    id_label = _uuid_label(out.get("decision_id"))

    if writer is None:
        logger.error(
            "F20 decision NOT RECEIPTED (no audit writer at emit time): "
            "event_type=%s decision_id=%s outcome=%s",
            event_label, id_label, outcome_label,
        )
        return RECEIPT_UNAVAILABLE

    try:
        await writer.write(out)
    except Exception as exc:
        logger.error(
            "F20 decision NOT RECEIPTED (audit write raised %s): "
            "event_type=%s decision_id=%s outcome=%s",
            type(exc).__name__, event_label, id_label, outcome_label,
        )
        return RECEIPT_UNAVAILABLE

    return RECEIPT_ENQUEUED


def build_key_load_record(
    *,
    outcome: str,
    key_source: str,
    revocation_state: str,
    key: Optional[bytes] = None,
    hosted_url: Optional[str] = None,
    encrypted_profile_count: int = 0,
    http_status: Optional[int] = None,
    error_type: Optional[str] = None,
) -> dict:
    """
    D1 — the record for "which key was loaded, and from where".

    Every value below is either a literal, a plain scalar argument, or a call to
    one of the non-reversible helpers above. That is not a coincidence: the floor
    test allow-lists exactly those forms, so a future field that carries ``key``
    or ``plaintext`` straight into the record fails the build.
    """
    if outcome not in KEY_LOAD_OUTCOMES:
        raise ValueError(f"key-load outcome {outcome!r} is outside the closed taxonomy")
    if key_source not in KEY_SOURCES:
        raise ValueError(f"key source {key_source!r} is outside the closed taxonomy")
    if revocation_state not in REVOCATION_STATES:
        raise ValueError(f"revocation state {revocation_state!r} is outside the closed taxonomy")
    return {
        "event_type": EVENT_KEY_LOAD,
        "risk_level": RISK_LEVEL,
        "source": "profile_key_loader",
        "outcome": outcome,
        "key_source": key_source,
        "revocation_state": revocation_state,
        "key_id": key_id(key) if key else None,
        "key_length_bytes": len(key) if key else None,
        "hosted_origin": hosted_origin(hosted_url) if hosted_url else None,
        "encrypted_profile_count": encrypted_profile_count,
        "http_status": http_status,
        "error_type": error_type,
    }


def build_profile_auth_record(
    *,
    outcome: str,
    profile_name: Optional[str] = None,
    ciphertext: Optional[bytes] = None,
    key: Optional[bytes] = None,
    error_type: Optional[str] = None,
    skipped_profile_names: Optional[list] = None,
    plaintext_profile_names: Optional[list] = None,
    plaintext_opt_in_env: Optional[str] = None,
    plaintext_policy_state: Optional[str] = None,
) -> dict:
    """
    D2 — the record for "did this profile authenticate?".

    ``outcome == PROFILE_AUTH_FAILED`` is the tamper signal: AES-GCM refused the
    tag, which means the bytes on disk are not the bytes that were sealed, or the
    key is not the key they were sealed with. ``ciphertext_sha256`` pins which
    bytes were rejected; ``key_id`` pins which key rejected them. Neither is
    recoverable to the value it describes.
    """
    if outcome not in PROFILE_AUTH_OUTCOMES:
        raise ValueError(f"profile-auth outcome {outcome!r} is outside the closed taxonomy")
    if plaintext_policy_state is not None and plaintext_policy_state not in PLAINTEXT_POLICY_STATES:
        raise ValueError(
            f"plaintext policy state {plaintext_policy_state!r} is outside the closed taxonomy"
        )
    return {
        "event_type": EVENT_PROFILE_AUTH,
        "risk_level": RISK_LEVEL,
        "source": "profile_router",
        "outcome": outcome,
        "profile_name": profile_name,
        "ciphertext_sha256": ciphertext_id(ciphertext) if ciphertext else None,
        "ciphertext_bytes": len(ciphertext) if ciphertext else None,
        "key_id": key_id(key) if key else None,
        "error_type": error_type,
        "skipped_profile_names": sorted(skipped_profile_names) if skipped_profile_names else None,
        "skipped_count": len(skipped_profile_names) if skipped_profile_names else 0,
        "plaintext_profile_names": sorted(plaintext_profile_names) if plaintext_profile_names else None,
        "plaintext_count": len(plaintext_profile_names) if plaintext_profile_names else 0,
        "plaintext_opt_in_env": plaintext_opt_in_env,
        "plaintext_policy_state": plaintext_policy_state,
    }


def _deferral_ms(decided_at: Optional[str], enqueued_at: datetime) -> Optional[float]:
    """Milliseconds between the decision and its hand-off, or None if unknown."""
    if not decided_at:
        return None
    try:
        decided = datetime.fromisoformat(decided_at)
    except (TypeError, ValueError):
        return None
    return round((enqueued_at - decided).total_seconds() * 1000.0, 3)


async def flush_journal(journal: DecisionJournal, writer: Any) -> list[tuple[str, str]]:
    """
    Drain a journal to the rail. Returns ``[(decision_id, receipt_status), ...]``.

    Any evictions are emitted as a single overflow record so a reader learns that
    decisions were taken which no row describes — the count is named, never
    summarised away.
    """
    entries, dropped = journal.drain()
    results: list[tuple[str, str]] = []
    for entry in entries:
        results.append((entry["decision_id"], await emit(writer, entry)))

    if dropped:
        # Stamped through the same one function as every other record — an
        # inline dict is exactly the shape that used to escape identity.
        overflow = stamp_decision({
            "event_type": EVENT_JOURNAL_OVERFLOW,
            "risk_level": RISK_LEVEL,
            "source": "profile_decision_journal",
            "dropped_decisions": dropped,
            "journal_capacity": journal.capacity,
        }, source=DECIDED_AT_JOURNALLED)
        logger.error(
            "F20 decision journal overflowed: %d decision(s) were taken and are "
            "described by no audit row (capacity=%d)", dropped, journal.capacity,
        )
        results.append((overflow["decision_id"], await emit(writer, overflow)))

    return results
