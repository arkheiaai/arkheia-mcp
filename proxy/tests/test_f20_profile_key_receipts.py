"""
F20 / D1 — **which key was loaded, and from where**, as a record on the rail.

WHAT WAS WRONG
--------------
``DynamicKeyLoader.fetch_key()`` chooses between three sources — the hosted
endpoint, an on-disk cache, or nothing — and the choice decides what this
process will decrypt customer profiles with. The cache branch is the sharp one:
it is taken *precisely* when the issuer was unreachable, so nothing has confirmed
the key is still valid. That was a single ``logger.warning`` on an unchained log.

Root cause was ordering, not omission: ``proxy/main.py`` built the ``AuditWriter``
at step 3 and loaded the key at step 1b, so at the moment of the decision there
was no writer. The fix moves the writer to step 0 (see ``proxy/main.py``) and
hands it to the loader at construction; ``fetch_key`` is async, so D1 is now
receipted *at* decision time and ``receipt_deferred_ms`` proves that rather than
asserting it.

WHAT THESE TESTS DRIVE — nothing is mocked
------------------------------------------
* the REAL ``DynamicKeyLoader.fetch_key()``,
* over REAL ``httpx`` against a REAL socket served by ``http.server``,
* writing through the REAL ``AuditWriter`` (via the consolidated
  ``proxy/tests/_receipt_probe.py``), read back off disk,
* looked up BY THE ``decision_id`` the loader was handed, with a fabricated id
  proven to find nothing.

There is no ``respx``, no ``AsyncMock`` and no recording stub anywhere in this
file. A receipt suite that asserts on the dict a helper *returns* proves what the
flow hands the audit layer and nothing about what reaches disk.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

import pytest

from proxy.audit.decision_journal import (
    EVENT_JOURNAL_OVERFLOW,
    EVENT_KEY_LOAD,
    KEY_LOAD_FETCHED_CACHE,
    KEY_LOAD_FETCHED_HOSTED,
    KEY_LOAD_KEY_PRECONFIGURED,
    KEY_LOAD_LOADER_ERROR,
    KEY_LOAD_NO_API_KEY,
    KEY_LOAD_NO_ENCRYPTED_PROFILES,
    KEY_LOAD_UNAVAILABLE,
    KEY_SOURCE_CACHE,
    KEY_SOURCE_HOSTED,
    KEY_SOURCE_NONE,
    KEY_SOURCE_PRECONFIGURED,
    RECEIPT_ENQUEUED,
    RECEIPT_UNAVAILABLE,
    REVOCATION_CHECKED,
    REVOCATION_NOT_APPLICABLE,
    REVOCATION_UNKNOWN_OFFLINE,
    RISK_LEVEL,
    DecisionJournal,
    build_key_load_record,
    emit,
    flush_journal,
    key_id,
)
from proxy.crypto.profile_crypto import DynamicKeyLoader
from proxy.tests._receipt_probe import (
    ReceiptProbe,
    assert_decision_identity,
    contains,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# ``key_server`` (a real HTTP server on a real socket, not a transport mock) and
# ``isolated_key_cache`` live in ``proxy/tests/conftest.py`` — the startup
# ordering suite drives the same endpoint, and one definition cannot drift from
# itself.
# ---------------------------------------------------------------------------


@pytest.fixture
async def probe(tmp_path):
    """A live ``AuditWriter`` over a temp log, driven through the production API."""
    p = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await p.start()
    try:
        yield p
    finally:
        await p.stop()


def _key() -> bytes:
    return secrets.token_bytes(32)


# ---------------------------------------------------------------------------
# D1 — the three sources, each with its own row
# ---------------------------------------------------------------------------

async def test_hosted_key_load_is_receipted_with_its_source(probe, key_server):
    """A key fetched from the issuer is recorded as such, with the issuer named."""
    key = _key()
    key_server.serve(key)

    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    got = await loader.fetch_key()
    assert got == key, "control: the loader must actually have fetched the key"

    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)

    assert row["event_type"] == EVENT_KEY_LOAD
    assert row["outcome"] == KEY_LOAD_FETCHED_HOSTED
    assert row["key_source"] == KEY_SOURCE_HOSTED
    assert row["revocation_state"] == REVOCATION_CHECKED
    assert row["key_id"] == key_id(key)
    # Pinned INDEPENDENTLY of the helper, not merely equal to it. `key_id(key)`
    # alone cannot discriminate a change to key_id's construction — both sides of
    # the comparison move together, which is exactly the "green by construction"
    # failure DONE.md v1.15 clause 3 names.
    assert row["key_id"] == hashlib.sha256(
        b"arkheia.profile-key-id.v1|" + key
    ).hexdigest()[:16]
    assert row["key_length_bytes"] == 32
    assert row["http_status"] == 200
    assert row["hosted_origin"] == key_server.url
    assert row["risk_level"] == RISK_LEVEL
    assert loader.last_receipt_status == RECEIPT_ENQUEUED


async def test_cached_key_records_that_revocation_is_UNKNOWN(probe, key_server):
    """
    The sharp case. A cached key is served exactly when the issuer could not be
    reached, so nothing revoked it *to us*. The record must say so — recording
    ``checked_with_issuer`` here would be a false attestation about a live key.
    """
    key = _key()
    # Populate the cache the way production does: one successful fetch.
    key_server.serve(key)
    warmup = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    assert await warmup.fetch_key() == key

    # Now the issuer is down.
    key_server.fail(503)
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    got = await loader.fetch_key()
    assert got == key, "control: the cache branch must actually have been taken"

    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)

    assert row["outcome"] == KEY_LOAD_FETCHED_CACHE
    assert row["key_source"] == KEY_SOURCE_CACHE
    assert row["revocation_state"] == REVOCATION_UNKNOWN_OFFLINE
    assert row["key_id"] == key_id(key)
    assert row["http_status"] == 503

    # And the two rows agree it is the SAME key — which is the whole point of a
    # correlation id that is not the key.
    warm_row = probe.require(warmup.last_decision_id)
    assert warm_row["key_id"] == row["key_id"]
    assert warm_row["revocation_state"] == REVOCATION_CHECKED


async def test_no_key_at_all_is_a_decision_and_is_receipted(probe, key_server):
    key_server.fail(503)
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    assert await loader.fetch_key() is None

    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)
    assert row["outcome"] == KEY_LOAD_UNAVAILABLE
    assert row["key_source"] == KEY_SOURCE_NONE
    assert row["revocation_state"] == REVOCATION_NOT_APPLICABLE
    assert row["key_id"] is None
    assert row["key_length_bytes"] is None


async def test_a_rejected_api_key_records_the_status_that_rejected_it(probe, key_server):
    key_server.fail(401)
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    assert await loader.fetch_key() is None

    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)
    assert row["outcome"] == KEY_LOAD_UNAVAILABLE
    assert row["http_status"] == 401, (
        "401 (this deployment is not entitled) and 503 (the issuer is down) are "
        "different governance facts; a record that collapses them is not evidence"
    )


# ---------------------------------------------------------------------------
# What must never be in a record
# ---------------------------------------------------------------------------

async def test_no_key_material_reaches_disk_in_any_encoding(probe, key_server):
    """
    The key must not appear raw, base64, hex, or as its own bare SHA-256.

    Paired with a positive control: the domain-separated ``key_id`` IS present,
    so this is an assertion about *which* bytes landed, not a test that passes
    because the probe was pointed at an empty file.
    """
    key = _key()
    key_server.serve(key)
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()

    blob = probe.raw_bytes()
    assert blob, "control: something must have been written for this to mean anything"
    assert contains(blob, key_id(key)), "control: the correlation id IS expected on disk"

    assert key not in blob
    assert base64.b64encode(key) not in blob
    assert key.hex().encode() not in blob
    assert hashlib.sha256(key).hexdigest().encode() not in blob, (
        "an undomain-separated digest of the key is a verification oracle for it; "
        "key_id() exists to be a correlation handle instead"
    )


async def test_a_fabricated_decision_id_finds_nothing(probe, key_server):
    """The vacuity guard: without it every read-back assertion could pass by luck."""
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()

    assert probe.find(loader.last_decision_id) is not None       # positive control
    assert probe.find("00000000-0000-0000-0000-000000000000") is None


# ---------------------------------------------------------------------------
# The ordering fix, and the honest account of the gap that is left
# ---------------------------------------------------------------------------

async def test_the_decision_carries_its_own_timing_gap(probe, key_server):
    """
    Every record states when the decision was taken, when it was handed to the
    rail, and the gap between them as a number.

    For D1 the gap is ~0 because ``fetch_key`` is async and the writer now exists
    before the loader is constructed. That is the ordering fix, measured rather
    than asserted — and the same field is what makes D2's genuinely deferred
    records honest instead of quietly late.
    """
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)

    assert row["decided_at"]
    assert row["receipt_enqueued_at"]
    assert isinstance(row["receipt_deferred_ms"], (int, float))
    assert row["receipt_deferred_ms"] >= 0
    assert row["receipt_deferred_ms"] < 1000, (
        "D1 is receipted in the same coroutine as the decision; a gap of seconds "
        "would mean the writer is no longer being handed in at construction"
    )


async def test_status_is_enqueued_never_recorded(probe, key_server):
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "test-api-key", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()
    row = probe.require(loader.last_decision_id)

    assert row["receipt_status"] == RECEIPT_ENQUEUED
    assert row["receipt_status"] != "recorded", (
        "AuditWriter cannot acknowledge a landing; claiming one would be the "
        "exact overclaim this repo exists to refuse"
    )


async def test_disclosed_rail_gap_enqueued_does_not_mean_landed(probe, key_server, tmp_path):
    """
    Prove the overclaim we are refusing is a REAL possibility — with a real
    filesystem failure, not a patched exception.

    ``AuditWriter._writer_loop`` catches every exception raised while appending.
    Make the log file unwritable at the OS level and the record is silently lost
    while ``emit`` still returns ``"enqueued"``. That is why the word is
    ``enqueued``.
    """
    key_server.serve(_key())
    control = DynamicKeyLoader(key_server.url, "k", audit_writer=probe.writer)
    await control.fetch_key()
    await probe.writer._queue.join()
    assert probe.find(control.last_decision_id) is not None, "control must land first"

    log = Path(probe.log_path)
    original_mode = log.stat().st_mode
    os.chmod(log, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    try:
        # Verify the environment ACTUALLY denies the write. If it does not
        # (running as root), nothing was observed — and an unobserved proof must
        # fail loudly, never pass quietly.
        denied = False
        try:
            with open(log, "a", encoding="utf-8"):
                pass
        except PermissionError:
            denied = True
        assert denied, (
            "this environment did not deny an append to a 0444 file, so the "
            "fire-and-forget gap was NOT demonstrated. Not observed is not a pass."
        )

        key_server.serve(_key())
        lost = DynamicKeyLoader(key_server.url, "k", audit_writer=probe.writer)
        await lost.fetch_key()
        await probe.writer._queue.join()

        assert lost.last_receipt_status == RECEIPT_ENQUEUED, (
            "the rail reported success — that is the whole disclosure"
        )
    finally:
        os.chmod(log, stat.S_IMODE(original_mode))

    assert probe.find(lost.last_decision_id) is None, (
        "nothing landed, yet the status was 'enqueued'"
    )


async def test_emit_reports_unavailable_when_there_is_no_writer():
    """
    The pre-fix world, exercised: a decision taken with no writer in existence.

    This is what every F20 decision used to be. ``emit`` returns
    ``"unavailable"`` and logs at ERROR; it does not raise, because a receipt
    failure must never turn a detected tamper into a crash that hides it.
    """
    record = build_key_load_record(
        outcome=KEY_LOAD_UNAVAILABLE,
        key_source=KEY_SOURCE_NONE,
        revocation_state=REVOCATION_NOT_APPLICABLE,
    )
    assert await emit(None, record) == RECEIPT_UNAVAILABLE


async def test_the_failure_log_can_only_contain_taxonomy_members_and_a_uuid(caplog):
    """
    Found by CodeQL on PR #34 (two HIGH, py/clear-text-logging-sensitive-data).

    A decision record is built from arguments that include key material, so
    every field read out of one carries that lineage. ``emit``'s ERROR path now
    resolves its labels THROUGH the taxonomy, so what reaches the log is a
    module-level literal or a sentinel — never a value from the record. Drive it
    with a record whose fields have been overwritten with hostile content and
    assert none of it appears.
    """
    import logging as _logging

    poisoned = build_key_load_record(
        outcome=KEY_LOAD_UNAVAILABLE,
        key_source=KEY_SOURCE_NONE,
        revocation_state=REVOCATION_NOT_APPLICABLE,
    )
    poisoned["outcome"] = "SENTINEL-OUTCOME-9f2a"
    poisoned["event_type"] = "SENTINEL-EVENT-9f2a"
    poisoned["decision_id"] = "SENTINEL-ID-9f2a"

    with caplog.at_level(_logging.ERROR):
        assert await emit(None, poisoned) == RECEIPT_UNAVAILABLE

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert logged, "control: the failure MUST be logged loudly, never swallowed"
    assert "SENTINEL-OUTCOME-9f2a" not in logged
    assert "SENTINEL-EVENT-9f2a" not in logged
    assert "SENTINEL-ID-9f2a" not in logged
    assert "<outside-taxonomy>" in logged and "<non-uuid>" in logged


async def test_the_failure_log_still_names_a_legitimate_decision(caplog):
    """
    Control row for the test above: a well-formed record must still be
    identifiable in the log, or the sanitiser has traded a real capability for a
    clean scan result.
    """
    import logging as _logging

    record = build_key_load_record(
        outcome=KEY_LOAD_UNAVAILABLE,
        key_source=KEY_SOURCE_NONE,
        revocation_state=REVOCATION_NOT_APPLICABLE,
    )
    journal = DecisionJournal()
    decision_id = journal.record(record)
    entries, _dropped = journal.drain()

    with caplog.at_level(_logging.ERROR):
        assert await emit(None, entries[0]) == RECEIPT_UNAVAILABLE

    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert decision_id in logged
    assert KEY_LOAD_UNAVAILABLE in logged
    assert "profile_key.load" in logged


async def test_a_rail_that_REFUSES_the_write_is_reported_as_unavailable():
    """
    Found by the mutation campaign (M08 survived the first run — a real hole in
    this suite, not an equivalent mutant).

    ``emit`` accepts any duck-typed rail. A rail object whose ``write`` raises is
    a reachable state — a stopped writer, a swapped implementation, a queue
    replaced by something that is not one — and the contract is that ``emit``
    neither raises nor claims success. Note this is a REAL object raising a REAL
    exception, not a monkeypatch of production code: the object under test is the
    parameter, so substituting it is the test, not a way around it.
    """
    class _RefusingRail:
        async def write(self, record):
            raise OSError("no space left on device")

    record = build_key_load_record(
        outcome=KEY_LOAD_UNAVAILABLE,
        key_source=KEY_SOURCE_NONE,
        revocation_state=REVOCATION_NOT_APPLICABLE,
    )
    assert await emit(_RefusingRail(), record) == RECEIPT_UNAVAILABLE


async def test_a_loader_whose_rail_refuses_reports_unavailable_end_to_end(key_server):
    """The same refusal, seen through the loader the caller actually uses."""
    class _RefusingRail:
        async def write(self, record):
            raise OSError("no space left on device")

    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "k", audit_writer=_RefusingRail())
    assert await loader.fetch_key() is not None, "the key load itself must still succeed"
    assert loader.last_receipt_status == RECEIPT_UNAVAILABLE


async def test_a_loader_with_no_rail_REPORTS_unavailable_rather_than_assuming(key_server):
    """
    The loader must report the status the rail actually gave it. A caller that
    hardcodes ``"enqueued"`` is asserting an outcome it never observed — the same
    class of overclaim as saying ``"recorded"``.
    """
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "k")          # no writer attached
    assert await loader.fetch_key() is not None
    assert loader.last_receipt_status == RECEIPT_UNAVAILABLE
    assert loader.decision_journal.pending == 1, (
        "with nowhere to write it, the decision is HELD rather than discarded"
    )


# ---------------------------------------------------------------------------
# Journal mechanics — the not-observed bucket
# ---------------------------------------------------------------------------

async def test_journal_overflow_is_its_own_record_not_a_silence(probe):
    """
    A bounded journal can lose decisions. The loss gets a row naming the count —
    it is never folded into the successes and never merely logged.
    """
    journal = DecisionJournal(capacity=2)
    for _ in range(5):
        journal.record(build_key_load_record(
            outcome=KEY_LOAD_UNAVAILABLE,
            key_source=KEY_SOURCE_NONE,
            revocation_state=REVOCATION_NOT_APPLICABLE,
        ))
    assert journal.dropped == 3

    await flush_journal(journal, probe.writer)
    await probe.writer._queue.join()

    overflow = [r for r in probe.rows() if r["event_type"] == EVENT_JOURNAL_OVERFLOW]
    assert len(overflow) == 1
    assert overflow[0]["dropped_decisions"] == 3
    assert overflow[0]["journal_capacity"] == 2
    # And the survivors are still there, so the overflow row supplements rather
    # than replaces.
    assert len([r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]) == 2


async def test_no_overflow_row_when_nothing_was_dropped(probe):
    """Negative control for the row above: it must not fire spuriously."""
    journal = DecisionJournal(capacity=8)
    journal.record(build_key_load_record(
        outcome=KEY_LOAD_UNAVAILABLE,
        key_source=KEY_SOURCE_NONE,
        revocation_state=REVOCATION_NOT_APPLICABLE,
    ))
    await flush_journal(journal, probe.writer)
    await probe.writer._queue.join()
    assert [r for r in probe.rows() if r["event_type"] == EVENT_JOURNAL_OVERFLOW] == []


# ---------------------------------------------------------------------------
# The taxonomy is closed
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,kwargs", [
    ("outcome", {"outcome": "made_up", "key_source": KEY_SOURCE_NONE,
                 "revocation_state": REVOCATION_NOT_APPLICABLE}),
    ("key_source", {"outcome": KEY_LOAD_UNAVAILABLE, "key_source": "somewhere",
                    "revocation_state": REVOCATION_NOT_APPLICABLE}),
    ("revocation_state", {"outcome": KEY_LOAD_UNAVAILABLE, "key_source": KEY_SOURCE_NONE,
                          "revocation_state": "probably_fine"}),
])
async def test_a_value_outside_the_taxonomy_is_refused(field, kwargs):
    with pytest.raises(ValueError, match="closed taxonomy"):
        build_key_load_record(**kwargs)


async def test_the_taxonomy_admits_its_own_members(probe):
    """
    Control row for the table above (DONE.md v1.15 clause 5): a table whose every
    row asserts failure cannot discriminate.
    """
    record = build_key_load_record(
        outcome=KEY_LOAD_FETCHED_HOSTED,
        key_source=KEY_SOURCE_HOSTED,
        revocation_state=REVOCATION_CHECKED,
        key=b"\x01" * 32,
    )
    assert record["outcome"] == KEY_LOAD_FETCHED_HOSTED


# ---------------------------------------------------------------------------
# Ties to the tamper-evident chain, and does not pollute the detection summary
# ---------------------------------------------------------------------------

async def test_the_row_is_inside_the_hash_chain_as_written(probe, key_server):
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "k", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()

    row = probe.require(loader.last_decision_id)
    assert probe.recompute_this_hash(row) == row["this_hash"]
    assert probe.verify_chain()["ok"] is True


async def test_governance_rows_are_not_counted_as_detection_verdicts(probe, key_server):
    """
    ``AuditWriter.read_recent`` buckets rows by ``risk_level``. A governance
    decision that landed in LOW would inflate the count of screened responses
    with events that screened nothing.
    """
    key_server.serve(_key())
    loader = DynamicKeyLoader(key_server.url, "k", audit_writer=probe.writer)
    await loader.fetch_key()
    await probe.writer._queue.join()

    summary = probe.writer.read_recent()["summary"]
    assert summary["LOW"] == 0 and summary["MEDIUM"] == 0 and summary["HIGH"] == 0
    assert summary["UNKNOWN"] == 0
    assert summary.get(RISK_LEVEL) == 1


# ---------------------------------------------------------------------------
# Step 1b's own branches — including the one that fires in production TODAY
# ---------------------------------------------------------------------------

async def test_a_deployment_with_no_encrypted_profiles_still_leaves_a_row(probe, tmp_path):
    """
    0 of 60 profiles in this repo are encrypted, so THIS is the branch that runs
    in production. A control whose only evidence appears on the exotic paths is
    indistinguishable, from the outside, from a control that is switched off.
    """
    from proxy.main import _record_key_load_posture
    from proxy.router.profile_router import ProfileRouter

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    router = ProfileRouter(str(profiles), audit_writer=probe.writer)

    status = await _record_key_load_posture(probe.writer, profiles, router)
    await probe.writer._queue.join()

    assert status == RECEIPT_ENQUEUED
    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_NO_ENCRYPTED_PROFILES
    assert rows[0]["encrypted_profile_count"] == 0
    assert_decision_identity(rows[0], branch=KEY_LOAD_NO_ENCRYPTED_PROFILES)
    assert probe.require(rows[0]["decision_id"]) == rows[0]
    assert probe.find("00000000-0000-4000-8000-000000000000") is None, (
        "vacuity guard: if a fabricated id also found a row, the lookup above "
        "would prove nothing about identity"
    )


async def test_encrypted_profiles_without_an_api_key_leave_a_row(probe, tmp_path, monkeypatch):
    from proxy.main import _record_key_load_posture
    from proxy.router.profile_router import ProfileRouter

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "a.yaml.enc").write_bytes(b"x" * 64)
    (profiles / "b.yaml.enc").write_bytes(b"y" * 64)
    monkeypatch.delenv("ARKHEIA_API_KEY", raising=False)

    router = ProfileRouter(str(profiles), audit_writer=probe.writer)
    await _record_key_load_posture(probe.writer, profiles, router)
    await probe.writer._queue.join()

    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_NO_API_KEY
    assert rows[0]["encrypted_profile_count"] == 2
    assert rows[0]["key_source"] == KEY_SOURCE_NONE
    assert_decision_identity(rows[0], branch=KEY_LOAD_NO_API_KEY)


async def test_a_preconfigured_key_is_recorded_as_such(probe, tmp_path):
    from proxy.main import _record_key_load_posture
    from proxy.router.profile_router import ProfileRouter

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "a.yaml.enc").write_bytes(b"x" * 64)
    key = _key()

    router = ProfileRouter(str(profiles), decryption_key=key, audit_writer=probe.writer)
    await _record_key_load_posture(probe.writer, profiles, router)
    await probe.writer._queue.join()

    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_KEY_PRECONFIGURED
    assert rows[0]["key_source"] == KEY_SOURCE_PRECONFIGURED
    assert rows[0]["key_id"] == key_id(key)
    assert_decision_identity(rows[0], branch=KEY_LOAD_KEY_PRECONFIGURED)


async def test_a_loader_that_explodes_leaves_a_row_naming_the_failure(
    probe, tmp_path, monkeypatch
):
    from proxy import main as proxy_main
    from proxy.router.profile_router import ProfileRouter

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "a.yaml.enc").write_bytes(b"x" * 64)
    monkeypatch.setenv("ARKHEIA_API_KEY", "some-key")

    import proxy.crypto.profile_crypto as pc

    class _Exploding(pc.DynamicKeyLoader):
        def __init__(self, *a, **kw):
            raise RuntimeError("boom")

    monkeypatch.setattr(pc, "DynamicKeyLoader", _Exploding)

    router = ProfileRouter(str(profiles), audit_writer=probe.writer)
    status = await proxy_main._record_key_load_posture(probe.writer, profiles, router)
    await probe.writer._queue.join()

    assert status == RECEIPT_ENQUEUED
    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_LOADER_ERROR
    assert rows[0]["error_type"] == "RuntimeError"
    assert_decision_identity(rows[0], branch=KEY_LOAD_LOADER_ERROR)
    assert "boom" not in json.dumps(rows[0]), (
        "an exception MESSAGE can echo whatever the code choked on; only the "
        "class name is structural enough to record"
    )
