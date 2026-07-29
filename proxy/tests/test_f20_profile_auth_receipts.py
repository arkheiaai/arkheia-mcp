"""
F20 / D2 — **whether a profile authenticated**, as a record on the rail.

WHAT WAS WRONG
--------------
``ProfileRouter.load_all()`` decrypts every ``*.yaml.enc`` under one bare
``except Exception``. AES-256-GCM refusing a tag is not an error like any other:
it means the bytes on disk are not the bytes that were sealed, or the key is not
the key they were sealed with. That is a **tamper signal**, and it was one
``logger.error`` line on an unchained log — indistinguishable, to any consumer,
from an expired licence or a YAML typo.

This repo already owns a hash-chained audit rail. The signal had somewhere to go
and did not go there, because ``proxy/main.py`` built the writer at step 3 and
the router decided at step 1.

WHAT THESE TESTS DRIVE
----------------------
The REAL ``ProfileRouter`` over REAL ciphertext produced by the REAL
``encrypt_profile``, writing through the REAL ``AuditWriter`` via the
consolidated ``proxy/tests/_receipt_probe.py``, read back off disk and looked up
by the ``decision_id`` the journal minted. Nothing is mocked.

THE DELIBERATE GAP, STATED RATHER THAN HIDDEN
---------------------------------------------
``load_all()`` is synchronous — it is called from ``__init__`` — while the rail
is async. So a per-profile decision cannot be handed over in the same statement
in which it is taken. It is journalled with its true ``decided_at`` and flushed
as soon as the caller is back in async context, and every row carries
``receipt_deferred_ms``. ``test_the_deferral_is_recorded_not_hidden`` asserts the
field is present and finite; that is the honest form of "we could not write it at
decision time", as opposed to writing it late and calling it timely.
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
from datetime import date, timedelta

import pytest
import yaml

from proxy.audit.decision_journal import (
    EVENT_PROFILE_AUTH,
    PROFILE_AUTH_AUTHENTICATED,
    PROFILE_AUTH_EMPTY,
    PROFILE_AUTH_FAILED,
    PROFILE_AUTH_LICENSE_REJECTED,
    PROFILE_AUTH_MALFORMED,
    PROFILE_AUTH_NOT_YAML,
    PROFILE_AUTH_NO_MODEL_ID,
    PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
    PROFILE_AUTH_PLAINTEXT_REJECTED,
    PROFILE_AUTH_SKIPPED_NO_KEY,
    PLAINTEXT_POLICY_DEVELOPMENT,
    PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY,
    PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY,
    PLAINTEXT_POLICY_UNMARKED_PLAINTEXT_DIRECTORY,
    RECEIPT_ENQUEUED,
    RISK_LEVEL,
    build_profile_auth_record,
    key_id,
)
from proxy.crypto.profile_crypto import encrypt_profile
from proxy.router.profile_router import ProfileRouter
from proxy.tests._receipt_probe import ReceiptProbe, contains

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def probe(tmp_path):
    p = ReceiptProbe(tmp_path / "audit.jsonl", id_field="decision_id")
    await p.start()
    try:
        yield p
    finally:
        await p.stop()


@pytest.fixture
def profiles(tmp_path):
    d = tmp_path / "profiles"
    d.mkdir()
    return d


def _key() -> bytes:
    return secrets.token_bytes(32)


def _seal(profiles, name: str, key: bytes, body: dict | None = None) -> bytes:
    """Write a REAL encrypted profile using the production encryptor."""
    doc = body if body is not None else {
        "model": name, "version": "1.0", "thresholds": {"cohens_d": 0.5},
    }
    blob = encrypt_profile(yaml.dump(doc).encode("utf-8"), key, name)
    (profiles / f"{name}.yaml.enc").write_bytes(blob)
    return blob


def _rows(probe, outcome: str | None = None) -> list[dict]:
    rows = [r for r in probe.rows() if r.get("event_type") == EVENT_PROFILE_AUTH]
    if outcome is not None:
        rows = [r for r in rows if r["outcome"] == outcome]
    return rows


async def _build(
    profiles,
    probe,
    key=None,
    *,
    encrypted_profile_policy: bool | None = None,
    plaintext_development_mode: bool | None = None,
) -> ProfileRouter:
    router = ProfileRouter(
        str(profiles),
        decryption_key=key,
        audit_writer=probe.writer,
        encrypted_profile_policy=encrypted_profile_policy,
        plaintext_development_mode=plaintext_development_mode,
    )
    await router.flush_decision_journal()
    await probe.writer._queue.join()
    return router


# ---------------------------------------------------------------------------
# The happy path — a profile that authenticates says so
# ---------------------------------------------------------------------------

async def test_an_authenticated_profile_leaves_a_row(profiles, probe):
    key = _key()
    blob = _seal(profiles, "test-model", key)

    router = await _build(profiles, probe, key)
    assert router.loaded_count == 1, "control: the profile must actually have loaded"

    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_AUTHENTICATED
    assert row["profile_name"] == "test-model"
    assert row["ciphertext_sha256"] == hashlib.sha256(blob).hexdigest()
    assert row["ciphertext_bytes"] == len(blob)
    assert row["key_id"] == key_id(key)
    assert row["error_type"] is None
    assert row["risk_level"] == RISK_LEVEL
    assert row["receipt_status"] == RECEIPT_ENQUEUED
    # Looked up BY the id the journal minted, and a fabricated one finds nothing.
    assert probe.require(row["decision_id"])["profile_name"] == "test-model"
    assert probe.find("00000000-0000-0000-0000-000000000000") is None


# ---------------------------------------------------------------------------
# THE TAMPER SIGNAL
# ---------------------------------------------------------------------------

async def test_a_tampered_profile_is_recorded_as_an_AUTHENTICATION_FAILURE(profiles, probe):
    """
    Flip one byte of real ciphertext. AES-GCM refuses the tag. The row must name
    that specifically — not "failed to load" — and must pin WHICH bytes were
    rejected and WHICH key rejected them, because that is the whole forensic
    value of a tamper record.
    """
    key = _key()
    good = _seal(profiles, "test-model", key)
    path = profiles / "test-model.yaml.enc"
    tampered = bytearray(good)
    tampered[-1] ^= 0x01           # last byte of the GCM tag
    path.write_bytes(bytes(tampered))

    router = await _build(profiles, probe, key)
    assert router.loaded_count == 0

    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_FAILED
    assert row["error_type"] == "InvalidTag"
    assert row["profile_name"] == "test-model"
    assert row["key_id"] == key_id(key)
    assert row["ciphertext_sha256"] == hashlib.sha256(bytes(tampered)).hexdigest()
    assert row["ciphertext_sha256"] != hashlib.sha256(good).hexdigest(), (
        "the record must pin the bytes that were REJECTED, which is the evidence "
        "an investigator compares against the file still sitting on disk"
    )


async def test_the_WRONG_KEY_is_also_an_authentication_failure_and_says_which_key(
    profiles, probe
):
    sealed_with = _key()
    opened_with = _key()
    _seal(profiles, "test-model", sealed_with)

    await _build(profiles, probe, opened_with)

    rows = _rows(probe)
    assert len(rows) == 1
    assert rows[0]["outcome"] == PROFILE_AUTH_FAILED
    assert rows[0]["error_type"] == "InvalidTag"
    assert rows[0]["key_id"] == key_id(opened_with)
    assert rows[0]["key_id"] != key_id(sealed_with), (
        "the record names the key that FAILED to open it — which is what turns "
        "'a profile did not load' into 'this deployment holds the wrong key'"
    )


async def test_a_truncated_file_is_MALFORMED_not_a_tamper(profiles, probe):
    """
    Discrimination, not a catch-all. Too short to contain a nonce and a tag never
    reached the cipher at all; filing it as a tamper would cry wolf.
    """
    key = _key()
    (profiles / "test-model.yaml.enc").write_bytes(b"\x00" * 8)

    await _build(profiles, probe, key)

    rows = _rows(probe)
    assert len(rows) == 1
    assert rows[0]["outcome"] == PROFILE_AUTH_MALFORMED
    assert rows[0]["error_type"] == "ValueError"


async def test_an_expired_LICENCE_is_never_confused_with_a_tamper(profiles, probe):
    """
    The profile authenticated — the tag verified — and was then refused on
    content. Two different facts, two different outcomes. Before this change both
    were a `continue` and neither reached any consumer.
    """
    key = _key()
    yesterday = (date.today() - timedelta(days=1)).isoformat()
    _seal(profiles, "test-model", key, {
        "model": "test-model", "version": "1.0",
        "license": {"customer_id": "acme", "valid_until": yesterday},
    })

    await _build(profiles, probe, key)

    rows = _rows(probe)
    assert len(rows) == 1
    assert rows[0]["outcome"] == PROFILE_AUTH_LICENSE_REJECTED
    assert rows[0]["outcome"] != PROFILE_AUTH_FAILED


async def test_decrypted_but_empty_and_decrypted_but_unusable_are_distinct(profiles, probe):
    key = _key()
    (profiles / "empty.yaml.enc").write_bytes(encrypt_profile(b"\n", key, "empty"))
    _seal(profiles, "nomodel", key, {"version": "1.0", "thresholds": {}})

    await _build(profiles, probe, key)

    assert len(_rows(probe, PROFILE_AUTH_EMPTY)) == 1
    assert len(_rows(probe, PROFILE_AUTH_NO_MODEL_ID)) == 1
    assert _rows(probe, PROFILE_AUTH_FAILED) == []


async def test_decrypted_but_not_yaml_is_its_own_outcome(profiles, probe):
    key = _key()
    (profiles / "junk.yaml.enc").write_bytes(
        encrypt_profile(b"{[not: yaml: at all", key, "junk")
    )

    await _build(profiles, probe, key)

    rows = _rows(probe)
    assert len(rows) == 1
    assert rows[0]["outcome"] == PROFILE_AUTH_NOT_YAML


# ---------------------------------------------------------------------------
# The branch where nothing was attempted
# ---------------------------------------------------------------------------

async def test_no_key_records_which_surfaces_went_dark_and_does_not_fake_per_profile_verdicts(
    profiles, probe
):
    for n in ("alpha", "beta", "gamma"):
        (profiles / f"{n}.yaml.enc").write_bytes(b"x" * 64)

    await _build(profiles, probe, key=None)

    rows = _rows(probe)
    assert len(rows) == 1, (
        "no per-profile decision was TAKEN, so emitting three per-profile rows "
        "would record verdicts that never happened"
    )
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_SKIPPED_NO_KEY
    assert row["profile_name"] is None
    assert row["skipped_count"] == 3
    assert row["skipped_profile_names"] == ["alpha.yaml.enc", "beta.yaml.enc",
                                            "gamma.yaml.enc"]


# ---------------------------------------------------------------------------
# Plaintext policy bypasses — file inventory is not the authority
# ---------------------------------------------------------------------------

async def test_plaintext_is_refused_when_enc_was_unlinked_but_key_is_trusted(
    profiles, probe
):
    key = _key()
    _seal(profiles, "legit-model", key)
    (profiles / "legit-model.yaml.enc").unlink()
    (profiles / "attacker.yaml").write_text(
        yaml.dump({"model": "attacker-model", "version": "1.0"}),
        encoding="utf-8",
    )

    router = await _build(profiles, probe, key)

    assert router.loaded_count == 0
    assert router.get("attacker-model") is None
    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert row["skipped_profile_names"] == ["attacker.yaml"]
    assert row["plaintext_policy_state"] == PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY
    assert row["receipt_status"] == RECEIPT_ENQUEUED


async def test_plaintext_is_refused_when_enc_was_renamed_but_policy_is_set(
    profiles, probe
):
    key = _key()
    blob = _seal(profiles, "legit-model", key)
    (profiles / "legit-model.yaml.enc").rename(profiles / "legit-model.yaml.enc.bak")
    assert (profiles / "legit-model.yaml.enc.bak").read_bytes() == blob
    (profiles / "attacker.yaml").write_text(
        yaml.dump({"model": "attacker-model", "version": "1.0"}),
        encoding="utf-8",
    )

    router = await _build(profiles, probe, key=None, encrypted_profile_policy=True)

    assert router.loaded_count == 0
    assert router.get("attacker-model") is None
    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert row["skipped_profile_names"] == ["attacker.yaml"]
    assert row["plaintext_policy_state"] == PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY
    assert row["receipt_status"] == RECEIPT_ENQUEUED


async def test_explicit_plaintext_opt_in_is_receipted(profiles, probe, monkeypatch):
    key = _key()
    (profiles / "migration.yaml").write_text(
        yaml.dump({"model": "migration-model", "version": "1.0"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARKHEIA_ALLOW_PLAINTEXT_PROFILES", "true")

    router = await _build(profiles, probe, key, encrypted_profile_policy=True)

    assert router.loaded_count == 1
    assert router.get("migration-model") is not None
    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN
    assert row["plaintext_profile_names"] == ["migration.yaml"]
    assert row["plaintext_count"] == 1
    assert row["plaintext_opt_in_env"] == "ARKHEIA_ALLOW_PLAINTEXT_PROFILES"
    assert row["plaintext_policy_state"] == PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY
    assert row["receipt_status"] == RECEIPT_ENQUEUED


async def test_unmarked_audited_plaintext_directory_is_rejected_and_receipted(
    profiles, probe, monkeypatch
):
    monkeypatch.delenv("ARKHEIA_ALLOW_PLAINTEXT_PROFILES", raising=False)
    (profiles / "attacker.yaml").write_text(
        yaml.dump({"model": "attacker-model", "version": "1.0"}),
        encoding="utf-8",
    )

    router = await _build(profiles, probe, key=None)

    assert router.loaded_count == 0
    assert router.get("attacker-model") is None
    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert row["skipped_profile_names"] == ["attacker.yaml"]
    assert row["plaintext_policy_state"] == PLAINTEXT_POLICY_UNMARKED_PLAINTEXT_DIRECTORY
    assert row["receipt_status"] == RECEIPT_ENQUEUED


async def test_explicit_plaintext_development_mode_loads_and_is_receipted(
    profiles, probe, monkeypatch
):
    monkeypatch.setenv("ARKHEIA_ALLOW_PLAINTEXT_PROFILES", "true")
    (profiles / "dev.yaml").write_text(
        yaml.dump({"model": "dev-model", "version": "1.0"}),
        encoding="utf-8",
    )

    router = await _build(
        profiles,
        probe,
        key=None,
        plaintext_development_mode=True,
    )

    assert router.loaded_count == 1
    assert router.get("dev-model") is not None
    rows = _rows(probe)
    assert len(rows) == 1
    row = rows[0]
    assert row["outcome"] == PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN
    assert row["plaintext_profile_names"] == ["dev.yaml"]
    assert row["plaintext_policy_state"] == PLAINTEXT_POLICY_DEVELOPMENT
    assert row["plaintext_opt_in_env"] == "ARKHEIA_ALLOW_PLAINTEXT_PROFILES"
    assert row["receipt_status"] == RECEIPT_ENQUEUED


# ---------------------------------------------------------------------------
# Mixed estate — one bad profile among good ones
# ---------------------------------------------------------------------------

async def test_one_tampered_profile_among_many_is_individually_attributable(
    profiles, probe
):
    key = _key()
    _seal(profiles, "good-a", key)
    _seal(profiles, "good-b", key)
    blob = _seal(profiles, "bad", key)
    path = profiles / "bad.yaml.enc"
    corrupt = bytearray(blob)
    corrupt[20] ^= 0xFF
    path.write_bytes(bytes(corrupt))

    router = await _build(profiles, probe, key)
    assert router.loaded_count == 2

    assert {r["profile_name"] for r in _rows(probe, PROFILE_AUTH_AUTHENTICATED)} == {
        "good-a", "good-b"
    }
    failed = _rows(probe, PROFILE_AUTH_FAILED)
    assert len(failed) == 1 and failed[0]["profile_name"] == "bad"
    assert len(_rows(probe)) == 3, "every profile examined leaves exactly one row"


# ---------------------------------------------------------------------------
# What must never reach disk
# ---------------------------------------------------------------------------

async def test_no_plaintext_no_ciphertext_and_no_key_reaches_disk(profiles, probe):
    key = _key()
    secret_marker = "SENTINEL-PROFILE-CONTENT-b4d1f0"
    blob = _seal(profiles, "test-model", key, {
        "model": "test-model", "version": "1.0", "notes": secret_marker,
    })

    await _build(profiles, probe, key)

    raw = probe.raw_bytes()
    assert raw, "control: something must have been written"
    assert contains(raw, hashlib.sha256(blob).hexdigest()), (
        "control: the ciphertext DIGEST is expected on disk"
    )
    assert not contains(raw, secret_marker), "decrypted profile content leaked"
    assert blob not in raw and blob.hex().encode() not in raw, "ciphertext leaked"
    assert key not in raw and key.hex().encode() not in raw, "key material leaked"


# ---------------------------------------------------------------------------
# The ordering fix and the residual gap
# ---------------------------------------------------------------------------

async def test_the_deferral_is_recorded_not_hidden(profiles, probe):
    """
    ``load_all()`` is sync and the rail is async, so D2 is journalled at the
    decision and flushed just after. The gap is a NUMBER in the row. A record
    written late and labelled late is honest; the failure mode this guards
    against is writing it late and presenting it as timely.
    """
    key = _key()
    _seal(profiles, "test-model", key)
    await _build(profiles, probe, key)

    row = _rows(probe)[0]
    assert row["decided_at"] and row["receipt_enqueued_at"]
    assert isinstance(row["receipt_deferred_ms"], (int, float))
    assert row["receipt_deferred_ms"] >= 0
    assert row["decided_at"] <= row["receipt_enqueued_at"], (
        "ISO-8601 UTC timestamps sort lexicographically; a receipt cannot "
        "precede the decision it describes"
    )


async def test_a_router_built_with_no_writer_holds_its_decisions_rather_than_losing_them(
    profiles, probe
):
    """
    The pre-fix world: a decision taken before any writer exists. The journal
    keeps it, so attaching the rail afterwards still records it. Nothing is
    silently dropped just because the ordering was wrong.
    """
    key = _key()
    _seal(profiles, "test-model", key)

    router = ProfileRouter(str(profiles), decryption_key=key)   # no writer at all
    assert router.decision_journal.pending == 1
    assert await router.flush_decision_journal() == []          # nowhere to put it

    router.attach_audit_writer(probe.writer)
    results = await router.flush_decision_journal()
    await probe.writer._queue.join()

    assert [status for _id, status in results] == [RECEIPT_ENQUEUED]
    assert _rows(probe)[0]["outcome"] == PROFILE_AUTH_AUTHENTICATED


async def test_a_scheduled_reload_receipts_its_decisions_too(profiles, probe):
    """
    A registry pull reloads profiles hours after startup. Those authentication
    decisions are as governed as the ones at boot; the router self-schedules a
    flush so they do not depend on anyone remembering to drain the journal.
    """
    key = _key()
    _seal(profiles, "test-model", key)
    router = await _build(profiles, probe, key)
    baseline = len(_rows(probe))

    blob = _seal(profiles, "test-model", key)
    corrupt = bytearray(blob)
    corrupt[-1] ^= 0x01
    (profiles / "test-model.yaml.enc").write_bytes(bytes(corrupt))

    await router.reload()
    # Deliberately NOT calling flush_decision_journal(): the router must schedule
    # its own drain. A test that flushes by hand here would pass against a
    # _schedule_flush() that does nothing, which is the whole behaviour under test.
    await asyncio.sleep(0.05)
    await probe.writer._queue.join()

    assert len(_rows(probe)) == baseline + 1
    assert _rows(probe, PROFILE_AUTH_FAILED)[0]["profile_name"] == "test-model"


async def test_set_decryption_key_receipts_the_reload_it_triggers(profiles, probe):
    key = _key()
    _seal(profiles, "test-model", key)

    router = await _build(profiles, probe, key=None)
    assert _rows(probe, PROFILE_AUTH_SKIPPED_NO_KEY)

    router.set_decryption_key(key)
    await router.flush_decision_journal()
    await probe.writer._queue.join()

    assert _rows(probe, PROFILE_AUTH_AUTHENTICATED)[0]["profile_name"] == "test-model"


# ---------------------------------------------------------------------------
# Chain and taxonomy
# ---------------------------------------------------------------------------

async def test_the_tamper_row_is_inside_the_hash_chain_as_written(profiles, probe):
    """
    The point of putting the tamper signal on THIS rail: the row describing a
    tampered profile is itself tamper-evident.
    """
    key = _key()
    blob = _seal(profiles, "test-model", key)
    corrupt = bytearray(blob)
    corrupt[-1] ^= 0x01
    (profiles / "test-model.yaml.enc").write_bytes(bytes(corrupt))

    await _build(profiles, probe, key)

    row = _rows(probe, PROFILE_AUTH_FAILED)[0]
    assert probe.recompute_this_hash(row) == row["this_hash"]
    assert probe.verify_chain()["ok"] is True


async def test_a_profile_auth_outcome_outside_the_taxonomy_is_refused():
    with pytest.raises(ValueError, match="closed taxonomy"):
        build_profile_auth_record(outcome="probably_fine", profile_name="x")


async def test_the_profile_auth_taxonomy_admits_its_own_members():
    """Control row: a table whose every row asserts failure cannot discriminate."""
    record = build_profile_auth_record(
        outcome=PROFILE_AUTH_AUTHENTICATED, profile_name="x", ciphertext=b"abc",
    )
    assert record["outcome"] == PROFILE_AUTH_AUTHENTICATED
    assert record["ciphertext_sha256"] == hashlib.sha256(b"abc").hexdigest()

    rejected = build_profile_auth_record(
        outcome=PROFILE_AUTH_PLAINTEXT_REJECTED,
        skipped_profile_names=["plain.yaml"],
    )
    assert rejected["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert rejected["skipped_profile_names"] == ["plain.yaml"]


async def test_plaintext_profiles_without_a_writer_keep_the_local_developer_path(profiles):
    """
    Negative control for the whole file. Direct no-writer router use stays usable
    for local unit/developer callers, but audited startup must mark plaintext
    explicitly and receipt it.
    """
    (profiles / "plain.yaml").write_text(yaml.dump({"model": "plain", "version": "1"}))

    router = ProfileRouter(str(profiles), decryption_key=None)
    assert router.loaded_count == 1
    assert router.get("plain") is not None
    assert router.decision_journal.drain() == ([], 0)
