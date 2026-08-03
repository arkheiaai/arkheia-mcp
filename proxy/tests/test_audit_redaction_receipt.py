"""
RECEIPTED — Audit redactor (secret scrub before disk).

Phase 1: what decision are we demanding a record of?
----------------------------------------------------
The redactor decides, per value: *this string matched a known credential shape,
so it does not go to disk.* That is a real decision — it silently changes what
the compliance artefact contains — and it DOES leave a durable record. The record
is the substitution the redactor writes in place of the secret::

    [REDACTED:<first 8 hex of sha256(secret)>]

That token is not a placeholder. It is the receipt: it says *a redaction happened
here*, and its hash prefix says *of which value* — the property
``proxy/audit/redactor.py`` describes as "preserves enough identity to correlate
across records without exposing the secret value". It is written by the
production writer loop into the append-only JSONL, and it is sealed into the
tamper-evident hash chain, so it is durable and non-repudiable in the same sense
every other audit field is.

So this is not an ``n/a``: the decision exists, and its record exists. What was
missing was any proof that the record is real — every existing test of the
redactor calls ``redact()`` directly and asserts on its return value, which is a
test of the function, not of the artefact. ``redact()`` returning a clean dict and
a clean dict reaching disk are different claims: between them sit
``AuditWriter._writer_loop``'s chain fields, its serialisation, its blanket
``except Exception`` (which drops the record and logs), and ``write()``'s silent
drop on a full queue.

Phase 2: what proving it requires
---------------------------------
* **Production write path, never a helper.** ``ReceiptProbe`` drives the real
  ``AuditWriter`` — ``start()``, ``write()``, the background ``_writer_loop`` —
  and reads the artefact back off disk as bytes.
* **Tie the record to its decision.** The token is compared against a sha256
  computed independently in the test, over the specific secret that was written.
  A record containing *some* redaction token is not a record of *this* redaction:
  ``test_the_receipt_identifies_which_secret_was_redacted`` puts two credentials
  in one record and requires the two tokens to differ and each to match its own
  source value.
* **Vacuity guards, both kinds.**
  ``test_fabricated_detection_id_does_not_satisfy_the_read_back`` proves the
  lookup discriminates — a fabricated UUID, and a one-character mutation of the
  real id, both find nothing while the real id finds the row.
  ``test_the_absence_of_plaintext_is_not_vacuous`` proves the absence assertion is
  load-bearing by neutering the redactor at source and showing the plaintext then
  DOES reach disk. Without it, "the secret is not on disk" would pass just as
  happily if nothing were written at all.
* **Every absence assertion is paired with a positive control.** Each check that
  something is missing from the bytes on disk sits next to a check that a
  non-secret marker from the same record IS present, so "not found" can never mean
  "looked at the wrong file".

Not proven here, and not claimed: that a receipt is *guaranteed* to be written.
``AuditWriter.write()` drops on a full queue and ``_writer_loop`` swallows write
exceptions, both with only a log line. This module proves the record produced on
the normal path is genuine; it does not prove the rail is lossless.
"""
from __future__ import annotations

import hashlib
import json
import uuid

import pytest

from proxy.tests._receipt_probe import ReceiptProbe, contains

# ---------------------------------------------------------------------------
# Synthetic credentials.
#
# Assembled from fragments at runtime so no credential-shaped literal ever sits
# in this file: a secret scanner reading the source must not have to decide
# whether these are real, and a test fixture must never be the thing that trips
# the repo's own secret gate. The VALUES are still exact matches for the
# patterns in proxy/audit/redactor.py — that is what is under test.
# ---------------------------------------------------------------------------

_BODY = "A9fK2mQ7xR4tL8vN3wB6yC1zD5eG0hJ" * 2  # 62 chars, matches [A-Za-z0-9._-]{20,}


def _cred(prefix: str, body: str = _BODY) -> str:
    return prefix + body


SECRETS = {
    "anthropic": _cred("sk-" + "ant-"),
    "openai": _cred("sk-" + "proj-"),
    "xai": _cred("xai" + "-", "A9fK2mQ7xR4tL8vN3wB6yC1zD5eG0hJ2"),
    "google": _cred("AIza" + "Sy"),
    "github": _cred("github" + "_pat_", "A9fK2mQ7xR4tL8vN3wB6yC1zD5eG0hJ2"),
    "arkheia": _cred("ak_" + "live_", "0123456789abcdef0123456789abcdef"),
}

# A value that is NOT a credential and must survive verbatim. It is the positive
# control for every "the secret is absent" assertion: if this is missing too,
# the probe was reading the wrong bytes and the absence proves nothing.
MARKER = "receipt-probe-positive-control-7f3a"


def _expected_token(secret: str) -> str:
    """The receipt the redactor is contracted to leave, computed independently."""
    return f"[REDACTED:{hashlib.sha256(secret.encode()).hexdigest()[:8]}]"


def _record(detection_id: str, **extra) -> dict:
    """A realistically-shaped detection audit record."""
    rec = {
        "detection_id": detection_id,
        "timestamp": "2026-07-26T00:00:00+00:00",
        "session_id": MARKER,
        "model_id": "claude-opus-4-8",
        "profile_version": "1.0.0",
        "risk_level": "LOW",
        "confidence": 0.12,
        "features_triggered": [],
        "prompt_hash": "a" * 64,
        "response_hash": "b" * 64,
        "response_length": 42,
        "action_taken": "pass",
        "source": "proxy",
        "error": None,
    }
    rec.update(extra)
    return rec


@pytest.fixture
async def probe(tmp_path):
    p = ReceiptProbe(tmp_path / "audit.jsonl")
    await p.start()
    try:
        yield p
    finally:
        await p.stop()


# ---------------------------------------------------------------------------
# 1. The receipt reaches disk, on the production path, tied to its decision.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("label", sorted(SECRETS))
async def test_redaction_leaves_a_receipt_in_the_durable_record(probe, label):
    """
    Drive the real writer with a record carrying one credential; read the JSONL
    back off disk and require the exact receipt for THAT credential.
    """
    secret = SECRETS[label]
    det_id = str(uuid.uuid4())

    await probe.write(_record(det_id, error=f"upstream rejected key {secret}"))

    raw = probe.raw_bytes()

    # Positive control FIRST: prove we are looking at bytes that contain this
    # record at all, so the absence assertion below cannot pass by vacuity.
    assert contains(raw, MARKER), (
        f"positive control {MARKER!r} absent from {probe.log_path} — the record "
        f"never reached disk, so nothing below would be evidence of redaction"
    )
    assert not contains(raw, secret), (
        f"{label} credential reached disk verbatim in {probe.log_path}"
    )

    row = probe.require(det_id)
    assert row["error"] == f"upstream rejected key {_expected_token(secret)}", (
        f"the durable record does not carry the receipt for the {label} "
        f"credential. got: {row['error']!r}"
    )


async def test_the_receipt_identifies_which_secret_was_redacted(probe):
    """
    A record that says "something was redacted" is not a record of THIS
    redaction. Two credentials in one row must yield two distinct receipts, each
    tied by hash to its own source value.
    """
    a, b = SECRETS["anthropic"], SECRETS["openai"]
    det_id = str(uuid.uuid4())

    await probe.write(_record(det_id, features_triggered=[f"key_a={a}", f"key_b={b}"]))

    row = probe.require(det_id)
    tok_a, tok_b = _expected_token(a), _expected_token(b)

    assert tok_a != tok_b, "test setup: the two credentials must hash differently"
    assert row["features_triggered"] == [f"key_a={tok_a}", f"key_b={tok_b}"], (
        f"receipts are not value-specific: {row['features_triggered']!r}"
    )
    # The discriminating half: each receipt must NOT be the other's.
    assert tok_b not in row["features_triggered"][0]
    assert tok_a not in row["features_triggered"][1]


# ---------------------------------------------------------------------------
# 2. Vacuity guards.
# ---------------------------------------------------------------------------

async def test_fabricated_detection_id_does_not_satisfy_the_read_back(probe):
    """
    Without this, every read-back test above passes even when the id the caller
    was handed has nothing to do with the row that landed — because the probe
    would happily return "the row on disk" for any id at all.
    """
    det_id = str(uuid.uuid4())
    await probe.write(_record(det_id, error=f"key {SECRETS['anthropic']}"))

    # Positive: the real id resolves.
    assert probe.find(det_id) is not None

    # Negative 1: a wholly fabricated UUID resolves to nothing.
    fabricated = str(uuid.uuid4())
    assert fabricated != det_id
    assert probe.find(fabricated) is None, (
        "a fabricated detection_id matched a row — the read-back does not "
        "discriminate, so it ties no record to any decision"
    )

    # Negative 2: a one-character mutation of the REAL id — the near miss a
    # fabricated UUID is too different to catch.
    near_miss = det_id[:-1] + ("0" if det_id[-1] != "0" else "1")
    assert near_miss != det_id
    assert probe.find(near_miss) is None, (
        f"near-miss id {near_miss!r} matched the row for {det_id!r}"
    )


async def test_the_absence_of_plaintext_is_not_vacuous(probe, monkeypatch):
    """
    Source mutation, executed as a test: neuter the redactor at the point the
    writer calls it and show the credential DOES reach disk.

    "The secret is not in the file" is the weakest kind of assertion — it passes
    when nothing was written, when the wrong file was read, and when the record
    was silently dropped. This is the control that makes it mean something.
    """
    secret = SECRETS["anthropic"]

    # Baseline: with redaction live, the credential does not reach disk.
    live_id = str(uuid.uuid4())
    await probe.write(_record(live_id, error=f"key {secret}"))
    assert not contains(probe.raw_bytes(), secret)

    # Mutate the source seam the writer actually calls.
    monkeypatch.setattr("proxy.audit.writer.redact", lambda obj: obj)

    mutated_id = str(uuid.uuid4())
    await probe.write(_record(mutated_id, error=f"key {secret}"))

    raw = probe.raw_bytes()
    assert contains(raw, secret), (
        "with redaction neutered the credential STILL did not reach disk — so "
        "the absence assertions in this module are not observing redaction at "
        "all, and every one of them is vacuous"
    )
    # And the mutated row is the one that carries it: the mutation is scoped to
    # the second write, not a property of the whole file.
    assert secret in probe.require(mutated_id)["error"]
    assert secret not in probe.require(live_id)["error"]


# ---------------------------------------------------------------------------
# 3. The receipt is sealed into the chain, and reachable by the operator.
# ---------------------------------------------------------------------------

async def test_receipt_is_sealed_into_the_hash_chain_over_the_redacted_form(probe):
    """
    Ordering matters and is unobservable from ``redact()`` alone: the writer
    redacts BEFORE it chains, so the hash commits to the redacted record. If it
    chained first, an auditor replaying the chain over the stored (redacted) rows
    would find every hash broken — and a log whose chain never verifies is a log
    nobody can use as evidence.
    """
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for i, det_id in enumerate(ids):
        await probe.write(_record(det_id, error=f"key {SECRETS['anthropic']} #{i}"))

    rows = probe.rows()
    assert len(rows) == 3, f"expected 3 rows on disk, found {len(rows)}"

    for row in rows:
        assert row["this_hash"] == probe.recompute_this_hash(row), (
            f"row seq={row['seq']}: stored this_hash does not reproduce from the "
            f"redacted record on disk — the chain committed to something other "
            f"than what an auditor can read"
        )

    chain = probe.verify_chain()
    # Name the units: a chain report of ok=True over zero records is a
    # verification that verified nothing (DONE.md floor invariant 9).
    assert chain["verified"] == 3, f"verify_chain examined {chain['verified']} rows, expected 3"
    assert chain["breaks"] == [], f"unexpected chain breaks: {chain['breaks']}"
    assert chain["ok"] is True


async def test_chain_verification_can_actually_fail(probe):
    """
    Positive control for the test above. ``verify_chain()`` reporting ok=True is
    only evidence if it is capable of reporting otherwise over this exact
    artefact — so tamper with the receipt itself and require a break.
    """
    det_id = str(uuid.uuid4())
    secret = SECRETS["anthropic"]
    await probe.write(_record(det_id, error=f"key {secret}"))
    assert probe.verify_chain()["ok"] is True

    # Alter one character INSIDE the redaction token — the receipt is what we
    # are proving is protected, so that is what gets tampered with.
    token = _expected_token(secret)
    forged = "[REDACTED:" + ("0" if token[10] != "0" else "1") + token[11:]
    assert forged != token
    text = probe.log_path.read_text()
    assert token in text
    probe.log_path.write_text(text.replace(token, forged))

    chain = probe.verify_chain()
    assert chain["ok"] is False, (
        "editing the redaction receipt on disk did not break the hash chain — "
        "the receipt is not covered by the tamper-evidence it appears to sit under"
    )
    assert chain["verified"] == 1
    assert [b["seq"] for b in chain["breaks"]] == [1]


async def test_receipt_is_reachable_through_the_production_read_path(probe):
    """
    The operator does not read the JSONL; they read ``/audit/log``, which serves
    ``AuditWriter.read_recent()``. A receipt only an internal test can see is not
    a receipt anyone can act on, so prove the same row and the same token come
    back through the surface that is actually exposed.
    """
    secret = SECRETS["arkheia"]
    det_id = str(uuid.uuid4())
    await probe.write(_record(det_id, error=f"registry key {secret}"))

    served = probe.writer.read_recent(limit=50)
    matching = [e for e in served["events"] if e.get("detection_id") == det_id]
    assert len(matching) == 1, (
        f"the operator read path returned {len(matching)} rows for {det_id!r}; "
        f"it served {[e.get('detection_id') for e in served['events']]!r}"
    )
    assert matching[0]["error"] == f"registry key {_expected_token(secret)}"

    # Discriminating half: the served view is keyed, not "whatever is first".
    assert [e for e in served["events"] if e.get("detection_id") == str(uuid.uuid4())] == []

    # And the summary counted this row rather than reporting over nothing.
    assert served["summary"]["LOW"] == 1, f"summary miscounts: {served['summary']}"


async def test_the_record_is_valid_jsonl_after_redaction(probe):
    """
    The receipt is embedded by regex substitution into arbitrary string values.
    A substitution that produced unescaped bytes would corrupt the append-only
    log for every later reader — so parse the line as strict JSON, not via the
    helper that already tolerates failures.
    """
    det_id = str(uuid.uuid4())
    await probe.write(_record(det_id, error=f'"quoted" {SECRETS["openai"]} \\ tail'))

    lines = [ln for ln in probe.raw_bytes().decode().splitlines() if ln.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])  # strict: raises if the writer emitted bad JSON
    assert parsed["detection_id"] == det_id
    assert _expected_token(SECRETS["openai"]) in parsed["error"]
