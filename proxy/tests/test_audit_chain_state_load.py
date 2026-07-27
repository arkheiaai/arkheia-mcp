"""
Chain state recovered from disk is ATTACKER-CONTROLLED INPUT -- validate it.

Codex adversarial review of PR #37 @ 3251ef1. ``_load_chain_state()`` ended with::

    last = json.loads(lines[-1])
    return last.get("this_hash", "0" * 64), last.get("seq", 0)

``.get(k, default)`` only defends against a MISSING key. A key that is PRESENT
with a hostile value is adopted verbatim, whatever its type. One parseable line
carrying ``"this_hash": null`` therefore recovers ``_last_hash = None``, and from
that moment:

  1. ``start()`` adopts ``None`` as the chain head;
  2. the startup ``verify_chain()`` self-check DETECTS the break, logs one
     WARNING, and the service continues and reports healthy;
  3. every subsequent write reaches ``_compute_hash(clean, None)``, which raises
     ``TypeError: can only concatenate str (not "NoneType") to str``, is caught by
     ``_writer_loop``'s ``except``, and the record is DROPPED.

Step 3 never recovers: ``self._last_hash`` is only reassigned after a successful
write, so the poisoned value is permanent for the life of the process. The audit
log stops recording, forever, silently, while the service reports healthy.

This is the SAME failure this PR exists to close -- silent audit loss -- moved
from the write path to the LOAD path, and made permanent rather than per-record.
It is also a one-line denial of auditing: an attacker who can append a single
``{"this_hash": null}`` line disables the audit trail of the whole process.

Sibling of ``test_audit_chain_verification.py`` (a verifier that cannot see a
hole) and ``test_audit_writer_nonserialisable.py`` (a record that vanishes on
write). Same contract in all three: **fail-open, but NEVER fail-silent.**
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

import pytest

from proxy.audit.writer import AuditWriter, _compute_hash

HEX64 = re.compile(r"\A[0-9a-f]{64}\Z")
GENESIS = "0" * 64


def _writer(tmp_path: Path) -> AuditWriter:
    return AuditWriter(log_path=str(tmp_path / "audit.jsonl"), retention_days=365)


def _write_valid_chain(path: Path, n: int) -> str:
    """Write n genuinely valid, hash-linked records. Returns the final this_hash."""
    prev = GENESIS
    lines = []
    for seq in range(1, n + 1):
        record = {"seq": seq, "prev_hash": prev, "detection_id": f"real-{seq}"}
        this_hash = _compute_hash(record, prev)
        record["this_hash"] = this_hash
        lines.append(json.dumps(record))
        prev = this_hash
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return prev


def _append_tampered(path: Path, **fields) -> None:
    """Append one PARSEABLE line whose chain fields carry hostile values."""
    record = {"seq": 99, "prev_hash": GENESIS, "detection_id": "tampered"}
    record.update(fields)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def _records(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [
        json.loads(ln)
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]


def _ids(path: Path) -> list[str]:
    return [r.get("detection_id") for r in _records(path)]


async def _start_write_stop(writer: AuditWriter, records: list[dict]) -> None:
    await writer.start()
    for record in records:
        await writer.write(record)
    await writer.stop()  # drains the queue: every write has landed or failed


# ===========================================================================
# RED (a) -- a hostile value on disk must not become chain state
# ===========================================================================

def test_null_this_hash_on_disk_is_not_adopted_as_chain_state(tmp_path):
    """
    RED: ``"this_hash": null`` recovers ``_last_hash = None``.

    ``_last_hash`` is, by the module's own contract, a 64-char hex sha256 digest
    (or the all-zero genesis sentinel). Nothing else is a value -- it is corrupt
    state, and adopting it poisons every later write.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, this_hash=None)

    from proxy.audit.writer import _load_chain_state

    state = _load_chain_state(w.log_path)
    last_hash = state[0]

    assert isinstance(last_hash, str), (
        f"chain head recovered from disk is a {type(last_hash).__name__}, not a "
        f"str: {last_hash!r} -- a parseable tamper became the chain state"
    )
    assert HEX64.match(last_hash), (
        f"chain head recovered from disk is not a 64-char lowercase hex digest: "
        f"{last_hash!r}"
    )


@pytest.mark.parametrize("hostile", [
    None,
    123,
    12.5,
    True,
    [],
    {},
    "",
    "not-a-hash",
    "0" * 63,          # one char short
    "0" * 65,          # one char long
    "Z" * 64,          # right length, wrong alphabet
    "0" * 63 + "G",    # right length, one non-hex char
    "A" * 64,          # uppercase -- hexdigest() never emits this
])
def test_no_malformed_this_hash_is_ever_adopted(tmp_path, hostile):
    """
    The CLASS, not the one reported instance. ``null`` is only the value that
    crashes loudest; a wrong-length or wrong-alphabet string is adopted just as
    silently and yields a chain that can never verify.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, this_hash=hostile)

    from proxy.audit.writer import _load_chain_state

    last_hash = _load_chain_state(w.log_path)[0]
    assert isinstance(last_hash, str) and HEX64.match(last_hash), (
        f"adopted {hostile!r} as the chain head -> {last_hash!r}"
    )


@pytest.mark.parametrize("hostile", [None, "12", 1.5, [], {}, -1, True, False])
def test_no_malformed_seq_is_ever_adopted(tmp_path, hostile):
    """
    ``seq`` is adopted from the same untrusted line and never type-checked.

    ``"seq": "12"`` recovers ``_seq = "12"``, and the next write computes
    ``"12" + 1`` -> TypeError -> the same permanent silent drop. ``"seq": -1`` or
    a float is accepted outright and corrupts sequence continuity, which is the
    exact signal ``verify_chain``'s ``gaps`` list exists to protect.

    ``True``/``False`` are included deliberately: ``isinstance(True, int)`` is
    True in Python, so a naive int check adopts a bool as a sequence number.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, seq=hostile)

    from proxy.audit.writer import _load_chain_state

    last_seq = _load_chain_state(w.log_path)[1]
    assert type(last_seq) is int and last_seq >= 0, (
        f"adopted {hostile!r} as the sequence number -> {last_seq!r} "
        f"({type(last_seq).__name__})"
    )


def test_a_non_object_last_line_is_not_adopted(tmp_path):
    """A JSON array/string parses fine and has no ``.get`` -- and must not be trusted."""
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    with open(w.log_path, "a", encoding="utf-8") as f:
        f.write('["not", "an", "object"]\n')

    from proxy.audit.writer import _load_chain_state

    state = _load_chain_state(w.log_path)
    assert isinstance(state[0], str) and HEX64.match(state[0]), state
    assert type(state[1]) is int and state[1] >= 0, state


def test_a_valid_log_is_still_recovered_exactly(tmp_path):
    """
    POSITIVE CONTROL. Validation must not be a blanket reset to genesis: an
    untampered log still recovers its real head and its real seq, or every
    restart would silently restart the chain -- a worse bug than the one fixed.
    """
    w = _writer(tmp_path)
    final = _write_valid_chain(w.log_path, 5)

    from proxy.audit.writer import _load_chain_state

    state = _load_chain_state(w.log_path)
    assert state[0] == final, state
    assert state[1] == 5, state


# ===========================================================================
# RED (b2) -- a valid record LARGER than the fixed tail-read window must
# still be recovered correctly, or ordinary caller input (an unbounded
# session_id/model_id, see proxy/endpoints/detect.py's VerifyRequest) poisons
# recovery exactly like a hostile value does. Codex adversarial review of
# PR #37, second pass, 2026-07-27.
# ===========================================================================

def _write_one_record_with_a_big_field(path: Path, field_bytes: int) -> tuple[str, int]:
    """Write ONE valid, correctly hash-linked record whose JSON exceeds
    ``field_bytes`` bytes (via an oversized string field, mirroring an
    unbounded caller-controlled ``session_id``). Returns (this_hash, seq)."""
    record = {"seq": 1, "prev_hash": GENESIS, "session_id": "S" * field_bytes}
    this_hash = _compute_hash(record, GENESIS)
    record["this_hash"] = this_hash
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    return this_hash, 1


def test_a_record_bigger_than_the_tail_window_is_still_recovered(tmp_path):
    """
    RED, pre-fix: ``_load_chain_state`` read a fixed last-8KB window and
    treated a window with no complete line as "unrecoverable," falling back
    to genesis (seq 0). A single record whose JSON exceeds 8KB -- ordinary
    caller input, since ``session_id``/``model_id`` are unbounded strings
    persisted verbatim -- IS that case: the whole window is a headless
    fragment of the one giant line, gets dropped as a "probable partial
    leading record," and nothing is left. The fix grows the read window
    until it finds a complete record (or has read the whole file), so
    recovery must be EXACT here, not merely "did not crash."
    """
    w = _writer(tmp_path)
    this_hash, seq = _write_one_record_with_a_big_field(w.log_path, 12_000)
    assert w.log_path.stat().st_size > 8192, "test setup invalid -- record must exceed the window"

    from proxy.audit.writer import _load_chain_state

    state = _load_chain_state(w.log_path)
    assert state.ok is True, (
        f"a single oversized-but-VALID record must recover cleanly, not "
        f"ok=False: {state}"
    )
    assert state.last_hash == this_hash, state
    assert state.last_seq == seq, state


def test_a_record_needing_multiple_window_growths_is_still_recovered(tmp_path):
    """
    Same as above but sized so a single x4 growth (8192 -> 32768) is not
    enough (record is ~40KB, forcing two growth iterations: 8192 -> 32768 ->
    (clamped to file size)). Pins that growth actually loops rather than
    trying exactly once more.
    """
    w = _writer(tmp_path)
    this_hash, seq = _write_one_record_with_a_big_field(w.log_path, 40_000)
    assert w.log_path.stat().st_size > 32768, "test setup invalid -- needs >1 growth"

    from proxy.audit.writer import _load_chain_state

    state = _load_chain_state(w.log_path)
    assert state.ok is True, state
    assert state.last_hash == this_hash, state
    assert state.last_seq == seq, state


async def test_a_restart_after_an_oversized_record_does_not_duplicate_seq(tmp_path):
    """
    End-to-end version of the two tests above, through the real async writer
    across a real restart -- pins the actual observable failure (duplicate
    sequence numbers on disk) rather than only the internal recovery value.
    Before the fix: seq on disk was ``[1, 1]`` (the second process could not
    recover seq=1 and restarted counting from 0), which is itself a second,
    independent tamper-evidence defect (two on-disk records sharing a seq).
    """
    w1 = _writer(tmp_path)
    await w1.start()
    await w1.write({"event_type": "detect", "risk_level": "LOW",
                     "session_id": "S" * 12_000})
    await w1.stop()
    assert w1.log_path.stat().st_size > 8192

    w2 = _writer(tmp_path)
    await w2.start()
    assert w2._chain_ok is True, (
        f"restart after a valid oversized record must not report a degraded "
        f"chain: status={w2._chain_status!r} detail={w2._chain_detail!r}"
    )
    assert w2._seq == 1, f"expected seq to recover as 1, got {w2._seq}"
    await w2.write({"event_type": "detect", "risk_level": "LOW", "session_id": "small"})
    await w2.stop()

    seqs = [r["seq"] for r in _records(w2.log_path)]
    assert seqs == [1, 2], f"expected consecutive seqs, got {seqs} (duplicate = data loss risk)"

    report = w2.verify_chain()
    assert report["ok"] is True, report
    assert report["verified"] == 2, report


# ===========================================================================
# RED (c) -- every subsequent write is silently dropped
# ===========================================================================

@pytest.mark.parametrize("field,hostile", [
    ("this_hash", None),
    ("this_hash", "not-a-hash"),
    ("seq", None),
    ("seq", "12"),
])
async def test_writes_after_a_tampered_line_still_reach_disk(tmp_path, field, hostile):
    """
    RED: the whole remaining life of the process writes NOTHING.

    Through the real ``AuditWriter``, its real queue and its real loop. Today
    ``_compute_hash(clean, None)`` raises inside ``_writer_loop``'s try, the
    record is dropped, ``self._last_hash`` is never repaired, and the next
    record dies identically. Three writes in, zero on disk.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, **{field: hostile})
    before = len(_records(w.log_path))

    await _start_write_stop(w, [
        {"detection_id": "post-tamper-1", "risk_level": "HIGH"},
        {"detection_id": "post-tamper-2", "risk_level": "LOW"},
        {"detection_id": "post-tamper-3", "risk_level": "MEDIUM"},
    ])

    ids = _ids(w.log_path)
    assert len(_records(w.log_path)) == before + 3, (
        f"{before + 3 - len(_records(w.log_path))} of 3 audit records were "
        f"DROPPED after one tampered line ({field}={hostile!r}); on disk: {ids}"
    )
    for wanted in ("post-tamper-1", "post-tamper-2", "post-tamper-3"):
        assert wanted in ids, f"{wanted} vanished; on disk: {ids}"


async def test_a_high_risk_event_survives_a_poisoned_chain_head(tmp_path):
    """
    The record you most need on disk is the one this defect eats. Pinned
    separately so a future 'just refuse to write on a bad chain' regression
    reads as what it is: the same silent audit loss with a different excuse.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 1)
    _append_tampered(w.log_path, this_hash=None)

    await _start_write_stop(w, [{"detection_id": "the-one-that-matters",
                                 "risk_level": "HIGH"}])

    assert "the-one-that-matters" in _ids(w.log_path), _ids(w.log_path)


async def test_records_written_after_recovery_are_a_verifiable_chain(tmp_path):
    """
    Not merely present -- LINKED. Records written after a poisoned head must
    form a chain a verifier can walk, hashed over the exact bytes persisted.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, this_hash=None)

    await _start_write_stop(w, [{"detection_id": f"post-{i}"} for i in range(3)])

    written = _records(w.log_path)[-3:]
    prev = written[0]["prev_hash"]
    for rec in written:
        body = {k: v for k, v in rec.items() if k != "this_hash"}
        assert rec["prev_hash"] == prev, rec
        assert rec["this_hash"] == _compute_hash(body, prev), (
            f"this_hash does not match the persisted bytes: {rec}"
        )
        prev = rec["this_hash"]

    seqs = [r["seq"] for r in written]
    assert all(type(s) is int for s in seqs), seqs
    assert seqs == [seqs[0], seqs[0] + 1, seqs[0] + 2], seqs


async def test_a_write_that_cannot_be_hashed_is_surfaced_not_vanished(
    tmp_path, monkeypatch, caplog
):
    """
    RED (3): ``_compute_hash`` raising must never end in a dropped record with
    nothing durable to say so -- the same 'degrade, don't drop' treatment this
    PR already gave non-serialisable values.
    """
    w = _writer(tmp_path)

    import proxy.audit.writer as writer_mod

    real = writer_mod._compute_hash
    calls = {"n": 0}

    def _boom(record, prev_hash):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TypeError("synthetic hashing failure")
        return real(record, prev_hash)

    monkeypatch.setattr(writer_mod, "_compute_hash", _boom)

    with caplog.at_level(logging.WARNING, logger="proxy.audit.writer"):
        await _start_write_stop(w, [{"detection_id": "unhashable-event",
                                     "risk_level": "HIGH"}])

    records = _records(w.log_path)
    assert records, (
        "a hashing failure dropped the record entirely -- nothing on disk, only "
        "an ephemeral log line, which is exactly the silent audit loss this PR "
        "exists to close"
    )
    blob = json.dumps(records)
    assert "unhashable-event" in blob, records
    # And the writer must not report a healthy chain after that.
    assert w.chain_status()["ok"] is False, w.chain_status()


# ===========================================================================
# RED (b) -- a DETECTED break must not be survivable in silence
# ===========================================================================

async def test_writer_reports_a_degraded_chain_after_a_bad_load(tmp_path):
    """
    RED: the writer has no notion of 'my chain state is corrupt'. Startup
    detects the break, logs once, and every surface afterwards looks healthy.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, this_hash=None)

    await w.start()
    try:
        status = w.chain_status()
        assert status["ok"] is False, status
        assert status["status"] != "OK", status
        assert status["detail"], "a degraded chain must say WHY"
    finally:
        await w.stop()


async def test_a_degraded_chain_keeps_signalling_it_is_not_one_boot_line(
    tmp_path, caplog
):
    """
    RED: 'one log line at boot that scrolls away' is the failure mode named in
    the review. A degraded audit chain must keep saying so for as long as it is
    degraded -- a persistent, repeated, operator-visible signal.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 2)
    _append_tampered(w.log_path, this_hash=None)

    with caplog.at_level(logging.WARNING, logger="proxy.audit.writer"):
        await _start_write_stop(
            w, [{"detection_id": f"e{i}"} for i in range(120)]
        )

    # The signal must repeat while the writer is WORKING, not because every
    # write is failing -- a per-drop error line is the defect, not the fix.
    assert len(_ids(w.log_path)) == 3 + 120, (
        f"only {len(_ids(w.log_path))} records on disk of 3 pre-existing + 120 "
        f"written -- writes are being dropped, so any repeated log line here is "
        f"the failure itself, not a health signal"
    )

    degraded_lines = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING and "chain" in r.getMessage().lower()
    ]
    assert len(degraded_lines) >= 2, (
        f"a corrupted audit chain produced {len(degraded_lines)} warning(s) "
        f"across 120 writes -- a boot-time line that scrolls away is silence "
        f"by the time it matters"
    )


async def test_a_healthy_chain_does_not_cry_wolf(tmp_path, caplog):
    """
    POSITIVE CONTROL for the two tests above. A clean log must report ok and
    must NOT emit a repeated degraded signal, or the signal is worthless.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)

    with caplog.at_level(logging.WARNING, logger="proxy.audit.writer"):
        await _start_write_stop(w, [{"detection_id": f"e{i}"} for i in range(120)])

    status = w.chain_status()
    assert status["ok"] is True, status
    assert status["status"] == "OK", status
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == [], (
        [r.getMessage() for r in caplog.records]
    )
    assert w.verify_chain()["ok"] is True, w.verify_chain()


# ===========================================================================
# Class sibling: parsed-JSON values trusted by type on the READ path
# ===========================================================================

def test_read_recent_survives_a_hostile_risk_level(tmp_path):
    """
    ``read_recent`` does ``summary[event.get("risk_level", "UNKNOWN")] += 1``
    OUTSIDE its try/except. A log line with an unhashable ``risk_level``
    (``[]``/``{}``) raises TypeError straight out of the method -- taking down
    /audit/log and the MCP ``arkheia_audit_log`` tool from one appended line.
    Same class as the load path: parsed JSON trusted by type.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 1)
    with open(w.log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"detection_id": "x", "risk_level": ["HIGH"]}) + "\n")
        f.write(json.dumps({"detection_id": "y", "risk_level": {"a": 1}}) + "\n")

    out = w.read_recent()
    assert isinstance(out["summary"], dict), out
    assert all(isinstance(k, str) for k in out["summary"]), out["summary"]


def test_verify_chain_survives_a_non_string_this_hash(tmp_path):
    """
    ``prev_hash = stored_this or expected`` adopts whatever type ``this_hash``
    had. A non-empty non-str (``123``) becomes the next ``prev_hash`` and makes
    ``_compute_hash`` raise mid-walk, aborting verification of every record
    after it. It must report a break and keep walking, not stop looking.
    """
    w = _writer(tmp_path)
    _write_valid_chain(w.log_path, 3)
    lines = w.log_path.read_text(encoding="utf-8").splitlines()
    bad = json.loads(lines[1])
    bad["this_hash"] = 123
    lines[1] = json.dumps(bad)
    w.log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = w.verify_chain()
    assert report["ok"] is False, report
    assert report["verified"] == 3, (
        f"verification stopped early at a hostile this_hash type instead of "
        f"reporting it and continuing: {report}"
    )


# ===========================================================================
# RED (b), through the REAL lifespan -- "we noticed and did nothing"
# ===========================================================================

@pytest.fixture
def seeded_client_factory(monkeypatch, tmp_path):
    """
    A TestClient over the real proxy app whose audit log ALREADY EXISTS on disk
    with the content the test writes into it, before the lifespan runs.

    Same hermetic redirections as test_startup_integrity.py's client_factory:
    profile_dir and audit.log_path both default to absolute production paths
    that do not exist on a runner, and startup would fail before ever reaching
    the audit block -- which would let these assertions pass for the wrong
    reason.
    """
    from proxy.config import settings

    repo_profiles = Path(__file__).resolve().parents[2] / "profiles"
    assert repo_profiles.is_dir(), repo_profiles
    monkeypatch.setattr(settings.detection, "profile_dir", str(repo_profiles))

    log_path = tmp_path / "audit.jsonl"
    monkeypatch.setattr(settings.audit, "log_path", str(log_path))

    created = []

    def _make():
        from fastapi.testclient import TestClient

        from proxy.auth import require_auth
        from proxy.main import app

        app.dependency_overrides[require_auth] = lambda: "audit-chain-test@example.com"
        client = TestClient(app)
        created.append((app, client))
        return client

    yield log_path, _make
    for app, client in created:
        app.dependency_overrides.clear()


def test_startup_on_a_corrupt_chain_is_not_reported_as_healthy(seeded_client_factory):
    """
    RED: startup already DETECTS the break and carries on anyway -- the worst of
    both worlds. ``/admin/health`` returns ``{"status": "ok"}`` with no mention
    of the audit chain at all, so every operator surface says the service is
    fine while its audit log is corrupt and (before this fix) recording nothing.

    Posture pinned here: fail-open on availability -- the proxy DOES start,
    because refusing to boot on a corrupt audit log hands an attacker a
    one-append denial of the entire detection service -- but the degraded state
    is published, and the top-level health status must not read "ok".
    """
    log_path, make_client = seeded_client_factory
    _write_valid_chain(log_path, 2)
    _append_tampered(log_path, this_hash=None)

    client = make_client()
    with client:
        # Fail-open: the service is up. (Positive control for the assertions
        # below -- they must fail on a *running* service, not a dead one.)
        body = client.get("/admin/health").json()

        assert "audit_chain" in body, (
            f"/admin/health does not mention the audit chain at all, so a "
            f"corrupted audit log is indistinguishable from a healthy one on "
            f"the operator surface: {body}"
        )
        assert body["audit_chain"]["ok"] is False, body["audit_chain"]
        assert body["status"] != "ok", (
            f"the proxy reports top-level status 'ok' while its audit chain is "
            f"corrupt -- startup detected the break and nothing downstream can "
            f"tell: {body}"
        )


def test_startup_on_an_intact_chain_still_reports_ok(seeded_client_factory):
    """POSITIVE CONTROL: a clean log must still read fully healthy."""
    log_path, make_client = seeded_client_factory
    _write_valid_chain(log_path, 3)

    client = make_client()
    with client:
        body = client.get("/admin/health").json()
        assert body["status"] == "ok", body
        assert body["audit_chain"]["ok"] is True, body["audit_chain"]


def test_startup_past_the_old_1000_limit_still_catches_a_tail_tamper(seeded_client_factory):
    """
    RED, through the REAL lifespan and the REAL /admin/health -- the exact
    repro from Codex's second-pass adversarial review of PR #37, 2026-07-27:
    1001 valid records, tamper record #1001 (the last one), boot the real
    FastAPI app. Before the fix, ``verify_chain()``'s old default
    ``limit=1000`` never looked at record #1001 at all and startup reported
    "status": "ok" over a genuinely tampered chain -- past 1000 records is
    the STEADY STATE for a running deployment, not an edge case, and it is
    exactly where an attacker appending a tampered tail record would land.
    """
    log_path, make_client = seeded_client_factory
    _write_valid_chain(log_path, 1001)
    lines = log_path.read_text().splitlines()
    tampered = json.loads(lines[1000])  # record #1001 -- the LAST one
    tampered["detection_id"] = "TAMPERED"
    lines[1000] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n")

    client = make_client()
    with client:
        body = client.get("/admin/health").json()
        assert body["audit_chain"]["ok"] is False, (
            f"a tamper in record #1001 of a 1001-record chain was not caught "
            f"by the real startup self-check: {body['audit_chain']}"
        )
        assert body["status"] != "ok", (
            f"the real app reported top-level status 'ok' over a chain "
            f"tampered past the old 1000-record limit: {body}"
        )
