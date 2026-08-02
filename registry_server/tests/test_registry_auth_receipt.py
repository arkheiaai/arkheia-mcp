"""
RECEIPTED axis for flow F22 — "Registry API-key auth (fail-closed)".

The question the axis asks: *the flow makes a decision — does that decision
leave a durable record, written on the production path, that can be read back
and tied to the decision it describes?*

For an auth gate the sharp end of that question is the REFUSAL. A denied
request nobody can see later is indistinguishable from one that never
happened: there is no way to tell a credential-stuffing run from a quiet
afternoon, and no way to answer a customer asking why their pull 401'd.

Every test here goes through a live server: a request is issued, the receipt
id is taken from the response header the CALLER received, and the row is read
back off the real JSONL file the running app was configured to write. No
recording stub, no assertion on a helper's return value, no
`assert row is not None`.
"""

import asyncio
import hashlib
import pathlib

import pytest
from fastapi.testclient import TestClient

from registry_server import receipts
from registry_server.main import app
from registry_server.tests._auth_receipt_probe import AuthReceiptProbe

VALID_KEY = "ak_live_" + "a1b2c3d4" * 4
WRONG_KEY = "ak_live_" + "9f9f9f9f" * 4

PROFILE_YAML = 'model: receipted-model\nversion: "2.0"\n'


@pytest.fixture()
def profile_dir(tmp_path):
    d = tmp_path / "profiles"
    d.mkdir()
    (d / "receipted-model.yaml").write_text(PROFILE_YAML, encoding="utf-8")
    return d


@pytest.fixture()
def receipt_log(tmp_path):
    return tmp_path / "audit" / "registry_audit.jsonl"


@pytest.fixture()
def probe(receipt_log):
    return AuthReceiptProbe(receipt_log)


@pytest.fixture()
def env(monkeypatch, profile_dir, receipt_log):
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")
    monkeypatch.setenv("ARKHEIA_REGISTRY_AUDIT_LOG", str(receipt_log))
    return monkeypatch


@pytest.fixture()
def client(env):
    """
    A live server writing receipts to `receipt_log`.

    The `with` block is what runs lifespan, which is what starts and — on
    exit — FLUSHES the writer. Read-backs happen after the block for that
    reason: the drain is asynchronous, so asserting mid-flight would be
    asserting on a race.
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    with TestClient(app) as c:
        yield c


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def receipt_id_of(resp) -> str:
    """The id the CALLER was handed. Everything is looked up by this."""
    value = resp.headers.get(receipts.RECEIPT_HEADER)
    assert value, (
        f"response carried no {receipts.RECEIPT_HEADER} header "
        f"(status {resp.status_code}); the caller has no way to reference the "
        f"decision, so a record on disk could never be tied back to it"
    )
    assert len(value) == 32 and all(c in "0123456789abcdef" for c in value), value
    return value


# ---------------------------------------------------------------------------
# 1. Each of the three decisions leaves a record, read back BY SURFACED ID
# ---------------------------------------------------------------------------

def test_accepted_decision_is_receipted(env, client, probe):
    resp = client.get("/profiles", headers=auth(VALID_KEY))
    assert resp.status_code == 200
    rid = receipt_id_of(resp)
    client.__exit__(None, None, None)   # run shutdown -> flush

    row = probe.require(rid)
    assert row["event_type"] == "registry_auth_decision"
    assert row["decision"] == "accepted"
    assert row["outcome_status"] == 200
    assert row["method"] == "GET"
    assert row["path"] == "/profiles"
    assert row["credential_presented"] is True
    assert row["keys_configured"] == 1
    # POSITIVELY COMPUTED, not `is not None`: the fingerprint must be exactly
    # the one derivable from the key that was actually presented.
    expected = "sha256:" + hashlib.sha256(VALID_KEY.encode()).hexdigest()[:12]
    assert row["key_fingerprint"] == expected


def test_refusal_is_receipted(env, client, probe):
    """
    The decision that matters most. A 401 that leaves no trace is the one an
    operator most needs and is least likely to have.
    """
    resp = client.get("/profiles", headers=auth(WRONG_KEY))
    assert resp.status_code == 401
    rid = receipt_id_of(resp)
    client.__exit__(None, None, None)

    row = probe.require(rid)
    assert row["decision"] == "rejected"
    assert row["outcome_status"] == 401
    assert row["credential_presented"] is True
    assert row["key_fingerprint"] == "sha256:" + hashlib.sha256(WRONG_KEY.encode()).hexdigest()[:12]


def test_refusal_with_no_credential_at_all_is_receipted(env, client, probe):
    resp = client.get("/profiles/receipted-model/download")
    assert resp.status_code == 401
    rid = receipt_id_of(resp)
    client.__exit__(None, None, None)

    row = probe.require(rid)
    assert row["decision"] == "rejected"
    assert row["credential_presented"] is False
    assert row["key_fingerprint"] is None
    assert row["path"] == "/profiles/receipted-model/download"


def test_unprovisioned_refusal_is_receipted(env, probe):
    """The fail-closed branch the flow is named for must be observable."""
    env.delenv("ARKHEIA_REGISTRY_KEYS", raising=False)
    with TestClient(app) as c:
        resp = c.get("/profiles", headers=auth(VALID_KEY))
        assert resp.status_code == 503
        rid = receipt_id_of(resp)

    row = probe.require(rid)
    assert row["decision"] == "unprovisioned"
    assert row["outcome_status"] == 503
    assert row["keys_configured"] == 0


# ---------------------------------------------------------------------------
# 2. Vacuity guards — the read-back must be capable of NOT finding a row
# ---------------------------------------------------------------------------

def test_a_fabricated_receipt_id_finds_nothing(env, client, probe):
    """
    Without this, every `require()` above could be returning "the only row"
    regardless of the id, and the read-back would be decorative.
    Paired with a positive control on the SAME file so a null result cannot
    be explained by an empty or unreadable log.
    """
    resp = client.get("/profiles", headers=auth(VALID_KEY))
    real = receipt_id_of(resp)
    client.__exit__(None, None, None)

    assert probe.find("0" * 32) is None
    assert probe.find(real[:-1] + ("0" if real[-1] != "0" else "1")) is None
    # POSITIVE CONTROL: the probe was reading real bytes all along.
    assert probe.find(real) is not None
    assert len(probe.raw_bytes()) > 0


def test_each_request_gets_its_own_receipt_and_they_all_land(env, client, probe):
    """
    Ids must be per-request and every one must be findable — a shared or
    reused id would tie many decisions to one row, which is the same as
    tying none of them.
    """
    ids = []
    for key in (VALID_KEY, WRONG_KEY, VALID_KEY, "ak_live_" + "0" * 32):
        ids.append(receipt_id_of(client.get("/profiles", headers=auth(key))))
    ids.append(receipt_id_of(client.get("/profiles")))
    client.__exit__(None, None, None)

    assert len(set(ids)) == 5, f"receipt ids repeated across requests: {ids}"
    rows = [probe.require(i) for i in ids]
    assert [r["decision"] for r in rows] == [
        "accepted", "rejected", "accepted", "rejected", "rejected"
    ]
    assert len(probe.rows()) == 5, "extra or missing rows on disk"


def test_receipt_id_is_not_derived_from_the_credential(env, client, probe):
    """
    Two requests with the SAME wrong key must get DIFFERENT ids. If the id
    were a function of the credential it would itself be an oracle:
    identical ids would confirm two guesses were the same key, and a
    stable id would confirm a key had been seen before.
    """
    a = receipt_id_of(client.get("/profiles", headers=auth(WRONG_KEY)))
    b = receipt_id_of(client.get("/profiles", headers=auth(WRONG_KEY)))
    assert a != b
    # And the id is not a truncation of the fingerprint either.
    fp = hashlib.sha256(WRONG_KEY.encode()).hexdigest()
    assert not fp.startswith(a) and not fp.startswith(b)


# ---------------------------------------------------------------------------
# 3. What must NEVER be in the record
# ---------------------------------------------------------------------------

def test_no_presented_credential_ever_reaches_disk(env, client, probe):
    """
    Checked against the RAW BYTES, not the parsed row: a key hidden in a
    nested value, a header dump or an error string would survive a
    field-by-field assertion.
    """
    keys = [
        VALID_KEY,
        WRONG_KEY,
        "ak_live_" + "beef" * 8,
        # `ak_test_` DELIBERATELY included. proxy/audit/redactor.py's pattern is
        # `ak_live_[a-f0-9]{20,}` only, so an ak_test_ key — a shape
        # registry_server/auth.py's own docstring advertises, and one
        # scripts/pilot_validate.py now mints — is NOT covered by the redactor's
        # second layer. This assertion therefore tests THIS module's first layer
        # (never put the key in the record) rather than passing because the
        # redactor happened to clean up afterwards. Without this key the
        # mutation that writes the raw credential into the record SURVIVES.
        # The redactor gap itself is NOT fixed here: proxy/audit/redactor.py is
        # PR #16's file. Reported, not touched.
        "ak_test_" + "c0ffee12" * 4,
    ]
    for k in keys:
        client.get("/profiles", headers=auth(k))
    client.get("/profiles", headers={"Authorization": f"Bearer {VALID_KEY}"})
    client.__exit__(None, None, None)

    raw = probe.raw_bytes()
    assert raw, "nothing was written — the assertion below would be vacuous"
    for k in keys:
        assert k.encode() not in raw, f"raw key {k[:12]}… reached disk"
    # The fingerprints ARE there — proving the absence above is not simply
    # "the file has nothing about these requests in it".
    for k in keys:
        fp = ("sha256:" + hashlib.sha256(k.encode()).hexdigest()[:12]).encode()
        assert fp in raw, f"no fingerprint for the key presented; the record is not linkable"


def test_record_is_committed_in_its_redacted_form(env, client, probe):
    """
    The tamper-evident chain must be computed over what LANDED. If the stored
    `this_hash` reproduces from the on-disk row, the redacted form is what was
    committed — not a plaintext record scrubbed after the fact.
    """
    rid = receipt_id_of(client.get("/profiles", headers=auth(VALID_KEY)))
    client.__exit__(None, None, None)

    row = probe.require(rid)
    assert row["this_hash"] == probe.recompute_this_hash(row)
    assert row["seq"] == 1
    assert row["prev_hash"] == "0" * 64


def test_chain_links_successive_decisions(env, client, probe):
    """A chain that does not actually link is not tamper-evident."""
    for key in (VALID_KEY, WRONG_KEY, VALID_KEY):
        client.get("/profiles", headers=auth(key))
    client.__exit__(None, None, None)

    rows = probe.rows()
    assert [r["seq"] for r in rows] == [1, 2, 3]
    for i, row in enumerate(rows):
        assert row["prev_hash"] == ("0" * 64 if i == 0 else rows[i - 1]["this_hash"])
        assert row["this_hash"] == probe.recompute_this_hash(row)


# ---------------------------------------------------------------------------
# 4. The receipt must never become a precondition of the decision
# ---------------------------------------------------------------------------

def test_a_failing_receipt_writer_does_not_turn_a_refusal_into_an_acceptance(env, monkeypatch):
    """
    Standing ruling: a receipt failure must not block the halt. If the writer
    raises, the 401 must still be a 401 — not a 500, and emphatically not a
    200. Asserted for all three decisions.
    """
    async def boom(record):
        raise RuntimeError("audit rail down")

    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    with TestClient(app) as c:
        monkeypatch.setattr(receipts, "emit", boom)
        assert c.get("/profiles", headers=auth(WRONG_KEY)).status_code == 401
        assert c.get("/profiles").status_code == 401
        assert c.get("/profiles", headers=auth(VALID_KEY)).status_code == 200
        env.delenv("ARKHEIA_REGISTRY_KEYS")
        assert c.get("/profiles", headers=auth(VALID_KEY)).status_code == 503


def test_an_unstarted_writer_logs_loudly_rather_than_silently_dropping(env, caplog):
    """
    Fail-open, never fail-silent. With no writer started, a decision is
    UNRECORDED — and that must be visible in the operator's log, because
    silence is exactly what "no requests happened" looks like.
    """
    import logging

    asyncio.run(receipts.stop())
    assert receipts.get_writer() is None
    with caplog.at_level(logging.ERROR, logger="registry_server.receipts"):
        asyncio.run(receipts.emit(receipts.build_record(
            receipt_id="f" * 32, decision="rejected", outcome_status=401,
            method="GET", path="/profiles", client_ip="203.0.113.7",
            credential=WRONG_KEY, keys_configured=1,
        )))
    messages = [r.getMessage() for r in caplog.records]
    assert any("UNRECORDED" in m for m in messages), messages
    assert not any(WRONG_KEY in m for m in messages), "the log echoed the raw key"


def test_a_full_receipt_queue_logs_loudly_without_raw_credential(
    env, tmp_path, monkeypatch, caplog
):
    """
    Queue saturation is another UNRECORDED state. It must be visible in logs,
    but the log line must name structural receipt facts rather than the raw API
    key that caused the auth decision.
    """
    import logging

    from proxy.audit.writer import AuditWriter

    writer = AuditWriter(str(tmp_path / "registry_audit.jsonl"))
    n = 0
    while True:
        try:
            writer._queue.put_nowait({"receipt_id": f"filler-{n}"})
        except Exception:
            break
        n += 1
    assert n >= 1000, f"the queue accepted only {n} records; wrong premise"
    monkeypatch.setattr(receipts, "_writer", writer)

    with caplog.at_level(logging.ERROR, logger="registry_server.receipts"):
        asyncio.run(receipts.emit(receipts.build_record(
            receipt_id="e" * 32, decision="rejected", outcome_status=401,
            method="GET", path="/profiles", client_ip="203.0.113.7",
            credential=WRONG_KEY, keys_configured=1,
        )))
    messages = [r.getMessage() for r in caplog.records]
    assert any("audit queue full" in m and "UNRECORDED" in m for m in messages), messages
    assert not any(WRONG_KEY in m for m in messages), "the log echoed the raw key"


# ---------------------------------------------------------------------------
# 5. Receipts are ON by default — no env var required to enable them
# ---------------------------------------------------------------------------

def test_receipts_are_on_by_default(monkeypatch, tmp_path, profile_dir):
    """
    A guard whose default is off is not a guard. With ARKHEIA_REGISTRY_AUDIT_LOG
    UNSET, a decision must still land somewhere real — proven by reading the
    default path back, not by inspecting configuration.
    """
    monkeypatch.delenv("ARKHEIA_REGISTRY_AUDIT_LOG", raising=False)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)

    default_path = pathlib.Path(receipts.default_log_path())
    assert str(default_path), "no default receipt path — receipts would be off by default"

    # The default is package-relative (mirroring proxy.config), so this test
    # genuinely writes to the checkout. It must leave NO trace: the first
    # version of this test appended to the repo root on every run and the
    # mutation harness grew it to 3.3 MB of untracked audit log. Exact bytes
    # are captured and restored.
    existed = default_path.exists()
    original = default_path.read_bytes() if existed else b""
    try:
        probe = AuthReceiptProbe(default_path)
        before = len(probe.rows())
        with TestClient(app) as c:
            rid = receipt_id_of(c.get("/profiles", headers=auth(WRONG_KEY)))
        row = probe.require(rid)
        assert row["decision"] == "rejected"
        assert len(probe.rows()) == before + 1
    finally:
        if existed:
            default_path.write_bytes(original)
        else:
            default_path.unlink(missing_ok=True)
    assert default_path.exists() is existed, "test left an artifact in the checkout"


def test_shutdown_flushes_and_releases_the_writer(env, probe):
    """
    The lifespan must STOP the writer on shutdown, which is what drains the
    queue. Asserted on observable state rather than on timing: `stop()` clears
    the module-level writer, so a lifespan that skips it leaves one behind.
    Timing-based variants of this test pass by luck — the drain loop usually
    wins the race — which is exactly why the mutation that removes the flush
    survived until this test existed.
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    with TestClient(app) as c:
        rid = receipt_id_of(c.get("/profiles", headers=auth(WRONG_KEY)))
        assert receipts.get_writer() is not None, "writer was never started"
    assert receipts.get_writer() is None, (
        "lifespan shutdown did not stop the receipt writer; its queue is never "
        "drained and the last receipts of a process are lost on every restart"
    )
    assert probe.require(rid)["decision"] == "rejected"


def test_build_record_rejects_an_unknown_decision():
    """The decision vocabulary is closed; an unrecognised value must not
    quietly become a row that no query will ever match."""
    with pytest.raises(ValueError, match="unknown auth decision"):
        receipts.build_record(
            receipt_id="a" * 32, decision="maybe", outcome_status=200,
            method="GET", path="/profiles", client_ip=None,
            credential=None, keys_configured=1,
        )
