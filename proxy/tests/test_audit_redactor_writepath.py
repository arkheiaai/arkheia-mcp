"""
Secrets must not reach disk through the PRODUCTION HTTP entry point.

Companion to ``tests/test_audit_redactor_floor.py``. That file pins the audit
writer itself in the stdlib-only floor tier; this one closes the remaining
question at the layer above:

    does the real request path — POST /detect/verify, with the REAL AuditWriter
    that ``proxy.main.lifespan`` constructs — actually funnel every audit record
    through the redactor, on the success path AND on the fail-safe branches?

Why it is written this way
--------------------------
1. **The audit writer is NOT mocked.** ``proxy/tests/test_detect.py`` asserts
   "an audit record is written" against ``AsyncMock(spec=AuditWriter)``, which
   proves a call was made and nothing about what lands on disk. Here the app is
   started with ``settings.audit.log_path`` pointed at a tmp file, the real
   writer runs, and the assertions read the JSONL back OFF DISK.

2. **The redactor is never called by the test.** A test that calls ``redact()``
   and asserts on its return value exercises its own argument. The defect that
   matters is an entry point that bypasses the redactor.

3. **Every negative assertion has a POSITIVE CONTROL.** ``assert secret not in
   content`` passes on an empty file, a dropped write, or a wrong path. So each
   check also asserts the surrounding audit content IS on disk — the record's
   own detection_id, the hash-chain fields, and the redaction marker.

Which fields matter: ``_audit_record`` stores only the sha256 HASHES of prompt
and response (a good design — the text never reaches disk), so the
caller-supplied strings that DO reach disk verbatim are ``session_id`` and
``model_id``. Those are where a credential actually lands, so those are what
this file drives. Corpus values are SYNTHETIC and are never printed on failure.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from proxy.detection.engine import DetectionEngine, DetectionResult
from proxy.main import create_app

REDACTION_MARKER = "[REDACTED:"

# Synthetic credentials, distinct per shape so a leak names its own shape.
SECRETS = {
    "anthropic":      "sk-ant-api03-" + "Az9" * 27,
    "openai-classic": "sk-" + "Qw7" * 17,
    "github-classic": "ghp_" + "Zx4" * 13,
    "jwt-short":      "eyJhbGciOiJIUzI1NiJ9." + "aB3" * 11 + "." + "cD5" * 10,
    "bearer":         "Authorization: Bearer " + "Ef8" * 22,
    "conn-string":    "postgresql://svc:" + "Gh2" * 9 + "@db.internal:5432/arkheia",
}

SENTINEL_MODEL = "claude-opus-4-5"


@pytest.fixture
def mock_engine():
    """Engine stub — the subject under test is the audit disk path, not detection."""
    engine = AsyncMock(spec=DetectionEngine)

    async def _verify(prompt, response, model_id):
        return DetectionResult(
            risk_level="LOW",
            confidence=0.8,
            features_triggered=["unique_word_ratio"],
            model_id=model_id,
            profile_version="1.0",
            timestamp=datetime.now(timezone.utc).isoformat(),
            detection_id="det-writepath",
        )

    engine.verify.side_effect = _verify
    return engine


class _Harness:
    """Runs the real app against a real AuditWriter and reads the log off disk."""

    def __init__(self, tmp_path: Path, engine):
        self.log_path = tmp_path / "audit.jsonl"
        self._tmp = tmp_path
        self._engine = engine

    def post_all(self, payloads: list[dict], drop_engine: bool = False) -> str:
        profiles_dir = self._tmp / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        with patch("proxy.main.settings") as s:
            s.detection.profile_dir = str(profiles_dir)
            s.proxy.log_level = "WARNING"
            s.audit.log_path = str(self.log_path)      # REAL writer, real file
            s.audit.retention_days = 90
            s.registry.url = ""
            from pydantic import SecretStr
            s.arkheia_api_key = SecretStr("")
            s.synesis = MagicMock()
            s.synesis.enabled = False
            app = create_app()
            with TestClient(app, raise_server_exceptions=False) as client:
                # Override ONLY the engine. app.state.audit_writer stays the real
                # AuditWriter built by the lifespan.
                app.state.engine = None if drop_engine else self._engine
                assert isinstance(app.state.audit_writer, object)
                for payload in payloads:
                    resp = client.post("/detect/verify", json=payload)
                    assert resp.status_code == 200, resp.text
            # Leaving the context runs lifespan shutdown -> audit_writer.stop(),
            # which drains the queue, so the file is complete at this point.
        assert self.log_path.exists(), (
            "POSITIVE CONTROL FAILED: the real write path produced no audit file; "
            "every 'secret absent' assertion below would pass vacuously."
        )
        return self.log_path.read_text(encoding="utf-8")


@pytest.fixture
def harness(tmp_path, mock_engine):
    return _Harness(tmp_path, mock_engine)


def _lines(content: str) -> list[dict]:
    return [json.loads(ln) for ln in content.splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Success path
# ---------------------------------------------------------------------------

def test_secret_in_session_id_never_reaches_disk_via_the_endpoint(harness):
    """A credential passed as session_id is redacted before the JSONL is written."""
    payloads = [
        {
            "prompt": "what did the scanner report",
            "response": "The scanner reported four findings.",
            "model_id": SENTINEL_MODEL,
            "session_id": secret,
        }
        for secret in SECRETS.values()
    ]
    content = harness.post_all(payloads)
    records = _lines(content)

    # --- POSITIVE CONTROLS ---
    assert len(records) == len(SECRETS), (
        f"POSITIVE CONTROL FAILED: {len(records)} records on disk, expected "
        f"{len(SECRETS)}. Records were dropped, so absence proves nothing."
    )
    assert all(r["model_id"] == SENTINEL_MODEL for r in records), (
        "POSITIVE CONTROL FAILED: audit content missing — only the secret should be gone."
    )
    assert all(r["risk_level"] == "LOW" and r["source"] == "proxy" for r in records), (
        "POSITIVE CONTROL FAILED: the detection verdict did not reach disk."
    )
    assert all(r["seq"] >= 1 and len(r["this_hash"]) == 64 for r in records), (
        "POSITIVE CONTROL FAILED: hash-chain fields absent — not the real writer."
    )
    assert REDACTION_MARKER in content, (
        "POSITIVE CONTROL FAILED: no redaction marker anywhere on disk — the redactor "
        "never ran on the production endpoint path."
    )

    # --- THE CHECK ---
    leaked = [shape for shape, secret in SECRETS.items() if _body(secret) in content]
    assert not leaked, (
        f"credential(s) reached disk via POST /detect/verify ({len(leaked)} of "
        f"{len(SECRETS)}): {sorted(leaked)}. Values deliberately not printed."
    )


def test_secret_inside_a_LONG_caller_field_is_still_redacted(harness):
    """
    Length must not be an escape hatch.

    session_id is an arbitrary caller string, so a credential can arrive
    embedded in a long one (a pasted session label, a wrapped command). Added
    because a mutant that skipped redaction for strings over 200 chars SURVIVED
    this file's original corpus — every entry happened to be short, so the tests
    agreed with a broken implementation. The floor tier killed that mutant (its
    corpus holds a 292-char PAT); this closes it at the endpoint tier too.
    """
    secret = SECRETS["anthropic"]
    long_field = (
        "session-label " + "context padding that a caller might paste. " * 12
        + secret + " trailing context that must survive."
    )
    assert len(long_field) > 500, "the long-field case is not actually long"

    content = harness.post_all([{
        "prompt": "p", "response": "a response", "model_id": SENTINEL_MODEL,
        "session_id": long_field,
    }])
    records = _lines(content)

    assert len(records) == 1, "POSITIVE CONTROL FAILED: no record on disk."
    assert "trailing context that must survive." in records[0]["session_id"], (
        "POSITIVE CONTROL FAILED: the surrounding audit content was destroyed, not "
        "just the credential — over-redaction is also a defect."
    )
    assert REDACTION_MARKER in records[0]["session_id"], (
        "POSITIVE CONTROL FAILED: nothing was redacted in the field under test."
    )
    assert _body(secret) not in content, (
        "a credential embedded in a LONG caller field reached disk unredacted."
    )


def test_secret_in_model_id_never_reaches_disk_via_the_endpoint(harness):
    """model_id is caller-supplied and is stored verbatim — so it is a leak surface too."""
    secret = SECRETS["anthropic"]
    content = harness.post_all([{
        "prompt": "p", "response": "a response of some length", "model_id": secret,
        "session_id": "sess-model-id-case",
    }])
    records = _lines(content)

    assert len(records) == 1 and records[0]["session_id"] == "sess-model-id-case", (
        "POSITIVE CONTROL FAILED: the record did not reach disk intact."
    )
    assert REDACTION_MARKER in records[0]["model_id"], (
        "POSITIVE CONTROL FAILED: model_id carries no redaction marker, so nothing "
        "was scrubbed in the field under test."
    )
    assert _body(secret) not in content, (
        "a credential passed as model_id reached disk unredacted (value not printed)."
    )


# ---------------------------------------------------------------------------
# Fail-safe branches — /detect/verify writes an audit record on each of them.
# A redactor applied only on the happy path is the "wired but switched off"
# defect for every error branch.
# ---------------------------------------------------------------------------

def test_secret_is_redacted_on_the_missing_model_id_branch(harness):
    """model_id="" returns UNKNOWN early and still writes an audit record."""
    secret = SECRETS["github-classic"]
    content = harness.post_all([{
        "prompt": "p", "response": "r", "model_id": "", "session_id": secret,
    }])
    records = _lines(content)

    assert len(records) == 1, "POSITIVE CONTROL FAILED: early branch wrote no record."
    assert records[0]["error"] == "model_id_missing", (
        "POSITIVE CONTROL FAILED: this is not the model_id_missing branch."
    )
    assert REDACTION_MARKER in records[0]["session_id"], (
        "POSITIVE CONTROL FAILED: session_id was not scrubbed on this branch."
    )
    assert _body(secret) not in content, (
        "credential reached disk on the model_id_missing fail-safe branch."
    )


def test_secret_is_redacted_on_the_engine_unavailable_branch(harness):
    """engine is None -> UNKNOWN + audit record; the scrub must hold there too."""
    secret = SECRETS["jwt-short"]
    content = harness.post_all(
        [{"prompt": "p", "response": "r", "model_id": SENTINEL_MODEL, "session_id": secret}],
        drop_engine=True,
    )
    records = _lines(content)

    assert len(records) == 1, "POSITIVE CONTROL FAILED: no record on the engine-down branch."
    assert records[0]["error"] == "engine_unavailable", (
        f"POSITIVE CONTROL FAILED: expected engine_unavailable, got {records[0]['error']!r} — "
        "this test did not exercise the branch it claims to."
    )
    assert REDACTION_MARKER in records[0]["session_id"], (
        "POSITIVE CONTROL FAILED: session_id was not scrubbed on this branch."
    )
    assert _body(secret) not in content, (
        "credential reached disk on the engine_unavailable fail-safe branch."
    )


# ---------------------------------------------------------------------------
# The read-back surface: /audit/log must not serve what the file does not hold.
# ---------------------------------------------------------------------------

def test_audit_read_surface_serves_only_redacted_values(harness):
    """
    read_recent() backs the /audit/log endpoint and the MCP arkheia_audit_log
    tool. It must not surface a credential either.
    """
    secret = SECRETS["conn-string"]
    content = harness.post_all([{
        "prompt": "p", "response": "a response", "model_id": SENTINEL_MODEL,
        "session_id": secret,
    }])
    assert _body(secret) not in content, "credential on disk — precondition failed."

    from proxy.audit.writer import AuditWriter
    reader = AuditWriter(str(harness.log_path))
    out = reader.read_recent(limit=10)

    assert out["events"], (
        "POSITIVE CONTROL FAILED: read_recent() returned no events, so 'secret absent' "
        "from the read surface proves nothing."
    )
    assert out["summary"]["LOW"] == 1, (
        f"POSITIVE CONTROL FAILED: summary did not count the record: {out['summary']}"
    )
    served = json.dumps(out)
    assert REDACTION_MARKER in served, (
        "POSITIVE CONTROL FAILED: nothing in the served payload is redacted."
    )
    assert _body(secret) not in served, (
        "the /audit/log read surface served a credential (value not printed)."
    )


def _body(secret: str) -> str:
    """
    The credential body that must never appear. For labelled forms the label is
    audit content and is expected to survive, so the check targets the longest
    high-entropy run.
    """
    import re
    runs = re.findall(r"[A-Za-z0-9+/_-]{16,}", secret)
    assert runs, "corpus entry has no high-entropy body to check"
    return max(runs, key=len)
