"""
Sanitize-before-redact ordering: a string CREATED BY sanitization must still
be scrubbed -- not skipped because it did not exist yet when redact() ran.

Regression found in review of this same PR (2026-07-27). The first version of
the non-serialisable-value fix ran:

    clean = redact(record)
    clean, degraded = _sanitize_for_json(clean)

-- redact() FIRST, sanitize SECOND. redact() only descends into dict / list /
str; a ``set`` is not a container it enters, and an arbitrary object is not a
string it can scan, so BOTH pass through completely untouched. `
_sanitize_for_json` then turns EXACTLY those two shapes into NEW strings (a
sorted list of the set's raw elements; a bounded ``repr()`` of the object) --
strings created AFTER redaction has already run, so redact() never gets a
chance to look at them. A credential sitting inside a `set`, or embedded in
an object's `__repr__`, reached disk in the clear. `bytes` was fine only
because it is hashed rather than surfaced verbatim -- no content survives
either order for that one shape, which is why the original review missed it.

Fix (proxy/audit/writer.py, ``_writer_loop``): sanitize FIRST, then redact
the sanitized (fully JSON-native, all-string-shaped) result. This file pins
that order and does not regress, following the leak-corpus discipline used
in proxy/tests/test_audit_redactor_writepath.py:
  * the forbidden bytes are a LITERAL constant, never derived (no regex, no
    "longest high-entropy run" heuristic);
  * checked head-half and tail-half separately, in case a future change
    redacts only part of a value;
  * every assertion reads the REAL sink -- the JSONL file the real
    AuditWriter produced through its real async queue and writer loop -- not
    an in-memory return value from _sanitize_for_json or redact() directly.

Sibling: proxy/tests/test_audit_writer_nonserialisable.py pins that these
same shapes are not DROPPED; this file pins that they are not LEAKED.
"""
from __future__ import annotations

import json
from pathlib import Path

from proxy.audit.writer import AuditWriter

# The exact forbidden literal, named up front and never derived. Any fragment
# of it appearing anywhere in the file content is unambiguous evidence.
SECRET = "sk-ant-api03-" + "Qx7Az9Bw2Ck4Dm6Fn8" * 3  # realistic 40+ char key body
_HALF = len(SECRET) // 2
SECRET_HEAD = SECRET[:_HALF]
SECRET_TAIL = SECRET[_HALF:]
assert len(SECRET_HEAD) >= 16 and len(SECRET_TAIL) >= 16, "halves too short to be evidence"


class HolderWithSecretRepr:
    """
    An object whose __repr__ embeds a credential.

    Invisible to redact() on its own -- it is neither a str nor a dict/list
    it descends into. Only _sanitize_for_json's repr()-fallback turns it into
    a string, which is exactly why that step must run before redact(), not
    after.
    """

    def __repr__(self) -> str:
        return f"HolderWithSecretRepr(api_key={SECRET!r})"


def _writer(tmp_path: Path) -> AuditWriter:
    return AuditWriter(log_path=str(tmp_path / "audit.jsonl"), retention_days=365)


async def _write_and_read_raw(tmp_path: Path, record: dict) -> str:
    """
    Write ONE record through the REAL async writer loop and read the RAW
    bytes back off disk -- the actual sink, not a return value handed back
    from calling _sanitize_for_json / redact() directly in-memory.
    """
    writer = _writer(tmp_path)
    await writer.start()
    await writer.write(record)
    await writer.stop()  # drains the queue -- the write has landed (or failed) by the time this returns
    assert writer.log_path.exists(), "POSITIVE CONTROL FAILED: no audit file written at all."
    return writer.log_path.read_text(encoding="utf-8")


def _assert_secret_absent(content: str, case: str) -> None:
    assert SECRET not in content, f"{case}: the FULL secret reached disk."
    assert SECRET_HEAD not in content, f"{case}: the secret's HEAD half reached disk."
    assert SECRET_TAIL not in content, f"{case}: the secret's TAIL half reached disk."


def _only_record(content: str) -> dict:
    lines = [json.loads(ln) for ln in content.splitlines() if ln.strip()]
    assert len(lines) == 1, f"POSITIVE CONTROL FAILED: expected exactly 1 record, got {len(lines)}."
    return lines[0]


# ---------------------------------------------------------------------------
# THE CHECKS: shapes only the sanitizer can see must still come out redacted
# ---------------------------------------------------------------------------

async def test_secret_inside_a_bare_set_is_redacted_on_the_real_sink(tmp_path):
    """A `set` is not a container redact() enters -- only sanitizing it into
    a list makes the secret visible to the redactor at all."""
    content = await _write_and_read_raw(tmp_path, {
        "detection_id": "det-set-secret",
        "triggered": {SECRET, "unique_word_ratio", "entropy_spike"},
    })
    record = _only_record(content)
    assert record["detection_id"] == "det-set-secret", (
        "POSITIVE CONTROL FAILED: the record did not reach disk intact."
    )

    _assert_secret_absent(content, "secret inside a bare set")

    # Positive control: the OTHER (non-secret) set members must survive --
    # a scrubber that eats the whole field is also a defect.
    assert "unique_word_ratio" in content and "entropy_spike" in content, (
        "POSITIVE CONTROL FAILED: non-secret set members were destroyed too."
    )


async def test_secret_in_an_object_repr_is_redacted_on_the_real_sink(tmp_path):
    """An arbitrary object is not a string redact() can scan -- only
    sanitizing it into repr() text makes the embedded secret visible."""
    content = await _write_and_read_raw(tmp_path, {
        "detection_id": "det-repr-secret",
        "context": HolderWithSecretRepr(),
    })
    record = _only_record(content)
    assert record["detection_id"] == "det-repr-secret", (
        "POSITIVE CONTROL FAILED: the record did not reach disk intact."
    )

    _assert_secret_absent(content, "secret inside an object's __repr__")

    assert "HolderWithSecretRepr" in content, (
        "POSITIVE CONTROL FAILED: the non-secret type-name context was destroyed too."
    )


async def test_secret_nested_in_a_set_inside_a_dict_is_redacted_on_the_real_sink(tmp_path):
    """
    The set does not have to be a top-level field. Nested inside a dict --
    e.g. a features-triggered set on a nested detail object -- is the more
    realistic production shape, and recursion must carry the fix down to it.
    """
    content = await _write_and_read_raw(tmp_path, {
        "detection_id": "det-nested-set-secret",
        "detail": {
            "features": {SECRET, "keyword_density"},
            "note": "nested-context-survives",
        },
    })
    record = _only_record(content)
    assert record["detection_id"] == "det-nested-set-secret", (
        "POSITIVE CONTROL FAILED: the record did not reach disk intact."
    )

    _assert_secret_absent(content, "secret inside a set nested inside a dict")

    assert "nested-context-survives" in content and "keyword_density" in content, (
        "POSITIVE CONTROL FAILED: surrounding nested content was destroyed too."
    )


# ---------------------------------------------------------------------------
# Positive control: a scrubber that eats everything is also a defect
# ---------------------------------------------------------------------------

async def test_non_secret_content_survives_the_sanitize_then_redact_pipeline(tmp_path):
    """
    Sanity check on the fix itself: sanitize-then-redact must not turn into
    over-redaction of content that was never a secret. Read off the real
    parsed record (not just raw string containment) so a value surviving in
    a mangled form does not pass by accident.
    """
    content = await _write_and_read_raw(tmp_path, {
        "detection_id": "det-benign",
        "risk_level": "LOW",
        "triggered": {"unique_word_ratio", "keyword_density"},
        "context": {"note": "nothing sensitive here", "count": 3},
    })
    record = _only_record(content)

    assert record["risk_level"] == "LOW", "POSITIVE CONTROL FAILED: risk_level destroyed."
    assert set(record["triggered"]) == {"unique_word_ratio", "keyword_density"}, (
        f"POSITIVE CONTROL FAILED: benign set content destroyed: {record['triggered']!r}"
    )
    assert record["context"]["note"] == "nothing sensitive here", (
        "POSITIVE CONTROL FAILED: benign nested string content destroyed."
    )
    assert record["context"]["count"] == 3, (
        "POSITIVE CONTROL FAILED: benign nested int content destroyed."
    )
