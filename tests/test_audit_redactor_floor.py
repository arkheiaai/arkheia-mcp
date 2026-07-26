"""
FLOOR INVARIANT — secrets must not reach disk through the audit write path.

Floor tier contract: stdlib-only (``asyncio`` / ``ast`` / ``hashlib`` /
``json`` / ``pathlib`` / ``re``). No third-party import, no socket, no app
startup, so this runs under a bare ``pytest`` with zero project dependencies
and has zero interpreter variance.

------------------------------------------------------------------------------
What this pins, and why it is shaped this way
------------------------------------------------------------------------------
``proxy/audit/redactor.py`` claims to scrub secrets *before any record is
written to disk*. Before this file, NO test of it existed anywhere in the
repo, so neither its misses nor its over-matches were observed.

Two deliberate design choices, both earned from real incidents:

1. **The test drives the REAL WRITE PATH; it never calls ``redact()``
   directly.** A test that calls the redactor and asserts on the redactor's
   return value only proves the redactor is self-consistent — it cannot see
   the defect that actually matters, which is a write path that bypasses the
   redactor. So every assertion here goes through the production
   ``AuditWriter`` (queue → ``_writer_loop`` → ``redact()`` → hash chain →
   ``open(..., "a")``) and then **reads the bytes back off disk**.

2. **Every negative assertion carries a POSITIVE CONTROL.** ``assert secret
   not in content`` passes when the file is empty, when the write silently
   failed, when the record was dropped by an exception in the writer loop, and
   when the path is wrong. Each check therefore also asserts that the
   surrounding audit content IS on disk and only the secret is gone. An empty
   or missing file fails these tests rather than passing them.

Corpus provenance: every credential-shaped string below is SYNTHETIC, built
here from a seeded PRNG. No real credential is embedded in this file, and none
is ever printed — assertion messages name the SHAPE, never the value.
"""
from __future__ import annotations

import ast
import asyncio
import json
import random
import re
import string
from pathlib import Path

from proxy.audit.writer import AuditWriter

# Repo root: this file is <root>/tests/test_audit_redactor_floor.py
ROOT = Path(__file__).resolve().parents[1]

_ALNUM = string.ascii_letters + string.digits
_HEX = "0123456789abcdef"
_B64URL = _ALNUM + "-_"
_B64STD = _ALNUM + "+/"

REDACTION_MARKER = "[REDACTED:"


def _rnd(n: int, alphabet: str = _ALNUM, seed: int = 0) -> str:
    """Deterministic synthetic high-entropy body. Never a real credential."""
    rng = random.Random(f"arkheia-floor-{seed}-{n}-{len(alphabet)}")
    return "".join(rng.choice(alphabet) for _ in range(n))


# ---------------------------------------------------------------------------
# The corpus: shapes that ACTUALLY OCCUR in this system.
#
# `(shape, value)` — every one MUST be absent from disk. Structural cases at
# the end cover the forms a credential takes in a real store: a bare value on
# its own line with no `KEY=` prefix, a value under a `====label====` heading,
# a value inside JSON, and a value inside a quoted shell command. A pattern
# that only matched `KEY=value` would pass an invented corpus and still leak
# every one of those.
# ---------------------------------------------------------------------------

SECRET_SHAPES: list[tuple[str, str]] = [
    # --- provider API keys, value-shaped ---
    ("openai-project",        "sk-proj-" + _rnd(40, seed=1)),
    ("openai-classic",        "sk-" + _rnd(48, seed=2)),
    ("anthropic",             "sk-ant-api03-" + _rnd(80, seed=3)),
    ("xai",                   "xai-" + _rnd(40, seed=4)),
    ("google-api-key",        "AIzaSy" + _rnd(33, seed=5)),
    ("resend-plain",          "re_" + _rnd(24, seed=6)),
    ("resend-with-separator", "re_" + _rnd(9, seed=7) + "_" + _rnd(24, seed=8)),
    ("vercel-auth",           "vca_" + _rnd(24, seed=9)),
    ("vercel-project",        "vcp_" + _rnd(24, seed=10)),
    ("stripe-live",           "sk_live_" + _rnd(32, seed=11)),
    # --- source-control / cloud credentials ---
    ("github-fine-grained",   "github_pat_" + _rnd(70, _ALNUM + "_", seed=12)),
    ("github-classic-ghp",    "ghp_" + _rnd(36, seed=13)),
    ("github-oauth-gho",      "gho_" + _rnd(36, seed=14)),
    ("github-server-ghs",     "ghs_" + _rnd(36, seed=15)),
    ("aws-access-key-id",     "AKIA" + _rnd(16, string.ascii_uppercase + string.digits, seed=16)),
    ("slack-bot-token",       "xoxb-" + _rnd(12, string.digits, seed=17) + "-" + _rnd(24, seed=18)),
    # --- Arkheia's own keys, both body classes ---
    ("arkheia-live-hex",      "ak_live_" + _rnd(32, _HEX, seed=19)),
    ("arkheia-live-mixed",    "ak_live_" + _rnd(32, string.ascii_uppercase + string.digits, seed=20)),
    # --- JWTs: long AND short. A length-only rule missed the short one. ---
    ("jwt-long",              "eyJ" + _rnd(30, _B64URL, seed=21) + "."
                              + _rnd(120, _B64URL, seed=22) + "." + _rnd(43, _B64URL, seed=23)),
    ("jwt-short",             "eyJhbGciOiJIUzI1NiJ9." + _rnd(30, _B64URL, seed=24)
                              + "." + _rnd(27, _B64URL, seed=25)),
    # --- opaque credentials with no body shape ---
    ("bearer-header",         "Authorization: Bearer " + _rnd(64, seed=26)),
    ("bearer-lowercase",      "authorization: bearer " + _rnd(64, seed=27)),
    ("pat-292-char",          "access_token=" + _rnd(292, seed=28)),
    ("aws-secret-access-key", "aws_secret_access_key=" + _rnd(40, _B64STD, seed=29)),
    ("conn-string-password",  "postgresql://svc:" + _rnd(24, seed=30) + "@db.internal:5432/arkheia"),
    ("pem-private-key",       "-----BEGIN RSA PRIVATE KEY-----\n"
                              + _rnd(64, seed=31) + "\n-----END RSA PRIVATE KEY-----"),
    # --- structural forms: the shapes a real credentials file actually uses ---
    ("bare-value-own-line",   "\n" + "sk-ant-api03-" + _rnd(80, seed=32) + "\n"),
    ("under-equals-label",    "====SCANNER API TOKEN====\n" + "sk-ant-api03-" + _rnd(80, seed=33)),
    ("inside-json",           '{"api_key": "sk-ant-api03-' + _rnd(80, seed=34) + '"}'),
    ("inside-quoted-shell",   "curl -H 'x-api-key: sk-ant-api03-" + _rnd(80, seed=35)
                              + "' https://api.example"),
    ("key-eq-value-form",     "ANTHROPIC_API_KEY=sk-ant-api03-" + _rnd(80, seed=36)),
]

# ---------------------------------------------------------------------------
# Near-misses: audit content that MUST survive verbatim. Over-redaction that
# eats audit content is also a defect — an audit log scrubbed to uselessness
# fails its own purpose.
# ---------------------------------------------------------------------------

MUST_SURVIVE: list[tuple[str, str]] = [
    ("git-sha40",          _rnd(40, _HEX, seed=40)),
    ("git-sha7",           _rnd(7, _HEX, seed=41)),
    ("sha256-hex",         _rnd(64, _HEX, seed=42)),
    ("uuid4",              "3f9a1c22-7b1e-4d0a-9e3f-2c8b7a1d4e55"),
    ("iso8601-timestamp",  "2026-07-26T17:05:00+00:00"),
    ("model-id",           "claude-opus-4-5-20260101"),
    ("base64-png-payload", "iVBORw0KGgoAAAANSUhEUg" + _rnd(200, _B64STD, seed=43) + "=="),
    ("base64-json-blob",   "eyJ" + _rnd(200, _B64URL, seed=44)),
    ("feature-names",      "unique_word_ratio, hedge_density, type_token_ratio"),
    ("absolute-path",      "/var/log/arkheia/audit.jsonl"),
    ("upstream-url",       "https://api.anthropic.com/v1/messages"),
    ("prose",              "The response cited four sources, three of which resolve."),
]

# A stable non-secret token written alongside every record. Its presence on
# disk is the POSITIVE CONTROL: it proves the record actually reached the file,
# so a "secret not present" assertion cannot pass on an empty/missing file.
SENTINEL = "arkheia-floor-positive-control-sentinel"


# ---------------------------------------------------------------------------
# The real write path
# ---------------------------------------------------------------------------

def _drive_real_write_path(records: list[dict], log_path: Path) -> str:
    """
    Push records through the PRODUCTION AuditWriter and return the raw file text.

    This is the same code path every proxy endpoint uses: ``write()`` enqueues,
    the background ``_writer_loop`` redacts, chain-hashes and appends to disk.
    The test never calls ``redact()`` itself, so a write path that bypassed the
    redactor would be visible here.
    """
    async def _run() -> None:
        writer = AuditWriter(str(log_path))
        await writer.start()
        for rec in records:
            await writer.write(rec)
        await writer.stop()

    asyncio.run(_run())
    assert log_path.exists(), (
        f"POSITIVE CONTROL FAILED: the production write path produced no file at "
        f"{log_path}. Every 'secret absent' assertion would pass vacuously."
    )
    return log_path.read_text(encoding="utf-8")


def _record(shape: str, secret: str) -> dict:
    """An audit record shaped like the real ones, carrying a secret and the sentinel."""
    return {
        "detection_id": f"det-{shape}",
        "timestamp": "2026-07-26T17:05:00+00:00",
        "session_id": secret,          # caller-supplied, reaches disk verbatim
        "model_id": "claude-opus-4-5",
        "risk_level": "LOW",
        "confidence": 0.42,
        "features_triggered": ["unique_word_ratio", secret],
        "action_taken": "pass",
        "source": SENTINEL,
        "note": f"context before {secret} context after",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_secret_shape_survives_the_real_write_path(tmp_path):
    """
    Every credential shape that occurs in this system is absent from the file
    on disk, while the surrounding audit content is present.

    Assertion messages name the SHAPE only. A redaction test that printed the
    value it failed to redact would be its own leak.
    """
    assert SECRET_SHAPES, "corpus is empty — this test would assert nothing"

    log_path = tmp_path / "audit.jsonl"
    records = [_record(shape, secret) for shape, secret in SECRET_SHAPES]
    content = _drive_real_write_path(records, log_path)

    # --- POSITIVE CONTROLS: the records really landed, in full ---
    lines = [ln for ln in content.splitlines() if ln.strip()]
    assert len(lines) == len(SECRET_SHAPES), (
        f"POSITIVE CONTROL FAILED: expected {len(SECRET_SHAPES)} records on disk, "
        f"found {len(lines)}. Records were dropped, so 'secret absent' proves nothing."
    )
    assert content.count(SENTINEL) == len(SECRET_SHAPES), (
        f"POSITIVE CONTROL FAILED: sentinel appears {content.count(SENTINEL)} times, "
        f"expected {len(SECRET_SHAPES)} — audit content is missing, not just the secret."
    )
    for shape, _secret in SECRET_SHAPES:
        assert f"det-{shape}" in content, (
            f"POSITIVE CONTROL FAILED: record for shape {shape!r} is not on disk."
        )
    # Chain fields prove the write went through the production loop, not a stub.
    first = json.loads(lines[0])
    assert first["seq"] == 1 and len(first["this_hash"]) == 64, (
        "POSITIVE CONTROL FAILED: hash-chain fields absent — this was not the real write path."
    )
    assert REDACTION_MARKER in content, (
        "POSITIVE CONTROL FAILED: no redaction marker anywhere on disk — the redactor "
        "did not run at all on the production write path."
    )

    # --- THE ACTUAL CHECK: no secret body survives ---
    leaked = [shape for shape, secret in SECRET_SHAPES if _secret_body(secret) in content]
    assert not leaked, (
        "secret shapes reached disk UNREDACTED through the production audit write path "
        f"({len(leaked)} of {len(SECRET_SHAPES)}): {sorted(leaked)}. "
        "Values deliberately not printed."
    )


def _secret_body(secret: str) -> str:
    """
    The part of a corpus entry that must never reach disk.

    For labelled entries the LABEL is audit content and is expected to survive
    (`aws_secret_access_key=[REDACTED:…]` is the correct outcome), so the check
    targets the credential body — the longest high-entropy run in the value.
    """
    runs = re.findall(r'[A-Za-z0-9+/_-]{16,}', secret)
    assert runs, f"corpus entry has no high-entropy body to check: {len(secret)} chars"
    return max(runs, key=len)


def test_near_miss_audit_content_survives_verbatim(tmp_path):
    """
    Over-redaction guard: shas, UUIDs, timestamps, model ids, base64 payloads,
    feature names, paths, URLs and prose must reach disk UNCHANGED. An audit
    log scrubbed to uselessness fails its own purpose.
    """
    assert MUST_SURVIVE, "near-miss corpus is empty — this test would assert nothing"

    log_path = tmp_path / "audit.jsonl"
    records = [
        {"detection_id": f"det-{label}", "source": SENTINEL, "value": value}
        for label, value in MUST_SURVIVE
    ]
    content = _drive_real_write_path(records, log_path)

    lines = [ln for ln in content.splitlines() if ln.strip()]
    assert len(lines) == len(MUST_SURVIVE), (
        f"POSITIVE CONTROL FAILED: expected {len(MUST_SURVIVE)} records, found {len(lines)}."
    )

    eaten = []
    for (label, value), line in zip(MUST_SURVIVE, lines):
        record = json.loads(line)
        if record["value"] != value:
            eaten.append(label)
    assert not eaten, (
        "the redactor OVER-MATCHED and destroyed audit content for: "
        f"{sorted(eaten)}. Over-redaction is a defect: it makes the audit log "
        "useless for the purpose it exists to serve."
    )


def test_secret_in_a_field_NAME_does_not_reach_disk(tmp_path):
    """
    A credential placed in a dict KEY is just as durable on disk as one in a
    value. Key-space was previously untouched by the redactor.
    """
    secret = "sk-ant-api03-" + _rnd(80, seed=50)
    log_path = tmp_path / "audit.jsonl"
    content = _drive_real_write_path(
        [{"detection_id": "det-keyname", "source": SENTINEL, secret: "was-used"}],
        log_path,
    )

    assert SENTINEL in content and "was-used" in content, (
        "POSITIVE CONTROL FAILED: the record did not reach disk, so 'secret absent' "
        "would pass vacuously."
    )
    assert secret not in content, (
        "a secret used as a FIELD NAME reached disk unredacted (value not printed)."
    )


def test_split_secret_head_is_redacted_known_partial(tmp_path):
    """
    KNOWN PARTIAL, pinned deliberately rather than left as a silent surprise.

    A credential split across a line break is only partly recoverable by a
    shape-based redactor: the prefixed head is redacted, the suffix after the
    newline is an unprefixed high-entropy run indistinguishable from a hash or
    a base64 payload. Catching it needs an entropy heuristic, which over-
    redacts the near-miss corpus above. This asserts the half we DO guarantee,
    so a regression that stops redacting the head goes red.
    """
    head = "sk-ant-api03-" + _rnd(30, seed=51)
    tail = _rnd(60, seed=52)
    log_path = tmp_path / "audit.jsonl"
    content = _drive_real_write_path(
        [{"detection_id": "det-split", "source": SENTINEL, "blob": head + "\n" + tail}],
        log_path,
    )

    assert SENTINEL in content, "POSITIVE CONTROL FAILED: record not on disk."
    assert head not in content, (
        "the prefixed HEAD of a newline-split credential reached disk unredacted."
    )
    assert REDACTION_MARKER in content, (
        "no redaction happened at all on the split-credential record."
    )


# ---------------------------------------------------------------------------
# Structural invariants — is the redactor on EVERY path that writes to disk?
#
# A redactor that is correct but not universally applied is the "wired but
# switched off" defect class. These reason over source text (ast), so they run
# in the floor tier with no dependencies.
# ---------------------------------------------------------------------------

PROD_DIRS = ("proxy", "mcp_server", "registry_server")
PROD_ROOT_FILES = ("server.py",)

# Every production disk-write / persistence sink, with its redaction
# disposition and the reason for it. A sink NOT in this registry fails the
# build: a new writer must be classified, because "is the redactor on every
# path that writes to disk?" cannot be answered by a redactor test alone.
#
#   REDACTED         — the record passes through redact() before it is written.
#   PRE_REDACTED     — rewrites bytes that were already redacted on write.
#   NO_CALLER_DATA   — writes only self-derived or already-validated data
#                      (hashes, file lists, a profile we previously persisted);
#                      no free-text caller/model string can reach it.
#   SECRET_BY_DESIGN — the file's PURPOSE is to hold a credential. Redaction
#                      would break it; the control is file access, not scrubbing.
#   UNREDACTED_GAP   — free-text caller/model data reaches disk with NO scrub.
#                      A live finding. This bucket is a RATCHET: it may only SHRINK.
DISK_SINKS: dict[str, tuple[str, str]] = {
    "proxy/audit/writer.py:_writer_loop": (
        "REDACTED",
        "redact() precedes the append; pinned by test_writer_loop_redacts_before_it_writes",
    ),
    "proxy/audit/writer.py:purge_old_records": (
        "PRE_REDACTED",
        "rewrites retained lines read back from the log, already redacted on write",
    ),
    "proxy/license/integrity.py:generate_manifest": (
        "NO_CALLER_DATA",
        "build-time manifest of .so/.pyd sha256 digests and filenames",
    ),
    "proxy/registry/client.py:_download_and_apply": (
        "NO_CALLER_DATA",
        "registry-supplied profile YAML, checksum- and schema-validated; not an audit record",
    ),
    "proxy/endpoints/admin.py:rollback_profile": (
        "NO_CALLER_DATA",
        "copies a .bak of a profile we previously persisted back over the live profile",
    ),
    "proxy/crypto/profile_crypto.py:_save_cache": (
        "SECRET_BY_DESIGN",
        "deliberate profile-decryption-key cache; holding the key IS the purpose",
    ),
    "mcp_server/tools/memory.py:_get_conn": (
        "UNREDACTED_GAP",
        "memory_store persists caller-supplied observation text to sqlite with NO scrub — "
        "the redactor is not applied on this disk path at all",
    ),
}

# The ratchet bound on UNREDACTED_GAP. Reduce it when a gap is closed; it must
# never rise. Named units, not an aggregate: the one current gap is
# mcp_server/tools/memory.py:_get_conn.
MAX_UNREDACTED_GAPS = 1

_WRITE_MODES = ("w", "a", "x", "+")


def _production_py_files() -> list[Path]:
    files: list[Path] = []
    for d in PROD_DIRS:
        for p in sorted((ROOT / d).rglob("*.py")):
            if "tests" in p.relative_to(ROOT).parts:
                continue
            files.append(p)
    for f in PROD_ROOT_FILES:
        p = ROOT / f
        if p.exists():
            files.append(p)
    return files


def _enclosing_function(tree: ast.AST, target: ast.AST) -> str:
    """Name of the innermost function containing `target`, or '<module>'."""
    best = "<module>"
    best_span = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end = getattr(node, "end_lineno", node.lineno)
        if node.lineno <= target.lineno <= end:
            span = end - node.lineno
            if best_span is None or span < best_span:
                best, best_span = node.name, span
    return best


def _discover_disk_sinks() -> dict[str, list[int]]:
    """
    Find every production call that persists bytes: open() in a write mode,
    Path.write_text/write_bytes, and sqlite3.connect(). Returns
    {"<relpath>:<function>": [linenos]}.
    """
    sinks: dict[str, list[int]] = {}
    for path in _production_py_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(ROOT).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            hit = False
            if name == "open":
                mode = ""
                if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for kw in node.keywords:
                    if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                        mode = str(kw.value.value)
                hit = any(m in mode for m in _WRITE_MODES)
            elif name in ("write_text", "write_bytes"):
                hit = True
            elif name == "connect":
                mod = func.value if isinstance(func, ast.Attribute) else None
                hit = isinstance(mod, ast.Name) and mod.id == "sqlite3"
            if hit:
                key = f"{rel}:{_enclosing_function(tree, node)}"
                sinks.setdefault(key, []).append(node.lineno)
    return sinks


def test_every_production_disk_sink_is_classified_for_redaction():
    """
    The sibling question: is the redactor on EVERY path that writes to disk?

    Fails on any sink absent from DISK_SINKS, so a new writer cannot land
    unclassified, and holds UNREDACTED_GAP as a shrink-only ratchet.
    """
    discovered = _discover_disk_sinks()
    assert discovered, (
        "discovered ZERO production disk sinks — the scan is misconfigured and this "
        "invariant would be vacuous (proxy/audit/writer.py alone has two)."
    )

    unclassified = sorted(set(discovered) - set(DISK_SINKS))
    assert not unclassified, (
        "production disk-write sink(s) with no redaction disposition — a path that "
        "writes to disk without a recorded scrub decision is exactly the "
        "'redactor correct but not universally applied' defect. Classify each in "
        "DISK_SINKS (REDACTED / PRE_REDACTED / NO_CALLER_DATA / UNREDACTED_GAP):\n  - "
        + "\n  - ".join(f"{k} (line(s) {discovered[k]})" for k in unclassified)
    )

    stale = sorted(set(DISK_SINKS) - set(discovered))
    assert not stale, (
        "DISK_SINKS names sink(s) that no longer exist — a registry that drifts from "
        "the code stops meaning anything. Remove: " + ", ".join(stale)
    )

    known = {"REDACTED", "PRE_REDACTED", "NO_CALLER_DATA", "SECRET_BY_DESIGN", "UNREDACTED_GAP"}
    bad = sorted(k for k, (d, _n) in DISK_SINKS.items() if d not in known)
    assert not bad, f"sink(s) carry an unrecognised disposition: {bad}"
    thin = sorted(k for k, (_d, n) in DISK_SINKS.items() if len(n.strip()) < 20)
    assert not thin, (
        f"sink(s) classified with no stated reason: {thin}. A disposition without a "
        f"reason is an assertion nobody can check."
    )

    gaps = sorted(k for k, (d, _n) in DISK_SINKS.items() if d == "UNREDACTED_GAP")
    assert len(gaps) <= MAX_UNREDACTED_GAPS, (
        f"unredacted disk sinks rose to {len(gaps)} (bound {MAX_UNREDACTED_GAPS}). "
        f"Named units, never an aggregate: {gaps}"
    )


def test_writer_loop_redacts_before_it_writes():
    """
    Ordering invariant inside the audit writer: the redact() call must precede
    the disk write in the same function. Correct-but-late redaction writes the
    secret and scrubs the copy.
    """
    src = (ROOT / "proxy/audit/writer.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    loop = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_writer_loop"),
        None,
    )
    assert loop is not None, (
        "AuditWriter._writer_loop not found — the audit write path was renamed or "
        "removed and this invariant no longer observes its subject."
    )

    redact_lines, write_lines = [], []
    for node in ast.walk(loop):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name == "redact":
            redact_lines.append(node.lineno)
        elif name == "open" or name == "write":
            write_lines.append(node.lineno)

    assert redact_lines, (
        "AuditWriter._writer_loop contains NO call to redact() — the audit write path "
        "no longer scrubs secrets before writing to disk."
    )
    assert write_lines, (
        "no disk-write call found in AuditWriter._writer_loop — this invariant lost its "
        "subject and would pass vacuously."
    )
    assert min(redact_lines) < min(write_lines), (
        f"redact() at line {min(redact_lines)} does not precede the disk write at line "
        f"{min(write_lines)}: the record is written before it is scrubbed."
    )


def test_redactor_pattern_tables_are_non_empty_and_value_anchored():
    """
    Guard the shape of the pattern policy itself.

    The incident this file is grounded in was a redaction rule that only
    matched ``KEY=value`` while the real store held BARE VALUES under
    ``====label====`` headings. So the value-anchored table must exist and must
    be the larger of the two: context-scoped patterns are an ADDITION for
    opaque credentials, never the primary mechanism.
    """
    from proxy.audit import redactor as R

    assert len(R._SECRET_PATTERNS) >= 10, (
        f"value-shaped pattern table has only {len(R._SECRET_PATTERNS)} entries."
    )
    assert len(R._LABELLED_SECRET_PATTERNS) >= 1, "context-scoped pattern table is empty."
    assert len(R._SECRET_PATTERNS) > len(R._LABELLED_SECRET_PATTERNS), (
        "context-scoped patterns now outnumber value-shaped ones. A redactor that "
        "leans on assignment context misses the bare-value form entirely — the exact "
        "shape of the incident this test exists for."
    )
    for label, pattern in R._LABELLED_SECRET_PATTERNS:
        groups = pattern.groupindex
        assert {"pre", "secret", "post"} <= set(groups), (
            f"context-scoped pattern {label!r} must expose pre/secret/post groups so "
            f"only the credential is replaced and the label survives as audit content."
        )
