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
import base64
import json
import os
import quopri
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


# --- transport encodings, for the wrapper corpus ---------------------------
# These are the encodings a credential picks up in transit. None of them is
# obfuscation: each is reversed for free by a grep-and-decode.

def _pct(s: str) -> str:
    """STRICT percent-encoding — every non-alphanumeric, hyphens included."""
    return "".join(c if c.isalnum() else "%%%02X" % ord(c) for c in s)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _b64url(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")


def _qp(s: str) -> str:
    return quopri.encodestring(s.encode()).decode()


def _hexenc(s: str) -> str:
    return s.encode().hex()


def _b32(s: str) -> str:
    return base64.b32encode(s.encode()).decode()


def _b64_wrapped(s: str) -> str:
    """MIME base64 — the body split across 76-column lines. What `base64(1)`,
    `openssl base64` and every email/attachment pipeline emit by default."""
    return base64.encodebytes(s.encode()).decode()


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

    # --- ENCODING WRAPPERS (Codex review, PR #16) -------------------------
    # Every pattern above matches the credential's PLAINTEXT body, so a
    # reversible transport encoding removes the anchor and the value reaches
    # disk fully recoverable. Note `quote(safe="")` alone does NOT reproduce
    # this: it leaves `-._~` untouched, so a hyphenated key is unchanged and
    # the plain pattern still fires. The leak needs a STRICT encoder.
    ("pct-encoded-anthropic",   "callback=" + _pct("sk-ant-api03-" + _rnd(60, seed=50))),
    ("pct-encoded-double",      "cb=" + _pct("sk-ant-api03-" + _rnd(60, seed=51)).replace("%", "%25")),
    ("pct-encoded-github-pat",  "next=" + _pct("ghp_" + _rnd(36, seed=52))),
    ("b64-wrapped-anthropic",   "payload=" + _b64("sk-ant-api03-" + _rnd(60, seed=53))),
    ("b64-wrapped-labelled-aws",
     "blob=" + _b64("aws_secret_access_key=" + _rnd(40, _B64STD, seed=54))),
    ("b64url-wrapped-xai",      "state=" + _b64url("xai-" + _rnd(40, seed=55))),
    # An OPAQUE body behind an encoding. The entries above all decode to a
    # value some pattern recognises, so `_contains_secret` alone catches them
    # and they do NOT exercise the encoded pass's opaque branch: a mutation
    # deleting that branch survived until this case existed. Percent-encoding
    # only escapes `+` and `/` in a base64 body, which is enough to shatter it
    # into sub-threshold fragments that the entropy rule cannot see.
    # The `+` and `/` are placed EXPLICITLY, not left to the PRNG: a seeded
    # 40-char draw happened to contain neither, percent-encoding was then a
    # no-op, and the case silently tested the plain opaque rule instead of the
    # encoded one. A corpus entry that does not contain the thing it is testing
    # is not a test.
    ("pct-encoded-opaque-in-context",
     "aws_secret=" + _pct(_rnd(24, _ALNUM, seed=64) + "/"
                          + _rnd(24, _ALNUM, seed=65))),

    # --- ARMOURED BLOCKS beyond PEM --------------------------------------
    # Same delimiter, same armour, different noun. The first pattern hardcoded
    # the `PRIVATE KEY` label, so PGP walked through.
    ("pgp-private-key-block",
     "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
     + _rnd(64, _B64STD, seed=58) + "\n" + _rnd(64, _B64STD, seed=59)
     + "\n-----END PGP PRIVATE KEY BLOCK-----"),
    ("openssh-private-key-block",
     "-----BEGIN OPENSSH PRIVATE KEY-----\n"
     + _rnd(64, _B64STD, seed=60) + "\n-----END OPENSSH PRIVATE KEY-----"),

    # --- OPAQUE values no prefix identifies -------------------------------
    # The shape the real incident had. No value-anchored pattern can EVER fire
    # on these: there is nothing to anchor to. Caught by entropy gated on
    # credential context, which is what the `====AWS PROD====` heading is.
    ("opaque-aws-under-equals-heading",
     "====AWS PROD====\n" + _rnd(40, _B64STD, seed=61)),
    ("opaque-aws-bare-line-in-context",
     "credentials\n" + _rnd(40, _B64STD, seed=62) + "\nend"),
    ("opaque-token-under-heading",
     "====SERVICE ACCESS TOKEN====\n" + _rnd(48, _B64STD, seed=63)),
]

# ---------------------------------------------------------------------------
# EXPLICIT-BODY corpus (Codex review round 3, PR #16).
#
# `_secret_body()` below derives "the part that must not reach disk" as the
# LONGEST high-entropy run in the value. That derivation is right for a plain
# credential and WRONG for the three classes here, and it fails SILENTLY —
# it reports `ok` for a value that is on disk in full:
#
#   * a line-wrapped base64 body — the longest run is one 76-column fragment,
#     and redacting only the fragment that happens to carry the prefix leaves
#     every other fragment (i.e. most of the credential) on disk;
#   * a data-URI-poisoned line — the longest run is the PNG payload, which is
#     audit content and is supposed to survive, so the check reads `ok` while
#     the credential beside it leaks;
#   * a URI inline password — the password is split by the very characters
#     (`/ : ? #`) the run regex uses as boundaries.
#
# So each entry names its own forbidden bodies. `bodies` is a tuple because a
# split credential must be checked HALF BY HALF: asserting only on the whole
# password passes when half of it survives.
#
#   (shape, value, bodies-that-must-not-reach-disk)
# ---------------------------------------------------------------------------

_ANT = "sk-ant-api03-" + _rnd(60, seed=80)
_OPAQUE = _rnd(20, _ALNUM, seed=81) + "/" + _rnd(19, _ALNUM, seed=82)
_DATA_URI = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg" + _rnd(48, _B64STD, seed=83)

_PW_A = _rnd(12, seed=84)
_PW_B = _rnd(12, seed=85)

EXPLICIT_BODY_LEAKS: list[tuple[str, str, tuple[str, ...]]] = [
    # --- CLASS A: encoding normalisation is SHALLOW, PARTIAL and TOKEN-LOCAL.
    # `_decoded_views()` decodes a token exactly once per codec and knows only
    # percent and base64. Every gap below is a reversible transform a grep
    # undoes for free — the value reaches disk fully recoverable.
    #
    # A.1 no recursion: a decoded view is never itself decoded, so COMPOSING
    #     two encodings (or repeating one) restores nothing to scan.
    ("b64-double-wrapped",
     "payload=" + _b64(_b64(_ANT)),
     (_b64(_b64(_ANT)).rstrip("="),)),
    ("b64-triple-wrapped",
     "p=" + _b64(_b64(_b64(_ANT))),
     (_b64(_b64(_b64(_ANT))).rstrip("="),)),
    ("b64-of-percent-encoded",
     "payload=" + _b64(_pct(_ANT)),
     (_b64(_pct(_ANT)).rstrip("="),)),
    ("percent-of-b64",
     "cb=" + _pct(_b64(_ANT)),
     (_pct(_b64(_ANT)),)),
    # A.2 only two codecs: hex and base32 are ordinary transport encodings and
    #     neither is decoded at all.
    ("hex-encoded-lowercase", "blob=" + _hexenc(_ANT), (_hexenc(_ANT),)),
    ("hex-encoded-uppercase", "blob=" + _hexenc(_ANT).upper(), (_hexenc(_ANT).upper(),)),
    ("base32-encoded", "blob=" + _b32(_ANT), (_b32(_ANT).rstrip("="),)),

    # --- CLASS B: a BENIGN marker disables the whole line's protection.
    # `_redact_encoded_and_opaque` skips an entire line when it contains a data
    # URI. The exemption is right about the PNG payload and wrong about its
    # blast radius: every other token on that line loses the encoding pass AND
    # the opaque-entropy pass. One legitimate token must not switch off a
    # control for everything beside it.
    ("data-uri-poisons-line-opaque-value",
     "====AWS PROD==== " + _DATA_URI + " " + _OPAQUE,
     (_OPAQUE,)),
    ("data-uri-poisons-line-encoded-value",
     _DATA_URI + " callback=" + _pct(_ANT),
     (_pct(_ANT),)),
    ("data-uri-poisons-line-multiline",
     "detection complete\n" + _DATA_URI + " cb=" + _pct(_ANT),
     (_pct(_ANT),)),

    # --- CLASS C: the URI inline-password rule cannot see its own subject.
    # `conn_password`'s secret class is `[^\s:/?#@]{6,}`, so a password holding
    # any URI-reserved character never matches, and its user class is `+`, so
    # the empty-userinfo form (`redis://:pw@host`) never matches either. The
    # opaque-entropy rule cannot rescue either: `_CREDENTIAL_CONTEXT` has no
    # URI/DSN term, so a bare DSN line carries no credential context at all.
    # Generated DB passwords routinely contain `/` and `+`.
    ("conn-password-containing-slash",
     "postgresql://svc:" + _PW_A + "/" + _PW_B + "@db.internal:5432/arkheia",
     (_PW_A, _PW_B)),
    ("conn-password-containing-colon",
     "mongodb://svc:" + _PW_A + ":" + _PW_B + "@db.internal:27017/arkheia",
     (_PW_A, _PW_B)),
    ("conn-password-containing-hash",
     "amqp://svc:" + _PW_A + "#" + _PW_B + "@mq.internal:5672/vhost",
     (_PW_A, _PW_B)),
    ("conn-password-containing-question",
     "redis://svc:" + _PW_A + "?" + _PW_B + "@cache.internal:6379/0",
     (_PW_A, _PW_B)),
    ("conn-password-empty-userinfo",
     "redis://:" + _rnd(24, seed=86) + "@cache.internal:6379/0",
     (_rnd(24, seed=86),)),
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

    # --- ADVERSARIAL near-misses (Codex review, PR #16) -------------------
    # The opaque-value rule fires on ENTROPY gated by CONTEXT, so the cases
    # that matter are legitimate audit content sitting NEXT TO a credential
    # word. Entropy alone would eat every one of these, and an audit log
    # scrubbed to uselessness fails its own purpose just as surely as a leaky
    # one fails its own. Each is excluded structurally — hex-only, UUID shape,
    # no letters, or base64 that unwraps to clean text — not by a length
    # threshold that would drift.
    ("sha256-under-apikey-heading",
     "====api_key rotation audit====\n" + _rnd(64, _HEX, seed=70)),
    ("git-sha-in-secret-scan-line",
     "secret scan completed at commit " + _rnd(40, _HEX, seed=71)),
    ("uuid-beside-token-label",
     "token_request_id=3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
    ("docker-digest-in-credentials-line",
     "credentials image sha256:" + _rnd(58, _HEX, seed=72)),
    ("data-uri-png-under-password-heading",
     "====password reset email====\ndata:image/png;base64,iVBORw0KGgoAAAANSUhEUg"
     + _rnd(200, _B64STD, seed=73) + "=="),
    ("detection-id-near-auth",
     "auth event det_01HQ8X7Y6Z5W4V3U2T1S0R9Q8P recorded"),
    ("numeric-id-near-secret",
     "secret rotation for account 884723519920347715"),
    ("model-id-near-apikey",
     "api_key profile for claude-opus-4-8-20260115 loaded"),
    ("upper-constant-near-key",
     "key ARKHEIA_DETECTION_ENGINE_VERSION_TWO_POINT_ZERO"),
    ("b64-prose-near-token",
     "token note " + _b64("the quick brown fox jumps over the lazy dog")),
    ("pct-encoded-docs-url-near-apikey",
     "apikey docs https%3A%2F%2Fdocs.arkheia.ai%2Fguide%2Fgetting-started"),
    ("chain-hash-field-near-secret",
     "secret chain this_hash " + "0" * 64),
    ("semver-near-private-key",
     "private_key rotation shipped in v2.14.3+build.20260726.a1b2c3d"),
    ("prose-with-password-word",
     "The password policy requires rotation every ninety days for operators."),
    # MIXED-CASE hex and UUID. The lowercase forms above are excluded by the
    # upper/lower/digit rule alone, so they do NOT exercise the hex-only and
    # UUID guards; a mutation deleting those guards survived until these two
    # cases existed. Mixed-case digests and UUIDs occur wherever a value has
    # been through a display layer.
    ("mixed-case-hex-digest-near-secret",
     "secret chain 9F8e7D6c5B4a39281706F5e4D3c2B1a098765432abcd1234abcd1234"),
    ("mixed-case-uuid-near-token",
     "token id 3F2504e0-4F89-11d3-9A0c-0305E82c3301"),

    # --- Over-redaction guards for the round-3 fix (Codex review, PR #16) ---
    # Recursive multi-codec decoding and line de-wrapping widen what the
    # redactor LOOKS at. What it looks at must not become what it eats: a
    # decoded view may only trigger redaction when the DECODED text itself
    # holds a credential. These are the shapes that decode cleanly and hold
    # nothing, sitting in credential context so the entropy gate is open.
    ("hex-of-prose-near-secret",
     "secret note " + _hexenc("the quick brown fox jumps over the lazy dog")),
    ("base32-of-prose-near-token",
     "token note " + _b32("the quick brown fox jumps over the lazy dog")),
    ("nested-b64-of-prose-near-credentials",
     "credentials note " + _b64(_b64("the quick brown fox jumps over the lazy dog"))),
    # Line de-wrapping joins consecutive base64-ish lines. Wrapped BINARY
    # payloads and wrapped digests are exactly the audit content it must not
    # eat once it starts reassembling runs of lines.
    ("wrapped-base64-png-lines",
     "\n".join(("iVBORw0KGgoAAAANSUhEUg" + _rnd(228, _B64STD, seed=90))[i:i + 76]
               for i in range(0, 228, 76))),
    ("wrapped-hex-digest-lines-near-secret",
     "secret chain\n" + _rnd(64, _HEX, seed=91) + "\n" + _rnd(64, _HEX, seed=92)),
    # The URI inline-password rule is widened to accept URI-reserved characters
    # in the password. It must still not fire on a URL whose `:` is a PORT and
    # whose `@` is in the path — the shape that widening most easily eats.
    ("url-with-port-and-at-in-path",
     "http://localhost:8000/reports/user@example.com"),
    ("npm-scoped-package-url",
     "https://cdn.jsdelivr.net/npm/@vue/cli/dist/index.js"),
    # The data-URI exemption narrows from "skip the line" to "skip the payload".
    # The payload itself must still survive, including alongside other content.
    ("data-uri-beside-audit-content",
     "det_01HQ8X7Y6Z5W4V3U2T1S0R9Q8P " + _DATA_URI + " commit " + _rnd(40, _HEX, seed=93)),
    # The `_plausible_text` binary gate — the guard that stops decoding from
    # judging a payload by the MOJIBAKE inside it. It is NOT redundant with the
    # UTF-8 decode that follows it: these bytes decode cleanly (every byte is
    # < 0x80) while being 60% non-printable, and the printable part is a
    # 40-char high-entropy id. Remove the gate and the decoded view looks like
    # an opaque credential in credential context, so a wire frame captured into
    # an audit field is eaten. A mutation deleting the gate SURVIVED until this
    # case existed; the corpus held nothing that decoded to valid-UTF-8 binary.
    ("hex-encoded-binary-frame-near-credentials",
     "credentials frame "
     + (b"\x01\x00\x00\x2c" + _rnd(40, seed=95).encode() + b"\x00" * 24).hex()),
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


def test_explicit_body_leak_classes_do_not_reach_disk(tmp_path):
    """
    The three classes the derived-body check above cannot see.

    Each entry names the exact bytes that must be absent, half by half where
    the credential is split, so a partial survival cannot read as a pass.
    """
    assert EXPLICIT_BODY_LEAKS, "corpus is empty — this test would assert nothing"

    log_path = tmp_path / "audit.jsonl"
    records = [_record(shape, value) for shape, value, _bodies in EXPLICIT_BODY_LEAKS]
    content = _drive_real_write_path(records, log_path)

    # --- POSITIVE CONTROLS ---
    lines = [ln for ln in content.splitlines() if ln.strip()]
    assert len(lines) == len(EXPLICIT_BODY_LEAKS), (
        f"POSITIVE CONTROL FAILED: expected {len(EXPLICIT_BODY_LEAKS)} records on disk, "
        f"found {len(lines)} — records were dropped, so 'secret absent' proves nothing."
    )
    assert content.count(SENTINEL) == len(EXPLICIT_BODY_LEAKS), (
        "POSITIVE CONTROL FAILED: audit content is missing, not just the secret."
    )
    for shape, _v, _b in EXPLICIT_BODY_LEAKS:
        assert f"det-{shape}" in content, (
            f"POSITIVE CONTROL FAILED: record for shape {shape!r} is not on disk."
        )
    first = json.loads(lines[0])
    assert first["seq"] == 1 and len(first["this_hash"]) == 64, (
        "POSITIVE CONTROL FAILED: hash-chain fields absent — not the real write path."
    )

    # --- THE ACTUAL CHECK ---
    leaked = []
    for shape, _value, bodies in EXPLICIT_BODY_LEAKS:
        assert bodies, f"corpus entry {shape!r} names no forbidden body"
        for i, body in enumerate(bodies):
            assert len(body) >= 8, (
                f"corpus entry {shape!r} body #{i} is only {len(body)} chars — too "
                f"short to be evidence of anything."
            )
            if body in content:
                leaked.append(shape if len(bodies) == 1 else f"{shape}[{i}]")
    assert not leaked, (
        "secret material reached disk UNREDACTED through the production audit write "
        f"path ({len(leaked)} of {sum(len(b) for _s, _v, b in EXPLICIT_BODY_LEAKS)} "
        f"checked bodies): {sorted(leaked)}. Values deliberately not printed."
    )


def test_line_wrapped_base64_credential_does_not_survive_in_fragments(tmp_path):
    """
    MIME base64 wraps a body at 76 columns. The redactor decodes TOKENS inside
    a single line, so only the fragment carrying the credential's prefix is
    recognised — every later fragment decodes to an anonymous middle slice of
    the key, survives, and the surviving fragments concatenate back into most
    of the credential.

    Checked FRAGMENT BY FRAGMENT. A whole-blob check passes here while the
    credential is on disk, because the blob as written contains newlines.
    """
    secret = "sk-ant-api03-" + _rnd(120, seed=94)
    wrapped = _b64_wrapped(secret)
    fragments = [ln for ln in wrapped.split("\n") if ln]
    assert len(fragments) >= 3, (
        f"the case is not actually wrapped ({len(fragments)} fragment(s)) — it would "
        f"test the single-line path instead of the one it names."
    )

    log_path = tmp_path / "audit.jsonl"
    content = _drive_real_write_path(
        [{"detection_id": "det-wrapped-b64", "source": SENTINEL,
          "value": "payload=\n" + wrapped}],
        log_path,
    )

    assert SENTINEL in content and "det-wrapped-b64" in content, (
        "POSITIVE CONTROL FAILED: the record did not reach disk, so every 'absent' "
        "assertion below would pass vacuously."
    )
    assert REDACTION_MARKER in content, (
        "POSITIVE CONTROL FAILED: nothing was redacted at all on this record."
    )

    survivors = [i for i, frag in enumerate(fragments) if frag in content]
    assert not survivors, (
        f"{len(survivors)} of {len(fragments)} base64 fragments of a credential reached "
        f"disk (fragment indices {survivors}); concatenated they decode back to the "
        f"credential body. Values deliberately not printed."
    )


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
# Memory store (sqlite) — the real write path for mcp_server.tools.memory
#
# This closes the UNREDACTED_GAP named below in DISK_SINKS: memory_store /
# memory_relate persisted caller-supplied text to sqlite with NO scrub at all
# — a second, unguarded disk sink alongside the audit log. Same discipline as
# the JSONL tests above: drive the REAL production functions
# (`store_entity` / `store_relation`), never call `redact()` directly, then
# read the sqlite file's raw bytes back off disk — the same view a `grep
# memory.db` would get. Every forbidden value is a literal this file
# constructed and therefore knows exactly, never a span derived after the
# fact from the record (a derived span can be wrong while the secret sits on
# disk in full).
# ---------------------------------------------------------------------------

MEMORY_SENTINEL = "arkheia-memory-floor-positive-control"

# Named, not derived: these are the EXACT bytes planted below, and the exact
# bytes asserted absent from the sqlite file afterwards.
_MEM_ANTHROPIC_KEY = "sk-ant-api03-" + _rnd(40, seed=501)
_MEM_DSN_PASSWORD = "Qx7z" + _rnd(24, seed=502)
_MEM_DSN = f"postgresql://svc_intouch:{_MEM_DSN_PASSWORD}@db.internal.arkheia.ai:5432/appdb"
_MEM_RAW_SECRET_FOR_ENCODING = "sk-ant-api03-" + _rnd(40, seed=503)
_MEM_B64_ENCODED = base64.b64encode(_MEM_RAW_SECRET_FOR_ENCODING.encode()).decode()
_MEM_RELATION_SECRET = "ghp_" + _rnd(36, seed=504)


def _drive_memory_write_path(tmp_path: Path, call) -> bytes:
    """
    Point MEMORY_DB_PATH at a scratch file, invoke `call` — a zero-arg callable
    returning the coroutine of a REAL `mcp_server.tools.memory` function — and
    return the RAW BYTES of the sqlite file it produced.

    `mcp_server.tools.memory` reads `MEMORY_DB_PATH` from the environment at
    CALL time (`_db_path()` inside `_get_conn()`), not at import time, so the
    env var is set immediately before the call and restored immediately after
    — this test must not leak its scratch path into any other test.

    The import is local: this keeps the module out of the floor tier's
    collection-time surface, matching the pattern used for `AuditWriter` above
    (imported at module scope only because it is the file's sole subject).
    """
    db_path = tmp_path / "memory.db"
    old = os.environ.get("MEMORY_DB_PATH")
    os.environ["MEMORY_DB_PATH"] = str(db_path)
    try:
        asyncio.run(call())
    finally:
        if old is None:
            os.environ.pop("MEMORY_DB_PATH", None)
        else:
            os.environ["MEMORY_DB_PATH"] = old

    assert db_path.exists(), (
        f"POSITIVE CONTROL FAILED: the production memory write path produced no "
        f"file at {db_path}. Every 'secret absent' assertion below would pass "
        f"vacuously."
    )
    return db_path.read_bytes()


def test_memory_store_does_not_persist_secrets_unredacted(tmp_path):
    """
    `memory_store` (mcp_server.tools.memory.store_entity) is the sink named
    UNREDACTED_GAP in DISK_SINKS below. Plant realistic secret material in the
    observation text a caller would actually paste — a bare API key, a DSN
    with an inline password, and an encoded variant of a key — and require
    NONE of it to survive on disk once the fix lands.
    """
    from mcp_server.tools import memory as mem

    observations = [
        f"{MEMORY_SENTINEL} -- postmortem notes",
        f"rotate this immediately: {_MEM_ANTHROPIC_KEY}",
        f"prod DSN, do not share: {_MEM_DSN}",
        f"config backup (base64): {_MEM_B64_ENCODED}",
    ]
    content = _drive_memory_write_path(
        tmp_path,
        lambda: mem.store_entity("IncidentReport-501", "incident", observations),
    )

    # --- POSITIVE CONTROLS: the record really landed, in full ---
    assert MEMORY_SENTINEL.encode() in content, (
        "POSITIVE CONTROL FAILED: sentinel text is not in the sqlite file — the "
        "record was not written, so every 'secret absent' assertion below would "
        "pass vacuously."
    )
    assert b"IncidentReport-501" in content, (
        "POSITIVE CONTROL FAILED: the (non-secret) entity name did not reach "
        "disk — this is not the real write path."
    )
    assert REDACTION_MARKER.encode() in content, (
        "POSITIVE CONTROL FAILED: no redaction marker anywhere in the sqlite "
        "file — the redactor did not run on the memory write path at all."
    )

    # --- THE ACTUAL CHECK: named forbidden bytes, never derived ---
    assert _MEM_ANTHROPIC_KEY.encode() not in content, (
        "an Anthropic API key reached the memory sqlite file unredacted. "
        "Value deliberately not printed."
    )
    assert _MEM_B64_ENCODED.encode() not in content, (
        "a base64-encoded secret reached the memory sqlite file unredacted. "
        "Value deliberately not printed."
    )
    assert _MEM_RAW_SECRET_FOR_ENCODING.encode() not in content, (
        "the DECODED form of the base64-encoded secret is present verbatim in "
        "the memory sqlite file. Value deliberately not printed."
    )
    # DSN password, checked HALF BY HALF: a partial (prefix-only or
    # suffix-only) redaction must not read as a pass.
    half = len(_MEM_DSN_PASSWORD) // 2
    first_half, second_half = _MEM_DSN_PASSWORD[:half], _MEM_DSN_PASSWORD[half:]
    assert first_half.encode() not in content, (
        "the FIRST half of a DSN inline password reached the memory sqlite "
        "file unredacted. Value deliberately not printed."
    )
    assert second_half.encode() not in content, (
        "the SECOND half of a DSN inline password reached the memory sqlite "
        "file unredacted. Value deliberately not printed."
    )
    assert _MEM_DSN_PASSWORD.encode() not in content, (
        "a DSN inline password reached the memory sqlite file unredacted. "
        "Value deliberately not printed."
    )


def test_memory_relate_does_not_persist_secrets_unredacted(tmp_path):
    """
    The sibling write path: `memory_relate` (store_relation) inserts
    from_entity / relation_type / to_entity directly, with the same
    `sqlite3.connect()` sink as store_entity. A secret placed in ANY of the
    three fields must not survive on disk.
    """
    from mcp_server.tools import memory as mem

    async def _write_relation():
        await mem.store_entity(
            f"{MEMORY_SENTINEL} -- service-A",
            "service",
            ["relation source"],
        )
        await mem.store_entity(_MEM_RELATION_SECRET, "credential", ["relation target"])
        await mem.store_relation(
            from_entity=f"{MEMORY_SENTINEL} -- service-A",
            relation_type="uses_credential",
            to_entity=_MEM_RELATION_SECRET,
        )

    content = _drive_memory_write_path(
        tmp_path,
        _write_relation,
    )

    assert MEMORY_SENTINEL.encode() in content, (
        "POSITIVE CONTROL FAILED: sentinel text is not in the sqlite file — the "
        "record was not written, so 'secret absent' would pass vacuously."
    )
    assert b"uses_credential" in content, (
        "POSITIVE CONTROL FAILED: the (non-secret) relation_type did not reach "
        "disk — this is not the real write path."
    )
    assert REDACTION_MARKER.encode() in content, (
        "POSITIVE CONTROL FAILED: no redaction marker anywhere in the sqlite "
        "file — the redactor did not run on the memory_relate write path at all."
    )
    assert _MEM_RELATION_SECRET.encode() not in content, (
        "a GitHub-shaped token placed in `to_entity` reached the memory sqlite "
        "file unredacted. Value deliberately not printed."
    )


def test_memory_store_functions_call_redact_before_insert():
    """
    Ordering invariant, same shape as `test_writer_loop_redacts_before_it_writes`
    below: `redact()` must precede the first `conn.execute()` inside both
    `store_entity` and `store_relation`. Correct-but-late redaction writes the
    secret and scrubs a copy nobody reads.
    """
    src = (ROOT / "mcp_server/tools/memory.py").read_text(encoding="utf-8")
    tree = ast.parse(src)

    for fn_name in ("store_entity", "store_relation"):
        fn = next(
            (n for n in ast.walk(tree)
             if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
             and n.name == fn_name),
            None,
        )
        assert fn is not None, (
            f"mcp_server.tools.memory.{fn_name} not found — the memory write "
            f"path was renamed or removed and this invariant no longer "
            f"observes its subject."
        )

        redact_lines, execute_lines = [], []
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name == "redact":
                redact_lines.append(node.lineno)
            elif name == "execute":
                execute_lines.append(node.lineno)

        assert redact_lines, (
            f"mcp_server.tools.memory.{fn_name} contains NO call to redact() — "
            f"the memory write path no longer scrubs secrets before writing to "
            f"disk."
        )
        assert execute_lines, (
            f"no conn.execute() call found in {fn_name} — this invariant lost "
            f"its subject and would pass vacuously."
        )
        assert min(redact_lines) < min(execute_lines), (
            f"{fn_name}: redact() at line {min(redact_lines)} does not precede "
            f"the first conn.execute() at line {min(execute_lines)}: a value "
            f"can be written to sqlite before it is scrubbed."
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
        "REDACTED",
        "store_entity/store_relation pass every caller-supplied field (entity "
        "name/type, observation content, relation endpoints/type) through the "
        "shared redact() before the INSERT that follows; pinned by "
        "test_memory_store_does_not_persist_secrets_unredacted, "
        "test_memory_relate_does_not_persist_secrets_unredacted and "
        "test_memory_store_functions_call_redact_before_insert",
    ),
}

# The ratchet bound on UNREDACTED_GAP. Reduce it when a gap is closed; it must
# never rise. Zero named units: the one former gap,
# mcp_server/tools/memory.py:_get_conn, is now REDACTED (see DISK_SINKS
# above) and no other production disk sink is classified UNREDACTED_GAP.
MAX_UNREDACTED_GAPS = 0

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
