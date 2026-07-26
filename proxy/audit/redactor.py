"""
Secrets redactor — boundary layer for audit logs.

Scans string values for known secret patterns and replaces them with
[REDACTED:<sha256_prefix_8>] before any record is written to disk.

The replacement preserves enough identity (hash prefix) to correlate
across records without exposing the secret value.

DESIGN CONTRACT — read before adding or widening a pattern
----------------------------------------------------------
1. **Match the SHAPE OF THE VALUE, never an assignment.** A pattern that only
   matches ``KEY=value`` misses the same credential when it appears as a bare
   value on its own line, under a ``====label====`` heading, inside JSON, or
   inside a quoted shell command. Real credential stores use all four forms.
   Every prefix-anchored pattern below is therefore value-anchored: it fires on
   the credential body wherever it sits. Assignment-context patterns
   (``_LABELLED_SECRET_PATTERNS``) are an ADDITION for opaque, shapeless
   credentials that have no recognisable body — never the primary mechanism.

2. **Over-redaction is also a defect.** An audit log scrubbed to uselessness
   fails its own purpose, so a pattern must not eat audit content. Explicit
   near-misses that MUST survive verbatim: git commit shas (hex, 7 or 40),
   UUIDs, sha256 hashes, ISO-8601 timestamps, model ids, base64 image payloads,
   feature names, prose. Both directions are pinned by
   ``tests/test_audit_redactor_floor.py``; add a case there with every pattern.

3. **Known limitation, deliberately not "fixed":** a secret split across a line
   break is only PARTIALLY redacted — the prefixed head is replaced, the
   suffix after the newline survives as an unprefixed high-entropy run.
   Catching that needs an entropy heuristic, which over-redacts hashes and
   base64 payloads (see 2). Pinned as a known-partial case rather than left
   as an unstated surprise.

Hook for enterprise upgrade: swap the pattern tables for a runtime-loaded
policy (e.g. from HashiCorp Vault, AWS Secrets Manager) and add
field-name-based rules for context-sensitive redaction.
"""

import base64
import hashlib
import math
import quopri
import re
import urllib.parse
from typing import Any

# ---------------------------------------------------------------------------
# Value-shaped secret patterns (ordered most specific → least specific).
#
# These fire on the credential BODY, so they are indifferent to whether the
# value sits after `KEY=`, on a bare line, under a `====label====` heading,
# inside JSON, or inside a quoted shell command.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Armoured secret BLOCK, any `-----BEGIN <label>-----` delimiter — not just
    # `PRIVATE KEY`. The first cut hardcoded the PEM label, so a PGP private key
    # block (`-----BEGIN PGP PRIVATE KEY BLOCK-----`) walked straight through:
    # same delimiter, same armour, different noun.
    #
    # The label class is deliberately NARROW — PRIVATE / SECRET material and PGP
    # MESSAGE only. `-----BEGIN CERTIFICATE-----` and `PUBLIC KEY` are public by
    # definition and are audit content; eating them would be over-redaction.
    ("armoured_private_block",
     re.compile(r'-----BEGIN [A-Z0-9 ]*'
                r'(?:PRIVATE KEY|SECRET KEY|PGP MESSAGE|PRIVATE KEY BLOCK)'
                r'[A-Z0-9 ]*-----[\s\S]*?-----END [A-Z0-9 ]*-----')),
    # JWT / id_token: THREE dot-separated base64url segments. Matched on the
    # dot STRUCTURE, not on length: a real JWT can be well under 100 chars
    # (`eyJhbGciOiJIUzI1NiJ9.<claims>.<sig>`), and a length-only rule both
    # missed those AND over-redacted any dotless base64 blob of JSON (which
    # also starts `eyJ` — e.g. an embedded payload capture).
    ("jwt",
     re.compile(r'eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')),
    # OpenAI project key
    ("openai_proj",  re.compile(r'sk-proj-[A-Za-z0-9._-]{20,}')),
    # Anthropic (API key + OAuth)
    ("anthropic",    re.compile(r'sk-ant-[A-Za-z0-9._-]{20,}')),
    # Stripe restricted/secret key (underscore form — distinct from `sk-`)
    ("stripe",       re.compile(r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}')),
    # OpenAI CLASSIC key — `sk-` + body, NO `proj-`/`ant-` infix. Listed after
    # the two prefixed forms so those keep their own labels.
    ("openai",       re.compile(r'\bsk-[A-Za-z0-9]{32,}')),
    # xAI / Grok
    ("xai",          re.compile(r'\bxai-[A-Za-z0-9]{20,}')),
    # Google API key
    ("google",       re.compile(r'\bAIzaSy[A-Za-z0-9_-]{20,}')),
    # Resend email — real keys carry an internal `_` separator, so the body
    # class must include it (an alnum-only body matched fewer than 20 chars
    # and skipped the key entirely).
    ("resend",       re.compile(r'\bre_[A-Za-z0-9_]{20,}')),
    # Vercel auth token
    ("vercel_auth",  re.compile(r'\bvca_[A-Za-z0-9]{20,}')),
    # Vercel project token
    ("vercel_proj",  re.compile(r'\bvcp_[A-Za-z0-9]{20,}')),
    # GitHub fine-grained PAT
    ("github_fine",  re.compile(r'\bgithub_pat_[A-Za-z0-9_]{20,}')),
    # GitHub CLASSIC PAT / OAuth / server / user / refresh token
    ("github_classic", re.compile(r'\bgh[pousr]_[A-Za-z0-9]{30,}')),
    # AWS access key id (long-term, temporary, bearer, context-specific)
    ("aws_access_key_id",
     re.compile(r'\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b')),
    # Slack bot/user/app/refresh token
    ("slack",        re.compile(r'\bxox[baprse]-[A-Za-z0-9-]{10,}')),
    # Arkheia API key — body class widened beyond lowercase hex, and test keys
    # included (a non-hex or uppercase key was previously not matched at all).
    ("arkheia",      re.compile(r'\bak_(?:live|test)_[A-Za-z0-9]{20,}')),
]

# ---------------------------------------------------------------------------
# Context-scoped patterns for OPAQUE credentials — those with no recognisable
# body shape (a 292-char PAT, an AWS secret access key, a connection-string
# password, an opaque `Bearer` value). Only the `secret` group is replaced;
# the surrounding label/scheme/host is PRESERVED, because the label is audit
# content and dropping it would degrade the record for no security gain.
#
# These are an addition to, never a substitute for, the value-shaped patterns
# above: matching only an assignment is exactly the failure mode that let a
# bare-value credential through in the first place.
# ---------------------------------------------------------------------------

_LABELLED_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # URI with inline password: scheme://user:PASSWORD@host
    ("conn_password",
     re.compile(r'(?P<pre>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/?#@]+:)'
                r'(?P<secret>[^\s:/?#@]{6,})'
                r'(?P<post>@)')),
    # Authorization: Bearer <opaque token>
    ("bearer",
     re.compile(r'(?P<pre>(?i:bearer)\s+)'
                r'(?P<secret>[A-Za-z0-9._~+/\-]{20,}=*)'
                r'(?P<post>)')),
    # <secret-ish label> = / : <opaque value>
    ("labelled",
     re.compile(r'(?P<pre>(?i:aws_secret_access_key|secret_access_key|api[_-]?key|apikey'
                r'|auth[_-]?token|access[_-]?token|refresh[_-]?token|client[_-]?secret'
                r'|private[_-]?key|password|passwd)["\']?\s*[:=]\s*["\']?)'
                r'(?P<secret>[^\s"\',;}\]]{12,})'
                r'(?P<post>)')),
]


def _placeholder(secret: str) -> str:
    """Stable, non-reversible correlation handle for a redacted value."""
    return f"[REDACTED:{hashlib.sha256(secret.encode()).hexdigest()[:8]}]"


# ---------------------------------------------------------------------------
# ENCODING WRAPPERS — decode, rescan, redact the ORIGINAL span.
#
# Every pattern above matches the credential's plaintext body. Wrap that body in
# a transport encoding and the anchor disappears: strict percent-encoding turns
# `sk-ant-` into `sk%2Dant%2D`, and base64 turns it into `c2stYW50L…`. Both
# reach disk fully recoverable — the encoding is not obfuscation, it is a
# reversible transform an attacker (or a grep) undoes for free.
#
# Mechanism: split into tokens, decode each token, and if ANY decoded view
# contains a secret, redact the whole token. Token-level (not line-level) keeps
# the surrounding label — `callback=`, `blob=` — which is audit content.
# ---------------------------------------------------------------------------

# Token boundaries. `/` and `+` are NOT delimiters: they are base64 alphabet
# characters and part of an AWS secret body.
_TOKEN = re.compile(r'[^\s=&?,;:\'"<>\[\]{}()|\\]+')

_B64ISH = re.compile(r'^[A-Za-z0-9+/_-]{20,}={0,2}$')
_PCT = re.compile(r'%[0-9A-Fa-f]{2}')


def _percent_views(tok: str) -> list[str]:
    """Percent-decoded views, iterated for double-encoding (`%252D`)."""
    views, cur = [], tok
    for _ in range(3):
        if not _PCT.search(cur):
            break
        try:
            nxt = urllib.parse.unquote(cur, errors="strict")
        except Exception:
            break
        if nxt == cur:
            break
        views.append(nxt)
        cur = nxt
    return views


def _base64_views(tok: str) -> list[str]:
    """Base64-decoded view, only when the result is plausibly text."""
    if not _B64ISH.match(tok):
        return []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(tok + "=" * (-len(tok) % 4))
        except Exception:
            continue
        if len(raw) < 12:
            continue
        printable = sum(1 for b in raw if 32 <= b < 127)
        # Binary payloads (images, compressed blobs) are not credential
        # carriers worth scanning, and decoding them yields mojibake that
        # could match by accident.
        if printable / len(raw) < 0.9:
            continue
        try:
            return [raw.decode("utf-8")]
        except UnicodeDecodeError:
            continue
    return []


def _qp_views(tok: str) -> list[str]:
    """Quoted-printable view (`=3D` escapes). Soft line breaks: see LIMITS."""
    if not re.search(r'=[0-9A-F]{2}', tok):
        return []
    try:
        return [quopri.decodestring(tok.encode()).decode("utf-8")]
    except Exception:
        return []


def _contains_secret(text: str) -> bool:
    """Would any pattern fire on this text?"""
    return (
        any(p.search(text) for _l, p in _SECRET_PATTERNS)
        or any(p.search(text) for _l, p in _LABELLED_SECRET_PATTERNS)
    )


def _decoded_views(tok: str) -> list[str]:
    return _percent_views(tok) + _base64_views(tok) + _qp_views(tok)


# ---------------------------------------------------------------------------
# OPAQUE HIGH-ENTROPY VALUES — entropy AND context, never entropy alone.
#
# The incident's real shape: an AWS secret access key
# (`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) as a bare value under a
# `====AWS PROD====` heading. No prefix identifies it — that is what "opaque"
# means — so no value-anchored pattern can ever fire on it. Prefix matching is
# structurally incapable here; a different mechanism is required.
#
# Entropy ALONE would work and would be a disaster: sha256 digests, git shas,
# UUIDs and base64 image payloads are all high-entropy, all legitimate audit
# content, and eating them produces a log scrubbed to uselessness. So entropy
# is gated on CONTEXT — a credential-ish word in the same line or the three
# preceding lines (which is what a `====AWS PROD====` heading is). Both the
# leak corpus and the near-miss corpus are pinned in the floor tests.
# ---------------------------------------------------------------------------

_CREDENTIAL_CONTEXT = re.compile(
    r'(?i)(?:aws|secret|credential|password|passwd|token|api[_-]?key|apikey'
    r'|private[_-]?key|access[_-]?key|auth)'
)

#: Charset of an opaque credential body. Deliberately excludes `.` so dotted
#: identifiers and versions are not candidates.
_OPAQUE_TOKEN = re.compile(r'[A-Za-z0-9+/_-]{32,200}={0,2}')

_HEX_ONLY = re.compile(r'^[0-9a-fA-F]+$')
_UUID = re.compile(r'^[0-9a-fA-F-]{36}$')


def _shannon(s: str) -> float:
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    total = 0.0
    for c in counts.values():
        p = c / n
        total -= p * math.log2(p)
    return total


def _is_opaque_credential(tok: str) -> bool:
    """
    High-entropy, mixed-alphabet, and NOT one of the known audit shapes.

    The exclusions are the whole safety argument: a git sha and a sha256 digest
    are hex-only, a UUID is hex-and-dashes, a numeric id has no letters. Each is
    excluded structurally rather than by a length threshold that would drift.
    """
    if _HEX_ONLY.match(tok) or _UUID.match(tok):
        return False
    has_lower = any(c.islower() for c in tok)
    has_upper = any(c.isupper() for c in tok)
    has_digit = any(c.isdigit() for c in tok)
    # A credential body mixes all three. Lowercase-hex digests, uppercase
    # constants and numeric ids each fail this and survive.
    if not (has_lower and has_upper and has_digit):
        return False
    # Already decoded and inspected: if this is base64 that unwraps to clean
    # UTF-8 text, we KNOW what is inside it, and the encoding pass above would
    # have redacted it had that text held a credential. Exempting it stops the
    # entropy rule eating ordinary base64-wrapped audit content.
    #
    # This exemption is safe against the shape it must not miss: an AWS secret
    # access key is valid base64 by charset, but decodes to 20% printable
    # binary, so `_base64_views` returns nothing for it and it stays a
    # candidate. Verified against wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY.
    if _base64_views(tok):
        return False
    return _shannon(tok) >= 3.5


def _redact_encoded_and_opaque(value: str) -> str:
    """
    One line-oriented pass, so the two fallbacks agree.

    Running them separately made the encoded pass BLIND to opaque bodies: an
    AWS secret under an `aws_secret=` label was redacted in plaintext but
    survived percent-encoded, because the encoded pass only asked "does the
    decoded text match a pattern?" and never "is the decoded text an opaque
    credential in credential context?". An encoding must not decide whether a
    value is protected.
    """
    lines = value.split("\n")
    out = []
    for i, line in enumerate(lines):
        # A data URI's payload is audit content, never a credential, and it is
        # exactly the shape most at risk from the entropy rule.
        if "data:" in line and "base64," in line:
            out.append(line)
            continue
        window = lines[max(0, i - 3): i + 1]
        ctx = any(_CREDENTIAL_CONTEXT.search(w) for w in window)

        def repl(m: "re.Match") -> str:
            tok = m.group(0)
            for view in _decoded_views(tok):
                if _contains_secret(view) or (ctx and _is_opaque_credential(view)):
                    return _placeholder(tok)
            return tok

        line = _TOKEN.sub(repl, line)
        if ctx:
            line = _OPAQUE_TOKEN.sub(
                lambda m: _placeholder(m.group(0))
                if _is_opaque_credential(m.group(0)) else m.group(0),
                line,
            )
        out.append(line)
    return "\n".join(out)


def _redact_string(value: str) -> str:
    """
    Replace all secret patterns found in a string.

    Order matters. Value-shaped patterns run first so a recognisable credential
    keeps its specific label; the encoding and entropy passes are the fallbacks
    for bodies those patterns cannot see.
    """
    for _label, pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda m: _placeholder(m.group(0)), value)
    for _label, pattern in _LABELLED_SECRET_PATTERNS:
        value = pattern.sub(
            lambda m: m.group("pre") + _placeholder(m.group("secret")) + m.group("post"),
            value,
        )
    value = _redact_encoded_and_opaque(value)
    return value


def redact(obj: Any) -> Any:
    """
    Recursively redact secrets from any JSON-serialisable value.

    Returns a new object — does not mutate the original.
    Safe to call on dicts, lists, strings, and primitives.

    Dict KEYS are redacted as well as values: a caller that puts a credential
    in a field NAME (``{"sk-ant-...": "used"}``) leaks it just as durably as
    one that puts it in a value, and key-space was previously untouched.
    """
    if isinstance(obj, str):
        return _redact_string(obj)
    if isinstance(obj, dict):
        return {
            (_redact_string(k) if isinstance(k, str) else k): redact(v)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        # Build the sequence first: a namedtuple's constructor takes positional
        # fields, not an iterable, so `type(obj)(generator)` raised TypeError and
        # (inside the writer's try/except) silently DROPPED the whole record.
        items = [redact(item) for item in obj]
        if isinstance(obj, list):
            return items
        try:
            return type(obj)(items)
        except TypeError:
            return type(obj)(*items)
    return obj
