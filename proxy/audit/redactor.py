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

import hashlib
import re
from typing import Any

# ---------------------------------------------------------------------------
# Value-shaped secret patterns (ordered most specific → least specific).
#
# These fire on the credential BODY, so they are indifferent to whether the
# value sits after `KEY=`, on a bare line, under a `====label====` heading,
# inside JSON, or inside a quoted shell command.
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # PEM private key block (multi-line; matched before anything else so the
    # whole block goes, not just fragments of the base64 body).
    ("pem_private_key",
     re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')),
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


def _redact_string(value: str) -> str:
    """Replace all secret patterns found in a string."""
    for _label, pattern in _SECRET_PATTERNS:
        value = pattern.sub(lambda m: _placeholder(m.group(0)), value)
    for _label, pattern in _LABELLED_SECRET_PATTERNS:
        value = pattern.sub(
            lambda m: m.group("pre") + _placeholder(m.group("secret")) + m.group("post"),
            value,
        )
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
