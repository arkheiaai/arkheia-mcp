"""
Secrets redactor — boundary layer for audit logs.

Scans string values for known secret patterns and replaces them with
[REDACTED:<sha256_prefix_8>] before any record is written to disk.

The replacement preserves enough identity (hash prefix) to correlate
across records without exposing the secret value.

Hook for enterprise upgrade: swap _SECRET_PATTERNS for a runtime-loaded
policy (e.g. from HashiCorp Vault, AWS Secrets Manager) and add
field-name-based rules for context-sensitive redaction.
"""

import hashlib
import re
from typing import Any

# ---------------------------------------------------------------------------
# Known secret patterns (ordered most specific → least specific)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    # OpenAI
    ("openai",      re.compile(r'sk-proj-[A-Za-z0-9._-]{20,}')),
    # Anthropic (API key + OAuth)
    ("anthropic",   re.compile(r'sk-ant-[A-Za-z0-9._-]{20,}')),
    # xAI / Grok
    ("xai",         re.compile(r'xai-[A-Za-z0-9]{20,}')),
    # Google API key
    ("google",      re.compile(r'AIzaSy[A-Za-z0-9_-]{20,}')),
    # Resend email
    ("resend",      re.compile(r're_[A-Za-z0-9]{20,}')),
    # Vercel auth token
    ("vercel_auth", re.compile(r'vca_[A-Za-z0-9]{20,}')),
    # Vercel project token
    ("vercel_proj", re.compile(r'vcp_[A-Za-z0-9]{20,}')),
    # GitHub PAT
    ("github",      re.compile(r'github_pat_[A-Za-z0-9_]{20,}')),
    # Arkheia live API key
    ("arkheia",     re.compile(r'ak_live_[a-f0-9]{20,}')),
    # JWT tokens (long base64-URL strings — Bearer values, id_tokens)
    ("jwt",         re.compile(r'eyJ[A-Za-z0-9._-]{100,}')),
]


def _redact_string(value: str) -> str:
    """Replace all secret patterns found in a string."""
    for _label, pattern in _SECRET_PATTERNS:
        def _replace(m: re.Match) -> str:
            h = hashlib.sha256(m.group(0).encode()).hexdigest()[:8]
            return f"[REDACTED:{h}]"
        value = pattern.sub(_replace, value)
    return value


def redact(obj: Any) -> Any:
    """
    Recursively redact secrets from any JSON-serialisable value.

    Returns a new object — does not mutate the original.
    Safe to call on dicts, lists, strings, and primitives.
    """
    if isinstance(obj, str):
        return _redact_string(obj)
    if isinstance(obj, dict):
        return {k: redact(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return type(obj)(redact(item) for item in obj)
    return obj
