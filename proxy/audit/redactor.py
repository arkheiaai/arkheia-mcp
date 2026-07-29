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

4. **A value-anchored pattern cannot see an OPAQUE credential.** Point 1 says
   match the shape of the value; that is necessary and it is not sufficient.
   It holds for credentials with a recognisable prefix, and it fails entirely
   for ones without — an AWS secret access key has no prefix to anchor to, which
   is precisely the shape the real incident had. Those are caught by
   ``_is_opaque_credential``: entropy AND credential context, never entropy
   alone. Entropy alone eats every sha, UUID and base64 payload in the log.

5. **An ENCODING must never be the thing that protects a value, and a BENIGN
   token must never switch a control off.** Both are the same mistake — a
   detail of presentation deciding a security outcome — and both leaked:

   * Decoding was one pass per codec over two codecs. Encodings COMPOSE, so
     ``b64(b64(k))``, ``b64(pct(k))`` and ``pct(b64(k))`` each restored nothing
     to scan and reached disk intact, while their single-wrapped forms were
     caught. Hex and base32 were not decoded at all. ``_decoded_views`` is now
     BREADTH-FIRST over all four codecs to ``_MAX_DECODE_DEPTH``, feeding every
     decoded view back through every decoder.
   * Decoding was TOKEN-LOCAL inside one ``\\n``-split line, so a MIME-wrapped
     body was redacted only in the fragment carrying the credential's prefix —
     2 of 3 fragments of a wrapped key reached disk and concatenated back into
     it. Runs of wholly-encoded lines are now REJOINED before scanning.
   * A data URI anywhere on a line exempted the WHOLE LINE from both fallback
     passes, so a credential written beside a screenshot leaked. Only the
     payload SPAN is masked now.

   The safety argument is unchanged in shape: a decoded view may only *trigger*
   redaction, never *widen* what counts as a secret. ``_plausible_text`` is the
   gate that keeps this from eating the log — a sha256 digest decodes to
   high-entropy BINARY under hex, base32 and base64 alike and stops there.

WHAT IS NOT HANDLED — named, so absence is not mistaken for coverage
--------------------------------------------------------------------
  * **Quoted-printable.** Implemented, then removed: it could not be shown to
    catch anything (every mutation deleting it survived). In ASCII credential
    text QP only escapes ``=``, which in practice is trailing base64 padding,
    leaving the body in front of it long enough for the entropy rule. The
    ``=\\n`` soft-line-break form does hide a credential, but that is the same
    shape as limitation 3 and is pinned there.
  * **Opaque values with NO credential context anywhere in the string.** A bare
    high-entropy value under a neutral label (``redirect=<40 chars>``) is not
    redacted, encoded or not. Closing it needs entropy alone, which fails
    point 2. This is a deliberate trade, not an oversight.
  * **Compression wrappers** (gzip/zlib inside base64) are not decompressed.
  * **Split-across-records** secrets: redaction is per string value, so a
    credential assembled from two fields is invisible to it.
  * **Encodings past ``_MAX_DECODE_DEPTH``**, and encodings whose decoded form
    is not plausibly text (a credential wrapped so that it decodes to binary at
    an intermediate step). Bounded deliberately: an unbounded decode over
    caller-supplied strings is a decode bomb in the writer loop.
  * **Prefixed credentials in a case they are never issued in** — ``GHP_…``
    uppercase is not redacted. The provider prefixes are lowercase by
    specification; matching them case-insensitively buys nothing real and
    widens over-redaction.
  * **A URI password beginning digits-then-delimiter** (``//u:8080/x@h``) is
    skipped by the ``conn_password`` guard that stops it eating a PORT. A
    password of that exact shape is a trade taken knowingly.
  * **A non-str, non-container value** (``bytes``, ``set``) is not scrubbed —
    but it also cannot be serialised, so the writer's ``except`` DROPS the whole
    record rather than leaking it. Verified: no leak, but a silent audit loss.
    Tracked separately; it is a durability defect, not a redaction one.

Hook for enterprise upgrade: swap the pattern tables for a runtime-loaded
policy (e.g. from HashiCorp Vault, AWS Secrets Manager) and add
field-name-based rules for context-sensitive redaction.
"""

import base64
import hashlib
import math
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
    #
    # The secret class is `[^\s]`, NOT `[^\s:/?#@]`. The first cut excluded
    # every URI-reserved character from the password, which meant it could not
    # see its own subject: a generated DB password routinely contains `/` or
    # `+`, and `postgresql://svc:aB3/xY9z@db` matched NOTHING — not this rule
    # (the `/` broke the class) and not the opaque-entropy rule either, because
    # `_CREDENTIAL_CONTEXT` has no URI/DSN term so a bare DSN line carries no
    # credential context at all. The password reached disk in full.
    # The userinfo class is `*` for the same reason: `redis://:pw@host` is the
    # ordinary password-only form and `+` required a username that isn't there.
    #
    # Widening the secret class this far needs one guard, or it eats a PORT:
    # in `http://localhost:8000/reports/user@example.com` the `:` is a port
    # delimiter and the `@` is in the path. The negative lookahead rejects a
    # secret that STARTS as digits-then-URI-delimiter, which is exactly the
    # port shape and is not a shape a password takes. `post` additionally
    # requires a host-looking authority terminated the way a URI terminates,
    # so the non-greedy body cannot run off across the line.
    ("conn_password",
     re.compile(r'(?P<pre>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/?#@]*:)'
                r'(?P<secret>(?!\d{1,5}[/?#@])[^\s]{6,256}?)'
                r'(?P<post>@[A-Za-z0-9._\-\[\]]{1,255}(?::\d{1,5})?'
                r'(?=[\s/?#\'",\\]|$))')),
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

_B64ISH = re.compile(r'^[A-Za-z0-9+/_-]{16,}={0,2}$')
_B32ISH = re.compile(r'^[A-Z2-7]{16,}={0,6}$')
_HEXISH = re.compile(r'^[0-9a-fA-F]{16,}$')
_PCT = re.compile(r'%[0-9A-Fa-f]{2}')

#: How many times an encoding may be UNWRAPPED. One pass per codec was not
#: enough: encodings COMPOSE, and a decoded view was never itself decoded, so
#: `b64(b64(k))`, `b64(pct(k))` and `pct(b64(k))` each reached disk intact
#: while their single-wrapped forms were caught.
_MAX_DECODE_DEPTH = 3
#: Bound on total decoded views per token, so a pathological input cannot turn
#: the writer loop into a decode bomb.
_MAX_DECODED_VIEWS = 24
#: Below this, a token cannot carry a credential worth decoding.
_MIN_DECODABLE = 16


def _plausible_text(raw: bytes) -> str | None:
    """
    Decoded bytes as text, or None if they are not plausibly text.

    Binary payloads (images, compressed blobs) are not credential carriers
    worth scanning, and decoding them yields mojibake that could match by
    accident. This gate is what keeps hex and base32 decoding from turning
    every sha256 digest in the log into a redaction candidate: a digest
    decodes to high-entropy BINARY and stops here.
    """
    if len(raw) < 12:
        return None
    printable = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    if printable / len(raw) < 0.9:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _percent_decode_once(tok: str) -> list[str]:
    if not _PCT.search(tok):
        return []
    try:
        out = urllib.parse.unquote(tok, errors="strict")
    except Exception:
        return []
    return [out] if out != tok else []


def _base64_decode_once(tok: str) -> list[str]:
    """Base64 (standard and url-safe) decoded view, when it is plausibly text."""
    if not _B64ISH.match(tok):
        return []
    out = []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(tok + "=" * (-len(tok) % 4))
        except Exception:
            continue
        text = _plausible_text(raw)
        if text is not None and text != tok and text not in out:
            out.append(text)
    return out


def _hex_decode_once(tok: str) -> list[str]:
    """Hex is a transport encoding like any other; it was not decoded at all."""
    if len(tok) % 2 or not _HEXISH.match(tok):
        return []
    try:
        raw = bytes.fromhex(tok)
    except ValueError:
        return []
    text = _plausible_text(raw)
    return [text] if text is not None else []


def _base32_decode_once(tok: str) -> list[str]:
    if not _B32ISH.match(tok):
        return []
    try:
        raw = base64.b32decode(tok + "=" * (-len(tok) % 8))
    except Exception:
        return []
    text = _plausible_text(raw)
    return [text] if text is not None else []


_DECODERS = (
    _percent_decode_once,
    _base64_decode_once,
    _hex_decode_once,
    _base32_decode_once,
)


def _base64_views(tok: str) -> list[str]:
    """Single-step base64 view — the exemption in `_is_opaque_credential`."""
    return _base64_decode_once(tok)


# QUOTED-PRINTABLE is NOT handled. It was implemented, then removed, because it
# could not be shown to catch anything:
#   * `=XX` escapes — in ASCII credential text QP only ever escapes `=` itself,
#     which in practice is base64 padding at the END of a body. The body in
#     front of it stays long enough for the entropy rule to see, so a QP decode
#     changes no outcome. Every mutation deleting the QP pass SURVIVED.
#   * `=\n` soft line breaks — these do hide a credential, by wrapping it across
#     lines, but that is the same shape as limitation 3 above (a secret split
#     across a newline) and is pinned there as a known partial.
# An unproven mechanism is worse than an absent one: it reads as coverage.


def _contains_secret(text: str) -> bool:
    """Would any pattern fire on this text?"""
    return (
        any(p.search(text) for _l, p in _SECRET_PATTERNS)
        or any(p.search(text) for _l, p in _LABELLED_SECRET_PATTERNS)
    )


def _decoded_views(tok: str) -> list[str]:
    """
    Every view of `tok` reachable by unwrapping transport encodings.

    Breadth-first over the codecs, so COMPOSED and REPEATED encodings unwrap:
    a decoded view is fed back through every decoder, not just the one that
    produced it. Depth- and count-bounded, and cycle-guarded by `seen`.
    """
    views: list[str] = []
    seen = {tok}
    frontier = [tok]
    for _ in range(_MAX_DECODE_DEPTH):
        nxt: list[str] = []
        for cur in frontier:
            if len(cur) < _MIN_DECODABLE:
                continue
            for decoder in _DECODERS:
                for view in decoder(cur):
                    if view in seen:
                        continue
                    seen.add(view)
                    views.append(view)
                    nxt.append(view)
                    if len(views) >= _MAX_DECODED_VIEWS:
                        return views
        if not nxt:
            break
        frontier = nxt
    return views


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


# ---------------------------------------------------------------------------
# DATA URIs — exempt the PAYLOAD, never the LINE.
#
# A data URI's base64 payload is audit content, and it is the shape most at
# risk from the entropy rule, so it must be exempt. The first cut exempted the
# whole LINE that contained one, which is a blast radius wildly larger than the
# thing being protected: every other token on that line lost the encoding pass
# AND the opaque-entropy pass, so a credential written beside a screenshot
# reached disk. One legitimate token must not switch off a control for
# everything next to it.
#
# The payload spans are therefore masked out, the line is processed normally,
# and the spans are restored verbatim. The mask uses private-use codepoints so
# it cannot itself look like a credential: they are outside every character
# class here (`_B64ISH`, `_B32ISH`, `_HEXISH`, `_OPAQUE_TOKEN`).
# ---------------------------------------------------------------------------

_DATA_URI = re.compile(
    r'data:[A-Za-z0-9!#$&^+.\-/]*(?:;[A-Za-z0-9.+\-]+)*;base64,[A-Za-z0-9+/=_-]+'
)
_MASK_OPEN, _MASK_CLOSE = "\ue000", "\ue001"
_MASK_REF = re.compile(_MASK_OPEN + r'(\d+)' + _MASK_CLOSE)


def _mask_data_uris(line: str) -> tuple[str, list[str]]:
    saved: list[str] = []

    def _keep(m: "re.Match") -> str:
        saved.append(m.group(0))
        return f"{_MASK_OPEN}{len(saved) - 1}{_MASK_CLOSE}"

    return _DATA_URI.sub(_keep, line), saved


def _unmask_data_uris(line: str, saved: list[str]) -> str:
    if not saved:
        return line
    return _MASK_REF.sub(lambda m: saved[int(m.group(1))], line)


# ---------------------------------------------------------------------------
# LINE-WRAPPED BODIES — a credential does not stop being one at column 76.
#
# `base64(1)`, `openssl base64` and every MIME/attachment pipeline wrap their
# output. Scanning TOKENS inside a single line then recognises only the
# fragment that happens to carry the credential's prefix; every later fragment
# decodes to an anonymous middle slice, survives, and the survivors
# concatenate straight back into the credential body. Measured: 2 of 3
# fragments of a wrapped Anthropic key reached disk.
#
# So a run of consecutive wholly-encoded lines is REJOINED and scanned as one
# body. The join only ever decides whether to redact — it never widens what
# counts as a secret — so a wrapped PNG or a pair of wrapped digests still
# decodes to binary, fails `_plausible_text`, and survives verbatim.
# ---------------------------------------------------------------------------

_WRAPPED_LINE = re.compile(r'^[A-Za-z0-9+/_-]{16,}={0,6}$')
_MIN_WRAPPED_RUN = 2


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

    def _ctx_at(i: int) -> bool:
        return any(_CREDENTIAL_CONTEXT.search(w) for w in lines[max(0, i - 3): i + 1])

    def _view_is_secret(view: str, ctx: bool) -> bool:
        if _contains_secret(view):
            return True
        # Opaque bodies are only credentials in credential context, and the
        # candidate test must run on TOKENS inside the decoded view — a whole
        # decoded line of prose can trivially satisfy the mixed-case and
        # entropy tests that a credential body satisfies.
        return ctx and any(
            _is_opaque_credential(t) for t in _OPAQUE_TOKEN.findall(view)
        )

    # --- pass 1: rejoin runs of wholly-encoded lines ------------------------
    handled: dict[int, str | None] = {}
    i = 0
    while i < len(lines):
        if not _WRAPPED_LINE.match(lines[i].rstrip("\r")):
            i += 1
            continue
        j = i
        while j < len(lines) and _WRAPPED_LINE.match(lines[j].rstrip("\r")):
            j += 1
        if j - i >= _MIN_WRAPPED_RUN:
            joined = "".join(ln.rstrip("\r") for ln in lines[i:j])
            ctx = _ctx_at(i)
            if any(_view_is_secret(v, ctx) for v in _decoded_views(joined)):
                handled[i] = _placeholder(joined)
                for k in range(i + 1, j):
                    handled[k] = None      # absorbed into the placeholder
        i = j

    # --- pass 2: per line ---------------------------------------------------
    out: list[str] = []
    for i, line in enumerate(lines):
        if i in handled:
            if handled[i] is not None:
                out.append(handled[i])
            continue

        line, saved = _mask_data_uris(line)
        ctx = _ctx_at(i)

        def repl(m: "re.Match", _ctx: bool = ctx) -> str:
            tok = m.group(0)
            for view in _decoded_views(tok):
                if _view_is_secret(view, _ctx):
                    return _placeholder(tok)
            return tok

        line = _TOKEN.sub(repl, line)
        if ctx:
            line = _OPAQUE_TOKEN.sub(
                lambda m: _placeholder(m.group(0))
                if _is_opaque_credential(m.group(0)) else m.group(0),
                line,
            )
        out.append(_unmask_data_uris(line, saved))
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
