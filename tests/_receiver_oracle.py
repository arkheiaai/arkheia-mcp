"""
An ORACLE for the governance detection adapter: what the REAL receiver does.

WHY THIS EXISTS
---------------
The `adversarial` and `correctness` questions for an HMAC-signed push are not
"does the signer produce a signature" — it always does — but "would the thing on
the other end accept it, and reject anything tampered with". The thing on the
other end is not in this repo: it is a Rust service in `arkheia-synesis`,
`services/detection-adapter/src/hmac_auth.rs` + `normalise.rs`.

A test that checks the sender against a helper derived from the sender proves
only that the sender agrees with itself. That is how this module shipped for
months signing `f"{timestamp}.{body}"` against a receiver that verifies
`"POST\\n{path}\\n{ts}\\n{sha256_hex(body)}"` — the existing suite asserted the
signature HEADER WAS PRESENT and never asked whether it authenticates.

So this file is transcribed FROM THE RECEIVER, independently of the sender, and
frozen by `GOLDEN_*` constants below. If someone "fixes" a failing test by
editing this oracle to match a broken sender, the golden vector fails.

Source of truth, quoted:

    // hmac_auth.rs::verify
    if headers.key_id != expected_key_id { return Err(UnknownKeyId) }
    let delta = (now - headers.timestamp).abs();
    if delta > replay_window_s { return Err(ReplayWindowExceeded) }
    let body_hash = hex::encode(Sha256::digest(body));
    let signing_string = format!("POST\\n{}\\n{}\\n{}", path, headers.timestamp, body_hash);
    ... mac.verify_slice(&sig_bytes).map_err(|_| InvalidSignature)?;
    nonces.check_and_record(&headers.signature, headers.timestamp, now)?;

The ORDER matters and is reproduced exactly: key-id first, then the replay
window, then the signature, and only then the nonce — the Rust comment is
explicit that the nonce check runs last "so a forged signature can never pollute
or evict entries in the replay cache".

This module is deliberately NOT named `test_*` so pytest does not collect it.
"""
from __future__ import annotations

import hashlib
import hmac
import time
from typing import Optional

# ── Frozen cross-implementation vector ───────────────────────────────────────
# Inputs are the receiver's OWN unit-test fixture (hmac_auth.rs `valid_signature_passes`:
# secret `test-secret-32-bytes-minimum-len`, body `{"test": true}`, path
# `/v1/events/proxy`) at a pinned timestamp. The expected signature is a property
# of the receiver's construction, not of anything in this repo — so it pins the
# transcription below against silent drift.
GOLDEN_SECRET = b"test-secret-32-bytes-minimum-len"
GOLDEN_BODY = b'{"test": true}'
GOLDEN_PATH = "/v1/events/proxy"
GOLDEN_TIMESTAMP = 1700000000
GOLDEN_SIGNING_STRING = (
    "POST\n/v1/events/proxy\n1700000000\n"
    "80f65706d935d3b928d95207937dd81bad43ab56cd4d3b7ed41772318e734168"
)
GOLDEN_SIGNATURE = "f8b6a145595d5b911a5f67c9d7cf13194374ac662d9a4ce4f9e26bf92cc3a541"

REPLAY_WINDOW_S = 60  # config.rs default: DETECTION_ADAPTER_REPLAY_WINDOW_S=60


class AuthError(Exception):
    """Mirrors `hmac_auth::AuthError`. `.code` is the discriminant, pinned by tests."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


MISSING_HEADER = "MissingHeader"
REPLAY_WINDOW_EXCEEDED = "ReplayWindowExceeded"
REPLAY_DETECTED = "ReplayDetected"
UNKNOWN_KEY_ID = "UnknownKeyId"
INVALID_SIGNATURE = "InvalidSignature"
INVALID_TIMESTAMP = "InvalidTimestamp"


def signing_string(path: str, timestamp: int, body: bytes) -> str:
    """`format!("POST\\n{}\\n{}\\n{}", path, timestamp, hex(sha256(body)))`."""
    return f"POST\n{path}\n{timestamp}\n{hashlib.sha256(body).hexdigest()}"


def sign(secret: bytes, path: str, timestamp: int, body: bytes) -> str:
    """Port of `hmac_auth::sign` — the receiver's own signing helper."""
    return hmac.new(secret, signing_string(path, timestamp, body).encode(), hashlib.sha256).hexdigest()


class NonceStore:
    """
    Port of `hmac_auth::NonceStore`.

    Keyed on the SIGNATURE (the Rust code passes `&headers.signature` as the
    nonce), window-evicting, hard-capped. Replay protection lives entirely here —
    i.e. entirely in the RECEIVER. The sender contributes only a fresh timestamp.
    """

    def __init__(self, max_entries: int = 1024, window_s: int = REPLAY_WINDOW_S):
        self._seen: dict[str, int] = {}
        self._max_entries = max(1, max_entries)
        self._window_s = window_s

    def check_and_record(self, nonce: str, timestamp: int, now: int) -> None:
        self._seen = {k: v for k, v in self._seen.items() if abs(now - v) <= self._window_s}
        if nonce in self._seen:
            raise AuthError(REPLAY_DETECTED, "signature already used")
        if len(self._seen) >= self._max_entries:
            oldest = min(self._seen, key=lambda k: self._seen[k])
            del self._seen[oldest]
        self._seen[nonce] = timestamp


def extract_signing_headers(headers: dict) -> tuple[str, int, str]:
    """
    Port of `handlers.rs::extract_signing_headers`.

    Each missing header is its own 401 before verification is even attempted, so
    a push that omits one is rejected outright.
    """
    lower = {k.lower(): v for k, v in headers.items()}
    for name in ("x-arkheia-key-id", "x-arkheia-timestamp", "x-arkheia-signature"):
        if name not in lower:
            raise AuthError(MISSING_HEADER, name)
    try:
        timestamp = int(lower["x-arkheia-timestamp"])
    except (TypeError, ValueError):
        raise AuthError(INVALID_TIMESTAMP, lower["x-arkheia-timestamp"]) from None
    return lower["x-arkheia-key-id"], timestamp, lower["x-arkheia-signature"]


def verify(
    secret: bytes,
    expected_key_id: str,
    path: str,
    body: bytes,
    headers: dict,
    nonces: Optional[NonceStore] = None,
    replay_window_s: int = REPLAY_WINDOW_S,
    now: Optional[int] = None,
) -> None:
    """
    Port of `hmac_auth::verify`. Returns None on success, raises `AuthError`
    otherwise — never a bool, so a test cannot pass by ignoring the result.
    """
    key_id, timestamp, signature = extract_signing_headers(headers)
    now = int(time.time()) if now is None else now

    # 1. key-id binding (BEFORE the signature — a mismatch is UnknownKeyId even
    #    when the signature is also wrong).
    if key_id != expected_key_id:
        raise AuthError(UNKNOWN_KEY_ID, key_id)

    # 2. replay window
    if abs(now - timestamp) > replay_window_s:
        raise AuthError(REPLAY_WINDOW_EXCEEDED, f"delta={abs(now - timestamp)}s")

    # 3. signature, constant-time
    expected = sign(secret, path, timestamp, body)
    try:
        bytes.fromhex(signature)
    except ValueError:
        raise AuthError(INVALID_SIGNATURE, "not hex") from None
    if not hmac.compare_digest(expected, signature):
        raise AuthError(INVALID_SIGNATURE, "mismatch")

    # 4. nonce/replay — only after the signature is proven authentic
    if nonces is not None:
        nonces.check_and_record(signature, timestamp, now)


# ── Body schema oracle: `normalise.rs::ProxyEvent` ───────────────────────────
# serde rejects the WHOLE body if any non-Option field is absent or mistyped, so
# these are hard requirements, not suggestions.
PROXY_EVENT_REQUIRED = (
    "schema_version",
    "source_product",
    "source_version",
    "event_id",
    "emitted_at",
    "tenant",
    "invocation",
    "model",
    "detection",
    "context",
)
PROXY_TENANT_REQUIRED = ("tenant_id",)
PROXY_INVOCATION_REQUIRED = ("invocation_id", "intercepted_at")
PROXY_MODEL_REQUIRED = ("model_id",)
PROXY_DETECTION_REQUIRED = ("fabrication_risk", "confidence", "classification")
# Fields serde types as `Uuid` — a non-UUID string fails the whole deserialisation.
PROXY_EVENT_UUID_FIELDS = ("event_id",)
