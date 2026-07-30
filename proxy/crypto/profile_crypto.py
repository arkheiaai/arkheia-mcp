"""
Profile encryption and decryption using AES-256-GCM.

Build time: encrypt plaintext YAML profiles into .yaml.enc files.
Runtime: decrypt .yaml.enc files in memory using a key fetched from
the hosted endpoint (dynamic key loading) or from a local cache.

Key is NEVER embedded in the binary. It is:
  - Free/Pro: fetched from POST /v1/profile-key on startup
  - Enterprise: loaded from signed license file
  - Cached locally (encrypted with machine-derived salt) for offline resilience
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from arkheia_common.egress import egress_async_client
from proxy.audit.decision_journal import (
    KEY_LOAD_FETCHED_CACHE,
    KEY_LOAD_FETCHED_HOSTED,
    KEY_LOAD_UNAVAILABLE,
    KEY_SOURCE_CACHE,
    KEY_SOURCE_HOSTED,
    KEY_SOURCE_NONE,
    RECEIPT_ENQUEUED,
    RECEIPT_UNAVAILABLE,
    REVOCATION_CHECKED,
    REVOCATION_NOT_APPLICABLE,
    REVOCATION_UNKNOWN_OFFLINE,
    DecisionJournal,
    build_key_load_record,
    flush_journal,
)

logger = logging.getLogger(__name__)

# 12-byte nonce for AES-GCM (NIST recommended)
_NONCE_SIZE = 12
# 32-byte key for AES-256
_KEY_SIZE = 32


def derive_key(master_key: bytes, profile_name: str) -> bytes:
    """Derive a per-profile key from the master key using HKDF-like construction."""
    return hashlib.sha256(master_key + profile_name.encode("utf-8")).digest()


def encrypt_profile(plaintext: bytes, master_key: bytes, profile_name: str) -> bytes:
    """
    Encrypt a profile YAML file.

    Returns: nonce (12 bytes) || ciphertext+tag
    """
    key = derive_key(master_key, profile_name)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, profile_name.encode("utf-8"))
    return nonce + ciphertext


def decrypt_profile(encrypted: bytes, master_key: bytes, profile_name: str) -> bytes:
    """
    Decrypt a profile .yaml.enc file.

    Input: nonce (12 bytes) || ciphertext+tag
    Returns: plaintext YAML bytes.
    Raises: cryptography.exceptions.InvalidTag on tamper/wrong key.
    """
    if len(encrypted) < _NONCE_SIZE + 16:  # nonce + minimum GCM tag
        raise ValueError(f"Encrypted data too short for profile {profile_name}")
    nonce = encrypted[:_NONCE_SIZE]
    ciphertext = encrypted[_NONCE_SIZE:]
    key = derive_key(master_key, profile_name)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, profile_name.encode("utf-8"))


class DynamicKeyLoader:
    """
    Fetches the profile decryption key from the hosted endpoint.

    Fallback chain:
      1. Hosted endpoint POST /v1/profile-key → returns base64 key
      2. Local cache ~/.arkheia/profile_key.cache → AES-encrypted with machine salt
      3. No key → returns None (caller degrades to UNKNOWN)
    """

    CACHE_DIR = Path.home() / ".arkheia"
    CACHE_FILE = CACHE_DIR / "profile_key.cache"
    # Machine-derived salt for cache encryption (not secret, just prevents trivial copy)
    _MACHINE_SALT = hashlib.sha256(
        (os.environ.get("COMPUTERNAME", "") + os.environ.get("HOSTNAME", "")).encode()
    ).digest()[:16]

    def __init__(
        self,
        hosted_url: str,
        api_key: str,
        audit_writer: Optional[object] = None,
        journal: Optional[DecisionJournal] = None,
    ):
        self.hosted_url = hosted_url.rstrip("/")
        self.api_key = api_key
        self._cached_key: Optional[bytes] = None
        # The audit rail, handed in at CONSTRUCTION. This is the ordering fix:
        # ``proxy/main.py`` now builds the AuditWriter at step 0, so a writer
        # exists before this loader is created and D1 is receipted at the moment
        # it is decided rather than reconstructed afterwards.
        self._audit_writer = audit_writer
        self.decision_journal = journal or DecisionJournal()
        #: The id of the most recent key-load decision, for a caller to quote.
        self.last_decision_id: Optional[str] = None
        #: What the rail said about that record — "enqueued" or "unavailable".
        #: Reported, never assumed: a caller that prints "enqueued" without
        #: reading this is asserting an outcome it did not observe.
        self.last_receipt_status: Optional[str] = None
        self.last_http_status: Optional[int] = None

    def attach_audit_writer(self, writer: object) -> None:
        """Attach the rail after construction (used by callers that build the
        writer late). Anything already journalled is flushed on the next
        ``fetch_key`` or explicit ``flush_decisions``."""
        self._audit_writer = writer

    async def flush_decisions(self) -> list:
        """Drain journalled key-load decisions to the rail, if one is attached."""
        if self._audit_writer is None:
            return []
        return await flush_journal(self.decision_journal, self._audit_writer)

    async def fetch_key(self) -> Optional[bytes]:
        """
        Fetch profile decryption key. Returns 32-byte AES key or None.

        Whichever branch is taken, the decision — *which key, from where, and
        whether anyone has confirmed it is still valid* — is journalled and
        handed to the audit rail before this returns. A key silently promoted
        from an offline cache is exactly the decision an auditor needs to see,
        and it was previously a single WARNING line in a log nobody chains.
        """
        # 1. Try hosted endpoint
        key = await self._fetch_from_hosted()
        if key:
            self._cached_key = key
            self._save_cache(key)
            await self._record_key_load(
                outcome=KEY_LOAD_FETCHED_HOSTED,
                key_source=KEY_SOURCE_HOSTED,
                revocation_state=REVOCATION_CHECKED,
                key=key,
            )
            return key

        # 2. Try local cache
        key = self._load_cache()
        if key:
            logger.warning(
                "Using cached profile key (hosted endpoint unreachable) — this key "
                "MAY HAVE BEEN REVOKED; nothing has confirmed it with the issuer"
            )
            self._cached_key = key
            await self._record_key_load(
                outcome=KEY_LOAD_FETCHED_CACHE,
                key_source=KEY_SOURCE_CACHE,
                # The cache is read precisely because the issuer was unreachable,
                # so no revocation check happened. "Unknown" is the only honest
                # value; recording it as checked would be a false attestation.
                revocation_state=REVOCATION_UNKNOWN_OFFLINE,
                key=key,
            )
            return key

        # 3. No key available
        logger.error("No profile decryption key available — detection will return UNKNOWN")
        await self._record_key_load(
            outcome=KEY_LOAD_UNAVAILABLE,
            key_source=KEY_SOURCE_NONE,
            revocation_state=REVOCATION_NOT_APPLICABLE,
        )
        return None

    async def _record_key_load(
        self,
        *,
        outcome: str,
        key_source: str,
        revocation_state: str,
        key: Optional[bytes] = None,
    ) -> str:
        record = build_key_load_record(
            outcome=outcome,
            key_source=key_source,
            revocation_state=revocation_state,
            key=key,
            hosted_url=self.hosted_url,
            http_status=self.last_http_status,
        )
        self.last_decision_id = self.decision_journal.record(record)
        results = await self.flush_decisions()
        statuses = {status for _id, status in results}
        self.last_receipt_status = (
            RECEIPT_UNAVAILABLE if (not results or RECEIPT_UNAVAILABLE in statuses)
            else RECEIPT_ENQUEUED
        )
        return self.last_decision_id

    async def _fetch_from_hosted(self) -> Optional[bytes]:
        """POST /v1/profile-key with API key to get decryption key."""
        if not self.api_key:
            logger.warning("No API key configured — cannot fetch profile key")
            return None
        try:
            async with egress_async_client(timeout=30) as client:
                resp = await client.post(
                    f"{self.hosted_url}/v1/profile-key",
                    headers={"X-Arkheia-Key": self.api_key},
                )
                # Structural evidence for the key-load record: a status code, not
                # a body. 401 vs 429 vs a network failure are different
                # governance facts and were previously distinguishable only in a
                # log line.
                self.last_http_status = resp.status_code
                if resp.status_code == 200:
                    data = resp.json()
                    key_b64 = data.get("profile_key", "")
                    key = base64.b64decode(key_b64)
                    if len(key) == _KEY_SIZE:
                        logger.info("Profile decryption key fetched from hosted endpoint")
                        return key
                    logger.error("Invalid key length from hosted endpoint: %d", len(key))
                elif resp.status_code == 401:
                    logger.error("API key rejected by hosted endpoint (401)")
                elif resp.status_code == 429:
                    logger.warning("Rate limited fetching profile key (429)")
                else:
                    logger.warning("Hosted endpoint returned %d", resp.status_code)
        except Exception as exc:
            logger.warning("Failed to reach hosted endpoint: %s", exc)
        return None

    def _save_cache(self, key: bytes) -> None:
        """Save key to local cache, XOR'd with machine salt."""
        try:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            # Simple XOR obfuscation with machine salt (not cryptographic security,
            # just prevents trivial copying of cache file between machines)
            obfuscated = bytes(a ^ b for a, b in zip(key, (self._MACHINE_SALT * 2)[:_KEY_SIZE]))
            self.CACHE_FILE.write_bytes(obfuscated)
            logger.debug("Profile key cached to %s", self.CACHE_FILE)
        except Exception as exc:
            logger.warning("Failed to cache profile key: %s", exc)

    def _load_cache(self) -> Optional[bytes]:
        """Load key from local cache."""
        try:
            if not self.CACHE_FILE.exists():
                return None
            obfuscated = self.CACHE_FILE.read_bytes()
            if len(obfuscated) != _KEY_SIZE:
                return None
            key = bytes(a ^ b for a, b in zip(obfuscated, (self._MACHINE_SALT * 2)[:_KEY_SIZE]))
            return key
        except Exception as exc:
            logger.warning("Failed to load cached profile key: %s", exc)
            return None

    @property
    def has_key(self) -> bool:
        return self._cached_key is not None

    @property
    def current_key(self) -> Optional[bytes]:
        return self._cached_key
