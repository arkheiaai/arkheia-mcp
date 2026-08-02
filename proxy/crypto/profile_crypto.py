"""
Profile encryption and decryption using AES-256-GCM.

Build time: encrypt plaintext YAML profiles into .yaml.enc files.
Runtime: decrypt .yaml.enc files in memory using a key fetched from
the hosted endpoint (dynamic key loading) or from a local cache.

Key is NEVER embedded in the binary. It is:
  - Free/Pro: fetched from POST /v1/profile-key on startup
  - Enterprise: loaded from signed license file
  - Cached locally for offline resilience (see DynamicKeyLoader for the exact,
    and deliberately modest, protection that cache does and does not provide)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import platform
import secrets
import stat
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
# AES-GCM authentication tag length, in bytes.
_TAG_SIZE = 16


class InvalidMasterKey(ValueError):
    """The supplied profile master key is not a usable AES-256 key."""


def _require_master_key(master_key: bytes) -> bytes:
    """
    Reject a master key that is not exactly 32 bytes.

    WHY THIS EXISTS: ``derive_key`` hashes the master key, and SHA-256 accepts an
    input of ANY length -- including ``b""``. Before this guard, every entry point
    in this module happily encrypted and decrypted with an empty, truncated or
    otherwise malformed master key, because hashing normalised it into a
    well-formed 32-byte AES key. Measured 2026-07-26: master keys of length
    0, 1, 16, 31 and 64 all round-tripped successfully.

    That silence is the dangerous part. Every OTHER place in the repo already
    demands exactly 32 bytes (``scripts/build_release.py::resolve_profile_key``,
    ``scripts/encrypt_profiles.py``, ``DynamicKeyLoader._fetch_from_hosted``), so
    a caller that skipped those checks -- or a future one -- got a cipher that
    "worked" under a key that was never the key. A build run that way produces
    ciphertext nobody can ever decrypt with the real key, and the plaintext
    profiles have already been deleted by then.
    """
    if not isinstance(master_key, (bytes, bytearray)):
        raise InvalidMasterKey(
            f"Profile master key must be bytes, got {type(master_key).__name__}"
        )
    if len(master_key) != _KEY_SIZE:
        raise InvalidMasterKey(
            f"Profile master key must be exactly {_KEY_SIZE} bytes, got {len(master_key)}"
        )
    return bytes(master_key)


def derive_key(master_key: bytes, profile_name: str) -> bytes:
    """
    Derive a per-profile key from the master key.

    The per-profile derivation is what makes a profile's ciphertext unusable under
    another profile's name: ``gpt-4o.yaml.enc`` renamed to ``grok-4.yaml.enc``
    derives a different key AND presents a different AAD, so it fails to
    authenticate twice over.
    """
    master_key = _require_master_key(master_key)
    return hashlib.sha256(master_key + profile_name.encode("utf-8")).digest()


def encrypt_profile(plaintext: bytes, master_key: bytes, profile_name: str) -> bytes:
    """
    Encrypt a profile YAML file.

    Returns: nonce (12 bytes) || ciphertext+tag

    The nonce is freshly random per call (``secrets.token_bytes``) and is derived
    from NOTHING about the content or the profile name, so re-encrypting the same
    profile never reuses a (key, nonce) pair.
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

    Raises:
        InvalidMasterKey: the master key is not 32 bytes.
        ValueError: the blob is too short to contain a nonce and a tag.
        cryptography.exceptions.InvalidTag: authentication failed -- a tampered
            ciphertext, a tampered tag, a tampered nonce, a wrong key, or a blob
            presented under a profile name it was not encrypted for.

    There is NO recovery path and no plaintext fallback: an unauthenticated blob
    raises and this function returns nothing. Callers must treat the exception as
    "this profile does not exist", never as "load it anyway".
    """
    if len(encrypted) < _NONCE_SIZE + _TAG_SIZE:  # nonce + minimum GCM tag
        raise ValueError(f"Encrypted data too short for profile {profile_name}")
    nonce = encrypted[:_NONCE_SIZE]
    ciphertext = encrypted[_NONCE_SIZE:]
    key = derive_key(master_key, profile_name)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, profile_name.encode("utf-8"))


def key_fingerprint(key: bytes) -> str:
    """
    A short, non-reversing identifier for a key, safe to log.

    Eight bytes of SHA-256 over the key. Enough to answer "is the key this process
    is using the same one the build used?" without ever putting key material, or
    any prefix of it, into a log line or an audit record.
    """
    return hashlib.sha256(key).hexdigest()[:16]


def _machine_salt() -> bytes:
    """
    A per-machine, NON-SECRET salt used to obfuscate the on-disk key cache.

    Fixed 2026-07-26. The previous derivation was
    ``sha256(COMPUTERNAME + HOSTNAME)[:16]`` read from ``os.environ``. On POSIX
    neither variable is normally exported to a child process -- ``COMPUTERNAME``
    is Windows-only and ``HOSTNAME`` is a shell variable, not an environment one --
    so on every Linux and macOS install the salt collapsed to
    ``sha256(b"")[:16] == e3b0c44298fc1c149afbf4c8996fb924``: a published
    constant, identical on every machine on earth. Measured on macOS 2026-07-26,
    and the cached master key was recovered from the cache file using that
    constant alone.

    ``platform.node()`` is the POSIX-working component. The env vars are retained
    so an existing Windows cache still resolves to the same salt it was written
    with.
    """
    parts = (
        os.environ.get("COMPUTERNAME", "")
        + os.environ.get("HOSTNAME", "")
        + platform.node()
    )
    return hashlib.sha256(parts.encode("utf-8", "replace")).digest()[:16]


class DynamicKeyLoader:
    """
    Fetches the profile decryption key from the hosted endpoint.

    Fallback chain:
      1. Hosted endpoint POST /v1/profile-key → returns base64 key
      2. Local cache ~/.arkheia/profile_key.cache
      3. No key → returns None (caller degrades to UNKNOWN)

    WHAT THE CACHE IS AND IS NOT
    ----------------------------
    The cache is XOR-obfuscated with a per-machine salt and authenticated with an
    HMAC over that salt. Being explicit, because the docstring here previously
    said "AES-encrypted with machine salt" and that was never true:

      * It is **NOT encryption** and it is **NOT a confidentiality control**. The
        salt is derived from the hostname, which is not a secret. Anyone who can
        read the cache file can recover the master key.
      * What it DOES provide is (a) the file is not a verbatim copy of the key,
        (b) a cache copied from another machine, or corrupted, is **rejected**
        rather than silently returned as a wrong key, and (c) the file is written
        0600 in a 0700 directory, so "who can read it" is the OS's answer and not
        an accident of the default umask (it was 0644 before 2026-07-26).

    Treat the cache file as key material for the purposes of backups, container
    images and support bundles.
    """

    CACHE_DIR = Path.home() / ".arkheia"
    CACHE_FILE = CACHE_DIR / "profile_key.cache"

    # Cache framing: MAGIC || obfuscated key (32) || HMAC-SHA256(salt, MAGIC||obf)[:16]
    _CACHE_MAGIC = b"ARKPK1"
    _CACHE_MAC_SIZE = 16
    _CACHE_SIZE = len(_CACHE_MAGIC) + _KEY_SIZE + _CACHE_MAC_SIZE

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
        # The key-load decision, for the caller to surface. Never the key itself.
        self.last_source: Optional[str] = None
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

    @property
    def _machine_salt(self) -> bytes:
        return _machine_salt()

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
            self.last_source = "hosted"
            self._save_cache(key)
            logger.info(
                "Profile key source=hosted fingerprint=%s", key_fingerprint(key)
            )
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
                "Using CACHED profile key (hosted endpoint unreachable) "
                "source=cache fingerprint=%s — this key was not re-authorised by "
                "the hosted endpoint and may have been revoked",
                key_fingerprint(key),
            )
            self._cached_key = key
            self.last_source = "cache"
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
        self.last_source = "none"
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
            import httpx
            async with httpx.AsyncClient(timeout=30) as client:
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
                    # validate=True: without it b64decode silently DISCARDS every
                    # character outside the base64 alphabet, so a truncated or
                    # corrupted response can decode to a shorter-but-plausible
                    # blob instead of failing.
                    key = base64.b64decode(key_b64, validate=True)
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

    def _obfuscate(self, key: bytes, salt: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(key, (salt * 2)[:_KEY_SIZE]))

    def _cache_mac(self, obfuscated: bytes, salt: bytes) -> bytes:
        return hmac.new(
            salt, self._CACHE_MAGIC + obfuscated, hashlib.sha256
        ).digest()[: self._CACHE_MAC_SIZE]

    def _save_cache(self, key: bytes) -> None:
        """
        Save the key to the local cache, XOR-obfuscated and MAC'd.

        The MAC is not a confidentiality control (see the class docstring); it
        exists so ``_load_cache`` can tell "this cache was written by this machine
        and is intact" from "this is 32 bytes of something else". Before this, a
        cache written under a different salt -- or a corrupted one, or one an
        attacker dropped in -- was returned as a perfectly well-formed 32-byte key
        that then failed to decrypt every profile, and the only trace was a
        reason-free "Failed to decrypt profile X:" line per file.
        """
        try:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            try:
                self.CACHE_DIR.chmod(stat.S_IRWXU)  # 0700
            except OSError:  # pragma: no cover - platform-dependent (e.g. Windows)
                pass
            salt = self._machine_salt
            obfuscated = self._obfuscate(key, salt)
            blob = self._CACHE_MAGIC + obfuscated + self._cache_mac(obfuscated, salt)
            # Create 0600 BEFORE any bytes land, so the key is never briefly
            # world-readable under a permissive umask (it was 0644 before
            # 2026-07-26, measured).
            fd = os.open(
                self.CACHE_FILE,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                stat.S_IRUSR | stat.S_IWUSR,
            )
            try:
                os.write(fd, blob)
            finally:
                os.close(fd)
            try:
                self.CACHE_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
            except OSError:  # pragma: no cover - platform-dependent
                pass
            logger.debug("Profile key cached to %s", self.CACHE_FILE)
        except Exception as exc:
            logger.warning("Failed to cache profile key: %s", exc)

    def _load_cache(self) -> Optional[bytes]:
        """
        Load the key from the local cache, or return None.

        Returns None -- never a guess -- for: a missing file, a legacy
        pre-``ARKPK1`` cache, a wrong-sized file, a bad magic, or a MAC that does
        not verify under this machine's salt. Every rejection is logged with a
        reason, because the downstream symptom (every profile fails to decrypt) is
        otherwise indistinguishable from a genuine tamper.
        """
        try:
            if not self.CACHE_FILE.exists():
                return None
            blob = self.CACHE_FILE.read_bytes()
            if len(blob) == _KEY_SIZE and not blob.startswith(self._CACHE_MAGIC):
                logger.warning(
                    "Ignoring legacy unauthenticated profile key cache at %s — "
                    "it will be rewritten on the next successful key fetch",
                    self.CACHE_FILE,
                )
                return None
            if len(blob) != self._CACHE_SIZE or not blob.startswith(self._CACHE_MAGIC):
                logger.warning(
                    "Profile key cache at %s is malformed (%d bytes) — ignoring",
                    self.CACHE_FILE,
                    len(blob),
                )
                return None
            body = blob[len(self._CACHE_MAGIC):]
            obfuscated, mac = body[:_KEY_SIZE], body[_KEY_SIZE:]
            salt = self._machine_salt
            if not hmac.compare_digest(mac, self._cache_mac(obfuscated, salt)):
                logger.warning(
                    "Profile key cache at %s failed its integrity check — it was "
                    "written on a different machine or has been modified. Ignoring "
                    "rather than decrypting profiles with a key that is not the key.",
                    self.CACHE_FILE,
                )
                return None
            return self._obfuscate(obfuscated, salt)
        except Exception as exc:
            logger.warning("Failed to load cached profile key: %s", exc)
            return None

    @property
    def has_key(self) -> bool:
        return self._cached_key is not None

    @property
    def current_key(self) -> Optional[bytes]:
        return self._cached_key
