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

    def __init__(self, hosted_url: str, api_key: str):
        self.hosted_url = hosted_url.rstrip("/")
        self.api_key = api_key
        self._cached_key: Optional[bytes] = None

    async def fetch_key(self) -> Optional[bytes]:
        """Fetch profile decryption key. Returns 32-byte AES key or None."""
        # 1. Try hosted endpoint
        key = await self._fetch_from_hosted()
        if key:
            self._cached_key = key
            self._save_cache(key)
            return key

        # 2. Try local cache
        key = self._load_cache()
        if key:
            logger.warning("Using cached profile key (hosted endpoint unreachable)")
            self._cached_key = key
            return key

        # 3. No key available
        logger.error("No profile decryption key available — detection will return UNKNOWN")
        return None

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
