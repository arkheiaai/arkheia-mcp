"""
Multi-profile router with atomic reload, license enforcement, and encrypted profile support.

Loads YAML profiles at startup. Supports both plaintext (.yaml) and encrypted (.yaml.enc) files.
Encrypted profiles require a decryption key fetched dynamically from the hosted endpoint.
Reload is copy-and-swap -- zero dropped requests during update.

License verification:
  - Profiles with a 'license:' block are checked for expiry and HMAC signature.
  - ARKHEIA_LICENSE_KEY   — HMAC-SHA256 secret; if unset, signature check is skipped (dev mode)
  - ARKHEIA_REQUIRE_LICENSE — if true, profiles without a license block are rejected
  - Expired / tampered profiles are silently skipped; other profiles are unaffected.
"""

import asyncio
import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import sys
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

from proxy.audit.decision_journal import (
    PROFILE_AUTH_AUTHENTICATED,
    PROFILE_AUTH_EMPTY,
    PROFILE_AUTH_FAILED,
    PROFILE_AUTH_LICENSE_REJECTED,
    PROFILE_AUTH_MALFORMED,
    PROFILE_AUTH_NOT_YAML,
    PROFILE_AUTH_NO_MODEL_ID,
    PROFILE_AUTH_SKIPPED_NO_KEY,
    DecisionJournal,
    build_profile_auth_record,
    flush_journal,
)

logger = logging.getLogger(__name__)

# Read once at import time; NSSM AppEnvironmentExtra sets these per installation.
_LICENSE_KEY: str = os.getenv("ARKHEIA_LICENSE_KEY", "")
_REQUIRE_LICENSE: bool = os.getenv("ARKHEIA_REQUIRE_LICENSE", "false").lower() in (
    "true", "1", "yes"
)


def _canonical_profile(profile: dict) -> str:
    """Deterministic JSON serialization of profile content, excluding the license block."""
    content = {k: v for k, v in profile.items() if k != "license"}
    return json.dumps(content, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _verify_profile_license(profile: dict, filename: str) -> bool:
    """
    Verify the license block in a profile. Returns True if the profile may be loaded.

    Rules:
      - No license block + REQUIRE_LICENSE=false  → allowed (open / dev mode)
      - No license block + REQUIRE_LICENSE=true   → rejected, warning logged
      - Expired date                               → rejected, warning logged
      - HMAC mismatch                              → rejected, error logged
      - No LICENSE_KEY configured                  → HMAC check skipped (dev mode)
    """
    block = profile.get("license")

    if not block:
        if _REQUIRE_LICENSE:
            logger.warning(
                "Profile %s has no license block and ARKHEIA_REQUIRE_LICENSE=true — skipping",
                filename,
            )
            return False
        return True  # open mode: no license required

    valid_until_str = str(block.get("valid_until", ""))
    try:
        expiry = date.fromisoformat(valid_until_str)
    except ValueError:
        logger.error(
            "Profile %s has invalid valid_until %r — skipping", filename, valid_until_str
        )
        return False

    if expiry < date.today():
        logger.warning(
            "Profile %s license expired on %s — skipping (model returns UNKNOWN)",
            filename,
            valid_until_str,
        )
        return False

    if _LICENSE_KEY:
        customer_id = str(block.get("customer_id", ""))
        message = f"{_canonical_profile(profile)}|{customer_id}|{valid_until_str}"
        expected = _hmac_mod.new(
            _LICENSE_KEY.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        actual = str(block.get("signature", ""))
        if not _hmac_mod.compare_digest(expected, actual):
            logger.error(
                "Profile %s license signature mismatch — skipping (possible tampering)",
                filename,
            )
            return False

    return True


class ProfileRouter:
    """
    Thread-safe (asyncio-safe) profile dispatch table.

    Supports both plaintext (.yaml) and encrypted (.yaml.enc) profiles.
    Encrypted profiles require a decryption key (set via set_decryption_key).

    Lookup priority:
      1. Exact model_id match
      2. Prefix match (e.g. "claude-sonnet" matches "claude-sonnet-4-6")
      3. Family match (e.g. "claude" matches any Claude profile, uses latest version)
      4. No match -> None (caller returns UNKNOWN)
    """

    def __init__(
        self,
        profile_dir: str,
        decryption_key: Optional[bytes] = None,
        audit_writer: Optional[object] = None,
        journal: Optional[DecisionJournal] = None,
    ):
        self._profiles: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.profile_dir = profile_dir
        self._loaded_count = 0
        self._decryption_key = decryption_key
        # The audit rail, handed in at CONSTRUCTION. ``proxy/main.py`` builds the
        # AuditWriter at step 0 for exactly this reason: the router decides
        # whether each encrypted profile authenticated, and before this change no
        # writer existed when it decided.
        self._audit_writer = audit_writer
        self.decision_journal = journal or DecisionJournal()
        #: Fire-and-forget flush tasks, held so the GC cannot collect a pending
        #: one mid-flight (asyncio only holds a weak reference to a bare task).
        self._flush_tasks: set = set()
        self.load_all()
        self._schedule_flush()

    def attach_audit_writer(self, writer: object) -> None:
        """Attach the rail after construction. Anything already journalled is
        flushed by the next ``flush_decision_journal()``."""
        self._audit_writer = writer

    async def flush_decision_journal(self) -> list:
        """
        Drain journalled profile-authentication decisions to the audit rail.

        Returns ``[(decision_id, receipt_status), ...]``. Empty when no writer is
        attached — and in that case the entries are LEFT in the journal rather
        than discarded, so attaching a writer later still records them.
        """
        if self._audit_writer is None:
            return []
        return await flush_journal(self.decision_journal, self._audit_writer)

    def _schedule_flush(self) -> None:
        """
        Flush from a synchronous call site.

        ``load_all()`` is sync (it is called from ``__init__``) while the rail is
        async, so decisions taken inside it cannot be handed over in the same
        statement. Where a loop is already running — every reload path, and the
        proxy lifespan — schedule the drain immediately; the ``decided_at`` /
        ``receipt_enqueued_at`` / ``receipt_deferred_ms`` fields on each record
        make the resulting gap visible rather than hidden. Where no loop is
        running the entries stay journalled until someone flushes them.
        """
        if self._audit_writer is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self.flush_decision_journal())
        self._flush_tasks.add(task)
        task.add_done_callback(self._flush_tasks.discard)

    def set_decryption_key(self, key: bytes) -> None:
        """Set the decryption key and reload encrypted profiles."""
        self._decryption_key = key
        self.load_all()
        self._schedule_flush()

    def load_all(self) -> None:
        """Load all YAML profiles from profile_dir. Supports .yaml and .yaml.enc."""
        profiles: dict[str, dict] = {}
        path = Path(self.profile_dir).resolve()
        if not path.exists():
            logger.warning("Profiles directory not found: %s", self.profile_dir)
            self._profiles = profiles
            self._loaded_count = 0
            return

        # Load plaintext .yaml profiles
        for f in path.glob("*.yaml"):
            if not f.resolve().parent == path:  # aikido-ignore
                logger.warning("Skipping file outside profile dir: %s", f)
                continue
            if f.name == "schema.yaml":
                continue
            data = self._load_plaintext(f)
            if data:
                model_id = self._extract_model_id(data, f.name)
                if model_id:
                    profiles[model_id] = data

        # Load encrypted .yaml.enc profiles (if decryption key available)
        enc_files = list(path.glob("*.yaml.enc"))
        if enc_files and not self._decryption_key:
            logger.warning(
                "Found %d encrypted profiles but no decryption key — skipping. "
                "Detection will return UNKNOWN for these models.",
                len(enc_files),
            )
            # One record: no per-profile decision was TAKEN here, so emitting a
            # per-profile row would overstate what happened. The names are
            # journalled because "which surfaces went dark" is the fact an
            # operator needs.
            self.decision_journal.record(build_profile_auth_record(
                outcome=PROFILE_AUTH_SKIPPED_NO_KEY,
                skipped_profile_names=[f.name for f in enc_files],
            ))
        elif enc_files:
            from cryptography.exceptions import InvalidTag
            from proxy.crypto.profile_crypto import decrypt_profile
            for f in enc_files:
                if not f.resolve().parent == path:  # aikido-ignore
                    continue
                profile_name = f.name.replace(".yaml.enc", "")
                encrypted = b""
                try:
                    encrypted = f.read_bytes()
                    plaintext = decrypt_profile(encrypted, self._decryption_key, profile_name)
                except InvalidTag as e:
                    # THE TAMPER SIGNAL. AES-GCM refused the tag: the bytes on
                    # disk are not the bytes that were sealed, or this is not the
                    # key they were sealed with. Previously this was one ERROR
                    # line in an unchained log; it is now a row on the
                    # hash-chained rail carrying which bytes and which key.
                    logger.error(
                        "Profile %s FAILED AUTHENTICATION (AES-GCM tag rejected) — "
                        "tampered file or wrong key", f.name,
                    )
                    self._journal_auth(PROFILE_AUTH_FAILED, profile_name, encrypted, e)
                    continue
                except ValueError as e:
                    logger.error("Failed to decrypt profile %s: %s", f.name, e)
                    self._journal_auth(PROFILE_AUTH_MALFORMED, profile_name, encrypted, e)
                    continue
                except Exception as e:
                    logger.error("Failed to decrypt profile %s: %s", f.name, e)
                    self._journal_auth(PROFILE_AUTH_MALFORMED, profile_name, encrypted, e)
                    continue

                # From here the profile HAS authenticated; every further refusal
                # is a content decision, and each gets its own outcome so a
                # tamper can never be confused with a licence expiry.
                try:
                    data = yaml.safe_load(plaintext)
                except Exception as e:
                    logger.error("Decrypted profile %s is not valid YAML: %s", f.name, e)
                    self._journal_auth(PROFILE_AUTH_NOT_YAML, profile_name, encrypted, e)
                    continue
                if not data:
                    self._journal_auth(PROFILE_AUTH_EMPTY, profile_name, encrypted, None)
                    continue
                if not _verify_profile_license(data, f.name):
                    self._journal_auth(PROFILE_AUTH_LICENSE_REJECTED, profile_name, encrypted, None)
                    continue
                model_id = self._extract_model_id(
                    data,
                    f.name,
                    allow_filename_fallback=False,
                )
                if not model_id:
                    self._journal_auth(PROFILE_AUTH_NO_MODEL_ID, profile_name, encrypted, None)
                    continue
                profiles[model_id] = data
                logger.debug("Loaded encrypted profile: %s -> %s", f.name, model_id)
                self._journal_auth(PROFILE_AUTH_AUTHENTICATED, profile_name, encrypted, None)

        self._profiles = profiles
        self._loaded_count = len(profiles)
        logger.info(
            "ProfileRouter: loaded %d valid profiles from %s",
            len(profiles),
            self.profile_dir,
        )

    def _journal_auth(
        self,
        outcome: str,
        profile_name: str,
        ciphertext: bytes,
        error: Optional[BaseException],
    ) -> str:
        """
        Journal one profile-authentication decision.

        ``error`` contributes its TYPE only. An exception message can carry the
        text of whatever it choked on; a class name cannot.
        """
        return self.decision_journal.record(build_profile_auth_record(
            outcome=outcome,
            profile_name=profile_name,
            ciphertext=ciphertext or None,
            key=self._decryption_key,
            error_type=type(error).__name__ if error is not None else None,
        ))

    def _load_plaintext(self, f: Path) -> Optional[dict]:
        """Load and validate a plaintext YAML profile."""
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not data:
                return None
            if not _verify_profile_license(data, f.name):
                return None
            return data
        except Exception as e:
            logger.error("Failed to load profile %s: %s", f.name, e)
            return None

    @staticmethod
    def _extract_model_id(
        data: dict,
        filename: str,
        *,
        allow_filename_fallback: bool = True,
    ) -> Optional[str]:
        """Extract model_id from profile data.

        Primary source is the profile CONTENTS (``model:`` / ``metadata.model_id``).
        Optional fallback: a cache file written by the registry client is named with the
        reversibly-ENCODED model_id (``deepseek-ai%2FDeepSeek-V3.1.yaml``); if the
        contents somehow lack an id, recover it by DECODING the filename stem, so
        an encoded slash/colon id still round-trips to a loadable profile.
        """
        model_id = (
            data.get("model")
            or data.get("metadata", {}).get("model_id")
        )
        if not model_id:
            if not allow_filename_fallback:
                logger.warning("Profile %s has no model_id, skipping", filename)
                return None
            from proxy.pathsafe import decode_model_id
            stem = filename
            for suffix in (".yaml.enc", ".yaml"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            decoded = decode_model_id(stem)
            if decoded:
                logger.debug("Recovered model_id from filename %s -> %s", filename, decoded)
                return decoded
            logger.warning("Profile %s has no model_id, skipping", filename)
            return None
        return model_id

    def _by_model_id(self, target: str) -> Optional[dict]:
        """Case-insensitive direct lookup of a profile by its model id (no fuzzy)."""
        t = target.lower()
        if t in self._profiles:
            return self._profiles[t]
        for key, profile in self._profiles.items():
            stored = (profile.get("model") or profile.get("metadata", {}).get("model_id", "")).lower()
            if key.lower() == t or stored == t:
                return profile
        return None

    def _resolve_recent_gpt(self, model_lower: str) -> Optional[dict]:
        """Explicit, logged resolution for recent GPT-5.x IDs (surface-strategy 2026-06-30).
        Returns None to fall through when not a recent-GPT id."""
        if not model_lower.startswith("gpt-5"):
            return None
        if "codex" in model_lower:
            if "5.2-codex" in model_lower or "5.3-codex" in model_lower:
                return self._by_model_id("gpt-5.2-codex")
            if "5.1-codex-mini" in model_lower:
                return self._by_model_id("gpt-5.1-codex-mini")
            prof = self._by_model_id("gpt-5-codex")
            if prof is not None:
                logger.warning("Model %s: no dedicated Codex profile -- gpt-5-codex FALLBACK "
                               "pending subscription characterisation", model_lower)
            return prof
        # public-API GPT-5.x: prefer a version-specific profile if characterised
        # (gpt-5.5 covers gpt-5.5*, etc.), else nearest characterised API surface gpt-5.4.
        import re as _re
        _vm = _re.match(r"(gpt-5(?:\.\d+)?)", model_lower)
        if _vm:
            vprof = self._by_model_id(_vm.group(1))
            if vprof is not None:
                return vprof
        prof = self._by_model_id("gpt-5.4")
        if prof is not None and "5.4" not in model_lower:
            logger.warning("Model %s: no dedicated API profile -- gpt-5.4 (nearest API "
                           "surface) pending per-version drift validation", model_lower)
        return prof

    def _resolve_glm(self, model_lower: str) -> Optional[dict]:
        """Explicit version routing for GLM (Together) ids so a bare 'glm-5.2' or a canonical
        'zai-org/glm-5.2' resolves to the RIGHT together-glm-<ver> surface and never borrows a
        wrong-version GLM profile via the fuzzy prefix/family match below. Returns None to fall
        through when not a GLM-5.x id (glm4-9b keeps its own path). Parity with the API Proxy
        MODEL_PROFILE_MAP GLM entries (2026-07-05)."""
        if "glm" not in model_lower:
            return None
        import re as _re
        m = _re.search(r"glm-?(5(?:\.\d+)?)", model_lower)
        if not m:
            return None
        return self._by_model_id(f"zai-org/glm-{m.group(1)}")

    def get(self, model_id: str) -> Optional[dict]:
        """Return profile for model_id, or None if no match."""
        if not model_id:
            return None

        model_lower = model_id.lower()

        # 1. Exact match
        if model_lower in self._profiles:
            return self._profiles[model_lower]

        # Also try exact match against values (profiles may store mixed-case)
        for key, profile in self._profiles.items():
            stored_id = (
                profile.get("model")
                or profile.get("metadata", {}).get("model_id", "")
            ).lower()
            if stored_id == model_lower:
                return profile

        # 1b. Recent GPT-5.x explicit resolution (parity with the API Proxy loader,
        # 2026-06-30). Without this, recent IDs hit the crude family match below and could
        # borrow a wrong-surface profile (e.g. a Codex profile for an API model, or vice
        # versa). Route explicitly: Codex/subscription IDs -> gpt-5-codex; public-API
        # versions -> nearest characterised API surface (gpt-5.4) pending drift. A real
        # gpt-5.5.yaml dropped in supersedes this via the exact match above.
        gpt5 = self._resolve_recent_gpt(model_lower)
        if gpt5 is not None:
            return gpt5

        # 1c. GLM (Together) explicit version routing — before the fuzzy match, so a GLM id
        # resolves to its exact together-glm-<ver> surface and never borrows a wrong version.
        glm = self._resolve_glm(model_lower)
        if glm is not None:
            return glm

        # 2. Prefix match (either direction)
        for key in self._profiles:
            if key.startswith(model_lower) or model_lower.startswith(key):
                logger.debug("Profile prefix match: %s -> %s", model_lower, key)
                return self._profiles[key]

        # 3. Family match (first token of model_id)
        family = model_lower.split("-")[0]
        candidates = []
        for key, profile in self._profiles.items():
            stored_family = (
                profile.get("metadata", {}).get("model_family", "")
                or key.split("-")[0]
            ).lower()
            if stored_family == family:
                candidates.append(profile)

        if candidates:
            # Use highest version
            def _version_key(p: dict) -> str:
                return str(
                    p.get("version")
                    or p.get("metadata", {}).get("version", "0.0")
                )
            best = sorted(candidates, key=_version_key, reverse=True)[0]
            logger.debug("Profile family match: %s -> family=%s", model_lower, family)
            return best

        logger.debug("No profile match for model: %s", model_id)
        return None

    async def reload(self, profile_dir: Optional[str] = None) -> None:
        """
        Atomic reload -- build new profiles dict then swap.
        Requests in flight complete against old profiles.
        Handles both .yaml and .yaml.enc files.
        """
        target = profile_dir or self.profile_dir
        old_dir = self.profile_dir
        self.profile_dir = target
        self.load_all()
        self.profile_dir = old_dir if profile_dir else target
        # A scheduled registry pull reloads profiles hours after startup. The
        # authentication decisions it takes are as governed as the ones at boot,
        # so they go to the same rail rather than being lost because nobody was
        # holding the journal.
        self._schedule_flush()

        logger.info("ProfileRouter reloaded: %d valid profiles", self._loaded_count)

    @property
    def loaded_count(self) -> int:
        return self._loaded_count

    @property
    def profile_ids(self) -> list[str]:
        return list(self._profiles.keys())
