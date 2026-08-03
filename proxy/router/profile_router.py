"""
Multi-profile router with atomic reload, license enforcement, and encrypted profile support.

Loads YAML profiles at startup. Supports plaintext-only development directories
and encrypted (.yaml.enc) release directories. If a directory contains encrypted
profiles, plaintext siblings are refused unless explicitly opted in.
If the router is placed in encrypted-profile policy, plaintext is refused even
when no encrypted sibling remains on disk.
Encrypted profiles require a decryption key fetched dynamically from the hosted endpoint.
Reload is copy-and-swap -- zero dropped requests during update.

License verification:
  - Profiles with a 'license:' block are checked for expiry and HMAC signature.
  - ARKHEIA_LICENSE_KEY   — HMAC-SHA256 secret; signed profiles are rejected
    when this is unset unless ARKHEIA_ALLOW_UNSIGNED_LICENSE=true.
  - ARKHEIA_REQUIRE_LICENSE — if true, profiles without a license block are rejected
  - ARKHEIA_ALLOW_UNSIGNED_LICENSE — explicit local/dev escape hatch for unverified
    license blocks; expiry is still checked.
  - ARKHEIA_ALLOW_PLAINTEXT_PROFILES — explicit local/dev escape hatch for loading
    .yaml profiles from a directory that also contains encrypted profiles.
  - Expired / tampered profiles are silently skipped; other profiles are unaffected.
"""

import asyncio
import hashlib
import hmac as _hmac_mod
import json
import logging
import os
import sys
from dataclasses import dataclass, field
import re
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
    PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
    PROFILE_AUTH_PLAINTEXT_REJECTED,
    PROFILE_AUTH_PLAINTEXT_REJECTED_ENCRYPTED_DIR,
    PROFILE_AUTH_SKIPPED_NO_KEY,
    PLAINTEXT_POLICY_DEVELOPMENT,
    PLAINTEXT_POLICY_ENCRYPTED_INVENTORY,
    PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY,
    PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY,
    PLAINTEXT_POLICY_UNMARKED_PLAINTEXT_DIRECTORY,
    DecisionJournal,
    build_profile_auth_record,
    flush_journal,
)

logger = logging.getLogger(__name__)

def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


def _canonical_profile(profile: dict) -> str:
    """Deterministic JSON serialization of profile content, excluding the license block."""
    content = {k: v for k, v in profile.items() if k != "license"}
    return json.dumps(content, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _verify_profile_license(
    profile: dict,
    filename: str,
    *,
    license_key: Optional[str] = None,
    require_license: Optional[bool] = None,
    allow_unsigned_license: Optional[bool] = None,
) -> bool:
    """
    Verify the license block in a profile. Returns True if the profile may be loaded.

    Rules:
      - No license block + REQUIRE_LICENSE=false       → allowed (open profile)
      - No license block + REQUIRE_LICENSE=true        → rejected, warning logged
      - Expired date                                    → rejected, warning logged
      - HMAC mismatch / missing signature               → rejected, error logged
      - License block + no LICENSE_KEY                  → rejected unless
        ALLOW_UNSIGNED_LICENSE=true (explicit dev mode)
    """
    license_key = os.getenv("ARKHEIA_LICENSE_KEY", "") if license_key is None else license_key
    require_license = (
        _env_bool("ARKHEIA_REQUIRE_LICENSE")
        if require_license is None else require_license
    )
    allow_unsigned_license = (
        _env_bool("ARKHEIA_ALLOW_UNSIGNED_LICENSE")
        if allow_unsigned_license is None else allow_unsigned_license
    )

    if "license" not in profile:
        if require_license:
            logger.warning(
                "Profile %s has no license block and ARKHEIA_REQUIRE_LICENSE=true — skipping",
                filename,
            )
            return False
        return True

    block = profile.get("license")
    if not isinstance(block, dict):
        logger.error("Profile %s license block is not an object — skipping", filename)
        return False

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

    if not license_key:
        if allow_unsigned_license:
            logger.warning(
                "Profile %s license signature not verified because "
                "ARKHEIA_ALLOW_UNSIGNED_LICENSE=true",
                filename,
            )
            return True
        logger.error(
            "Profile %s has a license block but no ARKHEIA_LICENSE_KEY is configured — skipping",
            filename,
        )
        return False

    customer_id = str(block.get("customer_id", ""))
    message = f"{_canonical_profile(profile)}|{customer_id}|{valid_until_str}"
    expected = _hmac_mod.new(
        license_key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    actual = str(block.get("signature", ""))
    if not actual or not _hmac_mod.compare_digest(expected, actual):
        logger.error(
            "Profile %s license signature mismatch — skipping (possible tampering)",
            filename,
        )
        return False

    return True


@dataclass
class ProfileLoadReport:
    """
    What a profile load actually did — the work-done record for ``load_all``.

    Earned 2026-07-26. ``ProfileRouter.loaded_count`` is the TOTAL profile count,
    plaintext included, so it cannot answer "did the encrypted half work?". With a
    wrong decryption key over a directory of 3 plaintext + 2 encrypted profiles,
    ``loaded_count`` is 3 and ``proxy/main.py`` logs
    ``"Decryption key loaded — 3 encrypted profiles available"`` having decrypted
    exactly ZERO. Same shape as the integrity manifest that reported
    ``"Integrity check passed: 0 modules verified"``.

    Every field that can be non-zero is a count of work DONE, and every unit of
    work-not-done is carried by NAME, per DONE.md floor invariant 9(a).
    """

    key_present: bool = False
    plaintext_present: int = 0
    plaintext_loaded: int = 0
    plaintext_rejected: list[str] = field(default_factory=list)
    encrypted_present: int = 0
    encrypted_attempted: int = 0
    encrypted_decrypted: int = 0
    #: Files whose AES-GCM authentication FAILED (tamper or wrong key).
    encrypted_failed: list[str] = field(default_factory=list)
    #: Files that decrypted but were then rejected (bad YAML, licence, no model_id).
    encrypted_rejected: list[str] = field(default_factory=list)
    #: Encrypted files not even attempted because no key was available.
    encrypted_skipped_no_key: list[str] = field(default_factory=list)
    total_loaded: int = 0

    @property
    def clean(self) -> bool:
        """True only if every unit present was actually turned into a profile."""
        return (
            not self.encrypted_failed
            and not self.encrypted_rejected
            and not self.encrypted_skipped_no_key
            and not self.plaintext_rejected
            and self.encrypted_attempted == self.encrypted_present
            and self.encrypted_decrypted == self.encrypted_present
        )

    def summary(self, profile_dir: str) -> str:
        parts = [
            f"loaded {self.total_loaded} profiles from {profile_dir}",
            f"plaintext {self.plaintext_loaded}/{self.plaintext_present}",
            f"encrypted {self.encrypted_decrypted}/{self.encrypted_present} decrypted",
        ]
        if self.encrypted_skipped_no_key:
            parts.append(
                "NOT ATTEMPTED (no key): " + ", ".join(self.encrypted_skipped_no_key)
            )
        if self.encrypted_failed:
            parts.append("AUTHENTICATION FAILED: " + ", ".join(self.encrypted_failed))
        if self.encrypted_rejected:
            parts.append("decrypted but rejected: " + ", ".join(self.encrypted_rejected))
        if self.plaintext_rejected:
            parts.append("plaintext rejected: " + ", ".join(self.plaintext_rejected))
        return "; ".join(parts)


def _looks_versioned_or_dated(model_id: str) -> bool:
    return bool(re.search(r"(?:^|[-_:/])\d", model_id))


def _family_token(model_id: str) -> Optional[str]:
    """
    Conservative final-tier family key.

    Exact and prefix matching have already run by the time this is used. If the
    requested id carries a version/date and still did not match, a broad
    first-token family fallback would borrow an unreviewed sibling surface.
    """
    if _looks_versioned_or_dated(model_id):
        return None
    if "-" in model_id:
        return None
    return model_id


class ProfileRouter:
    """
    Thread-safe (asyncio-safe) profile dispatch table.

    Supports plaintext-only (.yaml) development directories and encrypted
    (.yaml.enc) release directories.
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
        license_key: Optional[str] = None,
        require_license: Optional[bool] = None,
        allow_unsigned_license: Optional[bool] = None,
        allow_plaintext_profiles: Optional[bool] = None,
        encrypted_profile_policy: Optional[bool] = None,
        plaintext_development_mode: Optional[bool] = None,
    ):
        self._profiles: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.profile_dir = profile_dir
        self._loaded_count = 0
        self._decryption_key = decryption_key
        self.last_load_report = ProfileLoadReport()
        # The audit rail, handed in at CONSTRUCTION. ``proxy/main.py`` builds the
        # AuditWriter at step 0 for exactly this reason: the router decides
        # whether each encrypted profile authenticated, and before this change no
        # writer existed when it decided.
        self._audit_writer = audit_writer
        # ``True`` means this installation is in encrypted-profile custody even
        # if the encrypted files have been removed or renamed before this load.
        self._encrypted_profile_policy = bool(encrypted_profile_policy)
        # Audited plaintext loading must be explicitly marked. Direct, no-writer
        # router use keeps the historical developer path; production startup
        # passes the env-derived value explicitly.
        self._plaintext_development_mode = (
            audit_writer is None
            if plaintext_development_mode is None
            else bool(plaintext_development_mode)
        )
        self.decision_journal = journal or DecisionJournal()
        self._license_key = (
            os.getenv("ARKHEIA_LICENSE_KEY", "") if license_key is None else license_key
        )
        self._require_license = (
            _env_bool("ARKHEIA_REQUIRE_LICENSE")
            if require_license is None else require_license
        )
        self._allow_unsigned_license = (
            _env_bool("ARKHEIA_ALLOW_UNSIGNED_LICENSE")
            if allow_unsigned_license is None else allow_unsigned_license
        )
        self._allow_plaintext_profiles = (
            _env_bool("ARKHEIA_ALLOW_PLAINTEXT_PROFILES")
            if allow_plaintext_profiles is None else allow_plaintext_profiles
        )
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

    def set_decryption_key(self, key: bytes) -> "ProfileLoadReport":
        """Set the decryption key and reload encrypted profiles.

        Returns the load report so the caller can state what the key actually
        achieved. ``loaded_count`` is NOT that number -- it counts plaintext
        profiles too, so it stays high (and reads like success) even when every
        single encrypted profile failed to decrypt.
        """
        self._decryption_key = key
        self.load_all()
        self._schedule_flush()
        return self.last_load_report

    def _plaintext_policy_state(self, enc_files: list[Path]) -> str:
        """
        Explain why plaintext needs an explicit opt-in for this load.

        The encrypted inventory is the weakest signal and deliberately last. A
        directory listing is attacker-mutable; a configured policy or trusted key
        remains true even if every ``*.yaml.enc`` has just been unlinked or
        renamed.
        """
        if self._encrypted_profile_policy:
            return PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY
        if self._decryption_key is not None:
            return PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY
        if enc_files:
            return PLAINTEXT_POLICY_ENCRYPTED_INVENTORY
        if self._plaintext_development_mode:
            return PLAINTEXT_POLICY_DEVELOPMENT
        return PLAINTEXT_POLICY_UNMARKED_PLAINTEXT_DIRECTORY

    @staticmethod
    def _plaintext_requires_opt_in(policy_state: str) -> bool:
        return policy_state != PLAINTEXT_POLICY_DEVELOPMENT

    def load_all(self) -> None:
        """Load all profiles from profile_dir.

        Plaintext YAML is allowed in development plaintext posture. Once policy
        or trust state says encrypted-profile custody is active, plaintext is
        refused by default even if the encrypted files have been removed from the
        directory. ``ARKHEIA_ALLOW_PLAINTEXT_PROFILES`` is an auditable migration
        override, not a silent bypass.
        """
        profiles: dict[str, dict] = {}
        report = ProfileLoadReport(key_present=self._decryption_key is not None)
        self.last_load_report = report
        path = Path(self.profile_dir).resolve()
        if not path.exists():
            logger.warning("Profiles directory not found: %s", self.profile_dir)
            self._profiles = profiles
            self._loaded_count = 0
            return

        enc_files = [
            f for f in path.glob("*.yaml.enc")
            if f.resolve().parent == path  # aikido-ignore
        ]
        report.encrypted_present = len(enc_files)
        plaintext_allowed = self._allow_plaintext_profiles
        plaintext_policy_state = self._plaintext_policy_state(enc_files)
        plaintext_requires_opt_in = self._plaintext_requires_opt_in(plaintext_policy_state)
        refusing_plaintext = plaintext_requires_opt_in and not plaintext_allowed
        receipting_development_opt_in = (
            plaintext_policy_state == PLAINTEXT_POLICY_DEVELOPMENT
            and plaintext_allowed
            and self._audit_writer is not None
        )
        plaintext_candidate_names: list[str] = []
        refused_plaintext_names: list[str] = []

        # Load plaintext .yaml profiles
        #
        # NOTE, and it is the load-bearing note for this whole module: these are
        # UNAUTHENTICATED. A .yaml dropped into the profile directory is parsed and
        # used with no key, no tag and -- unless ARKHEIA_LICENSE_KEY is set, which
        # it is not by default -- no signature check either. The AES-GCM path below
        # protects only the models that ship as .yaml.enc. See
        # tests/test_encrypted_profile_tamper.py::test_plaintext_yaml_bypasses_the
        # _entire_crypto_path.
        for f in sorted(path.glob("*.yaml")):
            if not f.resolve().parent == path:  # aikido-ignore
                logger.warning("Skipping file outside profile dir: %s", f)
                continue
            if f.name == "schema.yaml":
                continue
            report.plaintext_present += 1
            plaintext_candidate_names.append(f.name)
            if refusing_plaintext:
                logger.error(
                    "Skipping plaintext profile %s in governed profile directory %s "
                    "(policy_state=%s); set ARKHEIA_ALLOW_PLAINTEXT_PROFILES=true "
                    "only for an intentional migration or development window",
                    f.name,
                    path,
                    plaintext_policy_state,
                )
                refused_plaintext_names.append(f.name)
                report.plaintext_rejected.append(f.name)
                continue
            data = self._load_plaintext(f)
            if data:
                model_id = self._extract_model_id(data, f.name)
                if model_id:
                    profiles[model_id] = data
                    report.plaintext_loaded += 1
                    continue
            report.plaintext_rejected.append(f.name)

        if refused_plaintext_names:
            self.decision_journal.record(build_profile_auth_record(
                outcome=PROFILE_AUTH_PLAINTEXT_REJECTED,
                skipped_profile_names=refused_plaintext_names,
                plaintext_policy_state=plaintext_policy_state,
            ))
        elif plaintext_allowed and plaintext_requires_opt_in and plaintext_candidate_names:
            logger.warning(
                "Plaintext profile loading explicitly enabled by "
                "ARKHEIA_ALLOW_PLAINTEXT_PROFILES in %s (policy_state=%s).",
                self.profile_dir,
                plaintext_policy_state,
            )
            self.decision_journal.record(build_profile_auth_record(
                outcome=PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
                plaintext_profile_names=plaintext_candidate_names,
                plaintext_opt_in_env="ARKHEIA_ALLOW_PLAINTEXT_PROFILES",
                plaintext_policy_state=plaintext_policy_state,
            ))
        elif receipting_development_opt_in and plaintext_candidate_names:
            logger.warning(
                "Development plaintext profile loading explicitly enabled by "
                "ARKHEIA_ALLOW_PLAINTEXT_PROFILES in %s.",
                self.profile_dir,
            )
            self.decision_journal.record(build_profile_auth_record(
                outcome=PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
                plaintext_profile_names=plaintext_candidate_names,
                plaintext_opt_in_env="ARKHEIA_ALLOW_PLAINTEXT_PROFILES",
                plaintext_policy_state=plaintext_policy_state,
            ))

        # Load encrypted .yaml.enc profiles (if decryption key available)
        if enc_files and not self._decryption_key:
            report.encrypted_skipped_no_key = [f.name for f in enc_files]
            logger.warning(
                "Found %d encrypted profiles but no decryption key — skipping: %s. "
                "Detection will return UNKNOWN for these models.",
                len(enc_files),
                ", ".join(report.encrypted_skipped_no_key),
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
                report.encrypted_attempted += 1
                encrypted = b""
                try:
                    encrypted = f.read_bytes()
                    plaintext = decrypt_profile(encrypted, self._decryption_key, profile_name)
                except InvalidTag as e:
                    # THE TAMPER SIGNAL. AES-GCM refused the tag: the bytes on
                    # disk are not the bytes that were sealed, or this is not the
                    # key they were sealed with. Previously this was one ERROR
                    # line in an unchained log; it is now a row on the
                    # hash-chained rail carrying which bytes and which key, AND a
                    # named unit in the work-done report below -- it must never
                    # vanish into a log line while the summary reports a clean
                    # load. InvalidTag carries an EMPTY message, so the exception
                    # type is named explicitly or the operator gets no reason at
                    # all.
                    report.encrypted_failed.append(f.name)
                    logger.error(
                        "AUTHENTICATION FAILED for encrypted profile %s (%s) — "
                        "tampered file or wrong key. Profile DROPPED; no "
                        "plaintext fallback.",
                        f.name, type(e).__name__,
                    )
                    self._journal_auth(PROFILE_AUTH_FAILED, profile_name, encrypted, e)
                    continue
                except ValueError as e:
                    # Too short to contain a nonce and a tag -- never reached the
                    # cipher at all. Discriminated from a tamper (InvalidTag)
                    # rather than filed as one, so a truncated file does not cry
                    # wolf; still a dropped, named, non-clean unit.
                    report.encrypted_failed.append(f.name)
                    logger.error(
                        "AUTHENTICATION FAILED for encrypted profile %s (%s: %s) — "
                        "malformed ciphertext. Profile DROPPED; no plaintext "
                        "fallback.",
                        f.name, type(e).__name__, e or "<no detail>",
                    )
                    self._journal_auth(PROFILE_AUTH_MALFORMED, profile_name, encrypted, e)
                    continue
                except Exception as e:
                    report.encrypted_failed.append(f.name)
                    logger.error(
                        "AUTHENTICATION FAILED for encrypted profile %s (%s: %s) — "
                        "tampered, or the wrong decryption key. Profile DROPPED; "
                        "no plaintext fallback.",
                        f.name, type(e).__name__, e or "<no detail>",
                    )
                    self._journal_auth(PROFILE_AUTH_MALFORMED, profile_name, encrypted, e)
                    continue

                # From here the profile HAS authenticated; every further refusal
                # is a content decision, and each gets its own outcome so a
                # tamper can never be confused with a licence expiry -- and its
                # own named bucket in the work-done report.
                try:
                    data = yaml.safe_load(plaintext)
                except Exception as e:
                    report.encrypted_rejected.append(f.name)
                    logger.error("Decrypted profile %s is not valid YAML: %s", f.name, e)
                    self._journal_auth(PROFILE_AUTH_NOT_YAML, profile_name, encrypted, e)
                    continue
                if not data:
                    report.encrypted_rejected.append(f.name)
                    self._journal_auth(PROFILE_AUTH_EMPTY, profile_name, encrypted, None)
                    continue
                if not self._verify_license(data, f.name):
                    report.encrypted_rejected.append(f.name)
                    self._journal_auth(PROFILE_AUTH_LICENSE_REJECTED, profile_name, encrypted, None)
                    continue
                model_id = self._extract_model_id(
                    data,
                    f.name,
                    allow_filename_fallback=False,
                )
                if not model_id:
                    report.encrypted_rejected.append(f.name)
                    self._journal_auth(PROFILE_AUTH_NO_MODEL_ID, profile_name, encrypted, None)
                    continue
                profiles[model_id] = data
                report.encrypted_decrypted += 1
                logger.debug("Loaded encrypted profile: %s -> %s", f.name, model_id)
                self._journal_auth(PROFILE_AUTH_AUTHENTICATED, profile_name, encrypted, None)

        self._profiles = profiles
        self._loaded_count = len(profiles)
        report.total_loaded = len(profiles)
        # DONE.md floor invariant 9(b): the pass WORDING is gated on work done, not
        # on absence-of-failure, and every work-not-done unit is NAMED. Before
        # 2026-07-26 this line read "loaded N valid profiles" whatever happened to
        # the encrypted half, so a wrong key produced a clean-looking INFO summary
        # over zero successful decrypts.
        if report.encrypted_failed or report.encrypted_rejected:
            logger.error("ProfileRouter: %s", report.summary(self.profile_dir))
        else:
            logger.info("ProfileRouter: %s", report.summary(self.profile_dir))

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
            if not self._verify_license(data, f.name):
                return None
            return data
        except Exception as e:
            logger.error("Failed to load profile %s: %s", f.name, e)
            return None

    def _verify_license(self, data: dict, filename: str) -> bool:
        return _verify_profile_license(
            data,
            filename,
            license_key=self._license_key,
            require_license=self._require_license,
            allow_unsigned_license=self._allow_unsigned_license,
        )

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
        _vm = re.match(r"(gpt-5(?:\.\d+)?)", model_lower)
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
        m = re.search(r"glm-?(5(?:\.\d+)?)", model_lower)
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
        family = _family_token(model_lower)
        if family is None:
            logger.debug(
                "No safe family fallback for versioned or compound model: %s",
                model_id,
            )
            return None

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
