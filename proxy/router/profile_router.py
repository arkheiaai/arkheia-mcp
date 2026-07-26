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
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Optional

import yaml

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

    def __init__(self, profile_dir: str, decryption_key: Optional[bytes] = None):
        self._profiles: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self.profile_dir = profile_dir
        self._loaded_count = 0
        self._decryption_key = decryption_key
        self.last_load_report = ProfileLoadReport()
        self.load_all()

    def set_decryption_key(self, key: bytes) -> "ProfileLoadReport":
        """Set the decryption key and reload encrypted profiles.

        Returns the load report so the caller can state what the key actually
        achieved. ``loaded_count`` is NOT that number -- it counts plaintext
        profiles too, so it stays high (and reads like success) even when every
        single encrypted profile failed to decrypt.
        """
        self._decryption_key = key
        self.load_all()
        return self.last_load_report

    def load_all(self) -> None:
        """Load all YAML profiles from profile_dir. Supports .yaml and .yaml.enc."""
        profiles: dict[str, dict] = {}
        report = ProfileLoadReport(key_present=self._decryption_key is not None)
        self.last_load_report = report
        path = Path(self.profile_dir).resolve()
        if not path.exists():
            logger.warning("Profiles directory not found: %s", self.profile_dir)
            self._profiles = profiles
            self._loaded_count = 0
            return

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
            data = self._load_plaintext(f)
            if data:
                model_id = self._extract_model_id(data, f.name)
                if model_id:
                    profiles[model_id] = data
                    report.plaintext_loaded += 1
                    continue
            report.plaintext_rejected.append(f.name)

        # Load encrypted .yaml.enc profiles (if decryption key available)
        enc_files = sorted(path.glob("*.yaml.enc"))
        report.encrypted_present = len(enc_files)
        if enc_files and not self._decryption_key:
            report.encrypted_skipped_no_key = [f.name for f in enc_files]
            logger.warning(
                "Found %d encrypted profiles but no decryption key — skipping: %s. "
                "Detection will return UNKNOWN for these models.",
                len(enc_files),
                ", ".join(report.encrypted_skipped_no_key),
            )
        elif enc_files:
            from proxy.crypto.profile_crypto import decrypt_profile
            for f in enc_files:
                if not f.resolve().parent == path:  # aikido-ignore
                    continue
                profile_name = f.name.replace(".yaml.enc", "")
                report.encrypted_attempted += 1
                try:
                    encrypted = f.read_bytes()
                    plaintext = decrypt_profile(encrypted, self._decryption_key, profile_name)
                except Exception as e:
                    # An authentication failure is the whole point of AES-GCM. It
                    # is NOT recoverable and there is NO plaintext fallback: the
                    # profile is dropped. But it must never vanish into a log line
                    # while the summary below reports a clean load -- record the
                    # unit by name so the count of work-not-done is auditable.
                    # InvalidTag carries an EMPTY message, so name the exception
                    # type explicitly or the operator gets "Failed ... :" and no
                    # reason at all.
                    report.encrypted_failed.append(f.name)
                    logger.error(
                        "AUTHENTICATION FAILED for encrypted profile %s (%s: %s) — "
                        "tampered, or the wrong decryption key. Profile DROPPED; "
                        "no plaintext fallback.",
                        f.name,
                        type(e).__name__,
                        e or "<no detail>",
                    )
                    continue
                try:
                    data = yaml.safe_load(plaintext)
                    if not data:
                        report.encrypted_rejected.append(f.name)
                        continue
                    if not _verify_profile_license(data, f.name):
                        report.encrypted_rejected.append(f.name)
                        continue
                    model_id = self._extract_model_id(data, f.name)
                    if model_id:
                        profiles[model_id] = data
                        report.encrypted_decrypted += 1
                        logger.debug("Loaded encrypted profile: %s -> %s", f.name, model_id)
                    else:
                        report.encrypted_rejected.append(f.name)
                except Exception as e:
                    report.encrypted_rejected.append(f.name)
                    logger.error("Failed to parse decrypted profile %s: %s", f.name, e)

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
    def _extract_model_id(data: dict, filename: str) -> Optional[str]:
        """Extract model_id from profile data."""
        model_id = (
            data.get("model")
            or data.get("metadata", {}).get("model_id")
        )
        if not model_id:
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

        logger.info("ProfileRouter reloaded: %d valid profiles", self._loaded_count)

    @property
    def loaded_count(self) -> int:
        return self._loaded_count

    @property
    def profile_ids(self) -> list[str]:
        return list(self._profiles.keys())
