"""
F20 — Encrypted-profile decryption (AES-256-GCM) + dynamic key load.

Run to ground 2026-07-26 against ``origin/master`` @ 3037f0ca.

WHAT THIS FILE IS FOR
---------------------
AES-256-GCM is authenticated encryption, so the interesting question is not
whether the primitive works — it does — but whether this code **uses** the
authentication. A GCM decrypt that discards the tag, or catches ``InvalidTag``
and proceeds, is a plain cipher wearing a badge. The matrix below proves that
each of the four things an attacker can touch — the ciphertext body, the tag,
the nonce, and the AAD — independently causes a **hard failure with no plaintext
fallback**, at both the primitive and the ``ProfileRouter`` level.

ASSERTION DISCIPLINE (the defect class of 2026-07-26)
-----------------------------------------------------
``with pytest.raises(Exception)`` passes for the wrong exception.
``assert plaintext != ciphertext`` passes for garbage.
``assert x is not None`` passes for anything at all.

So, in this file:
  * every negative case pins an **exact** exception type (``InvalidTag``,
    ``InvalidMasterKey``, ``ValueError``) — never bare ``Exception``;
  * every negative case is paired with a **positive control** in the same test:
    the untampered blob decrypts to the byte-exact original plaintext, proving
    the failure came from the mutation and not from a broken fixture;
  * absence assertions ("the profile is not loaded") are paired with a positive
    control proving the loader would have loaded it but for the tamper.
"""
from __future__ import annotations

import hashlib
import logging
import os
import secrets
import stat
from pathlib import Path

import pytest
import yaml
from cryptography.exceptions import InvalidTag

from proxy.crypto.profile_crypto import (
    DynamicKeyLoader,
    InvalidMasterKey,
    _NONCE_SIZE,
    _TAG_SIZE,
    decrypt_profile,
    derive_key,
    encrypt_profile,
    key_fingerprint,
)
from proxy.router.profile_router import ProfileRouter

# The exact plaintext every positive control asserts against. Pinned as bytes so
# a test can never pass by comparing two things that are both wrong.
PLAINTEXT = yaml.dump(
    {
        "model": "gpt-4o",
        "version": "1.0",
        "thresholds": {"cohens_d": 0.35, "confidence": 0.85},
        "features": {"truth_mean": 0.72, "fab_mean": 0.31},
    }
).encode("utf-8")

PROFILE = "gpt-4o"


@pytest.fixture
def master_key() -> bytes:
    return secrets.token_bytes(32)


# ===========================================================================
# 1. Is authentication actually verified, or is the tag ignored?
# ===========================================================================


def test_untampered_blob_decrypts_to_the_exact_plaintext(master_key):
    """The positive control every negative test below leans on."""
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT


def test_tampered_ciphertext_body_fails_at_every_byte(master_key):
    """Flipping ANY byte of the ciphertext body must raise InvalidTag.

    The pre-existing test flipped byte 20 only. One byte position proves one byte
    position; a decrypt that authenticated a prefix would pass it.
    """
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    body_end = len(blob) - _TAG_SIZE

    # Positive control first.
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT

    positions = list(range(_NONCE_SIZE, body_end))
    assert positions, "fixture produced no ciphertext body to tamper with"
    for i in positions:
        mutated = bytearray(blob)
        mutated[i] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_profile(bytes(mutated), master_key, PROFILE)


def test_tampered_TAG_fails_at_every_byte(master_key):
    """Flipping any byte of the 16-byte GCM tag must raise InvalidTag.

    Not previously covered anywhere. This is the assertion that proves the tag is
    *consumed*: a decrypt that sliced the tag off and ignored it would return the
    correct plaintext here, and every ciphertext-body test would still pass.
    """
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT

    for i in range(len(blob) - _TAG_SIZE, len(blob)):
        mutated = bytearray(blob)
        mutated[i] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_profile(bytes(mutated), master_key, PROFILE)


def test_tampered_NONCE_fails_at_every_byte(master_key):
    """Flipping any byte of the transmitted nonce must raise InvalidTag.

    Not previously covered. The nonce travels with the ciphertext and is
    attacker-reachable; GCM authenticates under it, so a modified nonce must not
    silently produce a different (garbage) plaintext.
    """
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT

    for i in range(_NONCE_SIZE):
        mutated = bytearray(blob)
        mutated[i] ^= 0xFF
        with pytest.raises(InvalidTag):
            decrypt_profile(bytes(mutated), master_key, PROFILE)


def test_tampered_AAD_fails(master_key):
    """The AAD is the profile name. Presenting the blob under any other name fails."""
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT

    for wrong_name in ("gpt-4O", "gpt-4o ", " gpt-4o", "grok-4", "", "gpt-4o.yaml"):
        with pytest.raises(InvalidTag):
            decrypt_profile(blob, master_key, wrong_name)


def test_wrong_key_fails(master_key):
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT
    with pytest.raises(InvalidTag):
        decrypt_profile(blob, secrets.token_bytes(32), PROFILE)


def test_one_bit_wrong_key_fails(master_key):
    """A near-miss key, not just a random one — the case a coarse guard misses."""
    near = bytearray(master_key)
    near[0] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_profile(encrypt_profile(PLAINTEXT, master_key, PROFILE), bytes(near), PROFILE)


def test_substituting_one_profiles_ciphertext_for_anothers_fails(master_key):
    """Swap two profiles' encrypted bodies under the same master key.

    This is the realistic attack on a directory of shipped .enc files: an
    attacker with write access renames or swaps files to make a model resolve to
    a profile that scores everything LOW. It must fail on BOTH the derived key
    and the AAD.
    """
    a_plain = yaml.dump({"model": "gpt-4o", "thresholds": {"cohens_d": 0.35}}).encode()
    b_plain = yaml.dump({"model": "grok-4", "thresholds": {"cohens_d": 99.0}}).encode()
    a = encrypt_profile(a_plain, master_key, "gpt-4o")
    b = encrypt_profile(b_plain, master_key, "grok-4")

    assert decrypt_profile(a, master_key, "gpt-4o") == a_plain
    assert decrypt_profile(b, master_key, "grok-4") == b_plain

    with pytest.raises(InvalidTag):
        decrypt_profile(b, master_key, "gpt-4o")
    with pytest.raises(InvalidTag):
        decrypt_profile(a, master_key, "grok-4")


def test_truncation_and_extension_fail(master_key):
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert decrypt_profile(blob, master_key, PROFILE) == PLAINTEXT

    with pytest.raises(InvalidTag):
        decrypt_profile(blob[:-1], master_key, PROFILE)
    with pytest.raises(InvalidTag):
        decrypt_profile(blob + b"\x00", master_key, PROFILE)
    with pytest.raises(InvalidTag):
        decrypt_profile(blob[:_NONCE_SIZE] + blob[_NONCE_SIZE + 1:], master_key, PROFILE)


def test_blob_too_short_raises_ValueError_not_InvalidTag(master_key):
    """Pinned separately so the two failure modes cannot be conflated."""
    for short in (b"", b"short", bytes(_NONCE_SIZE + _TAG_SIZE - 1)):
        with pytest.raises(ValueError) as exc:
            decrypt_profile(short, master_key, PROFILE)
        assert not isinstance(exc.value, InvalidTag)
        assert "too short" in str(exc.value)


def test_error_text_leaks_no_key_material_and_no_ciphertext(master_key):
    """What a failure is allowed to say.

    ``InvalidTag`` carries an EMPTY message, which is why the router logs the
    exception TYPE — otherwise the operator gets "Failed ... :" and no reason.
    Neither the exception nor the ValueError may carry key bytes, derived-key
    bytes or ciphertext.
    """
    blob = bytearray(encrypt_profile(PLAINTEXT, master_key, PROFILE))
    blob[-1] ^= 0xFF
    derived = derive_key(master_key, PROFILE)

    with pytest.raises(InvalidTag) as exc:
        decrypt_profile(bytes(blob), master_key, PROFILE)
    text = f"{exc.value!r}{exc.value.args}"
    assert master_key.hex() not in text
    assert derived.hex() not in text
    assert bytes(blob).hex() not in text

    with pytest.raises(ValueError) as verr:
        decrypt_profile(b"short", master_key, PROFILE)
    assert master_key.hex() not in str(verr.value)
    assert derived.hex() not in str(verr.value)


# ===========================================================================
# 2. Nonce discipline
# ===========================================================================


def test_nonce_is_random_per_call_and_never_derived_from_content(master_key):
    """A repeated (key, nonce) pair is catastrophic for GCM.

    The nonce must depend on neither the plaintext nor the profile name, or two
    encryptions of identical content under the same derived key would collide.
    """
    identical = [encrypt_profile(PLAINTEXT, master_key, PROFILE)[:_NONCE_SIZE] for _ in range(256)]
    assert len(set(identical)) == 256, "nonce repeated across encryptions of identical content"

    # Not a function of the content...
    n_a = encrypt_profile(b"aaaa", master_key, PROFILE)[:_NONCE_SIZE]
    n_b = encrypt_profile(b"bbbb", master_key, PROFILE)[:_NONCE_SIZE]
    assert n_a != n_b
    # ...and not a function of the profile name.
    assert (
        encrypt_profile(PLAINTEXT, master_key, "x")[:_NONCE_SIZE]
        != encrypt_profile(PLAINTEXT, master_key, "x")[:_NONCE_SIZE]
    )


def test_nonce_is_twelve_bytes_and_the_blob_is_framed_as_documented(master_key):
    blob = encrypt_profile(PLAINTEXT, master_key, PROFILE)
    assert _NONCE_SIZE == 12
    assert len(blob) == _NONCE_SIZE + len(PLAINTEXT) + _TAG_SIZE


def test_per_profile_key_derivation_is_deterministic_and_separating(master_key):
    assert derive_key(master_key, PROFILE) == derive_key(master_key, PROFILE)
    assert len(derive_key(master_key, PROFILE)) == 32
    assert derive_key(master_key, "a") != derive_key(master_key, "b")
    assert derive_key(master_key, "a") != derive_key(secrets.token_bytes(32), "a")


# ===========================================================================
# 3. Key loading — absent, wrong, truncated; and no fallback to a constant
# ===========================================================================


@pytest.mark.parametrize("bad_len", [0, 1, 15, 16, 31, 33, 64])
def test_master_key_of_the_wrong_length_is_REJECTED(bad_len):
    """Regression for the silent-normalisation defect.

    ``derive_key`` hashes the master key and SHA-256 accepts any input length, so
    before 2026-07-26 an empty or truncated master key produced a perfectly
    well-formed AES key and every operation "succeeded". Measured: lengths
    0, 1, 16, 31 and 64 all round-tripped.
    """
    bad = bytes(bad_len)
    with pytest.raises(InvalidMasterKey):
        derive_key(bad, PROFILE)
    with pytest.raises(InvalidMasterKey):
        encrypt_profile(PLAINTEXT, bad, PROFILE)
    with pytest.raises(InvalidMasterKey):
        decrypt_profile(bytes(64), bad, PROFILE)

    # Positive control: 32 bytes still works, so the guard is not simply
    # rejecting everything.
    good = secrets.token_bytes(32)
    assert decrypt_profile(encrypt_profile(PLAINTEXT, good, PROFILE), good, PROFILE) == PLAINTEXT


def test_master_key_of_the_wrong_TYPE_is_rejected():
    for bad in ("a" * 32, None, 12345, ["x"] * 32):
        with pytest.raises(InvalidMasterKey):
            derive_key(bad, PROFILE)  # type: ignore[arg-type]


def test_key_fingerprint_does_not_reveal_the_key():
    key = secrets.token_bytes(32)
    fp = key_fingerprint(key)
    assert fp == hashlib.sha256(key).hexdigest()[:16]
    assert key.hex() not in fp
    assert key_fingerprint(key) != key_fingerprint(secrets.token_bytes(32))


class _IsolatedLoader(DynamicKeyLoader):
    """A DynamicKeyLoader whose cache lives in a tmp dir, not ~/.arkheia."""

    @classmethod
    def at(cls, tmp: Path) -> "_IsolatedLoader":
        loader = cls("https://example.invalid", "ak_live_test")
        loader.CACHE_DIR = tmp / ".arkheia"
        loader.CACHE_FILE = loader.CACHE_DIR / "profile_key.cache"
        return loader


def test_key_cache_round_trips_and_is_not_world_readable(tmp_path):
    loader = _IsolatedLoader.at(tmp_path)
    key = secrets.token_bytes(32)
    loader._save_cache(key)

    assert loader._load_cache() == key  # positive control

    mode = stat.S_IMODE(loader.CACHE_FILE.stat().st_mode)
    assert mode == 0o600, f"key cache is {oct(mode)}; it was 0o644 before 2026-07-26"
    assert stat.S_IMODE(loader.CACHE_DIR.stat().st_mode) == 0o700


def test_key_cache_does_not_contain_the_key_verbatim(tmp_path):
    loader = _IsolatedLoader.at(tmp_path)
    key = secrets.token_bytes(32)
    loader._save_cache(key)
    blob = loader.CACHE_FILE.read_bytes()
    assert key not in blob
    # ...but be honest about what that is worth: the obfuscation is reversible by
    # anyone who can read the file. The absence assertion above would pass over an
    # empty file, so pair it with the positive control that the key is recoverable
    # by the legitimate path.
    assert loader._load_cache() == key


def test_a_cache_written_under_a_DIFFERENT_machine_salt_is_rejected_not_guessed(tmp_path, monkeypatch):
    """The defect this replaces: ``_load_cache`` returned ANY 32-byte blob.

    A cache copied from another machine — or corrupted, or planted — was returned
    as a well-formed key that then failed to decrypt every profile, and the only
    trace was one reason-free log line per file. It must be refused instead.
    """
    loader = _IsolatedLoader.at(tmp_path)
    key = secrets.token_bytes(32)
    monkeypatch.setenv("HOSTNAME", "machine-a")
    loader._save_cache(key)
    assert loader._load_cache() == key  # positive control on machine A

    monkeypatch.setenv("HOSTNAME", "machine-b")
    assert loader._load_cache() is None


def test_a_corrupted_cache_is_rejected_not_guessed(tmp_path):
    loader = _IsolatedLoader.at(tmp_path)
    key = secrets.token_bytes(32)
    loader._save_cache(key)
    assert loader._load_cache() == key

    good = loader.CACHE_FILE.read_bytes()
    for i in range(len(good)):
        mutated = bytearray(good)
        mutated[i] ^= 0xFF
        loader.CACHE_FILE.write_bytes(bytes(mutated))
        assert loader._load_cache() is None, f"corrupt cache accepted (byte {i})"

    loader.CACHE_FILE.write_bytes(good)
    assert loader._load_cache() == key  # and back to green


def test_legacy_unauthenticated_cache_is_ignored(tmp_path):
    """Pre-ARKPK1 caches were a bare 32-byte XOR blob with no integrity at all."""
    loader = _IsolatedLoader.at(tmp_path)
    loader.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    loader.CACHE_FILE.write_bytes(secrets.token_bytes(32))
    assert loader._load_cache() is None


def test_missing_cache_returns_None(tmp_path):
    loader = _IsolatedLoader.at(tmp_path)
    assert loader._load_cache() is None


def test_machine_salt_is_no_longer_the_empty_string_constant(monkeypatch):
    """The salt was sha256(b'')[:16] on every POSIX box — a published constant."""
    from proxy.crypto.profile_crypto import _machine_salt

    monkeypatch.delenv("COMPUTERNAME", raising=False)
    monkeypatch.delenv("HOSTNAME", raising=False)
    assert _machine_salt() != hashlib.sha256(b"").digest()[:16]


# ===========================================================================
# 4. The router: no plaintext fallback, and no success wording over no work
# ===========================================================================


def _enc_dir(tmp_path: Path, master_key: bytes, names=("gpt-4o",)) -> Path:
    d = tmp_path / "profiles"
    d.mkdir(exist_ok=True)
    for n in names:
        body = yaml.dump({"model": n, "thresholds": {"cohens_d": 0.35}}).encode()
        (d / f"{n}.yaml.enc").write_bytes(encrypt_profile(body, master_key, n))
    return d


def test_router_loads_an_intact_encrypted_profile(tmp_path, master_key):
    """The positive control for every router-level absence assertion below."""
    d = _enc_dir(tmp_path, master_key)
    r = ProfileRouter(str(d), decryption_key=master_key)
    assert r.get("gpt-4o") == {"model": "gpt-4o", "thresholds": {"cohens_d": 0.35}}
    assert r.last_load_report.encrypted_decrypted == 1
    assert r.last_load_report.encrypted_failed == []
    assert r.last_load_report.clean is True


@pytest.mark.parametrize(
    "region", ["nonce", "body", "tag"]
)
def test_router_DROPS_a_tampered_profile_with_no_plaintext_fallback(tmp_path, master_key, region):
    d = _enc_dir(tmp_path, master_key)
    f = d / "gpt-4o.yaml.enc"
    blob = bytearray(f.read_bytes())
    idx = {"nonce": 0, "body": _NONCE_SIZE + 1, "tag": len(blob) - 1}[region]
    blob[idx] ^= 0xFF
    f.write_bytes(bytes(blob))

    r = ProfileRouter(str(d), decryption_key=master_key)

    assert r.get("gpt-4o") is None
    assert r.profile_ids == []
    assert r.loaded_count == 0
    assert r.last_load_report.encrypted_attempted == 1
    assert r.last_load_report.encrypted_decrypted == 0
    assert r.last_load_report.encrypted_failed == ["gpt-4o.yaml.enc"]
    assert r.last_load_report.clean is False


def test_router_drops_a_SUBSTITUTED_profile(tmp_path, master_key):
    """Rename one profile's ciphertext over another's filename."""
    d = _enc_dir(tmp_path, master_key, names=("gpt-4o", "grok-4"))
    (d / "grok-4.yaml.enc").write_bytes((d / "gpt-4o.yaml.enc").read_bytes())

    r = ProfileRouter(str(d), decryption_key=master_key)
    assert r.get("gpt-4o") is not None  # positive control: the untouched one loads
    assert r.last_load_report.encrypted_failed == ["grok-4.yaml.enc"]
    assert r.last_load_report.encrypted_decrypted == 1


def test_router_with_a_WRONG_key_decrypts_nothing_and_says_so(tmp_path, master_key, caplog):
    """The 'Integrity check passed: 0 modules verified' shape, at this flow.

    3 plaintext + 2 encrypted, wrong key. ``loaded_count`` is 3 — which is what
    ``proxy/main.py`` prints as "%d encrypted profiles available" — while the
    number of encrypted profiles that decrypted is ZERO. The report must state
    the real number and name the files.
    """
    d = _enc_dir(tmp_path, master_key, names=("gpt-4o", "grok-4"))
    for n in ("a-model", "b-model", "c-model"):
        (d / f"{n}.yaml").write_text(yaml.dump({"model": n}))

    # Capture at INFO, not ERROR: capturing only ERROR records makes the
    # "no clean success wording" assertion vacuous, because a summary downgraded
    # back to INFO would simply not be captured.
    with caplog.at_level(logging.INFO, logger="proxy.router.profile_router"):
        r = ProfileRouter(str(d), decryption_key=secrets.token_bytes(32))

    assert r.loaded_count == 3  # the misleading number, pinned so it cannot drift
    rep = r.last_load_report
    assert rep.encrypted_present == 2
    assert rep.encrypted_attempted == 2
    assert rep.encrypted_decrypted == 0
    assert sorted(rep.encrypted_failed) == ["gpt-4o.yaml.enc", "grok-4.yaml.enc"]
    assert rep.clean is False

    # DONE.md floor 9(a): the units of work-not-done are NAMED, not summarised.
    summary = rep.summary(str(d))
    assert "encrypted 0/2 decrypted" in summary
    assert "gpt-4o.yaml.enc" in summary and "grok-4.yaml.enc" in summary

    # 9(b): the wording is gated on work done. Assert over EVERY record, not just
    # the ERROR ones — scoping the negative assertion to ERROR records let a
    # mutation that merely downgraded the summary back to a clean INFO line
    # survive (M16, caught by tools/mutate_f20_profile_crypto.py).
    every = [r_.getMessage() for r_ in caplog.records]
    errors = [r_.getMessage() for r_ in caplog.records if r_.levelno >= logging.ERROR]
    assert any("AUTHENTICATION FAILED" in m for m in errors)
    assert not any("valid profiles" in m for m in every), (
        "the old clean-looking success wording is back"
    )
    # The summary itself must be emitted at ERROR and must name the failed files.
    summaries = [m for m in errors if "encrypted 0/2 decrypted" in m]
    assert len(summaries) == 1, f"expected one ERROR summary, got {summaries}"
    assert "gpt-4o.yaml.enc" in summaries[0] and "grok-4.yaml.enc" in summaries[0]


def test_router_names_the_files_it_could_not_even_attempt(tmp_path, master_key):
    """No key at all: nothing is attempted, and the skipped units are named."""
    d = _enc_dir(tmp_path, master_key, names=("gpt-4o", "grok-4"))
    r = ProfileRouter(str(d))
    rep = r.last_load_report
    assert rep.key_present is False
    assert rep.encrypted_attempted == 0
    assert sorted(rep.encrypted_skipped_no_key) == ["gpt-4o.yaml.enc", "grok-4.yaml.enc"]
    assert rep.clean is False
    assert r.get("gpt-4o") is None


def test_NOTHING_TO_DECRYPT_does_not_read_as_a_successful_decrypt(tmp_path, master_key):
    """"What does this code do when there is nothing to decrypt?"

    The sibling of ``generate_manifest`` over a directory with no ``.so``. Here
    the honest answer must be: zero attempted, zero decrypted, and the encrypted
    half is not claimed as clean-because-empty in any way that a consumer could
    read as "the encrypted profiles verified".
    """
    d = tmp_path / "profiles"
    d.mkdir()
    (d / "a-model.yaml").write_text(yaml.dump({"model": "a-model"}))

    r = ProfileRouter(str(d), decryption_key=master_key)
    rep = r.last_load_report
    assert rep.encrypted_present == 0
    assert rep.encrypted_attempted == 0
    assert rep.encrypted_decrypted == 0
    assert "encrypted 0/0 decrypted" in rep.summary(str(d))
    # And the plaintext work IS reported as done, so the summary is not vacuous.
    assert rep.plaintext_loaded == 1


def test_a_decrypt_failure_never_falls_back_to_reading_the_file_as_plaintext(tmp_path, master_key):
    """The highest-severity thing this flow could get wrong.

    Write a .yaml.enc whose bytes are perfectly valid, readable YAML naming a
    profile. If any path fell back to plaintext on decrypt failure, the profile
    would load. It must not.
    """
    d = tmp_path / "profiles"
    d.mkdir()
    (d / "gpt-4o.yaml.enc").write_bytes(
        yaml.dump({"model": "gpt-4o", "thresholds": {"cohens_d": 99.0}}).encode()
    )

    r = ProfileRouter(str(d), decryption_key=master_key)
    assert r.get("gpt-4o") is None
    assert r.profile_ids == []
    assert r.last_load_report.encrypted_failed == ["gpt-4o.yaml.enc"]


def test_plaintext_yaml_bypasses_the_entire_crypto_path(tmp_path, master_key):
    """OBSERVED-BAD, pinned deliberately. This is not a passing behaviour.

    A ``.yaml`` file dropped into the profile directory is loaded with no key, no
    tag and — because ``ARKHEIA_LICENSE_KEY`` is unset by default — no signature
    check. So the answer to "can a substituted profile be decrypted and used?" is:
    an attacker does not need to defeat AES-GCM at all, they add a plaintext file
    next to it. On ``origin/master`` the shipped repo carries 60 plaintext
    profiles and ZERO ``.yaml.enc``, so this is the ONLY live path.

    This test pins the gap so that closing it (David's call — see the PR body) is
    a visible, deliberate change and not a silent one.
    """
    assert os.environ.get("ARKHEIA_LICENSE_KEY", "") == "", (
        "this test characterises the default posture; a LICENSE_KEY is set"
    )
    d = _enc_dir(tmp_path, master_key, names=("gpt-4o",))
    hostile = {"model": "grok-4", "thresholds": {"cohens_d": 99.0, "confidence": 0.0}}
    (d / "grok-4.yaml").write_text(yaml.dump(hostile))

    r = ProfileRouter(str(d), decryption_key=master_key)

    assert r.get("grok-4") == hostile, "expected the unauthenticated path to accept it"
    assert r.last_load_report.plaintext_loaded == 1
    # ...and the encrypted one is unaffected, so the two paths are independent.
    assert r.get("gpt-4o") is not None


# ===========================================================================
# 5. The hosted key-fetch route — which had NO tests at all
# ===========================================================================
#
# Found by mutation, not by reading: M10 ("accept a key of any length from the
# hosted endpoint") and M14 ("restore silent discarding of non-base64
# characters") both SURVIVED the suite as first written, because nothing
# anywhere exercised `_fetch_from_hosted`. The length check and the
# `validate=True` were unproven code.

import base64  # noqa: E402  (grouped with the section it serves)

import httpx  # noqa: E402
import respx  # noqa: E402

HOSTED = "https://hosted.invalid"
KEY_URL = f"{HOSTED}/v1/profile-key"


def _loader(tmp_path: Path, api_key: str = "ak_live_test") -> _IsolatedLoader:
    loader = _IsolatedLoader(HOSTED, api_key)
    loader.CACHE_DIR = tmp_path / ".arkheia"
    loader.CACHE_FILE = loader.CACHE_DIR / "profile_key.cache"
    return loader


@respx.mock
async def test_hosted_200_with_a_valid_key_is_accepted_and_cached(tmp_path):
    """Positive control for every rejection test below."""
    key = secrets.token_bytes(32)
    respx.post(KEY_URL).mock(
        return_value=httpx.Response(200, json={"profile_key": base64.b64encode(key).decode()})
    )
    loader = _loader(tmp_path)
    assert await loader.fetch_key() == key
    assert loader.last_source == "hosted"
    assert loader.has_key is True
    assert loader.current_key == key
    assert loader._load_cache() == key  # it was written through to the cache


@pytest.mark.parametrize("nbytes", [0, 1, 16, 31, 33, 64])
@respx.mock
async def test_hosted_key_of_the_WRONG_LENGTH_is_refused(tmp_path, nbytes):
    """M10. A short key would otherwise be hashed into a well-formed AES key."""
    respx.post(KEY_URL).mock(
        return_value=httpx.Response(
            200, json={"profile_key": base64.b64encode(bytes(nbytes)).decode()}
        )
    )
    loader = _loader(tmp_path)
    assert await loader._fetch_from_hosted() is None
    assert await loader.fetch_key() is None
    assert loader.last_source == "none"
    assert loader.has_key is False


@pytest.mark.parametrize(
    "payload",
    [
        "not base64 at all!!",
        "AAAA AAAA",          # embedded whitespace
        "====",
        "",
    ],
)
@respx.mock
async def test_hosted_key_that_is_not_valid_base64_is_refused(tmp_path, payload):
    """M14. Without validate=True, b64decode silently DROPS stray characters."""
    respx.post(KEY_URL).mock(return_value=httpx.Response(200, json={"profile_key": payload}))
    loader = _loader(tmp_path)
    assert await loader._fetch_from_hosted() is None


@respx.mock
async def test_a_MANGLED_key_blob_is_refused_rather_than_silently_repaired(tmp_path):
    """The sharp form of M14, stated as what it actually is.

    ``b64decode`` without ``validate=True`` DISCARDS every character outside the
    base64 alphabet, so a corrupted payload is silently repaired into a
    well-formed 32-byte key and accepted. The response is then not the response
    the endpoint sent, and nothing anywhere records that. With ``validate=True``
    it is refused.

    The fixture below is checked in both directions in the test itself, so it
    cannot quietly stop demonstrating the hazard.
    """
    key = secrets.token_bytes(32)
    b64 = base64.b64encode(key).decode()
    mangled = b64[:20] + "!" + b64[20:]

    # The hazard, demonstrated: the lenient decode "succeeds".
    assert base64.b64decode(mangled) == key
    with pytest.raises(Exception):
        base64.b64decode(mangled, validate=True)

    respx.post(KEY_URL).mock(return_value=httpx.Response(200, json={"profile_key": mangled}))
    assert await _loader(tmp_path)._fetch_from_hosted() is None

    # Positive control: the same key, cleanly encoded, IS accepted.
    respx.post(KEY_URL).mock(return_value=httpx.Response(200, json={"profile_key": b64}))
    assert await _loader(tmp_path)._fetch_from_hosted() == key


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
@respx.mock
async def test_a_non_200_from_the_hosted_endpoint_yields_no_key(tmp_path, status):
    respx.post(KEY_URL).mock(return_value=httpx.Response(status, json={}))
    assert await _loader(tmp_path)._fetch_from_hosted() is None


@respx.mock
async def test_a_200_with_no_profile_key_field_yields_no_key(tmp_path):
    respx.post(KEY_URL).mock(return_value=httpx.Response(200, json={"expires_at": "2030-01-01"}))
    assert await _loader(tmp_path)._fetch_from_hosted() is None


@respx.mock
async def test_a_transport_error_yields_no_key_and_does_not_propagate(tmp_path):
    respx.post(KEY_URL).mock(side_effect=httpx.ConnectError("refused"))
    assert await _loader(tmp_path)._fetch_from_hosted() is None


async def test_no_api_key_means_no_hosted_fetch_is_attempted(tmp_path):
    """Absence assertion paired with a positive control: with respx active and
    NO route registered, any outbound request would raise. None is made."""
    with respx.mock:
        assert await _loader(tmp_path, api_key="")._fetch_from_hosted() is None


@respx.mock
async def test_fetch_key_falls_back_to_the_cache_then_to_None(tmp_path):
    """The full chain, in order, with each step observed.

    The cache fallback is deliberately NOT silent: a key that the hosted endpoint
    did not re-authorise may have been revoked, so the source is recorded.
    """
    key = secrets.token_bytes(32)
    loader = _loader(tmp_path)
    loader._save_cache(key)

    respx.post(KEY_URL).mock(return_value=httpx.Response(503, json={}))
    assert await loader.fetch_key() == key
    assert loader.last_source == "cache"

    loader.CACHE_FILE.unlink()
    loader2 = _loader(tmp_path)
    assert await loader2.fetch_key() is None
    assert loader2.last_source == "none"
    assert loader2.has_key is False


@respx.mock
async def test_no_log_line_from_a_key_fetch_contains_key_material(tmp_path, caplog):
    """What leaks on success and on failure."""
    key = secrets.token_bytes(32)
    respx.post(KEY_URL).mock(
        return_value=httpx.Response(200, json={"profile_key": base64.b64encode(key).decode()})
    )
    loader = _loader(tmp_path, api_key="ak_live_SUPERSECRET")
    with caplog.at_level(logging.DEBUG):
        assert await loader.fetch_key() == key

    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert key.hex() not in blob
    assert base64.b64encode(key).decode() not in blob
    assert "ak_live_SUPERSECRET" not in blob
    # Positive control: the fingerprint IS there, so the assertions above are not
    # passing over an empty capture.
    assert key_fingerprint(key) in blob
