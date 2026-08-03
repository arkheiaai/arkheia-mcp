"""
F20 — the ordering fix, proved by BOOTING THE REAL APP.

WHY THIS FILE EXISTS SEPARATELY
-------------------------------
The recorded reason the ``enforced`` axis failed begins: *a required CI context
ran green over a totally broken integration — transport mocked here, shape-only
on the proxy side.* The pre-existing ``tests/test_dynamic_key_startup.py`` is a
worked example of that shape. It is titled "Verify DynamicKeyLoader wiring in
proxy startup" and it never imports ``proxy.main``: it builds a ``MagicMock``,
calls ``mock_loader.fetch_key()``, and re-implements the startup block's ``if``
in the test body. It would pass unchanged if ``proxy/main.py``'s step 1b were
deleted outright.

So a receipt suite that only ever constructs ``ProfileRouter`` and
``DynamicKeyLoader`` by hand would inherit the same hole one level up: it would
prove the components CAN receipt, and prove nothing about whether the running
proxy WIRES them. This file drives the actual FastAPI lifespan — ``create_app()``
under ``TestClient``, which runs startup and shutdown for real — and reads the
rows back off the audit log the app itself chose to write to.

WHAT IT PINS
------------
1. Booting the proxy over encrypted profiles leaves BOTH decisions on the rail:
   the key-load posture and each profile's authentication verdict.
2. A tampered profile is on the rail after a real boot, not just after a
   hand-constructed router.
3. The writer is up before the first decision — asserted behaviourally here
   (the rows exist at all), and statically by
   ``tests/test_f20_profile_key_floor.py`` INV-1 so a re-ordering cannot pass by
   being untested.
"""
from __future__ import annotations

import secrets

import pytest
import yaml

from proxy.audit.decision_journal import (
    DECIDED_AT_JOURNALLED,
    EVENT_KEY_LOAD,
    EVENT_PROFILE_AUTH,
    KEY_LOAD_FETCHED_HOSTED,
    KEY_LOAD_NO_API_KEY,
    KEY_LOAD_NO_ENCRYPTED_PROFILES,
    KEY_LOAD_UNAVAILABLE,
    PROFILE_AUTH_AUTHENTICATED,
    PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,
    PROFILE_AUTH_FAILED,
    PROFILE_AUTH_PLAINTEXT_REJECTED,
    PROFILE_AUTH_SKIPPED_NO_KEY,
    PLAINTEXT_POLICY_DEVELOPMENT,
    PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY,
)
from proxy.crypto.profile_crypto import encrypt_profile
from proxy.tests._receipt_probe import ReceiptProbe, assert_decision_identity


@pytest.fixture
def booted(tmp_path, monkeypatch):
    """
    Boot the REAL app. Returns a factory: ``boot(profiles_dir) -> ReceiptProbe``.

    ``settings`` is a module-level singleton read at import, so the profile
    directory and audit path are pointed at the temp tree before ``create_app()``
    is called. Nothing else about the app is altered — the lifespan that runs is
    the production lifespan.
    """
    from starlette.testclient import TestClient

    from proxy import main as proxy_main
    from proxy.config import settings

    log_path = tmp_path / "audit" / "audit.jsonl"

    def boot(profiles_dir) -> ReceiptProbe:
        monkeypatch.setattr(settings.detection, "profile_dir", str(profiles_dir))
        monkeypatch.setattr(settings.audit, "log_path", str(log_path))
        # Keep the registry background task out of it: this test is about
        # startup ordering, not scheduled pulls.
        monkeypatch.setattr(settings.registry, "pull_on_startup", False)
        monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)

        app = proxy_main.create_app()
        with TestClient(app) as client:
            assert client.get("/").status_code == 200, (
                "control: the app must actually have come up, or an empty audit "
                "log would read as 'nothing decided' instead of 'never booted'"
            )
        return ReceiptProbe(log_path, id_field="decision_id")

    return boot


def _key() -> bytes:
    return secrets.token_bytes(32)


def _seal(profiles, name: str, key: bytes) -> bytes:
    doc = {"model": name, "version": "1.0", "thresholds": {"cohens_d": 0.5}}
    blob = encrypt_profile(yaml.dump(doc).encode("utf-8"), key, name)
    (profiles / f"{name}.yaml.enc").write_bytes(blob)
    return blob


def test_a_real_boot_with_explicit_plaintext_development_records_the_opt_in(
    booted, tmp_path, monkeypatch
):
    """
    The legitimate development branch is explicit and visible on the rail. A
    plaintext-only directory must not be byte-identical to an attacker plant that
    got every encrypted file unlinked before the router loaded.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "plain.yaml").write_text(yaml.dump({"model": "plain", "version": "1"}))
    monkeypatch.setenv("ARKHEIA_ALLOW_PLAINTEXT_PROFILES", "true")

    probe = booted(profiles)
    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_NO_ENCRYPTED_PROFILES
    assert rows[0]["receipt_status"] == "enqueued"

    auth_rows = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert len(auth_rows) == 1
    assert auth_rows[0]["outcome"] == PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN
    assert auth_rows[0]["plaintext_profile_names"] == ["plain.yaml"]
    assert auth_rows[0]["plaintext_policy_state"] == PLAINTEXT_POLICY_DEVELOPMENT


def test_a_real_boot_rejects_unmarked_plaintext_when_key_fetch_outage_unlinks_enc(
    booted, key_server, tmp_path, monkeypatch
):
    """
    Residual from PR #63: key loading observes encrypted inventory, returns no
    key, and the encrypted file is renamed before the router scans. Without
    carrying the earlier custody signal forward, the planted plaintext loads like
    a healthy dev directory and leaves no profile-auth receipt.
    """
    from proxy.crypto.profile_crypto import DynamicKeyLoader

    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _seal(profiles, "legit", _key())

    def unlink_before_no_key(_self):
        (profiles / "legit.yaml.enc").rename(profiles / "legit.yaml.enc.bak")
        (profiles / "attacker.yaml").write_text(
            yaml.dump({"model": "attacker-model", "version": "1"}),
            encoding="utf-8",
        )
        return None

    key_server.fail(503)
    monkeypatch.setenv("ARKHEIA_API_KEY", "an-api-key")
    monkeypatch.setenv("ARKHEIA_HOSTED_URL", key_server.url)
    monkeypatch.delenv("ARKHEIA_REQUIRE_ENCRYPTED_PROFILES", raising=False)
    monkeypatch.delenv("ARKHEIA_ALLOW_PLAINTEXT_PROFILES", raising=False)
    monkeypatch.setattr(DynamicKeyLoader, "_load_cache", unlink_before_no_key)

    probe = booted(profiles)

    key_rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert [r["outcome"] for r in key_rows] == [KEY_LOAD_UNAVAILABLE]

    auth_rows = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert len(auth_rows) == 1
    assert auth_rows[0]["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert auth_rows[0]["skipped_profile_names"] == ["attacker.yaml"]
    assert auth_rows[0]["plaintext_policy_state"] == PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY


def test_a_real_boot_with_encrypted_profile_policy_refuses_plaintext_without_enc_files(
    booted, tmp_path, monkeypatch
):
    """
    Cold-start deletion/rename case: if policy says this install is in encrypted
    custody, a plaintext plant must not load just because ``*.yaml.enc`` is now
    absent from the directory scan.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "attacker.yaml").write_text(
        yaml.dump({"model": "attacker-model", "version": "1"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ARKHEIA_REQUIRE_ENCRYPTED_PROFILES", "true")

    probe = booted(profiles)

    key_rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(key_rows) == 1
    assert key_rows[0]["outcome"] == KEY_LOAD_NO_ENCRYPTED_PROFILES

    auth_rows = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert len(auth_rows) == 1
    assert auth_rows[0]["outcome"] == PROFILE_AUTH_PLAINTEXT_REJECTED
    assert auth_rows[0]["skipped_profile_names"] == ["attacker.yaml"]
    assert auth_rows[0]["plaintext_policy_state"] == PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY


def test_a_real_boot_records_the_profile_authentication_verdicts(
    booted, tmp_path, monkeypatch
):
    """
    Both decisions, from one real startup: the key posture AND a per-profile
    verdict for every encrypted profile the router examined.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    key = _key()
    _seal(profiles, "good", key)
    blob = _seal(profiles, "bad", key)
    corrupt = bytearray(blob)
    corrupt[-1] ^= 0x01
    (profiles / "bad.yaml.enc").write_bytes(bytes(corrupt))

    # No API key and no cache (``isolated_key_cache`` points it at an empty temp
    # dir), so key loading is conclusively unavailable — the genuinely dark case.
    monkeypatch.setenv("ARKHEIA_API_KEY", "")

    probe = booted(profiles)

    key_rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(key_rows) == 1
    assert key_rows[0]["outcome"] == KEY_LOAD_NO_API_KEY
    assert key_rows[0]["encrypted_profile_count"] == 2

    auth_rows = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert len(auth_rows) == 1, (
        "no key, so no per-profile verdict was TAKEN — one skipped row naming the "
        "dark surfaces, never two fabricated verdicts"
    )
    assert auth_rows[0]["skipped_count"] == 2


def test_a_real_boot_that_fetches_its_key_never_reports_the_surfaces_dark(
    booted, key_server, tmp_path, monkeypatch
):
    """
    THE FALSE-ALARM CASE (Codex, PR #34).

    ``ProfileRouter`` was constructed at step 1 and the key fetched at step 1b, so
    the router's first ``load_all()`` ran with no key and journalled
    ``skipped_no_key`` — *these surfaces went dark* — for a startup that then
    fetched the key and authenticated every one of them. Codex's TestClient boot
    produced ``skipped_no_key -> fetched_from_hosted -> authenticated``.

    This is the inverse of the usual failure: the rail received a too-ALARMING
    value rather than a too-reassuring one. Both are the same defect — the record
    does not describe what happened — and a false alarm erodes an audit trail
    exactly as much as a false all-clear.

    The assertion is on the SEQUENCE the boot wrote, not on the presence of the
    good row: a suite that only asserts ``authenticated`` is present passes
    against the broken state, because the broken state emits it too.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    key = _key()
    _seal(profiles, "good", key)

    key_server.serve(key)
    monkeypatch.setenv("ARKHEIA_API_KEY", "an-api-key")
    monkeypatch.setenv("ARKHEIA_HOSTED_URL", key_server.url)

    probe = booted(profiles)

    key_rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert [r["outcome"] for r in key_rows] == [KEY_LOAD_FETCHED_HOSTED], (
        "control: this boot must actually have fetched a key over the socket, or "
        "'no skipped row' would be proved by a startup that had nothing to skip"
    )

    auth = [r["outcome"] for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert PROFILE_AUTH_SKIPPED_NO_KEY not in auth, (
        f"the boot journalled {PROFILE_AUTH_SKIPPED_NO_KEY!r} for a startup that "
        f"fetched its key and authenticated the profile. The rail says the "
        f"surfaces went dark; they never did. Sequence written: {auth}"
    )
    assert auth == [PROFILE_AUTH_AUTHENTICATED], (
        f"one encrypted profile, one authentication decision. Got {auth} — a "
        f"second load_all() over the same file is a second verdict about one "
        f"decision, and the audit rail counts rows"
    )
    assert_decision_identity(
        key_rows[0], branch=KEY_LOAD_FETCHED_HOSTED,
        # fetch_key() is async, so this one is JOURNALLED at the decision.
        expect_source=DECIDED_AT_JOURNALLED,
    )


def test_a_genuinely_keyless_boot_still_says_the_surfaces_went_dark(
    booted, key_server, tmp_path, monkeypatch
):
    """
    The control row for the test above (DONE.md v1.15 clause 5).

    The fix must be ORDERING, never suppression: when key loading is
    conclusively unavailable — the issuer answers 503 and no cache exists — the
    dark surfaces must still be named. A table whose every row asserts absence
    cannot discriminate between a fixed ordering and a deleted event.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _seal(profiles, "good", _key())

    key_server.fail(503)
    monkeypatch.setenv("ARKHEIA_API_KEY", "an-api-key")
    monkeypatch.setenv("ARKHEIA_HOSTED_URL", key_server.url)

    probe = booted(profiles)

    auth = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    assert [r["outcome"] for r in auth] == [PROFILE_AUTH_SKIPPED_NO_KEY]
    assert auth[0]["skipped_profile_names"] == ["good.yaml.enc"]
    assert auth[0]["skipped_count"] == 1


def test_a_real_boot_with_a_preconfigured_key_receipts_a_TAMPER(
    booted, tmp_path, monkeypatch
):
    """
    End to end, through the production lifespan: a tampered ``.yaml.enc`` on disk
    produces an ``authentication_failed`` row on the hash-chained audit log the
    running proxy writes to. This is the decision that had nowhere to go.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    key = _key()
    _seal(profiles, "good", key)
    blob = _seal(profiles, "bad", key)
    corrupt = bytearray(blob)
    corrupt[10] ^= 0xFF
    (profiles / "bad.yaml.enc").write_bytes(bytes(corrupt))

    # Give the process the key the way an enterprise licence would: pinned at
    # deploy time, so the boot exercises the decrypt loop for real. This is the
    # seam the lifespan actually reads — patched at the production function
    # rather than by substituting the router class, so the branch under test is
    # the branch that runs.
    import proxy.main as proxy_main
    monkeypatch.setattr(proxy_main, "_preconfigured_profile_key", lambda: key)

    probe = booted(profiles)

    auth_rows = [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH]
    outcomes = {r["profile_name"]: r["outcome"] for r in auth_rows}
    assert outcomes == {"good": PROFILE_AUTH_AUTHENTICATED, "bad": PROFILE_AUTH_FAILED}

    tamper = [r for r in auth_rows if r["outcome"] == PROFILE_AUTH_FAILED][0]
    assert tamper["error_type"] == "InvalidTag"
    assert probe.recompute_this_hash(tamper) == tamper["this_hash"]
    assert probe.verify_chain()["ok"] is True

    # And the key-load posture row is there too, from the same boot.
    key_rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(key_rows) == 1
    assert key_rows[0]["key_id"] is not None
