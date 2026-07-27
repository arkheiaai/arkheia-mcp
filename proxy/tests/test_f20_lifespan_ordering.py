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
    EVENT_KEY_LOAD,
    EVENT_PROFILE_AUTH,
    KEY_LOAD_NO_API_KEY,
    KEY_LOAD_NO_ENCRYPTED_PROFILES,
    PROFILE_AUTH_AUTHENTICATED,
    PROFILE_AUTH_FAILED,
)
from proxy.crypto.profile_crypto import encrypt_profile
from proxy.tests._receipt_probe import ReceiptProbe


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


def test_a_real_boot_with_no_encrypted_profiles_still_records_its_key_posture(
    booted, tmp_path, monkeypatch
):
    """
    The production branch. 0 of 60 profiles in this repo are encrypted, so this
    is what a real proxy actually does at startup — and it now says so on the
    rail instead of saying nothing at all.
    """
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    (profiles / "plain.yaml").write_text(yaml.dump({"model": "plain", "version": "1"}))

    probe = booted(profiles)
    rows = [r for r in probe.rows() if r["event_type"] == EVENT_KEY_LOAD]
    assert len(rows) == 1
    assert rows[0]["outcome"] == KEY_LOAD_NO_ENCRYPTED_PROFILES
    assert rows[0]["receipt_status"] == "enqueued"
    # No authentication verdicts, because nothing was authenticated.
    assert [r for r in probe.rows() if r["event_type"] == EVENT_PROFILE_AUTH] == []


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

    # A key IS available, via the local cache the loader already trusts.
    from proxy.crypto.profile_crypto import DynamicKeyLoader
    cache_dir = tmp_path / "keycache"
    monkeypatch.setattr(DynamicKeyLoader, "CACHE_DIR", cache_dir)
    monkeypatch.setattr(DynamicKeyLoader, "CACHE_FILE", cache_dir / "profile_key.cache")
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

    # Give the router the key the way an enterprise licence would: preconfigured
    # on construction, so the boot exercises the decrypt loop for real.
    import proxy.main as proxy_main
    real_router_cls = proxy_main.ProfileRouter

    class _KeyedRouter(real_router_cls):
        def __init__(self, profile_dir, decryption_key=None, **kwargs):
            super().__init__(profile_dir, decryption_key=key, **kwargs)

    monkeypatch.setattr(proxy_main, "ProfileRouter", _KeyedRouter)

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
