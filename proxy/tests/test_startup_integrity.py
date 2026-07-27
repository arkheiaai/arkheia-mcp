"""
Startup binary-integrity: fail OPEN on absence, fail CLOSED on evidence.

Codex finding 4 (2026-07-26). ``proxy/license/integrity.verify_integrity`` raises
``TamperDetected`` for a modified module, and ``proxy/main.py``'s startup block
then caught **all** exceptions and continued. So for a tampered detection engine
the observable outcome was *"error log plus service ready"* — the worst available
result, because a tampered engine that reports LOW is TRUSTED: every downstream
verdict, audit record and governance receipt inherits its authority.

The ruling adopted here splits the two states that the code collapsed:

  * **absent / unverifiable** (no manifest, source checkout, unreadable module) =
    absence of evidence -> fail OPEN, log, continue, and make the unverified state
    VISIBLE (``app.state.integrity`` + ``/admin/health``);
  * **positive ``TamperDetected``** (hash mismatch, manifest module missing from
    disk, corrupt manifest) = evidence -> **do not start**.

Both branches are proven here through the REAL FastAPI lifespan, not against the
library in isolation: a byte-modified module must refuse startup, and an absent
manifest must start with the unverified state visible. Every absence assertion is
paired with a positive control so that nothing passes by doing nothing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from proxy.license import integrity as integrity_mod  # noqa: E402
from proxy.license.integrity import (  # noqa: E402
    MANIFEST_FILE,
    IntegrityStatus,
    TamperDetected,
    generate_manifest,
    manifest_dirs,
    verify_all,
    verify_integrity,
)

MODULE_NAME = "_probe_features.cpython-312.so"
ORIGINAL_BYTES = b"pretend this is a compiled detection module"


@pytest.fixture
def scan_root(tmp_path, monkeypatch):
    """
    Redirect the startup integrity scan at a temporary tree.

    Deliberately NOT writing probe artifacts into the real ``proxy/`` package: a
    check that verifies a package must not be tested by mutating that package,
    and a leftover manifest would silently change every later test.
    """
    root = tmp_path / "proxy_pkg"
    (root / "detection").mkdir(parents=True)
    monkeypatch.setattr(integrity_mod, "_scan_root", lambda: root)
    return root


def _write_verified_module(root: Path) -> Path:
    mod_dir = root / "detection"
    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES)
    generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    return mod_dir


@pytest.fixture
def client_factory(monkeypatch, tmp_path):
    """
    Build a TestClient over the real proxy app with admin auth overridden.

    Redirects the two absolute production paths the lifespan touches so it is
    hermetic. Both defaults make startup raise BEFORE it reaches the integrity
    block, which would let every `pytest.raises` below pass for the wrong reason:
      * profile_dir defaults to /etc/arkheia/profiles, absent on a runner;
      * audit.log_path defaults to /var/log/arkheia/..., not writable by a runner.
    """
    from proxy.config import settings

    repo_profiles = Path(__file__).resolve().parents[2] / "profiles"
    assert repo_profiles.is_dir(), repo_profiles
    monkeypatch.setattr(settings.detection, "profile_dir", str(repo_profiles))
    monkeypatch.setattr(settings.audit, "log_path", str(tmp_path / "audit.jsonl"))

    created = []

    def _make():
        from proxy.auth import require_auth
        from proxy.main import app

        app.dependency_overrides[require_auth] = lambda: "startup-test@example.com"
        client = TestClient(app)
        created.append((app, client))
        return client

    yield _make
    for app, client in created:
        app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# The library must name the state instead of collapsing it into a bool
# ---------------------------------------------------------------------------

def test_verify_integrity_distinguishes_verified_from_no_manifest(scan_root):
    """The two states that used to be `True` must now be distinguishable."""
    empty = scan_root / "detection"
    absent = verify_integrity(empty)
    assert absent.status == IntegrityStatus.UNVERIFIED_NO_MANIFEST
    assert absent.verified is False
    assert absent.modules_checked == 0
    assert "NOT an integrity pass" in absent.detail

    mod_dir = _write_verified_module(scan_root)
    ok = verify_integrity(mod_dir)
    assert ok.status == IntegrityStatus.VERIFIED
    assert ok.verified is True
    assert ok.modules_checked == 1
    # The whole point: the two outcomes are no longer the same value.
    assert ok.status != absent.status
    assert ok.verified != absent.verified


def test_verify_integrity_raises_on_empty_manifest(scan_root):
    """
    RED (Codex adversarial review, 2026-07-27): an EMPTY manifest must NOT verify.

    ``verify_integrity`` used to loop ``for module_name, expected_hash in
    manifest.items()`` and, when the manifest existed but declared zero modules,
    the loop body never ran -- so no mismatch was ever found, and the function
    fell through to the VERIFIED return with ``modules_checked=0``. That is the
    `all([]) is True` class of bug: iterate nothing, conclude success. It is a
    DIFFERENT state from ``UNVERIFIED_NO_MANIFEST`` (no manifest at all, handled
    correctly above) -- here the manifest file EXISTS, so the artifact is claiming
    to be a built, integrity-checked release, and that claim is empty. Per this
    module's own ruling on corrupt manifests ("the manifest ships inside the
    artifact; if it exists and cannot be read... the engine cannot be trusted"),
    an empty manifest is EVIDENCE, not absence, and must raise TamperDetected
    exactly like a corrupt or mismatched one -- never silently read as verified.
    """
    mod_dir = scan_root / "detection"
    mod_dir.mkdir(exist_ok=True)
    (mod_dir / MANIFEST_FILE).write_text("{}")

    with pytest.raises(TamperDetected, match="[Ee]mpty"):
        verify_integrity(mod_dir)


def test_verify_integrity_raises_when_the_glob_finds_nothing_to_manifest(scan_root):
    """
    RED, sibling framing: an empty manifest PRODUCED BY THE BUILD (every entry
    filtered out by ``generate_manifest``'s ``*.so``/``*.pyd`` glob matching zero
    files) must fail the same way as a hand-written ``{}}``. This is the
    "all-entries-filtered-out" shape of the same defect: the collection feeding
    the manifest was empty, not the JSON text.
    """
    mod_dir = scan_root / "detection"
    mod_dir.mkdir(exist_ok=True)
    # No .so/.pyd files placed here -- generate_manifest's glob matches nothing.
    manifest = generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    assert manifest == {}, "test setup: expected the glob to match zero files"

    with pytest.raises(TamperDetected, match="[Ee]mpty"):
        verify_integrity(mod_dir)


def test_empty_manifest_is_not_the_same_state_as_no_manifest(scan_root):
    """
    Positive control tying the two together: EMPTY and ABSENT must not collapse
    into each other any more than VERIFIED and ABSENT did (the original Codex
    finding 4). Absent -> fail open (UNVERIFIED_NO_MANIFEST). Empty -> fail
    closed (TamperDetected). Confusing the two would silently re-open this hole.
    """
    absent_dir = scan_root / "detection"
    absent_dir.mkdir(exist_ok=True)
    absent = verify_integrity(absent_dir)
    assert absent.status == IntegrityStatus.UNVERIFIED_NO_MANIFEST
    assert absent.verified is False

    (absent_dir / MANIFEST_FILE).write_text("{}")
    with pytest.raises(TamperDetected):
        verify_integrity(absent_dir)


def test_verify_integrity_raises_on_each_positive_finding(scan_root):
    """Modified module, missing module and corrupt manifest are all EVIDENCE."""
    mod_dir = _write_verified_module(scan_root)

    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES + b"\x00tampered")
    with pytest.raises(TamperDetected, match="Modified module"):
        verify_integrity(mod_dir)

    (mod_dir / MODULE_NAME).unlink()
    with pytest.raises(TamperDetected, match="Missing module"):
        verify_integrity(mod_dir)

    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES)
    (mod_dir / MANIFEST_FILE).write_text("{ not json")
    with pytest.raises(TamperDetected, match="Corrupt integrity manifest"):
        verify_integrity(mod_dir)

    # POSITIVE CONTROL for the three assertions above: restored artifact verifies,
    # so `pytest.raises` was pinned to the defect and not to a function that always
    # raises.
    generate_manifest(mod_dir, mod_dir / MANIFEST_FILE)
    assert verify_integrity(mod_dir).status == IntegrityStatus.VERIFIED


def test_verify_all_reports_absence_without_raising(scan_root):
    reports = verify_all()
    assert len(reports) == 1
    assert reports[0].status == IntegrityStatus.UNVERIFIED_NO_MANIFEST
    assert manifest_dirs() == []

    # ...and finds the directory once a manifest exists (positive control).
    mod_dir = _write_verified_module(scan_root)
    assert manifest_dirs() == [mod_dir]
    assert [r.status for r in verify_all()] == [IntegrityStatus.VERIFIED]


# ---------------------------------------------------------------------------
# Through the REAL lifespan: fail closed on evidence
# ---------------------------------------------------------------------------

def test_startup_refuses_to_start_on_a_byte_modified_module(scan_root, client_factory):
    """
    A byte-modified compiled module must REFUSE startup.

    This is the branch that used to log an error and serve traffic anyway.
    """
    mod_dir = _write_verified_module(scan_root)
    (mod_dir / MODULE_NAME).write_bytes(ORIGINAL_BYTES.replace(b"pretend", b"PRETEND"))

    client = client_factory()
    with pytest.raises(TamperDetected, match="Modified module"):
        with client:
            pytest.fail(
                "the proxy served traffic with a tampered detection module: "
                "startup must not complete on a POSITIVE tamper finding"
            )


def test_startup_refuses_on_a_corrupt_manifest(scan_root, client_factory):
    mod_dir = _write_verified_module(scan_root)
    (mod_dir / MANIFEST_FILE).write_text("{{{ not json at all")

    client = client_factory()
    with pytest.raises(TamperDetected, match="Corrupt integrity manifest"):
        with client:
            pytest.fail("startup completed with an unreadable integrity manifest")


def test_startup_refuses_when_a_manifest_module_is_missing(scan_root, client_factory):
    mod_dir = _write_verified_module(scan_root)
    (mod_dir / MODULE_NAME).unlink()

    client = client_factory()
    with pytest.raises(TamperDetected, match="Missing module"):
        with client:
            pytest.fail("startup completed with a manifest module missing from disk")


def test_startup_refuses_on_an_empty_manifest(scan_root, client_factory):
    """
    RED (Codex adversarial review, 2026-07-27): through the REAL lifespan, an
    EMPTY manifest must refuse to start exactly like a corrupt one. Before the
    fix, ``verify_all()`` reported ``VERIFIED`` for a directory whose manifest
    declared zero modules, ``all(r.verified for r in integrity_reports)`` was
    vacuously True, and the proxy served traffic having verified nothing.
    """
    mod_dir = scan_root / "detection"
    mod_dir.mkdir(exist_ok=True)
    (mod_dir / MANIFEST_FILE).write_text("{}")

    client = client_factory()
    with pytest.raises(TamperDetected, match="[Ee]mpty"):
        with client:
            pytest.fail(
                "the proxy served traffic with an EMPTY integrity manifest: "
                "0 modules checked is not the same as 0 modules tampered"
            )


# ---------------------------------------------------------------------------
# Through the REAL lifespan: fail open on absence, but VISIBLY
# ---------------------------------------------------------------------------

def test_startup_continues_with_no_manifest_and_publishes_unverified(
    scan_root, client_factory
):
    """
    Absence of evidence must NOT block startup — and must not be silent either.

    Positive control for the three refusal tests above: the same lifespan, same
    client, same fixture, and here it DOES start. So `pytest.raises(TamperDetected)`
    there is pinned to the tamper finding, not to a lifespan that never starts.
    """
    assert manifest_dirs() == [], "fixture must start with no manifest anywhere"

    client = client_factory()
    with client:
        state = client.app.state.integrity
        assert state["status"] == IntegrityStatus.UNVERIFIED_NO_MANIFEST, state
        assert state["verified"] is False, state
        assert state["startup_blocked"] is False, state
        assert "NOT an integrity pass" in state["detail"], state

        # VISIBLE, not just logged: the operator surface reports it.
        resp = client.get("/admin/health")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["integrity"]["status"] == IntegrityStatus.UNVERIFIED_NO_MANIFEST
        assert body["integrity"]["verified"] is False
        # ...and the service itself is up, which is the whole point of fail-open.
        assert body["status"] == "ok"


def test_startup_reports_verified_when_the_manifest_matches(scan_root, client_factory):
    """Positive control on the visible state: a good artifact reads VERIFIED."""
    mod_dir = _write_verified_module(scan_root)

    client = client_factory()
    with client:
        state = client.app.state.integrity
        assert state["status"] == IntegrityStatus.VERIFIED, state
        assert state["verified"] is True, state
        assert state["modules_checked"] == 1, state
        assert state["directories"] == [str(mod_dir)], state

        body = client.get("/admin/health").json()
        assert body["integrity"]["verified"] is True, body


def test_startup_fails_open_and_visibly_when_the_check_cannot_run(
    scan_root, client_factory, monkeypatch
):
    """
    An UNVERIFIABLE environment (not a tamper) must start, and say so.

    Proves the split is a real branch and not just a renamed catch-all: the same
    startup path that halts on TamperDetected continues on a different exception,
    and publishes UNVERIFIABLE rather than pretending the modules are intact.
    """
    def _boom(*_args, **_kwargs):
        raise OSError("integrity scan tree is unreadable")

    monkeypatch.setattr(integrity_mod, "verify_all", _boom)

    client = client_factory()
    with client:
        state = client.app.state.integrity
        assert state["status"] == IntegrityStatus.UNVERIFIABLE, state
        assert state["verified"] is False, state
        assert state["startup_blocked"] is False, state
        assert "integrity scan tree is unreadable" in state["detail"], state
        assert client.get("/admin/health").json()["integrity"]["verified"] is False


def test_tamper_and_absence_produce_different_startup_outcomes(
    scan_root, client_factory
):
    """
    The one assertion the old code could not satisfy.

    Same tree, same lifespan: absence starts, evidence does not. If a future edit
    re-collapses the two states, exactly one half of this test breaks.
    """
    absent_client = client_factory()
    with absent_client:
        absent_status = absent_client.app.state.integrity["status"]
    assert absent_status == IntegrityStatus.UNVERIFIED_NO_MANIFEST

    mod_dir = _write_verified_module(scan_root)
    (mod_dir / MODULE_NAME).write_bytes(b"different bytes entirely")
    tampered_client = client_factory()
    with pytest.raises(TamperDetected):
        with tampered_client:
            pass

    # And the manifest still describes the module it was built from, so the tamper
    # was detected by the hash, not by a missing file.
    manifest = json.loads((mod_dir / MANIFEST_FILE).read_text())
    assert MODULE_NAME in manifest and len(manifest[MODULE_NAME]) == 64
