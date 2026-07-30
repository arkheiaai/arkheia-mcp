"""
RECEIPTED — Binary integrity verification (compiled .so/.pyd).

Phase 1: what decision are we demanding a record of?
----------------------------------------------------
This flow makes TWO decisions, and they are not the same decision:

**D1, at build time** — *"these hashes are the trusted state of this artifact."*
Made by ``scripts/build_release.py`` step 3 via
``proxy.license.integrity.generate_manifest``. It DOES leave a durable record:
``integrity_manifest.json``, written to disk, shipped inside the release, and
read back later by ``verify_integrity``. It is a real receipt — a signed-at-build
statement of trusted state that a verifier consumes — and this module proves it
end to end: written on the production path, read back off disk, and tied to the
decision by re-hashing the actual bytes of every file it names.

**D2, at runtime** — *"this artifact matches / does not match its manifest."*
On ``origin/master`` this decision does not happen at all: ``verify_integrity``
has ZERO production call sites, so nothing is ever verified and nothing is ever
recorded. PR #15 supplies the call site and publishes the outcome on
``app.state.integrity`` / ``/admin/health`` — but that is process-local state, not
a durable record: restart the proxy and the verdict is gone. **D2 is therefore
NOT receipted, and this module does not claim it is.** It is not ``n/a`` either:
a startup that refuses to serve because a detection binary was modified is
exactly the kind of decision an auditor needs a record of, and the audit rail to
write it on already exists in the same lifespan. It is FAIL / not-yet.

Phase 2: the defect this found
------------------------------
``generate_manifest`` globs ``*.so``/``*.pyd``. Over a directory containing none
it returned ``{}`` and ``step_generate_manifest`` wrote that out, printed
"Manifest written: … (0 modules)", and the build continued to exit 0. The empty
file is not neutral — ``verify_integrity`` treats a manifest that EXISTS as one
to check, iterates its zero entries, logs *"Integrity check passed: 0 modules
verified"* and returns success.

That is a receipt of a check that did not happen: the artifact reports VERIFIED
having established nothing, and downstream that verdict is trusted. It is DONE.md
floor invariant 9 in its exact form — a measurement gate that measures nothing
must not report a pass — and the brief's "an audit row showing a bare verdict for
something that scored nothing".

The compounding half: the build did not stop there. Step 4 then DELETED the
compiled Python sources named in ``COMPILED_MODULES``, so a build that produced
no binaries destroyed the originals and still printed "Release build complete".
``--skip-compile`` on a clean checkout reaches this.

Fixed in ``scripts/build_release.py`` (a file no open PR touches): the empty
manifest is deleted rather than shipped, and the build aborts at step 3 — before
step 4 can remove anything — naming the directory and the globs that found
nothing rather than reporting an aggregate zero.

The sharper sibling, which a non-empty manifest hides: ``COMPILED_MODULES`` is a
list of FILES while the manifest is generated per DIRECTORY, so one module that
compiled makes its whole directory look covered and a module that silently
produced no binary is absent from the record, never verified, and its source
deleted anyway. ``check_every_module_is_recorded`` now requires a manifest entry
per module and names the ones no record covers — "1 of 2 modules recorded"
passes every non-zero assertion, which is precisely the case floor invariant
9(a) exists for.

Left open deliberately, and named rather than hidden: ``verify_integrity``
ITSELF still reports a pass over a hand-written empty manifest. That fix belongs
in ``proxy/license/integrity.py``, which PR #15 is actively rewriting; PR #15's
new ``IntegrityReport`` returns ``VERIFIED`` with ``modules_checked=0`` for this
input, so the hole survives it. See the PR body.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import uuid
from pathlib import Path

import pytest

from proxy.license.integrity import (
    MANIFEST_FILE,
    TamperDetected,
    generate_manifest,
    verify_integrity,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_build_release():
    """Import scripts/build_release.py by path — ``scripts`` is not a package."""
    path = REPO_ROOT / "scripts" / "build_release.py"
    spec = importlib.util.spec_from_file_location("_build_release_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


build_release = _load_build_release()


def _fake_binary(directory: Path, name: str, payload: bytes) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / name
    p.write_bytes(payload)
    return p


@pytest.fixture
def module_dir(tmp_path):
    d = tmp_path / "detection"
    _fake_binary(d, "features.cpython-312-darwin.so", b"\x7fELF" + b"features-bytes" * 8)
    _fake_binary(d, "engine.cpython-312-darwin.so", b"\x7fELF" + b"engine-bytes" * 8)
    # A non-artifact that must NOT be recorded: the manifest is a statement about
    # compiled modules, and a receipt that over-claims its scope is also wrong.
    (d / "notes.txt").write_text("not a compiled module")
    return d


# ---------------------------------------------------------------------------
# 1. D1: the manifest is a real, durable, decision-tied record.
# ---------------------------------------------------------------------------

def test_manifest_is_written_on_the_production_path_and_reads_back(module_dir, capsys):
    """
    Drive ``scripts/build_release.py``'s real step 3 — not ``generate_manifest``
    directly — and read the artefact back off disk.
    """
    returned = build_release.step_generate_manifest(module_dir)

    manifest_path = module_dir / MANIFEST_FILE
    assert manifest_path.exists(), f"step 3 produced no record at {manifest_path}"

    on_disk = json.loads(manifest_path.read_text())
    assert on_disk == returned, (
        "what step 3 returned and what it wrote disagree; the caller's view of "
        "the decision is not the record that ships"
    )

    # Tie the record to the decision: every hash must reproduce from the actual
    # bytes of the file it names. A manifest of plausible-looking hex is not a
    # record of THIS artifact.
    assert set(on_disk) == {
        "features.cpython-312-darwin.so",
        "engine.cpython-312-darwin.so",
    }, f"manifest names the wrong modules: {sorted(on_disk)}"
    for name, recorded in on_disk.items():
        actual = hashlib.sha256((module_dir / name).read_bytes()).hexdigest()
        assert recorded == actual, f"{name}: manifest records {recorded}, file hashes {actual}"

    # Scope control: the non-artifact must be absent, and the two entries must
    # not share a hash (which would mean the record cannot distinguish them).
    assert "notes.txt" not in on_disk
    assert len(set(on_disk.values())) == 2

    # Name the units in the operator-visible output, not just an aggregate.
    printed = capsys.readouterr().out
    assert "(2 modules)" in printed
    for name in on_disk:
        assert name in printed, f"step 3 did not name {name} in its output"


def test_the_verifier_consumes_exactly_this_record(module_dir):
    """
    A record nothing reads is not a receipt. Prove the manifest step 3 wrote is
    the input ``verify_integrity`` decides on — and that it discriminates.
    """
    build_release.step_generate_manifest(module_dir)
    manifest_path = module_dir / MANIFEST_FILE

    # Positive: the artifact as built verifies.
    assert verify_integrity(module_dir) is True

    # Vacuity guard 1 — a FABRICATED entry. If the verifier did not really read
    # the record, adding a module that does not exist would change nothing.
    manifest = json.loads(manifest_path.read_text())
    fabricated = f"{uuid.uuid4().hex}.so"
    manifest[fabricated] = "0" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(TamperDetected, match=fabricated):
        verify_integrity(module_dir)

    # Vacuity guard 2 — a MISMATCHED hash for a module that does exist. This is
    # the near miss guard 1 is too coarse to catch: the name resolves, only the
    # recorded value is wrong.
    manifest.pop(fabricated)
    real = "engine.cpython-312-darwin.so"
    manifest[real] = "f" * 64
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(TamperDetected, match=real):
        verify_integrity(module_dir)

    # Vacuity guard 3 — the record is correct but the ARTIFACT changed. This is
    # the direction the whole flow exists for.
    manifest[real] = hashlib.sha256((module_dir / real).read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    assert verify_integrity(module_dir) is True  # restored: positive control
    (module_dir / real).write_bytes(b"\x7fELF" + b"tampered" * 8)
    with pytest.raises(TamperDetected, match=real):
        verify_integrity(module_dir)


# ---------------------------------------------------------------------------
# 2. The false receipt: a manifest that certifies nothing.
# ---------------------------------------------------------------------------

def test_an_empty_manifest_is_a_record_of_a_check_that_did_not_happen(tmp_path):
    """
    REWRITTEN, exactly as this test instructed its successor to do.

    It was a characterisation test: it asserted that ``verify_integrity`` returned
    True for a manifest that certifies nothing, and carried the message *"behaviour
    changed — if verify_integrity now refuses an empty manifest, this
    characterisation test has served its purpose and should be rewritten as the
    assertion that it refuses"*. The runtime half of F18 fixed the library, so it
    is that assertion now.

    Why the library had to change and not just the build: the manifest sits next
    to the artifacts it certifies, so an attacker with write access to one has
    write access to the other. Truncating it to ``{}`` made the pre-fix verifier
    iterate zero entries, log "Integrity check passed: 0 modules verified" and
    return True — a bypass of the whole mechanism, not merely a weak build. Step 3
    refusing to *ship* an empty manifest (next test) does not help against a
    manifest emptied after shipping.
    """
    empty_dir = tmp_path / "no_binaries"
    empty_dir.mkdir()

    manifest = generate_manifest(empty_dir, empty_dir / MANIFEST_FILE)
    assert manifest == {}, "test setup: the directory must contain no artifacts"

    # A manifest that EXISTS and lists nothing is now refused, not passed.
    with pytest.raises(TamperDetected, match="lists no modules"):
        verify_integrity(empty_dir)


def test_step_3_refuses_to_ship_a_manifest_that_certifies_nothing(tmp_path):
    """The fix: refuse, delete the false receipt, and NAME THE UNITS."""
    empty_dir = tmp_path / "no_binaries"
    empty_dir.mkdir()

    with pytest.raises(build_release.EmptyManifest) as exc:
        build_release.step_generate_manifest(empty_dir)

    message = str(exc.value)
    # Named units, not an aggregate zero: which directory, and what was sought.
    assert str(empty_dir) in message, f"refusal does not name the directory: {message}"
    for glob in build_release.COMPILED_ARTIFACT_GLOBS:
        assert glob in message, f"refusal does not name the glob {glob!r}: {message}"

    # The false receipt must not survive the refusal — verify_integrity would
    # read it and report a pass.
    assert not (empty_dir / MANIFEST_FILE).exists(), (
        "an empty manifest was left on disk after the refusal; a later "
        "verify_integrity() would read it and report VERIFIED over zero modules"
    )

    # Positive control: the same function accepts a directory that HAS artifacts,
    # so the refusal is not simply "this function always raises".
    good = tmp_path / "has_binaries"
    _fake_binary(good, "features.so", b"\x7fELFsome-real-bytes")
    assert build_release.step_generate_manifest(good) != {}
    assert (good / MANIFEST_FILE).exists()


# ---------------------------------------------------------------------------
# 3. The compounding half: the refusal must land BEFORE sources are destroyed.
# ---------------------------------------------------------------------------

def _release_repo(tmp_path) -> Path:
    """A minimal repo the release pipeline can be pointed at."""
    root = tmp_path / "repo"
    (root / "profiles").mkdir(parents=True)
    (root / "profiles" / "demo.yaml").write_text("model: demo\nversion: '1.0'\n")
    pkg = root / "proxy" / "detection"
    pkg.mkdir(parents=True)
    (pkg / "features.py").write_text("# real source, must survive a failed build\n")
    (pkg / "engine.py").write_text("# real source, must survive a failed build\n")
    return root


def test_a_build_that_produced_no_binaries_aborts_before_deleting_the_sources(
    tmp_path, monkeypatch, capsys
):
    """
    End-to-end through ``main()``. Before the fix this sequence produced empty
    manifests, DELETED both sources, printed "Release build complete" and exited
    0 — a destroyed checkout reported as a successful release.
    """
    root = _release_repo(tmp_path)
    sources = [
        root / "proxy" / "detection" / "features.py",
        root / "proxy" / "detection" / "engine.py",
    ]

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    key = "A" * 43 + "="  # 32 bytes once base64-decoded
    rc = build_release.main(["--skip-compile", "--profile-key", key])

    assert rc == 1, "a build that compiled nothing reported success"

    out = capsys.readouterr()
    assert "Release build complete" not in out.out, (
        "the build printed its success banner despite failing"
    )
    assert "ERROR:" in out.err

    for src in sources:
        assert src.exists(), (
            f"{src.name} was deleted by a build that produced no binary for it — "
            f"the checkout is destroyed and unrecoverable from the artifact"
        )
    assert not list(root.rglob(MANIFEST_FILE)), "an empty manifest was shipped"


def test_a_partly_compiled_build_names_the_modules_no_record_covers(
    tmp_path, monkeypatch, capsys
):
    """
    The sharper form of the same defect, and the one a non-empty manifest hides.

    ``COMPILED_MODULES`` is a list of FILES; the manifest is generated per
    DIRECTORY. One sibling that compiled makes the whole directory's manifest
    non-empty, so a module whose build silently produced nothing is absent from
    the record, never verified, and its source deleted regardless. "1 of 2
    modules recorded" passes every non-zero assertion.
    """
    root = _release_repo(tmp_path)
    pkg = root / "proxy" / "detection"
    # features compiled; engine did not.
    _fake_binary(pkg, "features.cpython-312-darwin.so", b"\x7fELF" + b"x" * 64)

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    key = "A" * 43 + "="
    rc = build_release.main(["--skip-compile", "--profile-key", key])
    out = capsys.readouterr()

    assert rc == 1, "a build missing one module's binary reported success"
    # NAME THE UNITS: the uncovered module, not just a count.
    assert "proxy/detection/engine.py" in out.err, (
        f"the failure does not name the uncovered module: {out.err!r}"
    )
    assert "proxy/detection/features.py" not in out.err, (
        "the covered module was reported as missing too — the check is not "
        "discriminating between recorded and unrecorded units"
    )
    # And the source that nothing verifies must still exist.
    assert (pkg / "engine.py").exists()
    assert (pkg / "features.py").exists()


def test_the_abort_is_specific_not_a_blanket_failure(tmp_path, monkeypatch, capsys):
    """
    Positive control for both aborts above: with every module compiled the same
    pipeline completes, removes the sources, and ships a manifest that names each
    one. Without this, ``rc == 1`` would be satisfied by a build that can never
    succeed at all.
    """
    root = _release_repo(tmp_path)
    pkg = root / "proxy" / "detection"
    _fake_binary(pkg, "features.cpython-312-darwin.so", b"\x7fELF" + b"x" * 64)
    _fake_binary(pkg, "engine.cpython-312-darwin.so", b"\x7fELF" + b"y" * 64)

    monkeypatch.setattr(build_release, "REPO_ROOT", root)
    monkeypatch.setattr(
        build_release,
        "COMPILED_MODULES",
        ["proxy/detection/features.py", "proxy/detection/engine.py"],
    )

    key = "A" * 43 + "="
    rc = build_release.main(["--skip-compile", "--profile-key", key])
    out = capsys.readouterr()

    assert rc == 0, out.err
    assert "Release build complete" in out.out
    assert "2 of 2 modules recorded" in out.out

    manifest = json.loads((pkg / MANIFEST_FILE).read_text())
    assert sorted(manifest) == [
        "engine.cpython-312-darwin.so",
        "features.cpython-312-darwin.so",
    ]
    for name, recorded in manifest.items():
        assert recorded == hashlib.sha256((pkg / name).read_bytes()).hexdigest()

    # Sources removed only once every one of them is covered by the record.
    assert not (pkg / "features.py").exists()
    assert not (pkg / "engine.py").exists()
