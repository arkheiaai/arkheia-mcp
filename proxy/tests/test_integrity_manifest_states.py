"""
CLOSURE TESTS — the manifest is an INPUT to the verifier, so every state it can
be in is an attack surface. This file enumerates them and pins the verdict.

THE P1 THIS WAS COMPILED FROM (reproduced by a second vendor, then here)
-----------------------------------------------------------------------
The previous round closed the *emptied* manifest: ``{}`` used to produce
*"Integrity check passed: 0 modules verified"* and a ``True``. Deleting the file
outright takes a different branch and was still a full bypass::

    write features.cpython-312-darwin.so   (tampered payload)
    rm  integrity_manifest.json
    -> build_integrity_record  verdict=unverifiable reason=no_manifest
    -> verify_integrity        returns True         NO HALT

Executed against the pre-fix tree, not inferred. So the previous fix taught an
attacker which file to *delete* rather than truncate, and deleting is easier.

The general lesson, which is why this file is a table and not a test: the fix for
one manifest state is worth very little, because the verifier reads its
expectations out of a file that sits next to the artifacts it is protecting.
Every state that file can be in has to have a decided verdict.

THE RULING — WHY ``unverifiable`` MUST NOT HALT, AND WHAT DOES
-------------------------------------------------------------
The tempting fix is "make ``unverifiable`` halt". It is the wrong fix twice over.

*It is a category error.* ``unverifiable`` is the bucket for **not-observed**
(DONE.md floor invariant 9(d)) — it exists precisely to say *no evidence either
way was obtained*. Halting on it converts an absence of evidence into an adverse
finding, and then the three honest buckets collapse to two and the receipt stops
carrying information.

*And it would refuse to boot production.* The proxy deploys as a source checkout
with nothing Cython-compiled, so ``runtime_module_dirs()`` returns
``proxy/detection`` and ``proxy/router``, neither has a manifest, and the live
verdict is ``unverifiable`` on **every boot** (recorded as a known limit by the
previous round). An unconditional halt breaks: the deployed proxy, local
``uvicorn`` runs, ``docker-compose.yaml``, the customer source-install path in
``ARKHEIA_INSTALL.md``, and ``test_the_proxy_actually_runs_this_at_startup``.

The real asymmetry is that a missing manifest is **two different facts**:

* **no compiled artifacts + no manifest** — nothing to verify and nothing
  claiming there was. Benign. ``unverifiable``. Boots.
* **compiled artifacts + no manifest** — something removed the file that was
  supposed to describe binaries that ARE there. That is not an absence of
  evidence, it is the affirmative observation that the expectations are gone.
  Adverse. ``tampered``. Halts.

So the fix narrows what *counts* as ``unverifiable`` rather than changing what
``unverifiable`` does: **the manifest's absence is only benign when the thing it
was supposed to describe is also absent.**

WHAT THIS BREAKS, STATED PLAINLY
--------------------------------
A directory compiled by ``python setup_cython.py build_ext --inplace`` alone
(without ``scripts/build_release.py``, which generates the manifest in step 3)
now refuses to boot. That is a real regression for a developer's in-place build
and it is accepted deliberately: a pile of compiled artifacts with no record of
what they should hash to is indistinguishable from the attack. The remedy is
named in the refusal text. Deliberately NOT provided: an environment-variable
bypass — an attacker who can delete a file in the package can also set an env
var, so a bypass would restore the exact fail-open being closed here.

THE SECOND HOLE THE ENUMERATION FOUND
-------------------------------------
``valid-but-missing-entries-for-present-artifacts``. The manifest is a
whitelist-by-enumeration, and pre-fix anything not enumerated was invisible:
list module A only, tamper module B, and the record read ``verified`` with
``modules_expected=1 modules_matched=1``. Truncating the manifest to drop one
entry was therefore a live bypass of the same family as deleting it, and no test
covered it. See ``S6`` / ``S9b``.

STRUCTURAL FIX, NOT JUST MORE BRANCHES
--------------------------------------
``verify_and_receipt`` halted on an enumerated ``tampered``, so any verdict added
later defaulted to *boot anyway* — fail-OPEN in a control whose entire job is to
refuse. The halt decision is now an allow-list of non-halting verdicts, so a
new verdict halts until someone deliberately exempts it. Pinned by
``tests/test_integrity_halt_floor.py``, which fails on an unclassified verdict.
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from proxy.license.integrity import (
    COMPILED_ARTIFACT_GLOBS,
    MANIFEST_FILE,
    VERDICT_TAMPERED,
    VERDICT_UNVERIFIABLE,
    VERDICT_VERIFIED,
    TamperDetected,
    build_integrity_record,
    compiled_artifacts,
    generate_manifest,
    verify_integrity,
)

#: A plausible compiled artifact name, in the exact shape Codex reproduced with.
SO = "features.cpython-312-darwin.so"
SO_B = "profile_router.cpython-312-darwin.so"
PAYLOAD = b"compiled feature extractor v1"
MALICIOUS = b"compiled feature extractor v1 + backdoor"


def _dir(tmp_path: Path, name: str = "pkg") -> Path:
    d = tmp_path / name
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# State builders. Each returns a directory in exactly one manifest state.
# Named S<n> to match the enumeration in the PR body one-for-one.
# ---------------------------------------------------------------------------


def s1_absent_no_artifacts(tmp_path: Path) -> Path:
    """Source checkout: nothing compiled, no manifest. THE LIVE PRODUCTION SHAPE."""
    return _dir(tmp_path)


def s2_absent_with_artifacts(tmp_path: Path) -> Path:
    """THE P1. Codex's exact case: a .so present and no manifest at all."""
    d = _dir(tmp_path)
    (d / SO).write_bytes(MALICIOUS)
    return d


def s3_empty_object(tmp_path: Path) -> Path:
    """Closed by the previous round; re-pinned so it cannot regress."""
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / MANIFEST_FILE).write_text("{}")
    return d


def s4_unparseable(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / MANIFEST_FILE).write_text('{"features')
    return d


def s5_valid_json_not_an_object(tmp_path: Path) -> Path:
    """``[]`` parses fine and is not a mapping — it certifies nothing, differently."""
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / MANIFEST_FILE).write_text("[]")
    return d


def s6_missing_entry_for_present_artifact(tmp_path: Path) -> Path:
    """
    The second hole. Manifest lists A (and A matches); B is present, tampered,
    and simply not mentioned. Pre-fix this was ``verified``.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)     # lists SO only
    (d / SO_B).write_bytes(MALICIOUS)           # added AFTER the manifest
    return d


def s7_entry_for_absent_artifact(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    (d / SO).unlink()
    return d


def s8_wrong_digest(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    (d / SO).write_bytes(MALICIOUS)
    return d


def s9a_truncated_mid_json(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    raw = (d / MANIFEST_FILE).read_text()
    (d / MANIFEST_FILE).write_text(raw[: len(raw) // 2])
    return d


def s9b_truncated_to_valid_subset(tmp_path: Path) -> Path:
    """
    The nastier truncation: still valid JSON, one entry dropped, the dropped
    module still on disk and tampered. Pre-fix: ``verified``, 1 of 1.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / SO_B).write_bytes(PAYLOAD)
    manifest = generate_manifest(d, d / MANIFEST_FILE)
    del manifest[SO_B]
    (d / MANIFEST_FILE).write_text(json.dumps(manifest))
    (d / SO_B).write_bytes(MALICIOUS)
    return d


def s10_manifest_unreadable(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    (d / MANIFEST_FILE).chmod(0o000)
    return d


def s11_manifest_is_a_directory(tmp_path: Path) -> Path:
    """A degenerate ``exists() is True`` that is not a readable file."""
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / MANIFEST_FILE).mkdir()
    return d


def s12_module_unreadable(tmp_path: Path) -> Path:
    """
    The artifact itself cannot be hashed. Pre-fix this raised a bare
    ``PermissionError`` out of a function documented as never raising, so no
    verdict and therefore NO RECEIPT was produced at all.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    (d / SO).chmod(0o000)
    return d


def s13_non_string_digest(tmp_path: Path) -> Path:
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / MANIFEST_FILE).write_text(json.dumps({SO: None}))
    return d


def s14_entry_escapes_the_directory(tmp_path: Path) -> Path:
    """
    A manifest key is joined onto ``module_dir``, so ``..`` walks out and an
    absolute key replaces the base entirely (``Path('/a') / '/etc/hosts'`` is
    ``/etc/hosts``). A verifier must not be steered outside its own directory by
    the file it is verifying.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    generate_manifest(d, d / MANIFEST_FILE)
    manifest = json.loads((d / MANIFEST_FILE).read_text())
    manifest["../outside.so"] = "0" * 64
    (d / MANIFEST_FILE).write_text(json.dumps(manifest))
    (tmp_path / "outside.so").write_bytes(b"not ours")
    return d


def s15_manifest_symlinked_elsewhere(tmp_path: Path) -> Path:
    """
    Expectations sourced from outside the package. NO HALT — see the table's
    justification; it is recorded, not refused.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    real = tmp_path / "elsewhere.json"
    generate_manifest(d, real)
    (d / MANIFEST_FILE).symlink_to(real)
    return d


def s16_control_valid_and_matching(tmp_path: Path) -> Path:
    """THE CONTROL ROW THAT PASSES (DONE.md v1.15 clause 5)."""
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    (d / SO_B).write_bytes(b"compiled profile router v1")
    generate_manifest(d, d / MANIFEST_FILE)
    return d


def s17_directory_named_like_an_artifact(tmp_path: Path) -> Path:
    """
    ``*.so`` also matches directories. A directory is not an importable module,
    so counting it as a compiled artifact would refuse to boot a source checkout
    that happens to contain one — a false positive in a control that must not cry
    wolf. NO HALT, and the reason must still be the benign one.
    """
    d = _dir(tmp_path)
    (d / SO).mkdir()
    return d


#: (state id, builder, expected verdict, expected reason, must halt)
#:
#: The table is the ruling. A reviewer disagreeing with the design should be
#: able to disagree with exactly one row.
MANIFEST_STATES = [
    ("S1  absent, no compiled artifacts",       s1_absent_no_artifacts,             VERDICT_UNVERIFIABLE, "no_manifest",                              False),
    ("S2  absent, compiled artifacts present",  s2_absent_with_artifacts,           VERDICT_TAMPERED,     "manifest_missing_for_compiled_artifacts",  True),
    ("S3  empty object {}",                     s3_empty_object,                    VERDICT_TAMPERED,     "manifest_certifies_nothing",               True),
    ("S4  unparseable",                         s4_unparseable,                     VERDICT_TAMPERED,     "manifest_unparseable",                     True),
    ("S5  valid JSON, not an object",           s5_valid_json_not_an_object,        VERDICT_TAMPERED,     "manifest_not_an_object",                   True),
    ("S6  no entry for a present artifact",     s6_missing_entry_for_present_artifact, VERDICT_TAMPERED,  "unlisted_compiled_artifact",               True),
    ("S7  entry for an absent artifact",        s7_entry_for_absent_artifact,       VERDICT_TAMPERED,     "module_mismatch",                          True),
    ("S8  wrong digest",                        s8_wrong_digest,                    VERDICT_TAMPERED,     "module_mismatch",                          True),
    ("S9a truncated mid-JSON",                  s9a_truncated_mid_json,             VERDICT_TAMPERED,     "manifest_unparseable",                     True),
    ("S9b truncated to a valid subset",         s9b_truncated_to_valid_subset,      VERDICT_TAMPERED,     "unlisted_compiled_artifact",               True),
    ("S10 manifest unreadable",                 s10_manifest_unreadable,            VERDICT_TAMPERED,     "manifest_unreadable",                      True),
    ("S11 manifest is a directory",             s11_manifest_is_a_directory,        VERDICT_TAMPERED,     "manifest_unreadable",                      True),
    ("S12 module unreadable",                   s12_module_unreadable,              VERDICT_TAMPERED,     "module_mismatch",                          True),
    ("S13 non-string digest value",             s13_non_string_digest,              VERDICT_TAMPERED,     "module_mismatch",                          True),
    ("S14 entry escapes the directory",         s14_entry_escapes_the_directory,    VERDICT_TAMPERED,     "manifest_invalid_entry",                   True),
    ("S15 manifest symlinked elsewhere",        s15_manifest_symlinked_elsewhere,   VERDICT_VERIFIED,     "all_modules_matched",                      False),
    ("S16 valid and matching (CONTROL)",        s16_control_valid_and_matching,     VERDICT_VERIFIED,     "all_modules_matched",                      False),
    ("S17 directory named like an artifact",     s17_directory_named_like_an_artifact, VERDICT_UNVERIFIABLE, "no_manifest",                            False),
]


@pytest.fixture(autouse=True)
def _restore_permissions(tmp_path):
    """
    ``chmod 000`` states would otherwise make ``tmp_path`` teardown fail, and as
    root they would not deny anything either — see the skip in the tests.
    """
    yield
    for path in tmp_path.rglob("*"):
        try:
            path.chmod(path.stat(follow_symlinks=False).st_mode | stat.S_IRWXU)
        except (OSError, ValueError):
            pass


def _needs_permission_denial(state_id: str) -> bool:
    return "unreadable" in state_id


@pytest.mark.parametrize(
    "state_id,builder,expected_verdict,expected_reason,must_halt",
    MANIFEST_STATES,
    ids=[row[0].split()[0] for row in MANIFEST_STATES],
)
def test_every_manifest_state_has_a_pinned_verdict(
    tmp_path, state_id, builder, expected_verdict, expected_reason, must_halt
):
    """
    One row per manifest state: the verdict, the reason, and whether it halts.

    ``must_halt`` is asserted through the real policy function, not by reading
    the verdict string, because "the record says tampered" and "the process
    refuses to continue" are two different facts and the P1 was exactly their
    disagreement.
    """
    if _needs_permission_denial(state_id) and os.geteuid() == 0:
        pytest.skip("running as root: chmod 000 denies nothing, so this state cannot be built")

    d = builder(tmp_path)
    record = build_integrity_record(d)

    assert record["verdict"] == expected_verdict, (
        f"{state_id}: verdict {record['verdict']!r} (reason {record['reason']!r}), "
        f"expected {expected_verdict!r}"
    )
    assert record["reason"] == expected_reason, f"{state_id}: reason {record['reason']!r}"

    if must_halt:
        with pytest.raises(TamperDetected):
            verify_integrity(d)
    else:
        assert verify_integrity(d) is True, f"{state_id} must not refuse to boot"


def test_the_table_discriminates(tmp_path):
    """
    VACUITY GUARD. A table whose every row forbids proves nothing (DONE.md v1.15
    clause 5), and one whose every row permits proves less. Require both
    populations to be non-empty and require the halting rows to be the majority
    finding rather than an incidental one.
    """
    halting = [row for row in MANIFEST_STATES if row[4]]
    passing = [row for row in MANIFEST_STATES if not row[4]]
    assert halting, "no state halts — the table cannot detect anything"
    assert passing, "no state passes — the table forbids everything and cannot discriminate"
    verdicts = {row[2] for row in MANIFEST_STATES}
    assert verdicts == {VERDICT_TAMPERED, VERDICT_UNVERIFIABLE, VERDICT_VERIFIED}, (
        "the table must exercise all three honest buckets, not just the adverse one"
    )


# ---------------------------------------------------------------------------
# The P1 on its own, spelled out — this is the row a reviewer reads first
# ---------------------------------------------------------------------------


def test_deleting_the_manifest_over_compiled_artifacts_halts(tmp_path):
    """
    THE P1, RED-FIRST. Reproduced from Codex's report before any fix:

        verdict=unverifiable reason=no_manifest -> verify_integrity() == True

    A ``.so`` is present, so there was something to verify; the file that said
    what it should hash to is gone. The record must name the artifacts it found
    with no expectations, so the finding is investigable from the receipt alone.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(MALICIOUS)
    assert not (d / MANIFEST_FILE).exists()

    record = build_integrity_record(d)
    assert record["verdict"] == VERDICT_TAMPERED
    assert record["reason"] == "manifest_missing_for_compiled_artifacts"
    assert record["risk_level"] == "HIGH"
    assert record["manifest_present"] is False
    # The units are NAMED, not summarised (floor invariant 9(a)).
    assert record["compiled_artifacts_present"] == [SO]
    assert record["unlisted_artifacts"] == [SO]
    assert SO in record["detail"]

    with pytest.raises(TamperDetected, match="no integrity manifest"):
        verify_integrity(d)


def test_an_empty_source_checkout_still_boots(tmp_path):
    """
    THE OTHER HALF OF THE ASYMMETRY, and the reason ``unverifiable`` does not
    halt as a class. This is the shape the deployed proxy is in on every boot.
    If this test ever goes red, production stops starting.
    """
    d = _dir(tmp_path)
    (d / "engine.py").write_text("# pure python, nothing compiled\n")
    record = build_integrity_record(d)
    assert record["verdict"] == VERDICT_UNVERIFIABLE
    assert record["reason"] == "no_manifest"
    assert record["compiled_artifacts_present"] == []
    assert verify_integrity(d) is True


def test_the_refusal_says_what_would_clear_it(tmp_path):
    """
    Gate-9 legibility: an adverse verdict states the datum behind it and the
    action that resolves it. A developer who ran an in-place Cython build is the
    most likely person to hit S2, and the message must tell them what to run
    rather than leaving them to read the source.
    """
    d = _dir(tmp_path)
    (d / SO).write_bytes(PAYLOAD)
    detail = build_integrity_record(d)["detail"]
    assert SO in detail, "the refusal must name the artifact that has no expectation"
    assert "build_release" in detail, "the refusal must name the remedy"


# ---------------------------------------------------------------------------
# The PRODUCTION path — the halt has to reach the process, not just the record
# ---------------------------------------------------------------------------


async def test_the_proxy_refuses_to_boot_over_a_missing_manifest(tmp_path, monkeypatch):
    """
    THE ONE THAT MAKES THE TABLE MATTER IN PRODUCTION.

    Everything above drives ``verify_integrity``, and production drives
    ``verify_and_receipt`` from ``proxy/main.py``'s lifespan. Those are two
    functions and the P1 was a disagreement between a record and a behaviour, so
    the boot path is asserted directly: point the runtime at a directory with a
    compiled artifact and no manifest, run the REAL FastAPI lifespan, and require
    it to refuse — with the verdict already on disk, because a refusal nobody can
    evidence afterwards is the failure mode this whole flow exists to close.

    Pre-existing coverage drove the boot path only over a source checkout
    (verdict ``unverifiable``, no raise), so nothing observed the refusal at all:
    a mutant deleting the halt from the lifespan survived every test.
    """
    from proxy.config import settings
    import proxy.license.integrity as integrity_module
    import proxy.main as proxy_main

    release = _dir(tmp_path, "release")
    (release / SO).write_bytes(MALICIOUS)

    audit_log = tmp_path / "boot-audit.jsonl"
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    monkeypatch.setattr(settings.audit, "log_path", str(audit_log))
    monkeypatch.setattr(settings.detection, "profile_dir", str(profiles_dir))
    monkeypatch.setattr(settings.registry, "pull_on_startup", False)
    monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)
    monkeypatch.delenv("ARKHEIA_REQUIRE_LICENSE", raising=False)
    # The lifespan imports this name inside the function body, so patching the
    # module attribute is what the boot path actually resolves.
    monkeypatch.setattr(integrity_module, "runtime_module_dirs", lambda: [release])

    app = proxy_main.create_app()
    with pytest.raises(TamperDetected, match="no integrity manifest"):
        async with app.router.lifespan_context(app):
            pass

    rows = [
        json.loads(line) for line in audit_log.read_text().splitlines() if line.strip()
    ]
    integrity_rows = [
        r for r in rows if r.get("event_type") == "license.integrity_verification"
    ]
    assert len(integrity_rows) == 1, (
        f"the refusal left {len(integrity_rows)} integrity receipts — the verdict "
        f"must be recorded before the boot is refused"
    )
    assert integrity_rows[0]["verdict"] == VERDICT_TAMPERED
    assert integrity_rows[0]["reason"] == "manifest_missing_for_compiled_artifacts"
    assert integrity_rows[0]["risk_level"] == "HIGH"


async def test_the_proxy_still_boots_a_source_checkout(tmp_path, monkeypatch):
    """
    POSITIVE CONTROL for the test above, and the production-safety assertion for
    the whole ruling: the same real lifespan over a directory with nothing
    compiled must start normally and receipt ``unverifiable``. If this goes red,
    the deployed proxy stops booting.
    """
    from proxy.config import settings
    import proxy.license.integrity as integrity_module
    import proxy.main as proxy_main

    source = _dir(tmp_path, "source")
    (source / "engine.py").write_text("# nothing compiled\n")

    audit_log = tmp_path / "boot-audit.jsonl"
    profiles_dir = tmp_path / "profiles"
    profiles_dir.mkdir()
    monkeypatch.setattr(settings.audit, "log_path", str(audit_log))
    monkeypatch.setattr(settings.detection, "profile_dir", str(profiles_dir))
    monkeypatch.setattr(settings.registry, "pull_on_startup", False)
    monkeypatch.setattr(settings.registry, "pull_interval_hours", 0)
    monkeypatch.delenv("ARKHEIA_REQUIRE_LICENSE", raising=False)
    monkeypatch.setattr(integrity_module, "runtime_module_dirs", lambda: [source])

    app = proxy_main.create_app()
    async with app.router.lifespan_context(app):
        pass

    rows = [
        json.loads(line) for line in audit_log.read_text().splitlines() if line.strip()
    ]
    integrity_rows = [
        r for r in rows if r.get("event_type") == "license.integrity_verification"
    ]
    assert [r["verdict"] for r in integrity_rows] == [VERDICT_UNVERIFIABLE]


# ---------------------------------------------------------------------------
# The runtime detector and the build generator must see the same files
# ---------------------------------------------------------------------------


def test_the_artifact_detector_and_the_manifest_generator_agree(tmp_path):
    """
    DIFFERENTIAL (DONE.md v1.13). ``compiled_artifacts()`` decides whether a
    missing manifest is benign; ``generate_manifest()`` decides what a manifest
    contains. If they glob different sets, an artifact the build would have
    recorded can be invisible to the runtime check — which is the S2 bypass with
    extra steps.
    """
    d = _dir(tmp_path)
    for name in (SO, SO_B, "helper.pyd"):
        (d / name).write_bytes(b"x")
    for decoy in ("engine.py", "notes.txt", "libfoo.dylib", "integrity_manifest.json"):
        (d / decoy).write_text("x")

    detected = {p.name for p in compiled_artifacts(d)}
    generated = set(generate_manifest(d))
    assert detected == generated, (
        "the runtime artifact detector and the build-time manifest generator "
        f"disagree: detector-only {sorted(detected - generated)}, "
        f"generator-only {sorted(generated - detected)}"
    )
    assert detected == {SO, SO_B, "helper.pyd"}


def test_the_build_script_does_not_keep_its_own_copy_of_the_globs():
    """
    Registry / no-drift: ``scripts/build_release.py`` documented its
    ``COMPILED_ARTIFACT_GLOBS`` as a mirror of the library's. Two constants that
    must agree eventually will not, so it imports the one the runtime owns.
    """
    from scripts import build_release

    assert build_release.COMPILED_ARTIFACT_GLOBS is COMPILED_ARTIFACT_GLOBS, (
        "build_release must reuse proxy.license.integrity.COMPILED_ARTIFACT_GLOBS, "
        "not redeclare it"
    )
