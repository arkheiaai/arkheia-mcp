"""
FLOOR INVARIANT — a NEW first-party cross-package import reaches the published
tarball, on the branch that introduces it, without anyone editing the build.

Runs in the required `floor-invariants` context. Stdlib + pytest on the Python
side; it additionally needs `npm` and a Python 3 interpreter on PATH, both of
which the workflow installs and both of which the build itself needs.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT THAT EARNED THIS, AND WHY THE EXISTING FLOOR COULD NOT CATCH IT IN TIME
────────────────────────────────────────────────────────────────────────────────
`mcp_server/receipts.py` grew `from proxy.audit.writer import AuditWriter` — the
right call, because the audit rail is deliberately shared rather than duplicated.
The npm build copied `mcp_server/` and nothing else, so:

    PYTHONPATH=npm-wrapper/python python3.12 -c "import mcp_server.receipts"
    -> ModuleNotFoundError: No module named 'proxy'

i.e. `npx @arkheia/mcp-server` dead on a customer's first run, for the third time,
by the third distinct route (#19: nothing built the bundle; #23: the Docker image
COPYed too little; now: a cross-package import nobody added to the copy set).

`tests/test_packed_artifact_floor.py` compares the import closure against the
SHIPPED BYTES and would have failed on this — but only where both facts are
present at once. The branch introducing the import does not carry that floor; the
branch carrying the floor does not have the import. Both are green alone and the
merge is red. That is a UNION-SCOPED invariant (DONE.md v1.18), and this file
exists to convert it back into a branch-local one.

It does that by not waiting for a real cross-package import to appear. It
MANUFACTURES one — into a staged copy of the repo, never the repo itself — runs
the real `npm pack`, and requires the module to have shipped. So any branch, on
its own, is asked the question "can this build ship a cross-package import at
all?" — and the answer stops depending on which branch merges first.

The injected edge is `proxy.audit.writer` specifically: the exact module of the
real defect, and stdlib-only (`asyncio`, `hashlib`, `json`, `logging`, `datetime`,
`pathlib`, `typing`, plus `proxy.audit.redactor` which is `hashlib`/`re`/`typing`).
That is what lets the final assertion be a REAL subprocess import out of the
extracted tarball rather than a static resolution — the customer's failure,
reproduced verbatim, in the floor tier which has none of the server's third-party
dependencies.

────────────────────────────────────────────────────────────────────────────────
WHAT IS DERIVED
────────────────────────────────────────────────────────────────────────────────
ENTRY     — read out of the Node launcher (`floor_support.npm_bundle`), never
            written here.
BUNDLE    — the package-relative import root, likewise read out of the launcher.
REQUIRED  — the transitive first-party closure, walked with `ast` from the staged
            tree AFTER the injection, so the expectation is computed from the
            manufactured graph rather than listed.
OBSERVED  — `npm pack` over the staged package, then `tarfile`, then a real
            `python -c "import …"` against the extracted bundle.

Nothing is skipped. `npm` absent, python absent, a pack that errors — all FAIL:
an unobservable artifact has not been shown to be correct (DONE.md floor-ledger
clause 9d).

FALSE-POSITIVE-FREE: the assertion is that a module the packed entry package
imports can be imported from the packed bundle. There is no configuration of this
repo in which that is intended to be false.

SCOPE — the npm bundle only, and only the Python import graph. The Docker images
are a different set of artifacts (`proxy/Dockerfile`, `registry_server/Dockerfile`,
`mcp_server/Dockerfile`) and are not observed here; data the runtime reads but
does not import is a third axis and is not claimed. Third-party declarations
belong to `tests/test_declared_dependency_floor.py` (PR #27).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:  # floor tier runs bare pytest from the repo root
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import import_closure, npm_bundle  # noqa: E402

_ROOT = import_closure.REPO_ROOT

#: The real cross-package module of the defect this file was earned by. The
#: synthetic target below imports it, so the probe exercises the actual shared
#: audit rail rather than an empty stand-in — and, being stdlib-only, it can be
#: imported for real in the dependency-free floor tier.
_REAL_CROSS_PACKAGE_IMPORT = "proxy.audit.writer"

#: Module injected into the ENTRY package. Leading underscore and an unmistakable
#: name so that if one ever escapes its temporary directory it is obvious what
#: wrote it.
_PROBE_MODULE = "_floor_crosspackage_probe"

#: Module injected into a SIBLING first-party package, which the probe imports.
#:
#: The target is synthetic rather than an existing module ON PURPOSE, and this is
#: the difference between a differential and a false positive. Once a real
#: cross-package import lands (PR #28 does exactly that), an existing module is
#: already in the closure, so "injecting" it adds nothing and the control arm
#: already carries it — the differential silently stops discriminating, and it
#: fails while nothing is wrong. A name that cannot pre-exist is guaranteed to be
#: absent from the real closure however many real edges there are.
_TARGET_MODULE = "_floor_crosspackage_target"


# ---------------------------------------------------------------------------
# INVARIANT 1 — the build and the launcher agree on what is published
# ---------------------------------------------------------------------------

def test_the_build_entry_module_is_the_module_the_launcher_spawns():
    """
    The build derives its copy set from ONE entry module. If that literal drifts
    from the module the launcher actually spawns, the build computes a correct
    closure for the wrong program and every other check here passes while the
    published bundle is missing whatever the real entry point needs.

    Both sides are read, neither is written down: the launcher's `-m` spawn comes
    from `floor_support.npm_bundle`, the build's from `build.js` itself.
    """
    build_js = _ROOT / npm_bundle.PACKAGE_DIR / "scripts" / "build.js"
    assert build_js.exists(), f"{build_js} does not exist; there is no build to check"

    match = re.search(
        r"^const\s+ENTRY_MODULE\s*=\s*[\"']([\w.]+)[\"']\s*;",
        build_js.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert match, (
        f"{build_js.relative_to(_ROOT)}: no `const ENTRY_MODULE = \"…\";` found. "
        f"The bundle's copy set is derived from that module; if the build was "
        f"rewritten, teach this parser the new form rather than leaving the "
        f"agreement between build and launcher unchecked."
    )

    launcher_entry = npm_bundle.launcher_entry_module(_ROOT)
    assert match.group(1) == launcher_entry, (
        f"the build derives its copy set from {match.group(1)!r} but "
        f"{npm_bundle.launcher_relpath(_ROOT)} spawns `python -m {launcher_entry}`. "
        f"The bundle is being assembled for a different program than the one that "
        f"runs."
    )


# ---------------------------------------------------------------------------
# THE INJECTION DIFFERENTIAL
# ---------------------------------------------------------------------------

def _sibling_package(entry_package: str, first_party: frozenset[str]) -> str:
    """
    A first-party root that is NOT the entry package — discovered, not named.

    The probe's target goes here, so the manufactured edge crosses a package
    boundary exactly as the real defect does. Deterministic (`sorted`) so two runs
    manufacture the same graph.
    """
    siblings = sorted(first_party - {entry_package})
    if not siblings:
        pytest.fail(
            f"the repo has no first-party package other than {entry_package!r} "
            f"(found {sorted(first_party)}), so a cross-package import cannot be "
            f"manufactured and this floor cannot examine anything. If the repo "
            f"genuinely became single-package, delete this file in the same change "
            f"rather than leaving a floor that checks nothing."
        )
    return siblings[0]


class _StagedPack:
    """One staged repo copy, packed for real, extracted."""

    def __init__(
        self,
        tarball_paths: set[str],
        bundle_dir: Path,
        closure: set[Path],
        target_rel: Path,
    ):
        self.tarball_paths = tarball_paths
        self.bundle_dir = bundle_dir
        self.closure = closure
        self.target_rel = target_rel  # the synthetic sibling module, both arms


def _stage(tmp: Path, name: str, inject: bool) -> _StagedPack:
    """
    Copy the repo's packaging inputs into `tmp/name`, manufacture a cross-package
    edge (or not), run the REAL pack, extract it.

    BOTH arms write the synthetic sibling module to disk. Only the injected arm
    IMPORTS it. That is what makes the pair a differential rather than a pair of
    unrelated observations: the file is equally available to both builds, and the
    only thing that differs is whether the import graph reaches it. A build that
    copied its sibling packages wholesale would ship it in both arms and be
    caught; a build that follows the graph ships it in one.

    The repo is never mutated — everything is written into the staged copy — so a
    crash mid-test cannot leave a probe module behind in the source tree.
    """
    staged = tmp / name
    first_party = import_closure.first_party_roots(_ROOT)
    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    entry_package = entry_module.split(".")[0]
    sibling = _sibling_package(entry_package, first_party)
    bundle_root = npm_bundle.bundle_root(_ROOT)

    # Stages the package, every first-party root, and the shared import-graph
    # resolver the build invokes (a packaging input, see `stage_package_copy`).
    package_dir = npm_bundle.stage_package_copy(staged, set(first_party), _ROOT)

    # A stale generated bundle would make the pack look complete regardless of
    # what the build does — the same trap `test_packed_artifact_floor.py` avoids.
    npm_bundle.prune_generated(package_dir / bundle_root, set(first_party))

    _STAGED_ONLY = (
        "# Injected by tests/test_bundle_cross_package_import_floor.py into a\n"
        "# STAGED copy of the repo. If you are reading this inside the real source\n"
        "# tree, something escaped its temporary directory.\n"
    )

    # BOTH arms: the target exists on disk, importing the real shared audit rail,
    # so the probe exercises the actual module of the defect.
    target_rel = Path(sibling) / f"{_TARGET_MODULE}.py"
    (staged / target_rel).write_text(
        _STAGED_ONLY
        + f"from {_REAL_CROSS_PACKAGE_IMPORT} import AuditWriter  # noqa: F401\n"
        "\nMARKER = 'floor cross-package probe'\n",
        encoding="utf-8",
    )

    if inject:
        (staged / entry_package / f"{_PROBE_MODULE}.py").write_text(
            _STAGED_ONLY
            + f"from {sibling}.{_TARGET_MODULE} import MARKER  # noqa: F401\n",
            encoding="utf-8",
        )
        entry_file = staged / Path(*entry_module.split(".")).with_suffix(".py")
        assert entry_file.exists(), (
            f"the entry module {entry_module!r} has no file at "
            f"{entry_file.relative_to(staged)} in the staged tree"
        )
        with entry_file.open("a", encoding="utf-8") as handle:
            handle.write(
                f"\n\nfrom {entry_package} import {_PROBE_MODULE}  # noqa: F401,E402"
                "  # floor probe (staged copy only)\n"
            )

    tarball = npm_bundle.pack(package_dir, staged / "tgz")
    paths = npm_bundle.tarball_paths(tarball)
    package = npm_bundle.extract(tarball, staged / "extracted")

    closure = import_closure.required_files(
        (entry_module,), staged, import_closure.first_party_roots(staged)
    )
    return _StagedPack(paths, package / bundle_root, closure, target_rel)


@pytest.fixture(scope="module")
def with_edge(tmp_path_factory) -> _StagedPack:
    return _stage(tmp_path_factory.mktemp("crosspkg"), "with-edge", inject=True)


@pytest.fixture(scope="module")
def without_edge(tmp_path_factory) -> _StagedPack:
    return _stage(tmp_path_factory.mktemp("crosspkg"), "without-edge", inject=False)


def test_the_injection_actually_created_a_cross_package_requirement(
    with_edge: _StagedPack, without_edge: _StagedPack
):
    """
    WORK-DONE GUARD. Every assertion below passes by finding a module present, and
    "present" is also what a probe that was never injected, or an injection the
    closure walk never saw, would produce — because then nothing was required and
    nothing could be missing.

    So name the units: the injected arm's closure must gain exactly the
    manufactured edge over the control arm's.
    """
    added = {p.as_posix() for p in with_edge.closure} - {
        p.as_posix() for p in without_edge.closure
    }
    assert with_edge.target_rel.as_posix() in added, (
        f"injecting the probe did not add {with_edge.target_rel.as_posix()} to the "
        f"import closure. Either the injection did not land, or the resolver no "
        f"longer walks the entry module — either way this file is examining "
        f"nothing.\n"
        f"    added by the injection: {sorted(added)}"
    )
    assert with_edge.target_rel not in without_edge.closure, (
        f"the control arm's closure already requires "
        f"{with_edge.target_rel.as_posix()}, which is a name nothing in this repo "
        f"can legitimately import. The two arms are not isolated from each other."
    )


def test_a_new_cross_package_import_reaches_the_packed_tarball(
    with_edge: _StagedPack,
):
    """
    THE INVARIANT. A cross-package import that exists in the source must exist in
    the tarball, with no edit to the build script — because the branch that adds
    such an import will not think to edit it, and has not, three times running.
    """
    bundle_root = npm_bundle.bundle_root(_ROOT)
    prefix = bundle_root + "/"
    present = {
        p[len(prefix) :] for p in with_edge.tarball_paths if p.startswith(prefix)
    }
    missing = import_closure.missing_from(with_edge.closure, present)

    assert not missing, (
        f"the packed tarball is missing {len(missing)} of {len(with_edge.closure)} "
        f"first-party modules the entry point imports once a cross-package edge "
        f"exists:\n"
        + "\n".join(
            f"    MISSING  {bundle_root}/{p.as_posix()}"
            for p in sorted(missing, key=lambda q: q.as_posix())
        )
        + f"\n\nThe bundle carries: {sorted(present)}\n"
        f"This is the `npx` first-run ModuleNotFoundError, reproduced before "
        f"merge instead of after. The build must derive its copy set from the "
        f"import graph; a hand-maintained source list is what fails here, because "
        f"the branch that adds the import does not edit the list."
    )


def test_the_control_arm_does_not_ship_the_cross_package_files(
    without_edge: _StagedPack, with_edge: _StagedPack
):
    """
    THE ROW THAT PASSES BY BEING DIFFERENT (DONE.md v1.15 clause 5).

    Without the differential's other half, a build that unconditionally copied the
    whole repo would satisfy the invariant above while telling us nothing. The
    synthetic target is present ON DISK in both arms and imported in only one, so
    it isolates exactly that: a build following the graph ships it once, a build
    copying its siblings wholesale ships it twice.

    Scoped to the files the injection ADDED, not to every cross-package file: once
    a real cross-package import exists on master, the control arm legitimately
    carries its files, and asserting otherwise would be a floor crying wolf about
    a correct bundle.
    """
    bundle_root = npm_bundle.bundle_root(_ROOT)
    prefix = bundle_root + "/"
    control = {
        p[len(prefix) :] for p in without_edge.tarball_paths if p.startswith(prefix)
    }

    added = {p.as_posix() for p in with_edge.closure} - {
        p.as_posix() for p in without_edge.closure
    }
    leaked = sorted(added & control)

    assert not leaked, (
        f"the tarball built WITHOUT the injected import still contains {leaked}. "
        f"The build is not following the import graph — it is copying those files "
        f"for some other reason (a committed copy? a stale bundle the staging step "
        f"did not prune? a wildcard in `files`?). Whatever that reason is, it will "
        f"keep this floor green on the day the derivation breaks."
    )


def test_the_packed_bundle_actually_imports_the_cross_package_module(
    with_edge: _StagedPack,
):
    """
    The customer's command, verbatim, against the real extracted tarball.

    Everything above is a comparison of file sets, and a file set can be right
    while the import still fails — a file at the wrong path, a package missing its
    `__init__.py`, a truncated copy. This runs the actual reproduction:

        PYTHONPATH=<bundle> python -c "import <entry_package>.<probe>"

    `env` is replaced rather than extended so the host's PYTHONPATH cannot supply
    what the bundle failed to. `-S` and `-E` are not used: the interpreter needs
    its own stdlib, and it is only the FIRST-PARTY path that must come from the
    bundle. Nothing third-party is involved — the probe and everything it reaches
    are stdlib-only, which is why this can run in the dependency-free floor tier.
    """
    entry_package = npm_bundle.launcher_entry_module(_ROOT).split(".")[0]
    target = f"{entry_package}.{_PROBE_MODULE}"

    env = {
        "PYTHONPATH": str(with_edge.bundle_dir),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        # Windows needs SYSTEMROOT for the interpreter to start at all.
        **{k: v for k, v in os.environ.items() if k in {"SYSTEMROOT", "SystemRoot"}},
    }
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", f"import {target}"],
        cwd=str(with_edge.bundle_dir.parent),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )

    assert result.returncode == 0, (
        f"`PYTHONPATH={with_edge.bundle_dir} {Path(sys.executable).name} -c "
        f"\"import {target}\"` exited {result.returncode}. This is exactly the "
        f"failure a customer meets on `npx` — the bundle does not carry what its "
        f"own entry package imports.\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )


# ---------------------------------------------------------------------------
# PROVE THE CHECK CAN FAIL — a derived negative self-test of the import probe
# ---------------------------------------------------------------------------

def test_removing_the_cross_package_files_breaks_the_import(with_edge: _StagedPack):
    """
    The import above passes by succeeding, which is also what it would do if the
    probe module quietly stopped importing anything cross-package.

    So delete, from a COPY of the extracted bundle, exactly the cross-package
    files the closure says are required, and require the same command to fail with
    a ModuleNotFoundError naming the missing package. No path is written down: the
    files come from the closure, so this control cannot rot into a test of a module
    that no longer matters.
    """
    entry_package = npm_bundle.launcher_entry_module(_ROOT).split(".")[0]
    cross = sorted(
        p for p in with_edge.closure if p.parts[0] != entry_package
    )
    assert cross, "no cross-package files in the closure — see the work-done guard"

    wounded = with_edge.bundle_dir.parent / "wounded"
    if wounded.exists():
        shutil.rmtree(wounded)
    shutil.copytree(with_edge.bundle_dir, wounded)
    for rel in cross:
        victim = wounded / rel
        if victim.exists():
            victim.unlink()

    target = f"{entry_package}.{_PROBE_MODULE}"
    env = {
        "PYTHONPATH": str(wounded),
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        **{k: v for k, v in os.environ.items() if k in {"SYSTEMROOT", "SystemRoot"}},
    }
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", f"import {target}"],
        cwd=str(wounded.parent),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )

    assert result.returncode != 0, (
        f"with {[p.as_posix() for p in cross]} deleted from the bundle, "
        f"`import {target}` still succeeded. The probe is resolving those modules "
        f"from somewhere other than the bundle — the host's sys.path, most likely — "
        f"so the passing run above proves nothing about the artifact."
    )
    assert "ModuleNotFoundError" in result.stderr, (
        f"deleting the cross-package files made `import {target}` fail for a "
        f"reason other than the missing module:\n{result.stderr}"
    )


def test_the_resolver_cli_the_build_depends_on_is_present_and_answers():
    """
    The build derives its copy set by running the shared resolver as a script. If
    that entry point regressed — moved, renamed, stopped emitting JSON — the build
    fails loudly by design, but only when someone packs. Assert it here so the
    breakage is a floor failure rather than a release-day surprise.
    """
    tool = _ROOT / "tests" / "floor_support" / "import_closure.py"
    assert tool.exists(), f"{tool} is missing; the build cannot derive its copy set"

    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, str(tool), "--entry", entry_module],
        cwd=str(_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"the resolver CLI exited {result.returncode} for {entry_module!r}:\n"
        f"{result.stderr}"
    )
    sources = json.loads(result.stdout)
    assert isinstance(sources, list) and sources, (
        f"the resolver CLI emitted {sources!r}; the build would abort"
    )
    assert set(sources) == {
        p.as_posix()
        for p in import_closure.required_files(
            (entry_module,), _ROOT, import_closure.first_party_roots(_ROOT)
        )
    }, (
        "the resolver CLI and the in-process resolver disagree about the closure — "
        "the build and the floors would then be measuring different things"
    )
