"""
FLOOR INVARIANT — every container image copies in everything its entry point
imports, and the tree it produces can resolve it.

Runs in the required `floor-invariants` context. Stdlib + pytest only; no Docker
daemon, no network, no build.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT THAT EARNED THIS
────────────────────────────────────────────────────────────────────────────────
`mcp_server/Dockerfile` copies `mcp_server/` and nothing else. That is a DECLARED
copy set — a claim about the import graph — and this repo has now suffered the
declared-copy-set-diverging-from-the-graph failure three times on the npm axis
(#19, #23, #28). The npm axis was cured by deriving the set from the graph and
cleaning the destination. The Docker axis was left as a reviewer decision on two
successive rounds: named as a residual, not closed.

It is the same defect with the same blast radius. A single new
`from proxy.audit.writer import …` in `mcp_server/` ships fine from a git checkout
(the whole repo is on `sys.path`), passes every unit test, reaches the npm tarball
automatically now that the bundle is derived — and produces a container that dies
in ModuleNotFoundError the moment it starts. Nothing in CI would have said so.

It is also the union-scoped shape DONE.md v1.18 describes: the branch that adds the
import does not touch the Dockerfile, and the branch that edits the Dockerfile does
not have the import. Each is correct alone.

────────────────────────────────────────────────────────────────────────────────
WHY THIS DOES NOT HARD-CODE A `COPY proxy/` LINE
────────────────────────────────────────────────────────────────────────────────
Adding a COPY for today's closure is the enumeration cure that has already failed
three times, and it would be worse here than it looks: as of this commit the
closure of `mcp_server.server` is seven files, ALL of them under `mcp_server/`, so
there is no missing COPY to add. The Dockerfiles are correct today and structurally
unguarded — which is precisely the state a floor is for. Hard-coding a COPY of a
package nothing imports would ship dead weight AND leave the next cross-package
import unguarded.

So the fix is the check: the requirement is derived from the import graph, the
observation is the tree the COPY directives actually produce, and a Dockerfile that
falls behind the graph fails the build. There is no version of this that a future
build unit has to remember.

────────────────────────────────────────────────────────────────────────────────
WHAT IS DERIVED, AND FROM WHERE
────────────────────────────────────────────────────────────────────────────────
IMAGES    — every `Dockerfile*` in the repo, discovered by walking it.
ENTRY     — the module in the image's own CMD/ENTRYPOINT (`python -m pkg.mod`, or an
            ASGI `pkg.mod:attr`). Not written down here.
REQUIRED  — the transitive first-party import closure of that module, walked with
            `ast` from the repo source (`floor_support.import_closure`).
OBSERVED  — the file tree the image's COPY directives produce against the real build
            context, materialised on disk and resolved with `importlib`.

Everything unresolvable FAILS rather than skips: an unparseable CMD that clearly
launches Python, a multi-stage `COPY --from=`, a wildcard source, a COPY of a path
that is not in the context, a `.dockerignore` appearing. An image nobody could
observe has not been shown to be correct.

────────────────────────────────────────────────────────────────────────────────
SCOPE — read before trusting a green run
────────────────────────────────────────────────────────────────────────────────
* NOT THE BUILT IMAGE. No `docker build` runs. This is a materialised context, one
  step short of the artifact, and it is named as such: the npm floor gets the real
  bytes because `npm pack` is free; a container runtime in the floor tier is not.
* REQUIRED ⊆ COPIED ONLY, deliberately. The npm bundle also asserts the reverse
  (shipped ⊆ required), because that bundle is a build OUTPUT DIRECTORY that
  accumulates across runs. An image layer does not: each build starts from the
  context, so there is no stale-output class to close here, and `COPY proxy/` ships
  a whole package on purpose. Asserting shipped ⊆ required on an image would be a
  false positive, and a floor that cries wolf gets switched off.
* FIRST-PARTY PYTHON IMPORTS ONLY. Third-party declarations are
  `tests/test_tooling_dependency.py`. Data the runtime reads but does not import
  (`profiles/`) is a third axis and is not claimed.
* RUNTIME SOURCES ONLY for the self-sufficiency walk. `COPY proxy/ /app/proxy/`
  ships `proxy/tests/` into the production image, and those test modules import
  `mcp_server.proxy_client`, which the proxy image does not contain. Nothing on the
  runtime import path reaches them, so failing the image for it would be crying
  wolf — the assertion is scoped to non-test sources (the same exclusion
  `npm-wrapper/scripts/build.js` applies via `SKIP_NAMES`). That the images ship
  their own test suites is a REAL and separate finding about image surface, first
  surfaced by this floor on its first run; it is reported, not normalised away, and
  it is not closed here because no Docker build can be run to verify a change to
  these images (no daemon locally, none in CI).

FALSE-POSITIVE-FREE: a module the image's own entry point imports, which the image
does not contain, is unambiguously a container that crashes on start.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:  # floor tier runs bare pytest from the repo root
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import docker_context, import_closure  # noqa: E402

_ROOT = import_closure.REPO_ROOT


@pytest.fixture(scope="module")
def images() -> list[docker_context.Image]:
    return [docker_context.parse(rel, _ROOT) for rel in docker_context.dockerfiles(_ROOT)]


def _in_scope(images: list[docker_context.Image]) -> list[docker_context.Image]:
    return [i for i in images if i.entry_module]


# ---------------------------------------------------------------------------
# WORK-DONE GUARD — this floor passes by finding nothing
# ---------------------------------------------------------------------------

def test_the_images_were_found_and_their_entry_points_derived(images):
    """
    Name the units of work before asserting nothing is missing.

    "No image is missing a module" is also what zero images, an entry point nobody
    could derive, and a Dockerfile with no COPY would produce. Each is named here so
    a vacuous run fails as one (DONE.md floor-ledger clause 9).
    """
    assert images, (
        f"no Dockerfile found anywhere under {_ROOT}. This floor would then pass by "
        f"examining nothing. If the images were deliberately removed, remove this "
        f"floor in the same change."
    )

    scoped = _in_scope(images)
    assert scoped, (
        "no image starts a first-party Python module, so this floor examined "
        "nothing. Entry commands seen: "
        + "; ".join(f"{i.dockerfile}: {i.entry_text or '(none)'}" for i in images)
    )

    for image in scoped:
        assert image.copies, (
            f"{image.dockerfile} starts {image.entry_module} but declares no COPY, "
            f"so the image contains no application code at all"
        )
        closure = import_closure.required_files((image.entry_module,), _ROOT)
        assert len(closure) > 1, (
            f"the import walk from {image.entry_module!r} ({image.dockerfile}) found "
            f"only {sorted(p.as_posix() for p in closure)}; a closure that collapsed "
            f"to its own entry point means the walk is not walking"
        )


# ---------------------------------------------------------------------------
# THE INVARIANT
# ---------------------------------------------------------------------------

def test_every_image_contains_the_closure_of_the_module_it_starts(images, tmp_path):
    """
    Compare the import graph against the tree the COPY directives actually produce.

    Resolution, not path arithmetic: a Dockerfile can copy every required file and
    still put it where the interpreter will not look (`COPY proxy/ /app/` flattens
    the package away). `importlib` answers the question the container will ask.
    """
    findings: list[str] = []

    for image in _in_scope(images):
        workdir = docker_context.materialise(
            image, tmp_path / image.dockerfile.parent.name, _ROOT
        )
        closure = import_closure.required_files((image.entry_module,), _ROOT)

        if import_closure.resolve_in(image.entry_module, workdir) is None:
            findings.append(
                f"{image.dockerfile}: `{image.entry_text}` starts "
                f"{image.entry_module}, which does not resolve in the image at "
                f"{image.workdir}"
            )
        for path in sorted(closure, key=lambda p: p.as_posix()):
            module = import_closure.module_name_for(path)
            if import_closure.resolve_in(module, workdir) is None:
                findings.append(
                    f"{image.dockerfile}: {image.entry_module} imports {module} "
                    f"({path.as_posix()}), which the image does not contain"
                )

    assert not findings, (
        "container images are missing first-party modules their own entry points "
        "import:\n"
        + "\n".join(f"    {f}" for f in findings)
        + "\n\nThe COPY set is a DECLARATION about the import graph, and it has "
        "fallen behind it. The container will start and die in ModuleNotFoundError; "
        "a git checkout cannot show this, because a checkout has the whole repo on "
        "sys.path. Add the missing package to the image's COPY set — and note that "
        "the branch adding the import and the branch owning the Dockerfile are "
        "usually different branches, so this can only fail on the merge."
    )


def test_every_first_party_import_inside_an_image_resolves_inside_it(images, tmp_path):
    """
    Close the loop inside the artifact, as the packed-artifact floor does.

    The invariant above derives the requirement from the REPO. This derives it from
    the files that actually landed in the image: re-walk their imports and require
    every first-party edge to resolve in the image. That catches a package copied in
    whole whose own cross-package import was never copied — `COPY proxy/` brings
    `proxy.detection`, which may import something else entirely.
    """
    first_party = import_closure.first_party_roots(_ROOT)
    findings: list[str] = []

    for image in _in_scope(images):
        workdir = docker_context.materialise(
            image, tmp_path / image.dockerfile.parent.name, _ROOT
        )
        sources = docker_context.materialised_sources(workdir, runtime_only=True)
        assert sources, f"{image.dockerfile}: the image contains no runtime Python"

        for source in sources:
            tree = ast.parse(
                (workdir / source).read_text(encoding="utf-8"), filename=str(source)
            )
            package = source.parent.as_posix().replace("/", ".")
            for module in _first_party_imports(tree, package, first_party):
                if import_closure.resolve_in(module, workdir) is None:
                    findings.append(
                        f"{image.dockerfile}: {source.as_posix()} imports {module}, "
                        f"which the image does not contain"
                    )

    assert not findings, (
        "images ship first-party modules that import first-party modules the image "
        "does not carry:\n" + "\n".join(f"    {f}" for f in sorted(set(findings)))
    )


def _first_party_imports(tree: ast.AST, package: str, first_party) -> set[str]:
    """
    First-party modules imported by a materialised source.

    `from pkg import name` yields `pkg` only: `name` may be a function, and
    demanding it resolve as a module would be a false positive. Same rule, and same
    reason, as the packed-artifact floor.
    """
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: max(len(base) - node.level + 1, 0)]
                absolute = ".".join(
                    [p for p in base if p] + ([node.module] if node.module else [])
                )
            else:
                absolute = node.module or ""
            if absolute:
                found.add(absolute)
    return {m for m in found if m.split(".")[0] in first_party}


# ---------------------------------------------------------------------------
# PROVE THE CHECK CAN FAIL (DONE.md v1.22)
# ---------------------------------------------------------------------------

def test_dropping_a_copy_directive_is_detected(images, tmp_path):
    """
    Adverse control: rebuild each image with one COPY removed, and require the
    invariant to notice.

    Derived, not written down — every COPY in every in-scope image is dropped in
    turn. At least one drop per image must break resolution of the closure, which
    also proves the materialiser is really the thing being measured: if removing the
    directive that carries the entry package changed nothing, the tree under test was
    coming from somewhere else.

    A COPY whose removal changes nothing (`profiles/`, `requirements.txt`) is not a
    failure of this control — it carries no Python — so the assertion is per image,
    not per directive.
    """
    scoped = _in_scope(images)
    assert scoped, "no in-scope image — see the work-done guard"

    for image in scoped:
        closure = import_closure.required_files((image.entry_module,), _ROOT)
        detected: list[str] = []

        for index, copy in enumerate(image.copies):
            workdir = docker_context.materialise(
                image,
                tmp_path / f"{image.dockerfile.parent.name}-without-{index}",
                _ROOT,
                skip=copy,
            )
            missing = [
                import_closure.module_name_for(p)
                for p in closure
                if import_closure.resolve_in(
                    import_closure.module_name_for(p), workdir
                )
                is None
            ]
            if missing:
                detected.append(f"{copy.text} -> {len(missing)} module(s) unresolvable")

        assert detected, (
            f"{image.dockerfile}: removing ANY of its "
            f"{len(image.copies)} COPY directives "
            f"({[c.text for c in image.copies]}) left every module of "
            f"{image.entry_module}'s closure still resolvable. The check is not "
            f"observing this image's copy set — it is reading a tree that is there "
            f"for some other reason, and it would stay green if the Dockerfile "
            f"stopped copying the application in."
        )


def test_a_cross_package_import_that_is_not_copied_is_detected(images, tmp_path):
    """
    The defect in its exact shape: inject the edge, require the floor to fail.

    A new `mcp_server -> proxy.audit.writer` import is the case this floor exists
    for, and today no such edge exists — so the invariant above passes, and passing
    is indistinguishable from a comparison that cannot see the case. This synthesises
    it: materialise the image, add the import to a module that shipped, and require
    the self-sufficiency check to report the uncopied package.

    The injected target is DERIVED — a first-party root the image does not copy — so
    this control cannot rot into a test of a package that no longer exists.
    """
    first_party = import_closure.first_party_roots(_ROOT)
    scoped = _in_scope(images)
    assert scoped, "no in-scope image — see the work-done guard"

    exercised = 0
    for image in scoped:
        workdir = docker_context.materialise(
            image, tmp_path / f"inject-{image.dockerfile.parent.name}", _ROOT
        )
        present_roots = {p.parts[0] for p in docker_context.materialised_sources(workdir)}
        absent = sorted(first_party - present_roots)
        if not absent:
            continue  # this image copies every first-party package; nothing to inject

        victim = workdir / f"{image.entry_module.split('.')[0]}/__init__.py"
        if not victim.exists():
            continue
        victim.write_text(
            victim.read_text(encoding="utf-8") + f"\nimport {absent[0]}\n",
            encoding="utf-8",
        )

        tree = ast.parse(victim.read_text(encoding="utf-8"))
        found = _first_party_imports(tree, image.entry_module.split(".")[0], first_party)
        assert absent[0] in found, (
            f"the injected `import {absent[0]}` was not even seen by the import "
            f"reader, so this control proves nothing about {image.dockerfile}"
        )
        assert import_closure.resolve_in(absent[0], workdir) is None, (
            f"{image.dockerfile}: an import of {absent[0]!r} resolved inside an image "
            f"that copies no {absent[0]!r} — the resolution check is leaking onto the "
            f"host's sys.path, and would report a missing package as present"
        )
        exercised += 1

    assert exercised, (
        "no image could be given an uncopied cross-package import, so this control "
        "examined nothing. That happens only if every image already copies every "
        "first-party package; if that is now true, this control is obsolete and "
        "should be removed rather than left green."
    )
