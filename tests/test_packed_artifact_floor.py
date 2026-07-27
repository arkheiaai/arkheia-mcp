"""
FLOOR INVARIANT — the PACKED TARBALL contains every first-party module the
published entry point imports, and the packed tree can resolve them.

Runs in the required `floor-invariants` context. Python side is stdlib + pytest
only; it additionally needs `npm`, which the workflow installs. It never imports
the server (that would need `mcp`, `httpx`, …): it runs the real pack and reads
the real bytes.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT THAT EARNED THIS — and, more importantly, the defect in its FIX.
────────────────────────────────────────────────────────────────────────────────
`npm-wrapper/scripts/build.js` says "Run before `npm publish`" and copies the
right sources. `npm-wrapper/package.json` declared no `prepack` / `prepare` /
`prepublishOnly`, so at publish time nothing ran it. In a clean checkout
`npm pack` shipped SEVEN files — `python/mcp_server/__init__.py` and
`python/requirements.txt` and no server at all — so `npx @arkheia/mcp-server`
crashed into `ModuleNotFoundError: mcp_server.server` on a customer's first run.
Found by an external reviewer on two separate PRs, months after the packaging
"fix" landed.

The fix was present. Nothing connected it to the artifact.

WHY THE EXISTING PACKAGING FLOOR DID NOT CATCH IT — this is the real lesson.
The commissioned brief for that floor said "derive the requirement from the
import graph, never enumerate". It did exactly that, and it is a good floor. But
its OBSERVED side reads `PACKAGE_SOURCES` out of `npm-wrapper/scripts/build.js`:
it compares the import graph against **what the build script intends to copy**.
Intent was never the problem. The script's declared source list was correct and
complete; it simply never ran. So the floor was green while the artifact was
broken — and a check that measures nothing looks exactly like a check that
measures everything.

Hence the rule this module encodes: **for a distribution, the observed side must
be the shipped bytes.** Not the build script, not the manifest, not the COPY
directives. Those are all statements of intent, and intent is not a distribution.

────────────────────────────────────────────────────────────────────────────────
WHAT IS DERIVED, AND FROM WHERE
────────────────────────────────────────────────────────────────────────────────
REQUIRED  — the transitive first-party import closure of the entry point, walked
            from the repo source with `ast` (`floor_support.import_closure`).
            Function-level and conditional imports count: a deferred import is no
            less a packaging requirement than a top-level one.
ENTRY     — read out of the Node launcher's own `spawn(python, ["-m", …])`, and
            the launcher itself out of `package.json`'s `bin` map. Nothing about
            the entry point is written down here.
BUNDLE    — the package-relative import root, read out of the launcher's
            `path.join(__dirname, …)`. The floor follows the runtime; if the
            bundle moves, the required paths move with it.
OBSERVED  — `npm pack`, then `tarfile`. The actual archive, actual members.

Everything unresolvable FAILS: no `bin`, an unrecognised spawn form, an
unreadable bundle root, `npm` absent, a pack that errors, a tarball with an
unexpected layout. A distribution nobody could observe has not been shown to be
correct, and "not observed" must never land in the pass bucket (DONE.md
floor-ledger clause 9d). In particular this floor never `skip`s: a skipped
artifact check is indistinguishable from a passing one.

────────────────────────────────────────────────────────────────────────────────
WHY THE PACK RUNS AGAINST A CLEANED BUNDLE DIRECTORY
────────────────────────────────────────────────────────────────────────────────
The bundle directory is a build OUTPUT that partly lives in git. A developer who
once ran `node scripts/build.js` by hand has a populated bundle, and packing that
tree ships a complete artifact **whether or not the lifecycle wiring works**. The
floor would then pass, on the very machine a release is cut from, for the exact
defect it exists to catch. So the pack runs with the generated trees removed and
the directory restored afterwards — the artifact a clean checkout publishes.

────────────────────────────────────────────────────────────────────────────────
SCOPE — read before trusting a green run
────────────────────────────────────────────────────────────────────────────────
* THE NPM BUNDLE ONLY. The Docker images are a different set of artifacts and are
  NOT observed here. They are covered by `tests/test_docker_context_floor.py`,
  which materialises the tree their COPY directives produce and resolves the entry
  point in it — one step short of a real image, because there is no container
  runtime in CI. (This paragraph previously named `tests/test_mcp_packaging_floor.py`,
  which has never existed in this repo: a scope note claiming an axis was covered
  elsewhere, pointing at nothing. Corrected when the Docker axis was actually
  closed.)
* FIRST-PARTY PYTHON IMPORTS ONLY. Whether the bundle DECLARES the third-party
  packages it imports is the complementary axis and belongs to
  `tests/test_tooling_dependency.py` (which runs in `unit-tests`, not the floor
  tier — it needs the plugins installed to answer). Data the runtime reads but
  does not import (`profiles/`, model files) is a third axis and is not claimed.
* IMPORT RESOLUTION, NOT EXECUTION. The packed tree is checked with
  `importlib.machinery.PathFinder` and `compile()`: every first-party module
  resolves inside the bundle and every packed source parses. It is not executed,
  because executing it would need `mcp` and `httpx`, which the floor tier
  deliberately does not have. A module that resolves and compiles can still fail
  at runtime for reasons a packaging floor is not about.
* PACKED BY THIS NPM. The archive is produced by the `npm` on PATH. A publish
  from a materially older npm could behave differently; the `engines.node`
  floor (>=18, i.e. npm >=8) is what bounds that, and it is not checked here.

FALSE-POSITIVE-FREE: a first-party module the entry point imports and the tarball
does not contain is unambiguously a broken distribution. There is no
configuration in which that is intended.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:  # floor tier runs bare pytest from the repo root
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import import_closure, npm_bundle  # noqa: E402

_ROOT = import_closure.REPO_ROOT
_PROVENANCE = ".arkheia-bundle-provenance.json"
_PROVENANCE_SCHEMA = "arkheia.npm.bundle-provenance.v1"


# ---------------------------------------------------------------------------
# The artifact, produced once
# ---------------------------------------------------------------------------

class Artifact:
    """One real `npm pack` run, and everything read out of the archive it wrote."""

    def __init__(self, tarball: Path, paths: set[str], package: Path):
        self.tarball = tarball
        self.paths = paths          # file paths inside the tarball, prefix stripped
        self.package = package      # the extracted package/ directory
        self.entry_module = npm_bundle.launcher_entry_module(_ROOT)
        self.bundle_root = npm_bundle.bundle_root(_ROOT)
        self.first_party = import_closure.first_party_roots(_ROOT)
        self.required = import_closure.required_files(
            (self.entry_module,), _ROOT, self.first_party
        )
        self.pruned: list[str] = []

    @property
    def bundle_dir(self) -> Path:
        """The extracted import root — where the launcher points `PYTHONPATH`."""
        return self.package / self.bundle_root

    def artifact_path_for(self, repo_relative: Path) -> str:
        """Where a repo-relative module file must land inside the tarball."""
        return f"{self.bundle_root}/{repo_relative.as_posix()}"

    def bundle_paths(self) -> set[str]:
        """Tarball paths inside the bundle root, made repo-relative again."""
        prefix = self.bundle_root + "/"
        return {p[len(prefix):] for p in self.paths if p.startswith(prefix)}

    def packed_first_party_sources(self) -> list[Path]:
        """Bundle-relative `.py` files belonging to a first-party root package."""
        return sorted(
            Path(p)
            for p in self.bundle_paths()
            if p.endswith(".py") and Path(p).parts[0] in self.first_party
        )


def _pack_clean(tmp_dir: Path) -> Artifact:
    """
    Pack the REAL package directory, with generated trees removed first.

    Runs inside `tree_restored`, so the repo working tree is byte-identical
    afterwards regardless of what the build wrote or this floor deleted.
    """
    package_dir = _ROOT / npm_bundle.PACKAGE_DIR
    bundle_root = npm_bundle.bundle_root(_ROOT)
    bundle_dir = package_dir / bundle_root
    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    first_party = import_closure.first_party_roots(_ROOT)
    closure = import_closure.required_files((entry_module,), _ROOT, first_party)
    generated_roots = {p.parts[0] for p in closure}

    with npm_bundle.tree_restored(bundle_dir):
        pruned = npm_bundle.prune_generated(bundle_dir, generated_roots)
        tarball = npm_bundle.pack(package_dir, tmp_dir / "tgz")
        paths = npm_bundle.tarball_paths(tarball)
        package = npm_bundle.extract(tarball, tmp_dir / "extracted")

    artifact = Artifact(tarball=tarball, paths=paths, package=package)
    artifact.pruned = pruned
    return artifact


@pytest.fixture(scope="module")
def artifact(tmp_path_factory) -> Artifact:
    return _pack_clean(tmp_path_factory.mktemp("packed-artifact"))


# ---------------------------------------------------------------------------
# WORK-DONE GUARD — every invariant below passes by finding nothing
# ---------------------------------------------------------------------------

def test_the_pack_ran_and_the_archive_was_read(artifact: Artifact):
    """
    Name the units of work before asserting anything is missing.

    "Nothing is missing" is also what a pack that produced an empty archive, a
    closure walk that found no files, or a bundle-root mapping pointing at a
    directory nobody ships would return. Each of those is named here, so a
    vacuous run fails as a vacuous run instead of passing as a clean one.
    """
    assert artifact.paths, f"{artifact.tarball.name} listed no files"
    assert "package.json" in artifact.paths, (
        f"{artifact.tarball.name} does not even contain package.json "
        f"({len(artifact.paths)} files: {sorted(artifact.paths)[:10]})"
    )

    assert artifact.entry_module, "no entry module derived from the launcher"
    assert artifact.bundle_root, "no bundle root derived from the launcher"

    entry_paths = import_closure.module_to_paths(
        artifact.entry_module, _ROOT, artifact.first_party
    )
    assert entry_paths, (
        f"entry module {artifact.entry_module!r} resolves to no file in the repo — "
        f"the launcher and the source tree disagree about what is published"
    )
    assert len(artifact.required) > 1, (
        f"the import walk from {artifact.entry_module!r} found only "
        f"{sorted(p.as_posix() for p in artifact.required)}; a closure that "
        f"collapsed to its own entry point means the walk is not walking"
    )
    assert set(entry_paths) <= artifact.required, (
        "the closure does not contain its own entry point"
    )

    assert artifact.pruned, (
        f"no generated tree was removed before packing, so this run did not "
        f"observe what a clean checkout publishes. Expected to prune one of "
        f"{sorted({p.parts[0] for p in artifact.required})} from "
        f"{npm_bundle.PACKAGE_DIR}/{artifact.bundle_root}."
    )
    assert artifact.bundle_paths(), (
        f"nothing at all shipped under {artifact.bundle_root!r}, so either the "
        f"bundle root is wrong or the package ships no Python — either way the "
        f"comparison below would be against an empty observation"
    )


# ---------------------------------------------------------------------------
# THE INVARIANT
# ---------------------------------------------------------------------------

def test_the_packed_artifact_contains_every_first_party_import(artifact: Artifact):
    """
    The whole point: compare the import closure against the SHIPPED BYTES.

    The observed side here is `tarfile` over the archive `npm pack` wrote. Not
    `PACKAGE_SOURCES`, not `files`, not a COPY directive — those say what someone
    intended to ship, and the defect this floor was earned by was an intent that
    was entirely correct and never executed.
    """
    present = artifact.bundle_paths()
    missing = import_closure.missing_from(artifact.required, present)

    assert not missing, (
        f"{artifact.tarball.name} does not contain "
        f"{len(missing)} of {len(artifact.required)} first-party modules that "
        f"`python -m {artifact.entry_module}` imports:\n"
        + "\n".join(
            f"    MISSING  {artifact.artifact_path_for(p)}"
            for p in sorted(missing, key=lambda q: q.as_posix())
        )
        + f"\n\nThe archive carries {len(artifact.paths)} files and "
        f"{len(present)} under {artifact.bundle_root!r}: "
        f"{sorted(present)}.\n"
        f"`npx {json_name()}` would start, spawn "
        f"`python -m {artifact.entry_module}`, and die in ModuleNotFoundError on a "
        f"customer's first run. A git checkout cannot show this, because a checkout "
        f"has the whole repo on sys.path.\n"
        f"If the build script is correct, the fault is that nothing RUNS it: wire "
        f"it to a pack-time lifecycle hook "
        f"({' / '.join(npm_bundle.PACK_TIME_HOOKS)}) in "
        f"{npm_bundle.PACKAGE_DIR}/package.json. "
        f"{npm_bundle.PUBLISH_ONLY_HOOKS[0]} is NOT sufficient: it does not run on "
        f"`npm pack`, so no check could ever observe whether it works."
    )


def json_name() -> str:
    return npm_bundle.package_manifest(_ROOT).get("name", "@arkheia/mcp-server")


# ---------------------------------------------------------------------------
# THE OTHER DIRECTION — everything PRESENT must be REQUIRED
# ---------------------------------------------------------------------------
#
# The invariant above asserts required ⊆ shipped. On its own that is a check which
# can only fail in the direction somebody thought of, and a second vendor showed
# what lives in the other one: the build derived its copy set from the import graph
# and then copied it OVER `npm-wrapper/python`, which `package.json` ships whole. A
# stale `python/proxy/_stale_should_not_ship.py` survived a real `npm pack` while the
# closure contained no `proxy` file at all. A derived copy set does not make a
# derived artifact if the destination is never cleaned.
#
# So: shipped ⊆ required ∪ HAND_MAINTAINED, where the exception list is ASKED OF THE
# BUILD (`node scripts/build.js --print-hand-maintained`) rather than restated here.


def test_the_packed_bundle_ships_nothing_it_does_not_require(artifact: Artifact):
    """
    Every file under the bundle root is either derived or a named exception.

    Scoped to the bundle root on purpose. `bin/`, `scripts/`, `README.md` and
    `package.json` are hand-maintained package content, not build output, and
    requiring them to appear in an import closure would be a false positive — and a
    floor that cries wolf gets switched off. The bundle root is the one directory
    this build WRITES, so it is the one directory whose contents must be a function
    of the graph.
    """
    exceptions = npm_bundle.hand_maintained(_ROOT)
    required = {p.as_posix() for p in artifact.required}
    shipped = artifact.bundle_paths()

    assert shipped, "nothing shipped under the bundle root — see the work-done guard"

    unexplained = sorted(shipped - required - exceptions)
    assert not unexplained, (
        f"{artifact.tarball.name} ships {len(unexplained)} file(s) under "
        f"{artifact.bundle_root!r} that `python -m {artifact.entry_module}` does not "
        f"import and the build does not declare hand-maintained:\n"
        + "\n".join(f"    UNREQUIRED  {artifact.bundle_root}/{p}" for p in unexplained)
        + f"\n\nThe bundle is an accumulation, not a derivation. The build copies "
        f"into {npm_bundle.PACKAGE_DIR}/{artifact.bundle_root} and `files` ships all "
        f"of it, so anything ever generated there keeps shipping — including a "
        f"module deleted from the repo, or a whole package that is no longer "
        f"imported. Clean the generated tree in the build before copying, or, if one "
        f"of these is genuinely hand-maintained, add it to HAND_MAINTAINED in the "
        f"build script WITH the reason.\n"
        f"Derived: {sorted(required)}\nDeclared hand-maintained: {sorted(exceptions)}"
    )


def test_every_declared_exception_is_live_and_does_not_shadow_a_derivation(
    artifact: Artifact,
):
    """
    An allow-list is only as honest as its entries, so both failure modes are closed.

    A rotting entry (naming a file that no longer ships) is a hole nobody is using
    and nobody will notice growing. An entry naming a file the import closure
    already requires would exempt a real module from the check above — the
    accumulation reintroduced by policy rather than by accident.
    """
    exceptions = npm_bundle.hand_maintained(_ROOT)
    required = {p.as_posix() for p in artifact.required}
    shipped = artifact.bundle_paths()

    dead = sorted(e for e in exceptions if e not in shipped)
    assert not dead, (
        f"the build declares {dead} hand-maintained, but {artifact.tarball.name} does "
        f"not ship them under {artifact.bundle_root!r} (it ships {sorted(shipped)}). "
        f"An exception for a file that does not exist is a permanent hole in the "
        f"shipped ⊆ required assertion; delete the entry or restore the file."
    )

    shadowing = sorted(e for e in exceptions if e in required)
    assert not shadowing, (
        f"the build declares {shadowing} hand-maintained, but the import closure of "
        f"{artifact.entry_module} already requires them. An exception may not shadow "
        f"a derived source: it would both survive the clean and be excused from the "
        f"check, which is exactly the accumulation the clean removes."
    )


def test_the_packed_bundle_provenance_manifest_pins_runtime_content(
    artifact: Artifact,
):
    """
    The runtime launcher trusts package bytes, not a git checkout.

    The provenance manifest is generated by the same pack-time build that copies
    the Python tree. It pins the exact files the launcher may use before it creates
    a venv, installs dependencies, or starts the server.
    """
    manifest_path = artifact.bundle_dir / _PROVENANCE
    assert manifest_path.is_file(), (
        f"{artifact.tarball.name} does not ship {artifact.bundle_root}/{_PROVENANCE}. "
        "The launcher cannot verify the bundled server tree before runtime setup."
    )

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    package_json = json.loads(
        (artifact.package / "package.json").read_text(encoding="utf-8")
    )

    assert manifest.get("schema") == _PROVENANCE_SCHEMA
    assert manifest.get("package") == {
        "name": package_json.get("name"),
        "version": package_json.get("version"),
    }
    assert manifest.get("entry_module") == artifact.entry_module
    assert manifest.get("bundle_root") == artifact.bundle_root

    entries = manifest.get("files")
    assert isinstance(entries, list) and entries, (
        f"{artifact.bundle_root}/{_PROVENANCE} contains no pinned files"
    )
    by_path = {entry.get("path"): entry.get("sha256") for entry in entries}
    assert len(by_path) == len(entries), "duplicate paths in bundle provenance"

    required_runtime_inputs = {"requirements.txt", "mcp_server/server.py"}
    assert required_runtime_inputs <= set(by_path), (
        "bundle provenance does not pin every runtime bootstrap input: "
        f"missing {sorted(required_runtime_inputs - set(by_path))}"
    )

    pinned = set(by_path)
    shipped = artifact.bundle_paths() - {_PROVENANCE}
    assert pinned == shipped, (
        f"bundle provenance must describe the exact bundled tree. "
        f"Unpinned shipped files: {sorted(shipped - pinned)}; "
        f"missing shipped files: {sorted(pinned - shipped)}"
    )

    bad_hashes = []
    for rel, expected in sorted(by_path.items()):
        actual = hashlib.sha256((artifact.bundle_dir / rel).read_bytes()).hexdigest()
        if actual != expected:
            bad_hashes.append(f"{rel}: manifest {expected}, actual {actual}")

    assert not bad_hashes, (
        f"{artifact.bundle_root}/{_PROVENANCE} hash mismatches:\n"
        + "\n".join(f"    {line}" for line in bad_hashes)
    )


def test_stale_bundle_output_does_not_reach_the_tarball(tmp_path):
    """
    CODEX'S REPRODUCTION, EXECUTED ON EVERY CI RUN — against a real tarball.

    The assertions above run against a bundle directory the fixture PRUNED before
    packing, so they observe a clean checkout and cannot see accumulation at all. The
    defect only exists when the destination already has something in it. So this
    seeds stale output the way a previous build would have left it, and packs twice,
    changing exactly one variable — whether the build runs:

      RED   pack-time hook stripped -> the stale file MUST ship (the probe is real,
                                       the observation can see it, and nothing else
                                       in the pipeline removes it)
      GREEN hook left as it is      -> the stale file MUST be absent, and the derived
                                       closure MUST still be complete (the clean
                                       removed the debris, not the bundle)

    The red arm is what makes the green one mean something: without it, "the stale
    file is absent" is equally consistent with a probe that was never written, a
    tarball nobody read, and a path this harness spells differently from npm.

    Probe paths are derived (`stale_probe_paths`), so this cannot rot into a test of
    a package that no longer exists.
    """
    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    first_party = import_closure.first_party_roots(_ROOT)
    closure = import_closure.required_files((entry_module,), _ROOT, first_party)
    bundle_root = npm_bundle.bundle_root(_ROOT)
    generated_roots = {p.parts[0] for p in closure}

    probes = npm_bundle.stale_probe_paths(set(first_party), closure)
    assert len(probes) >= 2, (
        f"only {probes} could be derived as stale-output probes. Both shapes are "
        f"needed — one inside a required root, one under a first-party root the "
        f"closure does not require — because a clean can close one and leave the "
        f"other open. First-party roots: {sorted(first_party)}; required roots: "
        f"{sorted(generated_roots)}."
    )
    assert not (set(probes) & {p.as_posix() for p in closure}), (
        f"a probe path collides with a real required module ({probes}); the probe "
        f"would be indistinguishable from a legitimate source"
    )

    def pack_arm(name: str, strip_hooks: bool) -> set[str]:
        staged = tmp_path / name
        package_dir = npm_bundle.stage_package_copy(staged, generated_roots, _ROOT)
        bundle_dir = package_dir / bundle_root
        npm_bundle.prune_generated(bundle_dir, generated_roots)
        npm_bundle.write_stale_probes(bundle_dir, probes)

        if strip_hooks:
            manifest_path = package_dir / "package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            scripts = manifest.get("scripts") or {}
            for hook in npm_bundle.BUILD_HOOKS:
                scripts.pop(hook, None)
            manifest["scripts"] = scripts
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

        tarball = npm_bundle.pack(package_dir, staged / "tgz")
        prefix = bundle_root + "/"
        return {
            p[len(prefix):]
            for p in npm_bundle.tarball_paths(tarball)
            if p.startswith(prefix)
        }

    red = pack_arm("stale-without-build", strip_hooks=True)
    green = pack_arm("stale-with-build", strip_hooks=False)

    unseen = [p for p in probes if p not in red]
    assert not unseen, (
        f"with the build stripped out, the pack did NOT ship {unseen} — so this "
        f"harness cannot observe a stale file at all, and the green arm below would "
        f"pass for a reason nobody has established. It shipped {sorted(red)}."
    )

    survived = [p for p in probes if p in green]
    assert not survived, (
        f"stale bundle output survived a real `npm pack`: {survived} shipped inside "
        f"{bundle_root}/ even though the import closure of {entry_module} does not "
        f"contain it. The build copies into the bundle directory without clearing "
        f"it, so the published tarball is an accumulation of everything ever "
        f"generated there. Remove the generated tree before copying."
    )

    still_missing = import_closure.missing_from(closure, green)
    assert not still_missing, (
        f"the clean removed too much: {sorted(p.as_posix() for p in still_missing)} "
        f"are required by {entry_module} and did not ship. The differential needs a "
        f"passing row (DONE.md v1.15 clause 5) — a build that deletes the bundle and "
        f"copies nothing would satisfy the stale-output assertion above while "
        f"publishing an empty package."
    )


# ---------------------------------------------------------------------------
# PRESENT IS NOT THE SAME AS IMPORTABLE
# ---------------------------------------------------------------------------

def _resolve_in(module: str, bundle_dir: Path):
    """
    Resolve `module` using ONLY the extracted bundle as the search path.

    Delegates to the shared resolver: the Docker-context floor asks the identical
    question of a different tree, and two implementations of "does this module
    resolve here" would eventually disagree silently (floor_support/__init__.py).
    """
    return import_closure.resolve_in(module, bundle_dir)


def test_the_packed_tree_resolves_its_own_entry_point(artifact: Artifact):
    """Shipping the files is necessary; being importable at the right module path is the requirement."""
    spec = _resolve_in(artifact.entry_module, artifact.bundle_dir)
    assert spec is not None and spec.origin, (
        f"`import {artifact.entry_module}` does not resolve inside the packed "
        f"bundle at {artifact.bundle_root!r}. The files may have shipped at the "
        f"wrong path: the bundle contains {sorted(artifact.bundle_paths())}."
    )
    assert Path(spec.origin).is_relative_to(artifact.bundle_dir), (
        f"{artifact.entry_module} resolved to {spec.origin}, which is OUTSIDE the "
        f"packed bundle — the check leaked onto the host's sys.path"
    )


def test_every_first_party_import_inside_the_packed_tree_resolves_inside_it(
    artifact: Artifact,
):
    """
    Close the loop entirely inside the artifact.

    The invariant above derives the requirement from the REPO. This one derives it
    from the PACKED SOURCES themselves: re-walk the imports of every first-party
    file that actually shipped and require each first-party edge to resolve within
    the bundle. That catches the cross-package case the repo walk can hide — a
    packed module importing `proxy.audit.writer`, which the bundle does not carry
    and whose absence a checkout will never reveal.
    """
    sources = artifact.packed_first_party_sources()
    assert sources, (
        f"no first-party `.py` shipped under {artifact.bundle_root!r}, so this "
        f"check examined nothing"
    )

    unresolvable: list[str] = []
    for source in sources:
        text = (artifact.bundle_dir / source).read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(source))
        package = source.parent.as_posix().replace("/", ".")
        for module in _first_party_imports(tree, package, artifact.first_party):
            if _resolve_in(module, artifact.bundle_dir) is None:
                unresolvable.append(f"{source.as_posix()} imports {module}")

    assert not unresolvable, (
        f"{artifact.tarball.name} ships {len(sources)} first-party modules that "
        f"import first-party modules the archive does not carry:\n"
        + "\n".join(f"    {entry}" for entry in sorted(unresolvable))
        + "\nThe bundle is not self-sufficient: these imports resolve in a git "
        "checkout and fail from the published package."
    )


def _first_party_imports(
    tree: ast.AST, package: str, first_party: frozenset[str]
) -> set[str]:
    """
    First-party module names imported by a parsed packed source.

    A `from pkg import name` yields `pkg` only. `pkg.name` is deliberately NOT
    required here: `name` may be a function, and demanding it resolve as a module
    would be a false positive — and a floor that cries wolf gets switched off.
    The repo-side closure walk resolves that ambiguity against disk instead.
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
                absolute = ".".join([p for p in base if p] + ([node.module] if node.module else []))
            else:
                absolute = node.module or ""
            if absolute:
                found.add(absolute)
    return {m for m in found if m.split(".")[0] in first_party}


def test_every_packed_first_party_source_compiles(artifact: Artifact):
    """
    A truncated or mangled copy is present and useless.

    `compile()` on the packed bytes is cheap and rules out the class where a build
    copied a file badly — a form of "present" that a file-list comparison reports
    as covered.
    """
    sources = artifact.packed_first_party_sources()
    assert sources, "nothing to compile — see the work-done guard"

    broken: list[str] = []
    for source in sources:
        path = artifact.bundle_dir / source
        try:
            compile(path.read_text(encoding="utf-8"), str(source), "exec")
        except (SyntaxError, UnicodeDecodeError) as exc:
            broken.append(f"{source.as_posix()}: {exc}")

    assert not broken, (
        f"{artifact.tarball.name} ships first-party sources that do not compile:\n"
        + "\n".join(f"    {entry}" for entry in broken)
    )


# ---------------------------------------------------------------------------
# THE REGISTRY MANIFEST DESCRIBES THE ARTIFACT, SO CHECK IT AGAINST THE ARTIFACT
# ---------------------------------------------------------------------------

def test_the_mcp_registry_manifest_names_the_artifact_that_was_packed(
    artifact: Artifact,
):
    """
    `server.json` is what the MCP registry publishes: it tells every MCP client
    which npm package and which VERSION to install. It is a claim ABOUT the
    artifact, and until now nothing compared the two — so it drifted, and the
    thing a client installed was not the thing this repo builds.

    Found on master while sweeping for siblings: `server.json` advertised
    `@arkheia/mcp-server` at `0.1.1` while `package.json` was at `1.3.0`. A client
    following the registry entry would install a version predating everything in
    this repo, including the packaging fix — the defect this floor exists for,
    reached by a different route.

    The comparison is anchored on the TARBALL's own `package.json`, not the repo's,
    for the same reason as everything else here: the tarball is the artifact.
    """
    manifests = _registry_manifests()
    assert manifests, (
        "no MCP registry manifest found anywhere in the repo (searched for "
        "`server.json` files carrying a modelcontextprotocol `$schema`). If the "
        "registry entry was deliberately removed, remove this check in the same "
        "change rather than leaving a floor that examines nothing."
    )

    packed_manifest = json.loads(
        (artifact.package / "package.json").read_text(encoding="utf-8")
    )
    packed_name = packed_manifest.get("name")
    packed_version = packed_manifest.get("version")
    assert packed_name and packed_version, (
        f"the packed package.json has no name/version "
        f"({packed_name!r}/{packed_version!r}), so there is nothing to compare"
    )

    unmatched: list[str] = []
    drifted: list[str] = []
    for rel, registry in manifests:
        npm_entries = [
            p
            for p in registry.get("packages", [])
            if p.get("registryType") == "npm" and p.get("identifier") == packed_name
        ]
        if not npm_entries:
            listed = [p.get("identifier") for p in registry.get("packages", [])]
            unmatched.append(f"{rel}: declares {listed}, none of them {packed_name!r}")
            continue
        for entry in npm_entries:
            if entry.get("version") != packed_version:
                drifted.append(
                    f"{rel}: advertises {packed_name}@{entry.get('version')!r}"
                )

    assert not unmatched, (
        "an MCP registry manifest points clients at a package this repo does not "
        "build:\n" + "\n".join(f"    {u}" for u in unmatched)
    )
    assert not drifted, (
        f"the packed artifact is {packed_name}@{packed_version}, but:\n"
        + "\n".join(f"    {d}" for d in drifted)
        + "\nAn MCP client follows the registry entry, so this drift installs a "
        "different artifact than the one this repo's checks were run against. Bump "
        "both in the same change."
    )


def _registry_manifests() -> list[tuple[str, dict]]:
    """
    Every MCP registry manifest in the repo, discovered rather than named.

    Selected by `$schema` rather than by filename alone, so an unrelated
    `server.json` is not mistaken for a registry entry and a renamed one is not
    silently dropped from the check.
    """
    found: list[tuple[str, dict]] = []
    for path in sorted(_ROOT.rglob("server.json")):
        rel = path.relative_to(_ROOT)
        if any(part in {".git", "node_modules"} for part in rel.parts):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            pytest.fail(f"{rel} is not readable JSON ({exc}); it cannot be checked")
        if not isinstance(data, dict):
            continue
        if "modelcontextprotocol" in str(data.get("$schema", "")):
            found.append((rel.as_posix(), data))
    return found


# ---------------------------------------------------------------------------
# PROVE THE CHECK CAN FAIL (DONE.md v1.22) — two controls, one of them a real pack
# ---------------------------------------------------------------------------

def test_dropping_any_shipped_module_is_detected(artifact: Artifact):
    """
    Derived negative self-test of the comparison itself.

    The invariant passes by finding an empty set, which is also what a broken
    comparison returns. So run the SAME function against the real observation
    minus one real file, once per file, and require it to name exactly that file.
    No path is written down, so this control cannot rot into a test of a file that
    no longer matters.
    """
    present = artifact.bundle_paths()
    covered = {p for p in artifact.required if p.as_posix() in present}
    assert covered, (
        "the archive carries none of the required modules, so there is nothing to "
        "drop — see the invariant above, which is already failing"
    )

    for path in sorted(covered, key=lambda p: p.as_posix()):
        without = present - {path.as_posix()}
        missing = import_closure.missing_from(artifact.required, without)
        assert path in missing, (
            f"removing {path.as_posix()} from the observed file set left it "
            f"reported as shipped — the comparison cannot see a missing module"
        )


def test_an_empty_archive_is_detected(artifact: Artifact):
    """An archive containing nothing must not read as complete."""
    missing = import_closure.missing_from(artifact.required, set())
    assert missing == artifact.required, (
        "against an empty observation the comparison reported "
        f"{len(missing)} of {len(artifact.required)} modules missing"
    )


def test_the_pack_time_hook_is_what_puts_the_python_tree_in_the_tarball(
    tmp_path,
):
    """
    THE RED RUN, executed on every CI run, against a real tarball.

    Everything above would pass if the Python tree got into the bundle by some
    other means — a stale directory, a file committed by hand — and then the floor
    would be green while the publish path was still unwired. So this runs the pack
    TWICE over a staged copy of the package, changing exactly one variable: whether
    the pack-time lifecycle hook is declared.

      RED   hooks stripped from package.json  -> the closure must be MISSING
      GREEN hooks left as they are            -> the closure must be COMPLETE

    A differential needs a row that passes as well as a row that fails (DONE.md
    v1.15 clause 5), which is why the green arm is here and not assumed from the
    tests above. The staged copy exists so the repo's own manifest is never
    mutated: a crash mid-test must not leave a broken package.json behind.
    """
    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    first_party = import_closure.first_party_roots(_ROOT)
    closure = import_closure.required_files((entry_module,), _ROOT, first_party)
    bundle_root = npm_bundle.bundle_root(_ROOT)
    generated_roots = {p.parts[0] for p in closure}

    declared = npm_bundle.declared_build_hooks(_ROOT)
    pack_time = [h for h in declared if h in npm_bundle.PACK_TIME_HOOKS]
    assert pack_time, (
        f"{npm_bundle.PACKAGE_DIR}/package.json declares no pack-time lifecycle "
        f"hook (looked for {list(npm_bundle.PACK_TIME_HOOKS)}; found "
        f"{sorted(declared) or 'none'}). Nothing builds the bundle when a tarball "
        f"is assembled, so the invariant above is failing for the original reason: "
        f"the build script is never invoked."
    )

    def pack_arm(name: str, strip_hooks: bool) -> set[Path]:
        staged = tmp_path / name
        package_dir = npm_bundle.stage_package_copy(staged, generated_roots, _ROOT)
        npm_bundle.prune_generated(package_dir / bundle_root, generated_roots)

        if strip_hooks:
            manifest_path = package_dir / "package.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            scripts = manifest.get("scripts") or {}
            for hook in npm_bundle.BUILD_HOOKS:
                scripts.pop(hook, None)
            manifest["scripts"] = scripts
            manifest_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )

        tarball = npm_bundle.pack(package_dir, staged / "tgz")
        paths = npm_bundle.tarball_paths(tarball)
        prefix = bundle_root + "/"
        present = {p[len(prefix):] for p in paths if p.startswith(prefix)}
        return import_closure.missing_from(closure, present)

    red = pack_arm("without-hook", strip_hooks=True)
    green = pack_arm("with-hook", strip_hooks=False)

    assert red == closure, (
        f"with {list(npm_bundle.BUILD_HOOKS)} stripped, the pack still shipped "
        f"{sorted((closure - red))} — so the hook is NOT what puts the Python tree "
        f"in the tarball, and the invariant above is passing for a reason nobody "
        f"has established. Something else is carrying those files (a committed "
        f"copy? a stale directory the staging step did not prune?), and it will "
        f"keep the floor green when the wiring breaks."
    )
    assert not green, (
        f"with the real manifest, the pack is still missing "
        f"{sorted(p.as_posix() for p in green)}. The differential has no passing "
        f"row, so it forbids rather than discriminates — and the same harness "
        f"cannot then be trusted when it reports a failure."
    )
