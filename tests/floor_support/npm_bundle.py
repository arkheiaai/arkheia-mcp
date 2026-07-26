"""
The npm bundle as an ARTIFACT: run the real pack, read the real bytes.

`npx @arkheia/mcp-server` is the PRIMARY distribution of this repo. What it ships
is decided by npm at pack time — by `files`, by `.npmignore`, by `.gitignore`
fallback, and by whichever lifecycle hooks npm chooses to run — and none of those
decisions is visible by reading the build script. So this module does not read the
build script. It runs `npm pack` and opens the tarball.

Stdlib only. See `floor_support/__init__.py`.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from . import import_closure

REPO_ROOT = import_closure.REPO_ROOT

#: The npm package directory in this repo.
PACKAGE_DIR = Path("npm-wrapper")

#: Every member of an npm tarball lives under this single top-level directory.
TARBALL_PREFIX = "package"

#: Lifecycle hooks that npm runs BEFORE assembling a tarball, i.e. on both
#: `npm pack` and `npm publish`. A build wired to one of these is observable by
#: running `npm pack`, which is what makes it checkable.
PACK_TIME_HOOKS = ("prepack", "prepare")

#: Lifecycle hooks that run ONLY on `npm publish`. A build wired to one of these
#: cannot be observed without publishing, so no check can confirm it works — the
#: unverifiable-hook trap. Listed so the floor can name it, not to endorse it.
PUBLISH_ONLY_HOOKS = ("prepublishOnly",)

BUILD_HOOKS = PACK_TIME_HOOKS + PUBLISH_ONLY_HOOKS


class ArtifactUnobservable(AssertionError):
    """
    The artifact could not be produced or read.

    Deliberately an AssertionError subclass: an unobservable artifact FAILS. It is
    never skipped and never swallowed, because "not observed" must not land in the
    pass bucket (DONE.md floor-ledger clause 9d).
    """


# ---------------------------------------------------------------------------
# The package manifest and its launcher
# ---------------------------------------------------------------------------

def package_manifest(root: Path = REPO_ROOT) -> dict:
    path = root / PACKAGE_DIR / "package.json"
    if not path.exists():
        raise ArtifactUnobservable(f"{path} does not exist; there is no package to pack")
    return json.loads(path.read_text(encoding="utf-8"))


def launcher_relpath(root: Path = REPO_ROOT) -> Path:
    """
    The Node launcher, taken from the manifest's `bin` map rather than hard-coded.

    Hard-coding `bin/arkheia-mcp.js` is the enumeration defect one level up: the
    day the launcher moves, a floor that names it either errors confusingly or —
    worse, if it were tolerant — checks a file nobody runs.
    """
    manifest = package_manifest(root)
    bin_field = manifest.get("bin")
    if isinstance(bin_field, str):
        targets = [bin_field]
    elif isinstance(bin_field, dict):
        targets = sorted(set(bin_field.values()))
    else:
        raise ArtifactUnobservable(
            f"npm-wrapper/package.json has no usable `bin` field ({bin_field!r}), so "
            f"the launcher — and therefore the entry point of the published "
            f"distribution — cannot be derived. Teach this parser rather than "
            f"leaving the distribution unchecked."
        )
    if len(targets) != 1:
        raise ArtifactUnobservable(
            f"`bin` declares {len(targets)} distinct launchers ({targets}); this "
            f"parser assumes one. Teach it to analyse each."
        )
    return PACKAGE_DIR / targets[0].lstrip("./")


def launcher_entry_module(root: Path = REPO_ROOT) -> str:
    """The module the launcher spawns: `spawn(python, ["-m", "<module>"], …)`."""
    rel = launcher_relpath(root)
    text = (root / rel).read_text(encoding="utf-8")
    match = re.search(r"\[\s*[\"']-m[\"']\s*,\s*[\"']([\w.]+)[\"']\s*\]", text)
    if not match:
        raise ArtifactUnobservable(
            f"{rel}: no `[\"-m\", \"<module>\"]` spawn found. This is the PRIMARY "
            f"distribution's entry point; if the launcher was rewritten, teach this "
            f"parser the new form rather than letting the floor silently check "
            f"nothing."
        )
    return match.group(1)


def bundle_root(root: Path = REPO_ROOT) -> str:
    """
    The package-relative directory the launcher puts on `PYTHONPATH`, e.g. `python`.

    Derived from the launcher's own `path.join(__dirname, …)` expression, because
    this is the mapping between a repo-relative module path and a path inside the
    tarball. Getting it from the launcher means the floor follows the runtime: if
    the bundle moves, the required paths move with it.

    Bounded structural check, and it is bounded on purpose — this reads the
    launcher to learn WHERE the runtime looks. What actually SHIPPED is read from
    the tarball, never from here.
    """
    rel = launcher_relpath(root)
    text = (root / rel).read_text(encoding="utf-8")

    match = re.search(
        r"BUNDLED_PYTHON_DIR\s*=\s*path\.join\(\s*__dirname\s*,([^)]*)\)", text
    )
    if not match:
        raise ArtifactUnobservable(
            f"{rel}: could not find `BUNDLED_PYTHON_DIR = path.join(__dirname, …)`. "
            f"The bundle root is where the launcher points `PYTHONPATH`; without it "
            f"the floor cannot map a repo module path to a path inside the tarball. "
            f"Teach this parser the new form."
        )

    segments = re.findall(r"[\"']([^\"']*)[\"']", match.group(1))
    if not segments:
        raise ArtifactUnobservable(
            f"{rel}: `BUNDLED_PYTHON_DIR` join has no literal path segments "
            f"({match.group(1)!r}); it may be computed at runtime, which this parser "
            f"cannot follow."
        )

    if "PYTHONPATH" not in text or "BUNDLED_PYTHON_DIR" not in text:
        raise ArtifactUnobservable(
            f"{rel}: the launcher no longer references both `PYTHONPATH` and "
            f"`BUNDLED_PYTHON_DIR`, so the bundle may no longer be the import root."
        )

    # `path.join(__dirname, "..", "python")` is relative to the launcher's own
    # directory inside the package.
    resolved = Path(rel.relative_to(PACKAGE_DIR)).parent
    for segment in segments:
        for part in Path(segment).parts:
            resolved = resolved.parent if part == ".." else resolved / part
    posix = resolved.as_posix()
    if posix in {"", ".", "/"} or posix.startswith(".."):
        raise ArtifactUnobservable(
            f"{rel}: bundle root resolved to {posix!r}, which is not a directory "
            f"inside the package."
        )
    return posix


def declared_build_hooks(root: Path = REPO_ROOT) -> dict[str, str]:
    """Which lifecycle hooks the manifest declares. Used to BUILD the red arm."""
    scripts = package_manifest(root).get("scripts") or {}
    return {k: v for k, v in scripts.items() if k in BUILD_HOOKS}


# ---------------------------------------------------------------------------
# Running the real pack
# ---------------------------------------------------------------------------

def require_npm() -> str:
    npm = shutil.which("npm")
    if not npm:
        raise ArtifactUnobservable(
            "`npm` is not on PATH, so the published artifact cannot be produced and "
            "this floor cannot observe anything. It FAILS rather than skips: a "
            "skipped artifact check is indistinguishable from a passing one, and "
            "this floor exists because a packaging defect shipped while every other "
            "check was green. CI installs Node in "
            "`.github/workflows/floor-invariants.yml`."
        )
    return npm


def _npm_env() -> dict[str, str]:
    env = dict(os.environ)
    # Keep the pack hermetic and quiet: no registry chatter, no update notifier.
    env.update(
        {
            "npm_config_audit": "false",
            "npm_config_fund": "false",
            "npm_config_update_notifier": "false",
            "npm_config_progress": "false",
            "NO_COLOR": "1",
        }
    )
    return env


def pack(package_dir: Path, destination: Path) -> Path:
    """
    Run the REAL `npm pack` for `package_dir` and return the tarball it wrote.

    Lifecycle hooks run — that is the point. `npm pack` executes `prepack` and
    `prepare` exactly as `npm publish` does, so the tarball this produces is the
    tarball a customer would download.
    """
    npm = require_npm()
    destination.mkdir(parents=True, exist_ok=True)
    before = set(destination.glob("*.tgz"))

    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [npm, "pack", "--pack-destination", str(destination)],
        cwd=str(package_dir),
        capture_output=True,
        text=True,
        timeout=600,
        env=_npm_env(),
    )
    if result.returncode != 0:
        raise ArtifactUnobservable(
            f"`npm pack` failed in {package_dir} (exit {result.returncode}).\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )

    produced = sorted(set(destination.glob("*.tgz")) - before)
    if len(produced) != 1:
        raise ArtifactUnobservable(
            f"`npm pack` in {package_dir} produced {len(produced)} tarballs "
            f"({[p.name for p in produced]}); expected exactly one.\n"
            f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
        )
    return produced[0]


def tarball_paths(tarball: Path) -> set[str]:
    """
    Every file path inside the tarball, package-prefix stripped.

    Directory members are dropped: a directory entry proves nothing shipped in it.
    """
    with tarfile.open(tarball, "r:gz") as archive:
        members = archive.getmembers()

    if not members:
        raise ArtifactUnobservable(f"{tarball.name} contains no members at all")

    paths: set[str] = set()
    for member in members:
        if not member.isfile():
            continue
        name = member.name.lstrip("./")
        prefix = TARBALL_PREFIX + "/"
        if not name.startswith(prefix):
            raise ArtifactUnobservable(
                f"{tarball.name}: member {member.name!r} is not under "
                f"{prefix!r}. npm tarballs always are; this parser can no longer "
                f"map artifact paths and must be taught the new layout rather than "
                f"reporting a pass."
            )
        paths.add(name[len(prefix) :])

    if not paths:
        raise ArtifactUnobservable(f"{tarball.name} contains no FILE members")
    return paths


def extract(tarball: Path, destination: Path) -> Path:
    """Extract the tarball and return the extracted package directory."""
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball, "r:gz") as archive:
        try:
            archive.extractall(destination, filter="data")
        except TypeError:  # pragma: no cover - Python < 3.12
            archive.extractall(destination)
    package = destination / TARBALL_PREFIX
    if not package.is_dir():
        raise ArtifactUnobservable(
            f"{tarball.name}: no {TARBALL_PREFIX}/ directory after extraction"
        )
    return package


# ---------------------------------------------------------------------------
# Side-effect containment
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def tree_restored(path: Path):
    """
    Restore `path` byte-for-byte on exit, whatever happened to it in between.

    Two reasons this exists, and both are load-bearing:

    * Packing RUNS THE BUILD, and the build writes generated Python into the
      bundle directory. Correct for a publish; unwanted debris in a developer's
      working tree, where untracked generated files are one careless `git add`
      from being committed.
    * The floor must observe the artifact a CLEAN CHECKOUT produces, so it first
      DELETES any pre-existing generated tree. Without that, a developer who once
      ran the build by hand would have a bundle directory that makes the pack look
      complete while the lifecycle wiring is broken — the floor would report a pass
      for the exact defect it exists to catch, on the exact machine the release is
      cut from.

    A snapshot-and-remove-additions scheme cannot do the second one, so this saves
    and restores the whole directory. It is a handful of small files.
    """
    backup_parent = Path(tempfile.mkdtemp(prefix="floor-bundle-backup-"))
    backup = backup_parent / "tree"
    existed = path.exists()
    if existed:
        shutil.copytree(path, backup, symlinks=True)
    try:
        yield
    finally:
        if path.exists():
            shutil.rmtree(path)
        if existed:
            shutil.copytree(backup, path, symlinks=True)
        shutil.rmtree(backup_parent, ignore_errors=True)


def prune_generated(bundle_dir: Path, source_roots: set[str]) -> list[str]:
    """
    Remove the first-party trees a build would generate inside `bundle_dir`.

    Returns what was removed, so a caller can report the units of work rather than
    an unexplained silence. Only ever called inside `tree_restored`.
    """
    removed: list[str] = []
    for name in sorted(source_roots):
        target = bundle_dir / name
        if target.exists():
            shutil.rmtree(target)
            removed.append(name)
    return removed


def stage_package_copy(
    destination: Path,
    source_roots: set[str],
    root: Path = REPO_ROOT,
) -> Path:
    """
    Copy the package plus the first-party source trees it draws from into
    `destination`, preserving their relative layout.

    Used to run a REAL pack against a deliberately modified manifest without
    touching the repo. The relative layout matters: the build script resolves its
    sources relative to its own location, so the copy must keep `npm-wrapper/` a
    sibling of the packages it copies from.
    """
    ignore = shutil.ignore_patterns("node_modules", "__pycache__", "*.pyc", "*.tgz")
    shutil.copytree(root / PACKAGE_DIR, destination / PACKAGE_DIR, ignore=ignore)
    for name in sorted(source_roots):
        shutil.copytree(root / name, destination / name, ignore=ignore)
    return destination / PACKAGE_DIR
