"""
FLOOR INVARIANT — every distribution ships everything its entry point imports.

Runs in the required `floor-invariants` context: bare `pytest`, no project
dependencies. It never imports the servers (that would need `mcp`, `httpx`, …);
it derives the answer by parsing source, so it is affordable in that tier.

THE DEFECT CLASS THIS ENCODES — observed, not hypothesised.
`registry_server` added `from proxy.audit.writer import AuditWriter` while its
Dockerfile copied only `registry_server/` and `profiles/`. Every test on the
developer's machine passed, because a git checkout has the whole repo on
`sys.path`; the IMAGE would have booted straight into ModuleNotFoundError. The
same shape then reached `mcp_server`, which has TWO distribution boundaries — its
Dockerfile and `npm-wrapper/scripts/build.js`, the latter being the PRIMARY
distribution (`npx @arkheia/mcp-server` runs from the bundle with
`PYTHONPATH=<bundle>`, so a missing package is a crash on a customer's very first
run). The distribution boundary is invisible from inside the checkout, which is
what makes this failure mode so easy to ship.

WHY IT IS DERIVED RATHER THAN LISTED, TWICE OVER.
A test asserting "the Dockerfile contains `COPY proxy/audit/`" would pass forever
while a THIRD cross-package import went unshipped — the same defect class wearing
a test's clothes. So nothing here is enumerated by hand:

  * the DISTRIBUTIONS are discovered (every `Dockerfile*` in the tree, plus the
    npm bundle), so a new service's Dockerfile is covered the day it lands;
  * each distribution's ENTRY POINT is read out of its own `CMD`/`ENTRYPOINT`
    (or, for the bundle, out of the `python -m …` the Node wrapper spawns) —
    the previous version of this floor hard-coded `mcp_server/server.py`, which
    was the enumeration defect one level up;
  * each distribution's COPY SET is parsed from its own directives;
  * the REQUIRED SET is the transitive first-party import closure of the entry
    point.

An unresolvable entry point, an unparsable copy set, or an unrecognised COPY form
FAILS. None of them is skipped: a distribution nobody could analyse has not been
shown to be correct, and "not observed" must never land in the pass bucket.

UNION-SCOPED (DONE.md v1.18). The violation this catches is frequently created by
a MERGE: branch A adds `mcp_server.receipts -> proxy.audit.writer`, branch B
changes packaging, and each branch passes alone. Run it on the merge result.

SCOPE. First-party Python imports only. Data the runtime needs but does not
import — `profiles/`, `requirements.txt` — is a different invariant and is not
claimed here.

FALSE-POSITIVE-FREE: a first-party module that an entry point imports and its
distribution does not contain is unambiguously a broken distribution. There is no
configuration in which that is intended.
"""

import ast
import json
import re
import shlex
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

#: Never walked when discovering distributions: VCS internals, dependency trees,
#: caches, and the npm bundle's own OUTPUT directory (which is a build artifact,
#: not a source tree, and would otherwise be mistaken for one).
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache"}
)
_BUNDLE_OUTPUT = "npm-wrapper/python"

#: Top-level directories in this repo that are importable Python packages. A module
#: whose root package is NOT one of these is third-party or stdlib and is installed
#: by pip, not copied by a build.
_FIRST_PARTY_ROOTS = frozenset(
    p.name for p in _ROOT.iterdir() if p.is_dir() and (p / "__init__.py").exists()
)

_NPM_BUILD_SCRIPT = Path("npm-wrapper/scripts/build.js")
_NPM_LAUNCHER = Path("npm-wrapper/bin/arkheia-mcp.js")


# ---------------------------------------------------------------------------
# Derive: which first-party files does an entry point actually need?
# ---------------------------------------------------------------------------

def _module_to_paths(module: str) -> list[Path]:
    """
    Repo-relative files that must exist for `import module` to work.

    Includes every intermediate package's `__init__.py`: `import proxy.audit.writer`
    needs `proxy/__init__.py` and `proxy/audit/__init__.py` on disk, and a build that
    copied only `writer.py` would still fail.
    """
    parts = module.split(".")
    if not parts or parts[0] not in _FIRST_PARTY_ROOTS:
        return []

    terminal = Path(*parts)
    terminal_init = terminal / "__init__.py"
    terminal_file = terminal.with_suffix(".py")
    if not (_ROOT / terminal_init).exists() and not (_ROOT / terminal_file).exists():
        return []

    paths: list[Path] = []
    for i in range(1, len(parts) + 1):
        prefix = Path(*parts[:i])
        init = prefix / "__init__.py"
        if (_ROOT / init).exists():
            paths.append(init)
        module_file = prefix.with_suffix(".py")
        if i == len(parts) and (_ROOT / module_file).exists():
            paths.append(module_file)
    return paths


def _imported_modules(source_path: Path) -> set[str]:
    """
    Absolute module names imported by one file (relative imports resolved).

    `ast.walk` sees function-local imports too, which matters: several modules
    here defer a heavy import into the function that needs it, and a deferred
    import is no less a packaging requirement than a top-level one.
    """
    tree = ast.parse((_ROOT / source_path).read_text(encoding="utf-8"))
    package = source_path.parent.as_posix().replace("/", ".")

    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - node.level + 1]
                root = ".".join(base + ([node.module] if node.module else []))
            else:
                root = node.module or ""
            if not root:
                continue
            found.add(root)
            # `from proxy.audit import writer` names the submodule in the alias list.
            for alias in node.names:
                found.add(f"{root}.{alias.name}")
    return found


def required_files(entry_modules: tuple[str, ...]) -> set[Path]:
    """
    Transitive closure of first-party files reachable from these entry modules.

    Seeded through `_module_to_paths` rather than with the entry FILE, so a
    package `__init__.py` on the way to the entry point is required too —
    `python -m proxy.main` executes `proxy/__init__.py` first.

    A `from pkg import name` where `name` is a function, not a module, contributes
    nothing — `_module_to_paths` only returns paths that exist on disk.
    """
    seen: set[Path] = set()
    queue: list[Path] = []
    for module in entry_modules:
        queue.extend(_module_to_paths(module))

    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        for module in _imported_modules(current):
            for path in _module_to_paths(module):
                if path not in seen:
                    queue.append(path)
    return seen


# ---------------------------------------------------------------------------
# Parse: Dockerfiles — what do they copy, and what do they run?
# ---------------------------------------------------------------------------

def _logical_lines(text: str) -> list[str]:
    """
    Dockerfile lines with backslash continuations joined.

    Load-bearing, not tidiness: `HEALTHCHECK --interval=30s \\\n  CMD python -c …`
    puts a line starting with `CMD` in the file that is NOT the image's command. A
    naive per-line scan reads it as the entry point and analyses the wrong module.
    """
    joined: list[str] = []
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.lstrip().startswith("#") and not buffer:
            continue
        if line.endswith("\\"):
            buffer += line[:-1].strip() + " "
            continue
        buffer += line.strip()
        if buffer:
            joined.append(buffer)
        buffer = ""
    if buffer:
        joined.append(buffer)
    return joined


def dockerfile_copies(text: str, origin: str) -> list[tuple[str, str]]:
    """Every `COPY <src>… <dest>` as (source, dest) pairs, repo-relative sources."""
    pairs: list[tuple[str, str]] = []
    for line in _logical_lines(text):
        if not line.upper().startswith("COPY "):
            continue
        parts = shlex.split(line)[1:]
        flags = [p for p in parts if p.startswith("--")]
        if any(f.startswith("--from") for f in flags):
            raise AssertionError(
                f"{origin}: `COPY --from=` copies from a build stage, not from the "
                f"repo, and this parser cannot resolve it: {line!r}. Teach the "
                f"parser rather than letting the distribution go unanalysed."
            )
        operands = [p for p in parts if not p.startswith("--")]
        if len(operands) < 2:
            continue
        dest = operands[-1]
        pairs.extend((src, dest) for src in operands[:-1])
    return pairs


def dockerfile_command(text: str, origin: str) -> list[str]:
    """The image's effective command — the LAST `CMD`/`ENTRYPOINT`, as tokens."""
    command: list[str] = []
    for line in _logical_lines(text):
        head = line.split(None, 1)[0].upper() if line.split() else ""
        if head not in {"CMD", "ENTRYPOINT"}:
            continue
        body = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
        if body.startswith("["):
            try:
                command = [str(t) for t in json.loads(body)]
            except json.JSONDecodeError as exc:
                raise AssertionError(
                    f"{origin}: could not parse exec-form {head}: {body!r} ({exc})"
                ) from exc
        else:
            command = shlex.split(body)
    if not command:
        raise AssertionError(
            f"{origin}: no CMD or ENTRYPOINT found, so the entry point cannot be "
            f"derived and this distribution cannot be checked."
        )
    return command


def entry_module_from_command(command: list[str], origin: str) -> str:
    """
    The Python module a container command starts.

    Recognises the two forms this estate ships and REFUSES anything else. A form
    we cannot read is a distribution we have not checked, and a silent skip would
    report that as a pass.
    """
    tokens = [t for t in command if t not in {"sh", "-c", "bash"}]

    if tokens and Path(tokens[0]).name.startswith("python"):
        if "-m" in tokens:
            index = tokens.index("-m")
            if index + 1 < len(tokens):
                return tokens[index + 1]
        raise AssertionError(
            f"{origin}: python command {command!r} does not use `-m <module>`; the "
            f"entry module cannot be derived."
        )

    if tokens and Path(tokens[0]).name in {"uvicorn", "gunicorn", "hypercorn"}:
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            return token.split(":", 1)[0]

    raise AssertionError(
        f"{origin}: unrecognised entry-point form {command!r}. Extend "
        f"`entry_module_from_command` — do not leave the distribution unchecked."
    )


# ---------------------------------------------------------------------------
# Parse: the npm bundle
# ---------------------------------------------------------------------------

def buildjs_sources(text: str, entry_module: str) -> list[str]:
    """
    Sources the npm bundle carries for the launcher entry point.

    Older branches declared `PACKAGE_SOURCES`; current master derives the bundle
    from the import closure. Keep both forms readable here so the Docker floor can
    rebase over the stronger bundle builder without reintroducing the declared list.
    The packed-artifact floors observe the real tarball; this model is only the
    source-prefix analogue used by this multi-distribution floor.
    """
    match = re.search(r"PACKAGE_SOURCES\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if match:
        return re.findall(r"[\"']([^\"']+)[\"']", match.group(1))

    assert "function requiredSources()" in text, (
        f"{_NPM_BUILD_SCRIPT}: no PACKAGE_SOURCES declaration and no "
        "`requiredSources()` graph-derived builder found. The npm copy set cannot "
        "be analysed by this floor."
    )
    return sorted(p.as_posix() for p in required_files((entry_module,)))


def launcher_entry_module(text: str) -> str:
    """The module the Node launcher spawns: `spawn(python, ["-m", "<module>"], …)`."""
    match = re.search(r"\[\s*[\"']-m[\"']\s*,\s*[\"']([\w.]+)[\"']\s*\]", text)
    assert match, (
        f"{_NPM_LAUNCHER}: no `[\"-m\", \"<module>\"]` spawn found. The npm bundle "
        f"is the PRIMARY distribution; if its launcher was rewritten, this floor "
        f"must be taught the new form rather than silently checking nothing."
    )
    return match.group(1)


# ---------------------------------------------------------------------------
# Discover: the distributions
# ---------------------------------------------------------------------------

class Distribution:
    """One shipping boundary: what it runs, and what it carries."""

    def __init__(self, name: str, entry_modules: tuple[str, ...], copies: list[tuple[str, str]]):
        self.name = name
        self.entry_modules = entry_modules
        self.copies = copies

    @property
    def sources(self) -> list[str]:
        return [src for src, _dest in self.copies]

    def required(self) -> set[Path]:
        return required_files(self.entry_modules)

    def __repr__(self) -> str:  # pragma: no cover - test ids only
        return self.name


def _dockerfile_paths() -> list[Path]:
    """Every Dockerfile in the tree — glob-discovered, never listed."""
    found: list[Path] = []
    for path in _ROOT.rglob("Dockerfile*"):
        rel = path.relative_to(_ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if rel.as_posix().startswith(_BUNDLE_OUTPUT):
            continue
        if path.is_file():
            found.append(rel)
    return sorted(found)


def discover_distributions() -> list[Distribution]:
    distributions: list[Distribution] = []

    for rel in _dockerfile_paths():
        text = (_ROOT / rel).read_text(encoding="utf-8")
        origin = rel.as_posix()
        command = dockerfile_command(text, origin)
        module = entry_module_from_command(command, origin)
        distributions.append(
            Distribution(origin, (module,), dockerfile_copies(text, origin))
        )

    build_text = (_ROOT / _NPM_BUILD_SCRIPT).read_text(encoding="utf-8")
    launcher_text = (_ROOT / _NPM_LAUNCHER).read_text(encoding="utf-8")
    module = launcher_entry_module(launcher_text)
    sources = buildjs_sources(build_text, module)
    distributions.append(
        Distribution(
            _NPM_BUILD_SCRIPT.as_posix(),
            (module,),
            [(src, f"python/{src}") for src in sources],
        )
    )

    return distributions


DISTRIBUTIONS = discover_distributions()


# ---------------------------------------------------------------------------
# The coverage function
# ---------------------------------------------------------------------------

def uncovered(required: set[Path], sources: list[str]) -> set[Path]:
    """Required files no declared source copies — as a file, or as a parent directory."""
    normalised = [s.rstrip("/") for s in sources]
    missing = set()
    for path in required:
        posix = path.as_posix()
        if any(posix == s or posix.startswith(s + "/") for s in normalised):
            continue
        missing.add(path)
    return missing


def covering_sources(required: set[Path], sources: list[str]) -> dict[str, set[Path]]:
    """Which declared sources actually carry required files — the units of work."""
    mapping: dict[str, set[Path]] = {}
    for source in sources:
        norm = source.rstrip("/")
        carried = {
            p for p in required
            if p.as_posix() == norm or p.as_posix().startswith(norm + "/")
        }
        if carried:
            mapping[source] = carried
    return mapping


# ---------------------------------------------------------------------------
# WORK-DONE GUARDS — every invariant below passes by finding nothing
# ---------------------------------------------------------------------------

def test_the_discovery_reached_every_distribution_on_disk():
    """
    Every assertion in this module is "nothing is missing", which is also what a
    discovery that found no distributions returns. So the units of work are named
    and counted first: if a Dockerfile stops being discovered, or the npm bundle
    drops out, this fails rather than the coverage tests going quietly vacuous.
    """
    names = sorted(d.name for d in DISTRIBUTIONS)
    dockerfiles = sorted(p.as_posix() for p in _dockerfile_paths())

    assert dockerfiles, "no Dockerfile discovered anywhere in the repo"
    assert set(dockerfiles) <= set(names), (
        f"Dockerfiles on disk that no distribution covers: "
        f"{sorted(set(dockerfiles) - set(names))}"
    )
    assert _NPM_BUILD_SCRIPT.as_posix() in names, (
        "the npm bundle — the PRIMARY distribution — is not among the discovered "
        f"distributions {names}"
    )
    assert len(names) == len(dockerfiles) + 1, (
        f"distribution count {len(names)} does not match {len(dockerfiles)} "
        f"Dockerfile(s) + 1 npm bundle: {names}"
    )


@pytest.mark.parametrize(
    "module",
    [
        "proxy.does_not_exist",
        "mcp_server.server.nope",
        "registry_server.does_not_exist",
    ],
)
def test_entry_module_resolution_requires_the_terminal_component(module):
    """
    Reverse mutation for Docker CMD drift.

    A bad command such as `python -m proxy.does_not_exist` used to return the
    intermediate `proxy/__init__.py`, giving the work-done guard a non-empty
    closure and letting the floor pass over a container that cannot start.
    """
    assert _module_to_paths(module) == []
    assert required_files((module,)) == set()


@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_each_distribution_resolves_an_entry_point_and_a_copy_set(dist):
    """
    Per-distribution work-done guard, named per unit rather than as an aggregate:
    a run in which one of four distributions silently analysed nothing must be
    visible as that distribution, not folded into a total that looks right.
    """
    assert dist.entry_modules, f"{dist.name}: no entry module derived"
    assert dist.sources, f"{dist.name}: no copy directives parsed"

    required = dist.required()
    assert required, f"{dist.name}: the import walk from {dist.entry_modules} found no files"

    for module in dist.entry_modules:
        entry_paths = _module_to_paths(module)
        assert entry_paths, (
            f"{dist.name}: entry module {module!r} resolves to no file on disk"
        )
        assert set(entry_paths) <= required, (
            f"{dist.name}: the walk did not even include its own entry point"
        )

    assert covering_sources(required, dist.sources), (
        f"{dist.name}: not one declared source carries a required file — the copy "
        f"set and the import graph are describing different things"
    )


# ---------------------------------------------------------------------------
# THE INVARIANT
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_every_distribution_ships_every_first_party_import(dist):
    missing = uncovered(dist.required(), dist.sources)
    assert not missing, (
        f"{dist.name} does not ship these first-party modules that "
        f"{', '.join(dist.entry_modules)} imports: "
        f"{sorted(p.as_posix() for p in missing)}. The distribution boots into "
        f"ModuleNotFoundError while a git checkout passes, because a checkout has "
        f"the whole repo on sys.path."
    )


def landing_path(source: str, dest: str) -> str:
    """
    Where `COPY <source> <dest>` actually puts the source, per Docker's rules.

    Two forms, and conflating them is a false positive waiting to happen:
      * a DIRECTORY source copies its CONTENTS into dest, so `proxy/ -> /app/proxy/`
        lands the package at `/app/proxy`;
      * a FILE source copied to a dest ending in `/` gains the file's basename, so
        `proxy/__init__.py -> /app/proxy/` lands at `/app/proxy/__init__.py`.
    """
    norm_dest = dest.rstrip("/").lstrip("./") or "."
    is_dir = source.endswith("/") or (_ROOT / source.rstrip("/")).is_dir()
    if not is_dir and dest.endswith("/"):
        norm_dest = f"{norm_dest}/{Path(source).name}"
    return norm_dest


@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_every_shipped_package_keeps_its_import_path(dist):
    """
    Shipping the files is necessary but not sufficient: `COPY proxy/ /app/lib/`
    carries every byte and still breaks `import proxy`. Each source that carries a
    required file must LAND at a path ending in that same repo-relative path.
    """
    required = dist.required()
    for source, carried in covering_sources(required, dist.sources).items():
        dest = dict(dist.copies)[source]
        norm_src = source.rstrip("/")
        landed = landing_path(source, dest)
        assert landed == norm_src or landed.endswith("/" + norm_src), (
            f"{dist.name}: `{source}` -> `{dest}` lands at `{landed}`, which does "
            f"not preserve the import path, so "
            f"{sorted(p.as_posix() for p in carried)[:3]} ship at the wrong module "
            f"path and the import fails anyway."
        )


# ---------------------------------------------------------------------------
# PROVE THE CHECK CAN FAIL — derived, not hard-coded to a known-bad path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_removing_a_covering_source_is_detected(dist):
    """
    The invariant above passes by finding an empty set, which is what a broken
    derivation also returns. So run the SAME coverage function against a
    deliberately broken copy set for this distribution — its real declared set
    minus one source that genuinely carries required files — and require it to
    name exactly what that source was carrying.

    Derived from the distribution's own data: no path is written down here, so
    this control cannot rot into a test of a file that no longer matters.
    """
    required = dist.required()
    carriers = covering_sources(required, dist.sources)
    assert carriers, f"{dist.name}: nothing to break — see the work-done guard"

    for source, carried in carriers.items():
        broken = [s for s in dist.sources if s != source]
        missing = uncovered(required, broken)
        assert carried <= missing, (
            f"{dist.name}: dropping `{source}` from the copy set left "
            f"{sorted(p.as_posix() for p in carried - missing)} still reported as "
            f"covered — the check cannot see a missing source."
        )


@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_an_empty_copy_set_is_detected(dist):
    """A distribution that copies nothing must not read as complete."""
    missing = uncovered(dist.required(), [])
    assert missing == dist.required()
    assert missing, f"{dist.name}: a copy set of nothing reported nothing missing"


@pytest.mark.parametrize("dist", DISTRIBUTIONS, ids=lambda d: d.name)
def test_an_unshipped_cross_package_import_is_detected(dist):
    """
    THE REAL DEFECT, reproduced against this distribution's own declared copy set.

    `registry_server` importing `proxy.audit.writer` while shipping only
    `registry_server/` is the incident that earned this floor. Here it is
    reconstructed for every distribution: take a first-party package this
    distribution does NOT copy, pretend the entry point imports it, and require
    the coverage function to flag it.

    Derived, so it keeps working when the cross-package edge moves — and it holds
    on a branch where no such import exists yet, which is precisely when a floor
    written against a specific known-bad path would silently stop meaning
    anything.
    """
    required = dist.required()
    unshipped = [
        root for root in sorted(_FIRST_PARTY_ROOTS)
        if uncovered({Path(root) / "__init__.py"}, dist.sources)
    ]
    assert unshipped, (
        f"{dist.name} copies every first-party package in the repo "
        f"({sorted(_FIRST_PARTY_ROOTS)}), so this control has nothing to prove "
        f"with. Point it at a synthetic package rather than deleting it."
    )

    intruder = Path(unshipped[0]) / "__init__.py"
    missing = uncovered(required | {intruder}, dist.sources)
    assert intruder in missing, (
        f"{dist.name}: a cross-package import of `{unshipped[0]}` was NOT flagged "
        f"as unshipped — the coverage function cannot detect the defect class this "
        f"floor exists for."
    )
