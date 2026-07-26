"""
FLOOR INVARIANT — everything `mcp_server` imports is actually shipped with `mcp_server`.

Runs in the required `floor-invariants` context: bare `pytest`, no project dependencies.
It never imports the server (that would need `mcp`, `httpx`, …); it derives the answer by
parsing source, so it is affordable in that tier.

THE DEFECT CLASS THIS ENCODES — observed, not hypothesised.
`registry_server` added `from proxy.audit.writer import AuditWriter` and its Dockerfile
copied only `registry_server/` and `profiles/`. Every test on the developer's machine
passed, because a git checkout has the whole repo on `sys.path`; the IMAGE would have
booted straight into ModuleNotFoundError. The distribution boundary is invisible from
inside the checkout, which is what makes this failure mode so easy to ship.

`mcp_server` now has the same shape and TWO distribution boundaries, not one:

  * `mcp_server/Dockerfile` — `COPY mcp_server/` and nothing else, and
  * `npm-wrapper/scripts/build.js` — which builds the `@arkheia/mcp-server` npm bundle
    and used to copy `mcp_server/` and nothing else. That is the PRIMARY distribution:
    `npx @arkheia/mcp-server` runs from the bundle with `PYTHONPATH=<bundle>`, so a
    missing package is a crash on a customer's very first run.

`mcp_server.receipts` imports `proxy.audit.writer` (the shared audit rail — one rail
across proxy, registry and MCP rather than three), so both boundaries now have to carry
`proxy/__init__.py` and `proxy/audit/`.

WHY IT IS DERIVED RATHER THAN LISTED. A test that asserted "the Dockerfile contains
`COPY proxy/audit/`" would pass forever while a THIRD cross-package import went
unshipped. This walks the import graph from the entry point and demands that whatever it
finds is covered — so the invariant discovers its cases instead of enumerating them.

FALSE-POSITIVE-FREE: a first-party module that the entry point imports and the
distribution does not contain is unambiguously a broken distribution. There is no
configuration in which that is intended.
"""

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_ENTRY_POINTS = ("mcp_server/server.py",)

#: Top-level directories in this repo that are importable Python packages. A module whose
#: root package is NOT one of these is a third-party or stdlib import and is installed by
#: pip, not copied by a build.
_FIRST_PARTY_ROOTS = frozenset(
    p.name for p in _ROOT.iterdir() if p.is_dir() and (p / "__init__.py").exists()
)


# ---------------------------------------------------------------------------
# Derive: which first-party files does the entry point actually need?
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
    """Absolute module names imported by one file (relative imports resolved)."""
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


def required_files() -> set[Path]:
    """
    Transitive closure of first-party files reachable from the entry points.

    A `from pkg import name` where `name` is a function, not a module, contributes
    nothing — `_module_to_paths` only returns paths that exist on disk.
    """
    seen: set[Path] = set()
    queue = [Path(e) for e in _ENTRY_POINTS]
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
# Parse: what does each distribution actually copy?
# ---------------------------------------------------------------------------

def dockerfile_sources(text: str) -> list[str]:
    """Repo-relative source paths from every `COPY <src> <dest>` line."""
    sources: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.upper().startswith("COPY "):
            continue
        parts = line.split()[1:]
        if len(parts) < 2:
            continue
        sources.extend(p for p in parts[:-1] if not p.startswith("--"))
    return sources


def buildjs_sources(text: str) -> list[str]:
    """Entries of the declared `PACKAGE_SOURCES` array in the npm build script."""
    match = re.search(r"PACKAGE_SOURCES\s*=\s*\[(.*?)\]", text, re.DOTALL)
    if not match:
        return []
    return re.findall(r"[\"']([^\"']+)[\"']", match.group(1))


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


# ---------------------------------------------------------------------------
# The invariants
# ---------------------------------------------------------------------------

def test_the_import_walk_reaches_the_cross_package_dependency():
    """
    WORK-DONE GUARD. Every assertion below is of the form "nothing is missing", which is
    also what a walk that found nothing returns. So first prove the walk got somewhere:
    it must reach `mcp_server/receipts.py` and, through it, the shared audit rail in
    `proxy/`. If a refactor moves the rail behind a lazy import, this fails and the
    coverage tests stop being silently vacuous.
    """
    required = required_files()

    assert Path("mcp_server/server.py") in required
    assert Path("mcp_server/tools/memory.py") in required
    assert Path("mcp_server/receipts.py") in required
    assert Path("proxy/__init__.py") in required
    assert Path("proxy/audit/__init__.py") in required
    assert Path("proxy/audit/writer.py") in required

    cross_package = {p for p in required if p.parts[0] != "mcp_server"}
    assert cross_package, "no cross-package dependency found — the walk is not working"


def test_the_docker_image_ships_every_first_party_import():
    text = (_ROOT / "mcp_server" / "Dockerfile").read_text(encoding="utf-8")
    sources = dockerfile_sources(text)
    assert sources, "no COPY directives parsed from mcp_server/Dockerfile"

    missing = uncovered(required_files(), sources)
    assert not missing, (
        "mcp_server/Dockerfile does not COPY these first-party modules that "
        f"mcp_server.server imports: {sorted(p.as_posix() for p in missing)}. "
        "The image will boot into ModuleNotFoundError while the checkout passes."
    )


def test_the_npm_bundle_ships_every_first_party_import():
    text = (_ROOT / "npm-wrapper" / "scripts" / "build.js").read_text(encoding="utf-8")
    sources = buildjs_sources(text)
    assert sources, (
        "no PACKAGE_SOURCES array parsed from npm-wrapper/scripts/build.js — either the "
        "declaration was renamed or the build copies an undeclared set, and this check "
        "would then pass by finding nothing"
    )

    missing = uncovered(required_files(), sources)
    assert not missing, (
        "npm-wrapper/scripts/build.js does not copy these first-party modules that "
        f"mcp_server.server imports: {sorted(p.as_posix() for p in missing)}. "
        "`npx @arkheia/mcp-server` crashes on first run; a git checkout does not, "
        "because it has the whole repo on sys.path."
    )


@pytest.mark.parametrize(
    "sources, label",
    [
        (["mcp_server/"], "the Dockerfile COPY set before the proxy/ lines were added"),
        (["mcp_server"], "the build.js PACKAGE_SOURCES list before proxy/ was added"),
    ],
)
def test_the_check_goes_red_against_the_pre_fix_distribution(sources, label):
    """
    PROVE THE CHECK CAN FAIL. Both tests above pass by finding an empty set, which is
    indistinguishable from a broken derivation. Run the same coverage function against
    the exact copy-set each distribution carried BEFORE this change and require it to
    name the missing rail.
    """
    missing = uncovered(required_files(), sources)
    assert Path("proxy/audit/writer.py") in missing, label
    assert Path("proxy/__init__.py") in missing, label
