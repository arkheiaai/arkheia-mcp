"""
The FIRST-PARTY IMPORT CLOSURE of an entry point — the set of repo files that
must exist, at their repo-relative paths, for that entry point to import.

This is the "what is REQUIRED" half of every packaging invariant. It is derived
from the import graph and never enumerated: a list of expected files is the same
defect one level up, because it keeps passing while the next cross-package import
goes unshipped.

`ast.walk` is deliberate — it sees function-level and conditional imports, and a
deferred import is no less a packaging requirement than a top-level one.

Stdlib only. See `floor_support/__init__.py`.
"""

from __future__ import annotations

import ast
from pathlib import Path

#: Repo root — this file is `<root>/tests/floor_support/import_closure.py`.
REPO_ROOT = Path(__file__).resolve().parents[2]


def first_party_roots(root: Path = REPO_ROOT) -> frozenset[str]:
    """
    Top-level importable packages in `root`, discovered from disk.

    A module whose root package is not one of these is stdlib or third-party: it
    is installed by pip, not copied by a build, so it is out of scope here (it is
    the subject of the declared-dependency axis instead).
    """
    return frozenset(
        p.name for p in root.iterdir() if p.is_dir() and (p / "__init__.py").exists()
    )


def module_to_paths(
    module: str,
    root: Path = REPO_ROOT,
    first_party: frozenset[str] | None = None,
) -> list[Path]:
    """
    Repo-relative files that must exist for `import <module>` to work.

    Includes every intermediate package's `__init__.py`: `import a.b.c` needs
    `a/__init__.py` and `a/b/__init__.py` on disk too, and a build that copied
    only `c.py` would still fail at import time.

    Returns `[]` for a module that is not first-party, and for a
    `from pkg import name` where `name` is a function rather than a submodule —
    only paths that exist under `root` are returned, so a non-module name
    contributes nothing.
    """
    roots = first_party_roots(root) if first_party is None else first_party
    parts = module.split(".")
    if not parts or parts[0] not in roots:
        return []

    paths: list[Path] = []
    for i in range(1, len(parts) + 1):
        prefix = Path(*parts[:i])
        init = prefix / "__init__.py"
        if (root / init).exists():
            paths.append(init)
        module_file = prefix.with_suffix(".py")
        if i == len(parts) and (root / module_file).exists():
            paths.append(module_file)
    return paths


def imported_modules(rel_path: Path, root: Path = REPO_ROOT) -> set[str]:
    """
    Absolute module names imported by one file, with relative imports resolved.

    `from pkg import name` contributes both `pkg` and `pkg.name`, because at parse
    time there is no way to know whether `name` is a submodule (which must be
    shipped) or an attribute (which comes with `pkg`). Resolution against disk in
    `module_to_paths` decides.
    """
    tree = ast.parse((root / rel_path).read_text(encoding="utf-8"))
    package = rel_path.parent.as_posix().replace("/", ".")

    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[: len(base) - node.level + 1]
                absolute = ".".join(base + ([node.module] if node.module else []))
            else:
                absolute = node.module or ""
            if not absolute:
                continue
            found.add(absolute)
            for alias in node.names:
                found.add(f"{absolute}.{alias.name}")
    return found


def required_files(
    entry_modules: tuple[str, ...],
    root: Path = REPO_ROOT,
    first_party: frozenset[str] | None = None,
) -> set[Path]:
    """
    Transitive closure of first-party files reachable from these entry modules.

    Seeded through `module_to_paths` rather than with the entry FILE, so a package
    `__init__.py` on the way to the entry point is required too: `python -m
    pkg.mod` executes `pkg/__init__.py` first.
    """
    roots = first_party_roots(root) if first_party is None else first_party
    seen: set[Path] = set()
    queue: list[Path] = []
    for module in entry_modules:
        queue.extend(module_to_paths(module, root, roots))

    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        for module in imported_modules(current, root):
            for path in module_to_paths(module, root, roots):
                if path not in seen:
                    queue.append(path)
    return seen


def module_name_for(rel_path: Path) -> str:
    """Dotted module name of a repo-relative `.py` path (`a/b/__init__.py` -> `a.b`)."""
    parts = list(rel_path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def resolve_in(module: str, tree: Path):
    """
    Resolve `module` using ONLY `tree` as the search path, without importing it.

    `importlib.machinery.PathFinder` is the machinery the interpreter itself uses,
    so this answers "would `import module` find a file here?" against a built tree —
    a packed tarball, a materialised container context — with none of the
    third-party packages the floor tier deliberately does not have.

    Returns the spec, or None. Caches are invalidated first, because the adverse
    controls that prove these floors can fail work by DELETING a file from a tree
    that was just walked, and a cached directory listing would hide the deletion.
    """
    import importlib
    import importlib.machinery

    importlib.invalidate_caches()
    finder = importlib.machinery.PathFinder
    parts = module.split(".")
    search = [str(tree)]
    spec = None
    for depth in range(1, len(parts) + 1):
        spec = finder.find_spec(".".join(parts[:depth]), search)
        if spec is None:
            return None
        if spec.submodule_search_locations is not None:
            search = list(spec.submodule_search_locations)
        elif depth != len(parts):
            return None  # a module cannot contain a submodule
    return spec


def missing_from(required: set[Path], present: set[str]) -> set[Path]:
    """
    Required files that a set of ACTUALLY-PRESENT paths does not contain.

    `present` is an exact set of repo-relative POSIX paths read out of a built
    artifact — not a set of declared source prefixes. That distinction is the
    whole point of the floor that calls this: a prefix says what a build script
    intends to copy, a path says what shipped.
    """
    return {p for p in required if p.as_posix() not in present}


# ---------------------------------------------------------------------------
# CLI — so the BUILD and the FLOOR share one import graph
# ---------------------------------------------------------------------------
#
# `npm-wrapper/scripts/build.js` invokes this file as a script and copies exactly
# the paths it prints. That is deliberate and it is the point of the CLI existing
# at all: the packaging defect this repo keeps re-suffering is a *declared* copy
# set diverging from the *actual* import graph, and the only durable cure is to
# stop declaring it. A build that asks the graph cannot drift from the graph.
#
# The alternative — reimplementing this walk in JavaScript so the build owns its
# own copy — is the second-source-of-truth pattern DONE.md v1.13 clause 4 forbids,
# and it is exactly how two parsers of one artifact come to disagree silently.
#
# Stdlib only, no relative imports, so `python3 tests/floor_support/import_closure.py`
# works as a plain script with no package context and no install step.


def _main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="import_closure",
        description=(
            "Print, as a JSON array of repo-relative POSIX paths, the transitive "
            "first-party import closure of one or more entry modules. This is the "
            "set of files a build must copy for those modules to import outside a "
            "git checkout."
        ),
    )
    parser.add_argument(
        "--entry",
        required=True,
        action="append",
        dest="entries",
        metavar="MODULE",
        help="dotted entry module (repeatable), e.g. mcp_server.server",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="repo root (defaults to the root this file lives under)",
    )
    args = parser.parse_args(argv)

    root = Path(args.root).resolve() if args.root else REPO_ROOT
    roots = first_party_roots(root)
    files = required_files(tuple(args.entries), root, roots)

    # A closure that resolved to nothing is NOT an empty copy set — it is an
    # unanswered question (a misspelled entry module, a moved package, a root that
    # is not the repo). "Not observed" must never be handed to a caller as a clean
    # empty result (DONE.md floor-ledger clause 9d), so it exits non-zero and the
    # build stops rather than publishing a bundle with nothing in it.
    if not files:
        print(
            f"import_closure: entry module(s) {args.entries} resolve to no "
            f"first-party file under {root}. First-party roots discovered there: "
            f"{sorted(roots) or 'NONE'}.",
            file=sys.stderr,
        )
        return 2

    print(json.dumps(sorted(p.as_posix() for p in files)))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
