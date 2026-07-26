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


def missing_from(required: set[Path], present: set[str]) -> set[Path]:
    """
    Required files that a set of ACTUALLY-PRESENT paths does not contain.

    `present` is an exact set of repo-relative POSIX paths read out of a built
    artifact — not a set of declared source prefixes. That distinction is the
    whole point of the floor that calls this: a prefix says what a build script
    intends to copy, a path says what shipped.
    """
    return {p for p in required if p.as_posix() not in present}
