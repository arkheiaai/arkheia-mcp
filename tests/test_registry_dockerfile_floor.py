"""
FLOOR INVARIANT — the registry image must contain everything the registry
imports, transitively.

THE DEFECT THIS COMPILES
------------------------
``registry_server/Dockerfile`` copies a hand-written list of paths:

    COPY registry_server/ ./registry_server/
    COPY profiles/        ./profiles/

That list was correct only for as long as ``registry_server`` imported nothing
outside itself. The moment ``registry_server.receipts`` began importing
``proxy.audit.writer`` — to drive the SAME audit rail as the proxy rather than
growing a second one — the image became one that boots into ``ModuleNotFoundError``
while every test on the machine still passed, because the developer's checkout
has ``proxy/`` sitting right there.

This is the deploy-dependency class in general: *present in the working tree,
absent from the artifact*. Its signature is that it is invisible to the entire
test suite and shows up only at ``docker run``. A reviewer cannot catch it by
reading the diff either, because the import and the Dockerfile are different
files in different directories.

HOW THIS CHECK DISCOVERS ITS CASES
----------------------------------
It never enumerates. It:

  1. walks ``registry_server/*.py`` (excluding tests, which are not shipped),
  2. takes the TRANSITIVE closure of their first-party imports — first-party
     meaning a package directory at the repo root, discovered by looking for
     ``__init__.py``, not by a hardcoded list,
  3. simulates the image filesystem from the Dockerfile's own ``COPY`` lines,
  4. requires every module in the closure, and every ancestor package's
     ``__init__.py``, to be present in that simulated image.

A new cross-package import fails HERE, naming the missing ``COPY``, instead of
at deploy time.

Floor tier: stdlib only (ast, pathlib, re). No project imports, no pytest
plugins, nothing that could make this check depend on the code it audits.
"""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "registry_server" / "Dockerfile"
ENTRY_PACKAGE = "registry_server"

# Subdirectories of a shipped package that are NOT part of the runtime.
NON_RUNTIME_DIRS = {"tests", "__pycache__"}


def first_party_packages() -> set[str]:
    """Top-level importable packages in this repo — discovered, not listed."""
    return {
        p.name for p in ROOT.iterdir()
        if p.is_dir() and (p / "__init__.py").exists() and not p.name.startswith(".")
    }


def module_file(dotted: str) -> Path | None:
    """Repo path for a dotted module name, or None if it is not a real file."""
    base = ROOT / Path(*dotted.split("."))
    if (base / "__init__.py").exists():
        return base / "__init__.py"
    if base.with_suffix(".py").exists():
        return base.with_suffix(".py")
    return None


def imported_modules(path: Path, packages: set[str]) -> set[str]:
    """First-party dotted module names imported by one file."""
    found: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in packages:
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:          # relative import — resolved within its own package
                continue
            if node.module and node.module.split(".")[0] in packages:
                found.add(node.module)
                # `from proxy.audit import writer` — the name may be a submodule.
                for alias in node.names:
                    found.add(f"{node.module}.{alias.name}")
    return found


def runtime_sources() -> list[Path]:
    """Every .py file that ships as part of `registry_server`."""
    out = []
    for p in sorted((ROOT / ENTRY_PACKAGE).rglob("*.py")):
        if NON_RUNTIME_DIRS & set(p.relative_to(ROOT).parts):
            continue
        out.append(p)
    return out


def transitive_first_party_closure() -> set[Path]:
    """Every first-party file the registry needs at runtime, transitively."""
    packages = first_party_packages()
    seen: set[Path] = set()
    queue = list(runtime_sources())
    seen.update(queue)
    while queue:
        current = queue.pop()
        for dotted in imported_modules(current, packages):
            target = module_file(dotted)
            if target is None or target in seen:
                continue
            if NON_RUNTIME_DIRS & set(target.relative_to(ROOT).parts):
                continue
            seen.add(target)
            queue.append(target)
    return seen


def copied_paths() -> list[Path]:
    """Repo-relative sources named by the Dockerfile's COPY instructions."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    text = re.sub(r"\\\s*\n", " ", text)          # join line continuations
    sources: list[Path] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.upper().startswith("COPY "):
            continue
        parts = [p for p in stripped.split()[1:] if not p.startswith("--")]
        if len(parts) < 2:
            continue
        for src in parts[:-1]:                     # last token is the destination
            sources.append(ROOT / src.rstrip("/"))
    return sources


def image_contains(target: Path, copied: list[Path]) -> bool:
    """Would `target` exist in the built image?"""
    for src in copied:
        if target == src:
            return True
        if src.is_dir() and target.is_relative_to(src):
            return True
    return False


# ---------------------------------------------------------------------------

def test_dockerfile_exists_and_declares_copies():
    """Vacuity guard: with no COPY lines parsed, everything below is empty and
    would pass having checked nothing."""
    assert DOCKERFILE.exists(), DOCKERFILE
    assert copied_paths(), f"no COPY instructions parsed from {DOCKERFILE}"


def test_registry_runtime_sources_are_discovered():
    """Vacuity guard for the other half of the check."""
    sources = runtime_sources()
    assert sources, "no runtime sources found for registry_server"
    names = {p.name for p in sources}
    assert {"auth.py", "main.py"} <= names, names


def test_every_first_party_import_is_copied_into_the_registry_image():
    """
    THE INVARIANT. Every first-party module the registry needs at runtime —
    transitively — must be inside the image the Dockerfile builds.
    """
    copied = copied_paths()
    missing = sorted(
        str(p.relative_to(ROOT))
        for p in transitive_first_party_closure()
        if not image_contains(p, copied)
    )
    assert not missing, (
        "registry_server imports these first-party modules at runtime, but "
        "registry_server/Dockerfile does not COPY them into the image. The "
        "container will boot into ModuleNotFoundError while every test on this "
        "machine passes:\n  " + "\n  ".join(missing) +
        "\nAdd the corresponding COPY line(s) to registry_server/Dockerfile."
    )


def test_ancestor_packages_of_every_copied_import_are_present():
    """
    Copying ``proxy/audit/`` without ``proxy/__init__.py`` yields a directory
    Python will not import as a package. The ancestor ``__init__.py`` files are
    part of the dependency, not an implementation detail.
    """
    copied = copied_paths()
    missing = []
    for target in transitive_first_party_closure():
        rel = target.relative_to(ROOT)
        for depth in range(1, len(rel.parts)):
            init = ROOT / Path(*rel.parts[:depth]) / "__init__.py"
            if init.exists() and not image_contains(init, copied):
                missing.append(str(init.relative_to(ROOT)))
    assert not missing, (
        "these package __init__.py files are needed to import the copied modules "
        "but are not in the image: " + ", ".join(sorted(set(missing)))
    )


def test_the_check_would_fail_if_a_copy_line_were_removed():
    """
    RUN IT RED, in-process. A check that has never been observed failing has
    not been shown to be able to fail. Recomputes the invariant against a
    COPY list with the cross-package entries deleted and requires it to break.
    """
    closure = transitive_first_party_closure()
    entry_only = [p for p in copied_paths() if p.name in (ENTRY_PACKAGE, "profiles")]
    cross_package = [p for p in closure if not p.is_relative_to(ROOT / ENTRY_PACKAGE)]
    if not cross_package:
        # No cross-package imports on this revision: state it rather than
        # passing silently, so "nothing to check" is never mistaken for "checked".
        assert all(image_contains(p, copied_paths()) for p in closure)
        return
    still_covered = [p for p in cross_package if image_contains(p, entry_only)]
    assert not still_covered, (
        "with the cross-package COPY lines removed the invariant still passes; "
        f"it cannot observe its own subject: {still_covered}"
    )
