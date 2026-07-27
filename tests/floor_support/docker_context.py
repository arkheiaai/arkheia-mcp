"""
A container image as an ARTIFACT — the tree its COPY directives actually produce.

The npm bundle is checked by running the real `npm pack` and reading the bytes,
because intent is not a distribution. The Docker images are the same distribution
problem one axis over, and CI has no container runtime, so this module does the
next strongest thing available: it INTERPRETS the Dockerfile against the real build
context and MATERIALISES the file tree the image would contain, then resolves the
image's own entry point inside that tree.

That is deliberately not the same as parsing COPY directives and comparing prefixes.
A prefix comparison re-states what a human thinks `COPY proxy/ /app/proxy/` means;
this builds the directory and asks `importlib` whether `python -m proxy.main` would
find its imports there. The mapping from context path to image path — trailing
slashes, directory-contents-not-directory, WORKDIR-relative destinations — is where
a COPY goes wrong, and only executing it observes that.

WHAT IT STILL DOES NOT OBSERVE, named rather than silently inherited:
  * the real image. No `docker build` runs, so a base-image change, a failed pip
    layer, a `.dockerignore` (none exists; one appearing FAILS this parser rather
    than being ignored), or a multi-stage `COPY --from=` is out of reach.
  * third-party dependencies. Whether `pip install -r requirements.txt` installs
    what the image imports is the declared-dependency axis (`test_tooling_dependency.py`).
  * execution. Modules are resolved and compiled, never imported.

Stdlib only. See `floor_support/__init__.py`.
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from . import import_closure

REPO_ROOT = import_closure.REPO_ROOT

#: Directories never searched for Dockerfiles.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}

#: Command tokens that mean "this image runs Python code from this repo". Used to
#: decide whether an unparseable CMD is out of scope or a parser gap.
_PYTHON_LAUNCHERS = {"python", "python3", "uvicorn", "gunicorn", "hypercorn"}


class ContextUnobservable(AssertionError):
    """
    The image's file tree could not be derived.

    An AssertionError subclass on purpose: an artifact nobody could observe FAILS.
    It is never skipped, because "not observed" must not land in the pass bucket
    (DONE.md floor-ledger clause 9d).
    """


@dataclass
class Copy:
    """One COPY directive: context-relative sources, and one image destination."""

    sources: list[str]
    destination: PurePosixPath
    line: int
    text: str


@dataclass
class Image:
    """A Dockerfile, reduced to the things that decide what the image contains."""

    dockerfile: Path                      # repo-relative
    workdir: PurePosixPath = PurePosixPath("/")
    copies: list[Copy] = field(default_factory=list)
    entry_module: str | None = None
    entry_text: str = ""


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def dockerfiles(root: Path = REPO_ROOT) -> list[Path]:
    """
    Every Dockerfile in the repo, DISCOVERED rather than listed.

    A floor that names the three images we have today stops covering the fourth on
    the day it lands, which is the enumeration defect this whole branch is about.
    """
    found = []
    for path in sorted(root.rglob("Dockerfile*")):
        rel = path.relative_to(root)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.is_file():
            found.append(rel)
    return found


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _logical_lines(text: str) -> list[tuple[int, str]]:
    """
    Join backslash continuations into one logical instruction, keeping line numbers.

    This is what keeps `HEALTHCHECK --interval=30s … \\\\n CMD python -c …` from
    being read as a CMD: the instruction is whatever the LOGICAL line starts with.
    """
    lines: list[tuple[int, str]] = []
    buffer = ""
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not buffer and (not stripped or stripped.startswith("#")):
            continue
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        buffer += stripped
        lines.append((start, buffer.strip()))
        buffer = ""
    if buffer:
        lines.append((start, buffer.strip()))
    return lines


def _tokens(argument: str) -> list[str]:
    """
    Argument tokens, handling both Docker forms.

    Exec form is a JSON array (`["python", "-m", "proxy.main"]`); shell form is
    whitespace-separated. Quotes are stripped in the shell form so
    `CMD python -c "import x"` yields sane tokens.
    """
    text = argument.strip()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ContextUnobservable(
                f"exec-form argument is not valid JSON ({exc}): {text!r}"
            ) from exc
        if not isinstance(parsed, list) or not all(isinstance(t, str) for t in parsed):
            raise ContextUnobservable(f"exec-form argument is not a string list: {text!r}")
        return parsed
    return [t.strip("\"'") for t in text.split()]


def _entry_module(tokens: list[str], first_party: frozenset[str]) -> str | None:
    """
    The first-party module this image starts, or None if it does not start one.

    Two forms are understood, both present in this repo: `python -m pkg.mod`, and an
    ASGI target `pkg.mod:attr` handed to uvicorn/gunicorn. Anything that clearly
    launches Python but yields no module raises, rather than quietly reporting that
    the image is out of scope — an unrecognised launcher is a parser gap, and a
    parser gap that reads as "nothing to check" is how a floor goes green over a
    hole.
    """
    if not tokens:
        return None
    for index, token in enumerate(tokens):
        base = PurePosixPath(token).name
        if base in {"python", "python3"} and index + 2 < len(tokens):
            if tokens[index + 1] == "-m":
                return tokens[index + 2]
        if base in {"uvicorn", "gunicorn", "hypercorn"}:
            for candidate in tokens[index + 1 :]:
                if ":" in candidate and not candidate.startswith("-"):
                    module = candidate.split(":", 1)[0]
                    if module:
                        return module
    launcher = next(
        (t for t in tokens if PurePosixPath(t).name in _PYTHON_LAUNCHERS), None
    )
    if launcher is None:
        return None
    if any(t in {"-c", "--help"} for t in tokens):
        return None  # an inline snippet, e.g. a HEALTHCHECK probe: no module to ship
    raise ContextUnobservable(
        f"the start command runs {launcher!r} but no module could be derived from "
        f"{tokens!r}. Teach this parser the new form rather than leaving the image "
        f"unchecked — an image whose entry point cannot be identified is exactly the "
        f"one nothing is verifying."
    )


def parse(dockerfile: Path, root: Path = REPO_ROOT) -> Image:
    """Reduce a Dockerfile to its WORKDIR, its COPY set, and the module it starts."""
    text = (root / dockerfile).read_text(encoding="utf-8")
    image = Image(dockerfile=dockerfile)
    first_party = import_closure.first_party_roots(root)
    entry_tokens: list[str] | None = None

    for number, line in _logical_lines(text):
        match = re.match(r"^([A-Za-z]+)\s+(.*)$", line)
        if not match:
            continue
        instruction = match.group(1).upper()
        argument = match.group(2).strip()

        if instruction == "WORKDIR":
            target = PurePosixPath(_tokens(argument)[0])
            image.workdir = (
                target if target.is_absolute() else image.workdir / target
            )
        elif instruction in {"COPY", "ADD"}:
            image.copies.append(_parse_copy(dockerfile, number, instruction, argument, image.workdir))
        elif instruction in {"CMD", "ENTRYPOINT"}:
            entry_tokens = _tokens(argument)
            image.entry_text = line

    if entry_tokens is not None:
        module = _entry_module(entry_tokens, first_party)
        if module and module.split(".")[0] in first_party:
            image.entry_module = module
    return image


def _parse_copy(
    dockerfile: Path,
    number: int,
    instruction: str,
    argument: str,
    workdir: PurePosixPath,
) -> Copy:
    tokens = _tokens(argument)
    flags = [t for t in tokens if t.startswith("--")]
    operands = [t for t in tokens if not t.startswith("--")]

    for flag in flags:
        if flag.startswith("--from"):
            raise ContextUnobservable(
                f"{dockerfile}:{number}: `{instruction} {flag}` copies from another "
                f"build stage, which this parser cannot resolve from the context "
                f"alone. Teach it multi-stage builds rather than letting the image go "
                f"unchecked."
            )
    if len(operands) < 2:
        raise ContextUnobservable(
            f"{dockerfile}:{number}: `{instruction} {argument}` has fewer than two "
            f"operands; this parser cannot tell source from destination."
        )
    sources, destination = operands[:-1], operands[-1]
    for source in sources:
        if any(ch in source for ch in "*?["):
            raise ContextUnobservable(
                f"{dockerfile}:{number}: wildcard source {source!r} is not resolved "
                f"by this parser. Teach it globbing rather than under-reporting what "
                f"the image contains."
            )
    target = PurePosixPath(destination)
    absolute = target if target.is_absolute() else workdir / target
    return Copy(
        sources=sources,
        destination=absolute,
        line=number,
        text=f"{instruction} {argument}",
    )


# ---------------------------------------------------------------------------
# Materialising the tree
# ---------------------------------------------------------------------------

def materialise(
    image: Image,
    destination: Path,
    root: Path = REPO_ROOT,
    skip: Copy | None = None,
) -> Path:
    """
    Build the image's Python file tree under `destination`, and return its WORKDIR.

    Only `.py` files are written: this axis is about whether the first-party import
    graph survives the copy, and materialising the whole context would be slower for
    no extra signal. `skip` omits one COPY, which is how the adverse control proves
    the check can fail.

    Docker's directory semantics are honoured, because they are where the mistake
    lives: `COPY src/ /app/dst/` copies the CONTENTS of `src` into `/app/dst`, not
    `src` itself, so a Dockerfile that says `COPY proxy/ /app/` puts modules at
    `/app/main.py` and breaks the package.
    """
    if (root / ".dockerignore").exists():
        raise ContextUnobservable(
            "a .dockerignore appeared in the build context. It can remove files this "
            "materialiser copies, so the tree derived here would no longer be the "
            "image's. Teach this parser .dockerignore rather than over-reporting what "
            "ships."
        )

    for copy in image.copies:
        if skip is not None and copy is skip:
            continue
        for source in copy.sources:
            src = (root / source).resolve()
            if not src.exists():
                raise ContextUnobservable(
                    f"{image.dockerfile}:{copy.line}: `{copy.text}` copies "
                    f"{source!r}, which does not exist in the build context "
                    f"({root}). This image cannot build."
                )
            if src.is_dir():
                _copy_tree(src, _image_path(destination, copy.destination))
            else:
                target = copy.destination
                if str(copy.destination).endswith("/"):
                    target = copy.destination / src.name
                _copy_file(src, _image_path(destination, target))

    return _image_path(destination, image.workdir)


def _image_path(destination: Path, absolute: PurePosixPath) -> Path:
    """Map an absolute in-image path to its place under the materialised root."""
    relative = PurePosixPath(*absolute.parts[1:]) if absolute.is_absolute() else absolute
    return destination / relative


def _copy_tree(src: Path, dest: Path) -> None:
    for path in sorted(src.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.relative_to(src).parts):
            continue
        _copy_file(path, dest / path.relative_to(src))


def _copy_file(src: Path, dest: Path) -> None:
    if src.suffix != ".py":
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(src, dest)


#: Directory names whose contents are not on any runtime import path. `build.js`
#: applies the identical exclusion when it copies the npm bundle (`SKIP_NAMES`).
_NON_RUNTIME_DIRS = {"tests", "test"}


def materialised_sources(workdir: Path, runtime_only: bool = False) -> list[Path]:
    """
    Workdir-relative `.py` files in a materialised image tree.

    `runtime_only` drops test packages. They are genuinely IN the image — a bare
    `COPY proxy/ /app/proxy/` ships `proxy/tests/` — but nothing on the runtime
    import path reaches them, so holding their imports to the image's closure would
    report a container that starts perfectly well as broken, and a floor that cries
    wolf gets switched off. The observation stays honest (the tree is materialised in
    full); only the assertion is scoped.

    That the images ship their own test suites is a real and separate finding, about
    image surface rather than about whether the container starts. It is reported, not
    silently normalised here.
    """
    paths = sorted(p.relative_to(workdir) for p in workdir.rglob("*.py"))
    if not runtime_only:
        return paths
    return [p for p in paths if not (set(p.parts) & _NON_RUNTIME_DIRS)]
