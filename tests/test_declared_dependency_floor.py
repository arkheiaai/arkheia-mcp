"""
FLOOR INVARIANT — every third-party module a distribution imports is DECLARED in
the dependency file that distribution actually installs.

Runs in the required `floor-invariants` context: bare `pytest`, zero project
dependencies. It never imports the servers (that would need `mcp`, `httpx`,
`cryptography`, …); it derives the answer by parsing source, so it is affordable
in that tier and cannot be defeated by whatever happens to be in the runner's
site-packages — which is the whole point, because a dev venv holding the module
is precisely what hid the defect below.

THE DEFECT CLASS THIS ENCODES — suffered twice, in two repos.
`proxy/crypto/profile_crypto.py` does `from cryptography.hazmat.primitives.ciphers.aead
import AESGCM`, and `cryptography` was declared in NO requirements file in this
repo. `proxy/main.py` reaches that module through a FUNCTION-LEVEL import inside
the encrypted-profile startup branch, so nothing crashed while zero profiles were
encrypted, and CI stayed green because `unit-tests.yml` installed `cryptography`
ad hoc on its own pip line. The same dependency, used the same lazy way and
likewise undeclared, crashed swarm-runtime in arkheia-synesis when the App #10
Hermes SOC merge made the lazy path live. `python-dotenv` (imported
unconditionally at `proxy/main.py`'s top) was a third instance in this repo.

Three properties made all three invisible, and each is answered below:
  * the import is LAZY, so no test that boots the app touches it;
  * the module is present in the developer venv and in the CI runner, so the
    green run proves nothing about the built image;
  * the requirements file that governs a directory is NOT the one next to it —
    `mcp_server/Dockerfile` installs the ROOT `requirements.txt`, and the npm
    bundle installs `npm-wrapper/python/requirements.txt`. Reasoning "the code is
    under proxy/, so proxy/requirements.txt governs it" is a guess that happens
    to be right once out of four times here.

WHY IT IS DERIVED RATHER THAN LISTED.
A test asserting "cryptography is in proxy/requirements.txt" would pass forever
while the next undeclared import shipped — the same defect class wearing a test's
clothes. A hand-written "expected dependencies" list is the same defect one level
up. So nothing here is enumerated:

  * SCOPES are discovered — every `Dockerfile*` in the tree, plus the two
    distributions the npm launcher creates (the published bundle, and the
    git-clone fallback it performs when the bundle has no server code);
  * each scope's DECLARED SET is read out of the `pip install` commands that
    scope actually runs — an `-r <path>` is resolved back through that
    Dockerfile's own `COPY` directives and `WORKDIR` to a repo-relative file, so
    the code→requirements mapping is derived from the build, never assumed;
  * each scope's CHECKED SET is derived from the import graph: the first-party
    root packages transitively reachable from that scope's entry module,
    intersected with the files that scope ships;
  * `ast.walk` sees function-level and conditional imports, so a lazily imported
    dependency counts exactly as much as a top-level one. That is the mechanism
    that hid the incident, so it is the mechanism this floor is built around.

FAIL CLOSED — an unclassifiable import must never be skipped.
An unresolvable entry point, an unparsable `pip install`, an `-r` target that no
`COPY` explains, a `COPY --from=` build stage, a launcher whose spawn form has
changed, a requirements file no scope installs, or a first-party root package no
scope ships: every one of these FAILS. A distribution nobody could analyse has
not been shown to be correct, and "not observed" must never land in the pass
bucket (DONE.md floor-ledger clause 9d).

SCOPE — and what is NOT claimed. Read this before trusting a green run.
Third-party Python packages only. Whether a distribution SHIPS the first-party
files it imports is the complementary axis and belongs to
`tests/test_mcp_packaging_floor.py`; this floor deliberately does not restate it.
Test-only dependencies are out of scope: test files are not runtime code, so
`pytest`, `respx` and `locust` are not required to be declared here. Dependencies
a distribution needs but never imports from Python source — a `HEALTHCHECK
python -c "import httpx"`, a binary invoked by subprocess — are not derived, so a
declared-but-unimported package is never flagged.

Four named limits, so a green run is not read as more than it is:

  1. LOOSE ROOT SCRIPTS ARE NOT A SCOPE. `server.py`, `setup_cython.py` and
     `scripts/*.py` run from a bare checkout governed by the root
     `requirements.txt`, and no distribution's entry point reaches them, so this
     floor does not check their imports. That is a real gap: `scripts/build_release.py`
     imports `proxy.crypto.profile_crypto`, and its `cryptography` arrived only via
     `mcp -> pyjwt[crypto] -> cryptography` until it was declared explicitly. Closing
     it properly needs FILE-level import closure (this floor uses PACKAGE-level
     reachability, which for a loose script would demand every dependency of every
     module in a package it merely touches — a false positive, and a floor that
     cries wolf gets switched off).
  2. PACKAGE-LEVEL, NOT FILE-LEVEL. A scope is held to the third-party imports of
     every runtime file in the first-party packages its entry point reaches, not
     just the files on the import path. For an IMAGE that is the right strictness
     — the file was deliberately copied in, so something will import it — but it
     means an orphaned module inside a shipped package is treated as live.
  3. `try/except ImportError` GUARDS ARE NOT RECOGNISED. A genuinely optional
     dependency would be reported as a gap. There are none in this repo's runtime
     code today; if one is added, teach this floor to see the guard rather than
     baselining around it.
  4. VERSION FLOORS ARE NOT CHECKED. This floor asks whether a package is
     declared, never whether the pin is adequate or the CVE note is true. That is
     Gate 3's job (pip-audit / Snyk / Aikido) — but note that those scanners read
     requirements FILES, which is why `test_no_dependency_declaration_hides_in_a_dockerfile`
     exists: a dependency declared as a Dockerfile literal is scanned by nothing.

FALSE-POSITIVE-FREE: a module imported by a file a distribution ships, whose
package that distribution does not install, is unambiguously a latent
ModuleNotFoundError in that distribution. There is no configuration in which that
is intended. (An import deliberately guarded by `try/except ImportError` would be
the one exception; this repo has none in runtime code, and if one is added the
gate should be taught to see the guard rather than baselined around.)
"""

import ast
import re
import shlex
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

_STDLIB = frozenset(sys.stdlib_module_names)

#: Never walked: VCS internals, dependency trees, caches. `npm-wrapper/python` is
#: NOT skipped — it is a real published distribution, not a throwaway artifact.
_SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", ".egg-info"}
)

#: Importable first-party root packages, discovered from disk.
_FIRST_PARTY_ROOTS = frozenset(
    p.name for p in _ROOT.iterdir() if p.is_dir() and (p / "__init__.py").exists()
)

_NPM_BUILD_SCRIPT = Path("npm-wrapper/scripts/build.js")
_NPM_LAUNCHER = Path("npm-wrapper/bin/arkheia-mcp.js")
_NPM_BUNDLE_DIR = Path("npm-wrapper/python")

#: PyPI distribution name (normalised: lowercased, separators stripped) -> the
#: top-level module it provides. Only the MISMATCHES need listing; the generic
#: rule (`-` -> `_`) covers everything else. Kept small on purpose: an entry here
#: is a claim that a name differs, not a list of this repo's dependencies.
_DIST_IMPORT_ALIASES = {
    "pyjwt": "jwt",
    "pyyaml": "yaml",
    "pythondotenv": "dotenv",
    "pythonmultipart": "multipart",
    "pydanticsettings": "pydantic_settings",
    "prometheusclient": "prometheus_client",
    "psycopg2binary": "psycopg2",
    "pythondateutil": "dateutil",
    "beautifulsoup4": "bs4",
    "pillow": "PIL",
    "protobuf": "google",
    "grpcio": "grpc",
    "pycryptodome": "Crypto",
    "pytestasyncio": "pytest_asyncio",
}


# ---------------------------------------------------------------------------
# Requirement specs -> import names
# ---------------------------------------------------------------------------

def _normalise_dist(name: str) -> str:
    return name.lower().replace("-", "").replace("_", "").replace(".", "")


def dist_to_import_names(dist: str) -> set[str]:
    """Top-level import name(s) a distribution provides."""
    names = {dist.lower().replace("-", "_")}
    alias = _DIST_IMPORT_ALIASES.get(_normalise_dist(dist))
    if alias:
        names.add(alias)
    return names


def leading_dist_token(spec: str) -> str:
    """The distribution name at the head of a requirement spec.

    `uvicorn[standard]>=0.31.1`, `starlette==1.3.1  # CVE-…`, `mcp==1.28.1` all
    yield the bare name.
    """
    token = ""
    for char in spec.strip():
        if char in "[<>=!~ \t;(@#":
            break
        token += char
    return token


def declared_names_from_requirements(rel_path: Path) -> set[str]:
    """Import names declared by a requirements file, with nested `-r` followed."""
    declared: set[str] = set()
    path = _ROOT / rel_path
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-r") or line.startswith("--requirement"):
            nested = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if not nested:
                raise AssertionError(f"{rel_path}: bare `-r` with no target: {line!r}")
            target = (rel_path.parent / nested).resolve().relative_to(_ROOT)
            declared |= declared_names_from_requirements(target)
            continue
        if line.startswith("-"):
            # A pip option (--index-url, -e, …). It contributes no name we can
            # resolve; an `-e` editable install of a third-party source tree
            # would need teaching rather than silently ignoring.
            if line.startswith("-e"):
                raise AssertionError(
                    f"{rel_path}: `-e` editable install {line!r} declares a "
                    f"dependency this parser cannot resolve to an import name. "
                    f"Teach the parser rather than leaving the scope unchecked."
                )
            continue
        token = leading_dist_token(line.split(";", 1)[0])
        if token:
            declared |= dist_to_import_names(token)
    return declared


# ---------------------------------------------------------------------------
# Import graph
# ---------------------------------------------------------------------------

def is_test_path(rel_path: Path) -> bool:
    """Test code is not runtime code, so its imports are not runtime dependencies."""
    parts = rel_path.parts
    if any(segment in {"tests", "test", "e2e", "examples"} for segment in parts[:-1]):
        return True
    name = rel_path.name
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def imports_in_source(source: str, rel_path: Path) -> set[str]:
    """Absolute module names imported by a Python source string.

    `ast.walk` descends into function bodies and `if`/`try` branches, so a
    deferred import counts. That is deliberate and load-bearing: the two incidents
    this floor exists for were both function-level imports.

    Split out from `imported_modules` so the negative self-test can exercise the
    real extractor on a synthetic deferred import without writing a probe file
    into the working tree.
    """
    try:
        tree = ast.parse(source, filename=str(rel_path))
    except SyntaxError as exc:
        raise AssertionError(
            f"{rel_path}: could not be parsed ({exc}), so its imports are unknown. "
            f"An unanalysable runtime file is not a passing one."
        ) from exc

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
                found.add(".".join(base + ([node.module] if node.module else [])))
            elif node.module:
                found.add(node.module)
                # `from proxy.audit import writer` names a submodule in the aliases.
                for alias in node.names:
                    found.add(f"{node.module}.{alias.name}")
    return found


def imported_modules(rel_path: Path) -> set[str]:
    """Absolute module names imported by one repo file."""
    return imports_in_source(
        (_ROOT / rel_path).read_text(encoding="utf-8-sig"), rel_path
    )


def runtime_files_under(rel_dir: Path) -> list[Path]:
    """Every non-test `.py` file under a repo-relative directory."""
    found: list[Path] = []
    base = _ROOT / rel_dir
    if not base.is_dir():
        return found
    for path in base.rglob("*.py"):
        rel = path.relative_to(_ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if is_test_path(rel):
            continue
        found.append(rel)
    return sorted(found)


def module_to_file(module: str) -> Path | None:
    """The repo file backing a first-party module name, if one exists."""
    parts = module.split(".")
    if not parts or parts[0] not in _FIRST_PARTY_ROOTS:
        return None
    as_module = Path(*parts).with_suffix(".py")
    if (_ROOT / as_module).is_file():
        return as_module
    as_package = Path(*parts) / "__init__.py"
    if (_ROOT / as_package).is_file():
        return as_package
    return None


def reachable_first_party_roots(entry_module: str) -> set[str]:
    """First-party root packages transitively reachable from an entry module.

    This is what turns a copy set into a CHECKED set. It is the derived answer to
    "which of this repo's packages does this scope actually run?" — and it is why
    the git-clone scope, which has the entire repo on `sys.path`, is not held to
    `proxy`'s dependencies: nothing `mcp_server.server` imports reaches `proxy`.
    """
    seed = module_to_file(entry_module)
    roots: set[str] = set()
    if seed is None:
        return roots

    seen: set[Path] = set()
    queue = [seed]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        roots.add(current.parts[0])
        for module in imported_modules(current):
            nxt = module_to_file(module)
            if nxt is not None and nxt not in seen:
                queue.append(nxt)
    return roots


# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

def logical_lines(text: str) -> list[str]:
    """Dockerfile lines with backslash continuations joined.

    Load-bearing: a `RUN pip install foo \\\n  bar` is one command, and a
    `HEALTHCHECK --interval=30s \\\n  CMD python -c …` puts a line beginning
    `CMD` in the file that is NOT the image's command.
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


def _abs_in_image(path: str, workdir: str) -> str:
    """Normalise an in-image path against the current WORKDIR."""
    if path.startswith("/"):
        candidate = Path(path)
    else:
        candidate = Path(workdir) / path
    parts: list[str] = []
    for part in candidate.parts:
        if part in ("/", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


class DockerfileFacts:
    """What one Dockerfile copies, installs and runs — parsed, never assumed."""

    def __init__(self, rel_path: Path):
        self.origin = rel_path.as_posix()
        text = (_ROOT / rel_path).read_text(encoding="utf-8")
        self.copies: list[tuple[str, str]] = []       # (repo src, abs in-image dest)
        self.pip_commands: list[list[str]] = []
        self.command: list[str] = []

        workdir = "/"
        for line in logical_lines(text):
            words = line.split(None, 1)
            if not words:
                continue
            head = words[0].upper()
            body = words[1].strip() if len(words) > 1 else ""

            if head == "WORKDIR":
                workdir = _abs_in_image(shlex.split(body)[0], workdir)
            elif head == "COPY":
                self.copies.extend(self._parse_copy(body, workdir))
            elif head == "RUN":
                self.pip_commands.extend(self._parse_pip(body))
            elif head in {"CMD", "ENTRYPOINT"}:
                self.command = self._parse_command(head, body)
            elif head == "HEALTHCHECK":
                continue  # not the image command; see logical_lines
        self.workdir = workdir

    # -- COPY ------------------------------------------------------------
    def _parse_copy(self, body: str, workdir: str) -> list[tuple[str, str]]:
        parts = shlex.split(body)
        if any(p.startswith("--from") for p in parts if p.startswith("--")):
            raise AssertionError(
                f"{self.origin}: `COPY --from=` copies from a build stage, not the "
                f"repo, and this parser cannot resolve it: COPY {body!r}. Teach the "
                f"parser rather than letting the scope go unanalysed."
            )
        operands = [p for p in parts if not p.startswith("--")]
        if len(operands) < 2:
            return []
        dest_raw = operands[-1]
        dest_is_dir = dest_raw.endswith("/") or dest_raw in (".", "./")
        pairs: list[tuple[str, str]] = []
        for src in operands[:-1]:
            src_norm = src.rstrip("/")
            src_is_dir = src.endswith("/") or (_ROOT / src_norm).is_dir()
            dest = _abs_in_image(dest_raw, workdir)
            if not src_is_dir and dest_is_dir:
                dest = f"{dest.rstrip('/')}/{Path(src_norm).name}"
            pairs.append((src_norm, dest))
        return pairs

    # -- RUN pip install -------------------------------------------------
    def _parse_pip(self, body: str) -> list[list[str]]:
        """Every `pip install …` invocation inside one RUN, as token lists."""
        found: list[list[str]] = []
        for chunk in re.split(r"&&|;|\|\|", body):
            try:
                tokens = shlex.split(chunk)
            except ValueError as exc:
                raise AssertionError(
                    f"{self.origin}: could not tokenise RUN fragment {chunk!r} "
                    f"({exc}); a scope whose install command is unreadable has not "
                    f"been checked."
                ) from exc
            if not tokens:
                continue
            lowered = [t.lower() for t in tokens]
            if "install" not in lowered:
                continue
            if not any(Path(t).name in {"pip", "pip3"} or t == "pip" for t in tokens):
                continue
            found.append(tokens[lowered.index("install") + 1 :])
        return found

    # -- CMD / ENTRYPOINT ------------------------------------------------
    def _parse_command(self, head: str, body: str) -> list[str]:
        if body.startswith("["):
            # Exec form is JSON, but json is stdlib-cheap and shlex would eat the
            # brackets; parse with ast.literal_eval to stay in the stdlib set the
            # module already imports.
            try:
                parsed = ast.literal_eval(body)
            except (ValueError, SyntaxError) as exc:
                raise AssertionError(
                    f"{self.origin}: could not parse exec-form {head}: {body!r} ({exc})"
                ) from exc
            return [str(t) for t in parsed]
        return shlex.split(body)


def entry_module_from_command(command: list[str], origin: str) -> str:
    """The Python module a container command starts.

    Recognises the forms this repo ships and REFUSES anything else: a form we
    cannot read is a scope we have not checked, and a silent skip reports that as
    a pass.
    """
    tokens = [t for t in command if t not in {"sh", "-c", "bash"}]
    if not tokens:
        raise AssertionError(f"{origin}: empty container command")

    if Path(tokens[0]).name.startswith("python"):
        if "-m" in tokens:
            index = tokens.index("-m")
            if index + 1 < len(tokens):
                return tokens[index + 1]
        raise AssertionError(
            f"{origin}: python command {command!r} does not use `-m <module>`; the "
            f"entry module cannot be derived."
        )

    if Path(tokens[0]).name in {"uvicorn", "gunicorn", "hypercorn"}:
        for token in tokens[1:]:
            if token.startswith("-"):
                continue
            return token.split(":", 1)[0]

    raise AssertionError(
        f"{origin}: unrecognised entry-point form {command!r}. Extend "
        f"`entry_module_from_command` — do not leave the scope unchecked."
    )


# ---------------------------------------------------------------------------
# npm launcher parsing — the PRIMARY distribution, and its clone fallback
# ---------------------------------------------------------------------------

def launcher_entry_module(text: str) -> str:
    """The module the Node launcher spawns: `spawn(python, ["-m", "<module>"], …)`."""
    match = re.search(r"\[\s*[\"']-m[\"']\s*,\s*[\"']([\w.]+)[\"']\s*\]", text)
    if not match:
        raise AssertionError(
            f'{_NPM_LAUNCHER}: no `["-m", "<module>"]` spawn found. The npm bundle '
            f"is the PRIMARY distribution (`npx @arkheia/mcp-server`); if the "
            f"launcher was rewritten, teach this floor the new form rather than "
            f"silently checking nothing."
        )
    return match.group(1)


def launcher_requirements_candidates(text: str) -> tuple[str, str]:
    """The launcher's requirements ternary, read out of the launcher itself.

    `arkheia-mcp.js` resolves REQUIREMENTS as
    `<dir>/mcp_server/requirements.txt` if that exists, else `<dir>/requirements.txt`.
    Both arms are extracted and asserted against, so a change to either arm
    breaks this floor loudly instead of leaving the real install target
    unexamined.
    """
    block = re.search(
        r"REQUIREMENTS\s*=\s*(.*?);", text, re.DOTALL
    )
    if not block:
        raise AssertionError(
            f"{_NPM_LAUNCHER}: no `REQUIREMENTS = …` assignment found; the "
            f"dependency file the bundle installs cannot be derived."
        )
    # Three `path.join(PYTHON_DIR, …)` occurrences appear in the assignment: the
    # `fs.existsSync(...)` probe, then the two ternary arms. The probe comes first,
    # so first-seen is the PREFERRED candidate and the remaining distinct one is
    # the fallback — derived from the launcher's own control flow rather than
    # assumed.
    joins = re.findall(r"path\.join\(\s*PYTHON_DIR\s*,([^)]*)\)", block.group(1))
    ordered: list[str] = []
    for args in joins:
        segments = re.findall(r"[\"']([^\"']+)[\"']", args)
        if not segments:
            continue
        candidate = "/".join(segments)
        if candidate not in ordered:
            ordered.append(candidate)
    if len(ordered) != 2:
        raise AssertionError(
            f"{_NPM_LAUNCHER}: expected exactly two DISTINCT PYTHON_DIR-relative "
            f"requirements candidates in the REQUIREMENTS ternary, derived "
            f"{ordered!r}. Teach this floor the new form rather than letting the "
            f"npm distributions go unchecked."
        )
    return ordered[0], ordered[1]


def resolve_launcher_requirements(python_dir: Path, candidates: tuple[str, str]) -> Path:
    """Mirror the launcher's own existence check for a given PYTHON_DIR."""
    preferred, fallback = candidates
    if (_ROOT / python_dir / preferred).is_file():
        return python_dir / preferred
    resolved = python_dir / fallback
    if not (_ROOT / resolved).is_file():
        raise AssertionError(
            f"{_NPM_LAUNCHER}: neither {python_dir / preferred} nor {resolved} "
            f"exists, so `pip install -r` in the launcher would fail outright."
        )
    return resolved


def buildjs_bundle_dirs(text: str) -> list[tuple[str, str]]:
    """(repo source dir, bundle destination dir) the npm build script copies."""
    pairs: list[tuple[str, str]] = []
    for name, args in re.findall(
        r"(SRC|DEST)\s*=\s*path\.resolve\(\s*__dirname\s*,([^)]*)\)", text
    ):
        segments = re.findall(r"[\"']([^\"']+)[\"']", args)
        pairs.append((name, segments))
    lookup = dict(pairs)
    if set(lookup) != {"SRC", "DEST"}:
        raise AssertionError(
            f"{_NPM_BUILD_SCRIPT}: could not derive SRC/DEST from "
            f"`path.resolve(__dirname, …)`; derived {pairs!r}. The bundle's copy "
            f"set is unknown, so teach this floor rather than skipping it."
        )

    def _rel(segments: list[str]) -> str:
        # __dirname is npm-wrapper/scripts; ".." walks up.
        parts = list(_NPM_BUILD_SCRIPT.parent.parts)
        for segment in segments:
            if segment == "..":
                parts.pop()
            else:
                parts.append(segment)
        return "/".join(parts)

    return [(_rel(lookup["SRC"]), _rel(lookup["DEST"]))]


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------

class Scope:
    """One dependency boundary: what it installs, and what it runs."""

    def __init__(
        self,
        name: str,
        entry_module: str,
        requirements: list[Path],
        shipped_dirs: list[str],
        note: str = "",
    ):
        self.name = name
        self.entry_module = entry_module
        self.requirements = requirements
        self.shipped_dirs = shipped_dirs
        self.note = note

    # -- derived ---------------------------------------------------------
    def declared(self) -> set[str]:
        names: set[str] = set()
        for req in self.requirements:
            names |= declared_names_from_requirements(req)
        return names

    def checked_files(self) -> list[Path]:
        """Runtime files this scope ships, in the packages its entry point runs."""
        roots = reachable_first_party_roots(self.entry_module)
        shipped = {d.rstrip("/") for d in self.shipped_dirs}
        files: list[Path] = []
        for root in sorted(roots):
            if not any(root == s or root.startswith(s + "/") or s == "." for s in shipped):
                continue
            files.extend(runtime_files_under(Path(root)))
        return sorted(set(files))

    def gaps(self, declared: set[str] | None = None) -> dict[str, list[str]]:
        """{undeclared top-level module: [importing files]} for this scope."""
        allowed = self.declared() if declared is None else declared
        found: dict[str, list[str]] = {}
        for rel in self.checked_files():
            for module in imported_modules(rel):
                top = module.split(".")[0]
                if (
                    not top
                    or top == "__future__"
                    or top in _STDLIB
                    or top in _FIRST_PARTY_ROOTS
                    or top in allowed
                ):
                    continue
                found.setdefault(top, []).append(rel.as_posix())
        return {k: sorted(set(v)) for k, v in found.items()}

    def __repr__(self) -> str:  # pragma: no cover - test ids only
        return self.name


def dockerfile_paths() -> list[Path]:
    """Every Dockerfile in the tree — glob-discovered, never listed."""
    found: list[Path] = []
    for path in _ROOT.rglob("Dockerfile*"):
        rel = path.relative_to(_ROOT)
        if any(part in _SKIP_DIRS for part in rel.parts):
            continue
        if path.is_file():
            found.append(rel)
    return sorted(found)


def _requirements_from_pip_commands(facts: DockerfileFacts) -> list[Path]:
    """Resolve every `-r <path>` a Dockerfile installs back to a repo file."""
    reverse_copy = {dest: src for src, dest in facts.copies}
    resolved: list[Path] = []
    for tokens in facts.pip_commands:
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token in ("-r", "--requirement"):
                if index + 1 >= len(tokens):
                    raise AssertionError(
                        f"{facts.origin}: `pip install -r` with no target."
                    )
                target = _abs_in_image(tokens[index + 1], facts.workdir)
                src = reverse_copy.get(target)
                if src is None:
                    raise AssertionError(
                        f"{facts.origin}: installs `-r {tokens[index + 1]}` "
                        f"(= {target} in-image) but no COPY in this Dockerfile "
                        f"explains where that file came from, so the declared "
                        f"dependency set cannot be derived. Teach the parser — an "
                        f"unresolvable requirements target is not a pass."
                    )
                resolved.append(Path(src))
                index += 2
                continue
            index += 1
    return resolved


def _inline_dists_from_pip_commands(facts: DockerfileFacts) -> set[str]:
    """Bare package names a Dockerfile pip-installs inline (no requirements file)."""
    inline: set[str] = set()
    for tokens in facts.pip_commands:
        skip_next = False
        for token in tokens:
            if skip_next:
                skip_next = False
                continue
            if token in ("-r", "--requirement", "--index-url", "-i", "--extra-index-url"):
                skip_next = True
                continue
            if token.startswith("-"):
                continue
            name = leading_dist_token(token)
            if name:
                inline.add(name)
    return inline


def discover_scopes() -> list[Scope]:
    scopes: list[Scope] = []

    for rel in dockerfile_paths():
        facts = DockerfileFacts(rel)
        entry = entry_module_from_command(facts.command, facts.origin)
        requirements = _requirements_from_pip_commands(facts)
        inline = _inline_dists_from_pip_commands(facts)
        shipped = [src for src, _dest in facts.copies]

        scope = Scope(rel.as_posix(), entry, requirements, shipped)
        if inline:
            # An inline `pip install fastapi pyyaml …` is a dependency declaration
            # living in a Dockerfile literal: invisible to pip-audit, Snyk and
            # Aikido (which read requirements files) and free to drift from every
            # sibling pin. It is admitted into `declared` so this floor does not
            # cry wolf, and `test_no_dependency_declaration_hides_in_a_dockerfile`
            # fails on it separately.
            scope.inline_dists = inline  # type: ignore[attr-defined]
        else:
            scope.inline_dists = set()  # type: ignore[attr-defined]
        scope.copied_requirements = [  # type: ignore[attr-defined]
            src for src, _dest in facts.copies if Path(src).name.startswith("requirements")
        ]
        scopes.append(scope)

    launcher_text = (_ROOT / _NPM_LAUNCHER).read_text(encoding="utf-8")
    build_text = (_ROOT / _NPM_BUILD_SCRIPT).read_text(encoding="utf-8")
    entry = launcher_entry_module(launcher_text)
    candidates = launcher_requirements_candidates(launcher_text)

    # (1) the published bundle: `npx @arkheia/mcp-server` runs from npm-wrapper/python.
    bundle_src, bundle_dest = buildjs_bundle_dirs(build_text)[0]
    bundle = Scope(
        f"{_NPM_BUILD_SCRIPT.as_posix()} (published bundle)",
        entry,
        [resolve_launcher_requirements(_NPM_BUNDLE_DIR, candidates)],
        [bundle_src],
        note=f"bundle copies {bundle_src} -> {bundle_dest}",
    )
    bundle.inline_dists = set()  # type: ignore[attr-defined]
    bundle.copied_requirements = []  # type: ignore[attr-defined]
    scopes.append(bundle)

    # (2) the clone fallback the launcher performs when the bundle has no server
    #     code: the WHOLE repo on PYTHONPATH, with only the resolved requirements
    #     file installed. Shipped set is the repo; the checked set is still only
    #     what the entry module reaches, which is what keeps `proxy`'s deps out.
    clone = Scope(
        f"{_NPM_LAUNCHER.as_posix()} (git-clone fallback)",
        entry,
        [resolve_launcher_requirements(Path("."), candidates)],
        ["."],
        note="launcher clones the repo to ~/.arkheia/mcp and runs it in place",
    )
    clone.inline_dists = set()  # type: ignore[attr-defined]
    clone.copied_requirements = []  # type: ignore[attr-defined]
    scopes.append(clone)

    return scopes


SCOPES = discover_scopes()


def _declared_with_inline(scope: Scope) -> set[str]:
    names = scope.declared()
    for dist in getattr(scope, "inline_dists", set()):
        names |= dist_to_import_names(dist)
    return names


# ---------------------------------------------------------------------------
# WORK-DONE GUARDS — every invariant below passes by finding nothing
# ---------------------------------------------------------------------------

def test_the_discovery_reached_every_distribution_on_disk():
    """
    The invariants below all assert "no gaps", which is also what a discovery that
    found no scopes returns. So the units of work are named and counted first: if
    a Dockerfile stops being discovered, or the npm distributions drop out, this
    fails rather than the gate going quietly vacuous.
    """
    names = [s.name for s in SCOPES]
    dockerfiles = [p.as_posix() for p in dockerfile_paths()]

    assert dockerfiles, "no Dockerfile discovered anywhere in the repo"
    assert set(dockerfiles) <= set(names), (
        f"Dockerfiles on disk that no scope covers: "
        f"{sorted(set(dockerfiles) - set(names))}"
    )
    npm_scopes = [n for n in names if "npm-wrapper" in n]
    assert len(npm_scopes) == 2, (
        f"expected two npm distributions (published bundle + git-clone fallback), "
        f"found {npm_scopes}"
    )
    assert len(names) == len(dockerfiles) + 2, (
        f"scope count {len(names)} does not match {len(dockerfiles)} Dockerfile(s) "
        f"+ 2 npm distributions: {names}"
    )


def test_every_requirements_file_governs_a_discovered_scope():
    """
    A requirements file no scope installs is either dead weight or — the dangerous
    case — the file someone will edit believing it governs a deployment. Both are
    reported by name rather than assumed harmless.
    """
    # `*requirements*.txt`, not `requirements*.txt`: the narrower glob silently
    # missed `dev-requirements.txt`-style names, which was caught by running this
    # very check against a synthetic orphan. A discovery glob that cannot see a
    # file cannot report it as unowned.
    on_disk = sorted(
        p.relative_to(_ROOT).as_posix()
        for p in _ROOT.rglob("*requirements*.txt")
        if not any(part in _SKIP_DIRS for part in p.relative_to(_ROOT).parts)
    )
    installed = {
        req.as_posix() for scope in SCOPES for req in scope.requirements
    }
    assert on_disk, "no requirements file found anywhere in the repo"
    orphans = sorted(set(on_disk) - installed)
    assert not orphans, (
        f"requirements file(s) that NO discovered scope installs: {orphans}. Either "
        f"a distribution was missed by discovery (this floor is then checking less "
        f"than it claims), or the file is dead and should be deleted — an unowned "
        f"dependency file is a trap for the next editor. Installed by some scope: "
        f"{sorted(installed)}"
    )


def test_every_first_party_package_is_run_by_a_scope():
    """
    A first-party package no scope's entry point reaches has its imports checked
    by nothing. That is exactly the state `proxy/crypto` was in for the axis that
    mattered, so it is named rather than tolerated.
    """
    covered: set[str] = set()
    for scope in SCOPES:
        covered |= {p.parts[0] for p in scope.checked_files()}
    unreached = sorted(_FIRST_PARTY_ROOTS - covered)
    assert not unreached, (
        f"first-party package(s) whose imports no scope checks: {unreached}. Either "
        f"a distribution runs them and discovery missed it, or they are dead code. "
        f"Checked packages: {sorted(covered)}"
    )


@pytest.mark.parametrize("scope", SCOPES, ids=lambda s: s.name)
def test_each_scope_resolves_a_declared_set_and_a_checked_set(scope):
    """
    Per-scope work-done guard, named per unit rather than as an aggregate: a run in
    which one of five scopes silently analysed nothing must be visible as THAT
    scope, not folded into a total that looks right (DONE.md clause 9a).
    """
    assert scope.entry_module, f"{scope.name}: no entry module derived"
    assert _declared_with_inline(scope), (
        f"{scope.name}: derived an EMPTY declared dependency set — the pip install "
        f"command was not understood, and an empty set makes every import a gap or "
        f"none of them. Requirements resolved: {[r.as_posix() for r in scope.requirements]}"
    )
    assert module_to_file(scope.entry_module) is not None, (
        f"{scope.name}: entry module {scope.entry_module!r} resolves to no file on "
        f"disk, so the import walk starts nowhere."
    )
    checked = scope.checked_files()
    assert checked, (
        f"{scope.name}: the import walk from {scope.entry_module} over shipped set "
        f"{scope.shipped_dirs} selected no runtime file to check."
    )
    third_party = {
        m.split(".")[0]
        for rel in checked
        for m in imported_modules(rel)
        if m.split(".")[0] not in _STDLIB
        and m.split(".")[0] not in _FIRST_PARTY_ROOTS
        and m.split(".")[0] != "__future__"
    }
    assert third_party, (
        f"{scope.name}: not one third-party import found across {len(checked)} "
        f"checked file(s) — the import extraction is describing nothing, so a "
        f"missing declaration could not be seen."
    )


# ---------------------------------------------------------------------------
# THE INVARIANT
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scope", SCOPES, ids=lambda s: s.name)
def test_every_scope_declares_every_third_party_module_it_imports(scope):
    gaps = scope.gaps(_declared_with_inline(scope))
    detail = "\n".join(
        f"    {module}  <- {', '.join(files[:3])}" for module, files in sorted(gaps.items())
    )
    assert not gaps, (
        f"{scope.name} imports {len(gaps)} third-party module(s) it does NOT "
        f"install — a latent ModuleNotFoundError in that distribution, invisible in "
        f"a checkout or a CI runner that happens to have the package:\n{detail}\n"
        f"  installs: {[r.as_posix() for r in scope.requirements]}\n"
        f"Declare each (pinned, with the CVE note this repo's convention uses) in "
        f"that file — or remove the import. Do not add an ad-hoc `pip install` line "
        f"to CI: that hides the gap instead of closing it."
    )


def test_no_dependency_declaration_hides_in_a_dockerfile():
    """
    A dependency set written as a `RUN pip install a b c` literal is a declaration
    that no dependency scanner reads. pip-audit, Snyk and Aikido all consume
    requirements files, so an inline list ships un-scanned and drifts from every
    sibling CVE pin. It is also the shape that makes `COPY requirements.txt .`
    followed by an inline install look correct while installing something else.
    """
    offenders: dict[str, dict[str, object]] = {}
    for scope in SCOPES:
        inline = getattr(scope, "inline_dists", set())
        if inline:
            offenders[scope.name] = {
                "inline": sorted(inline),
                "copied_but_maybe_unused": getattr(scope, "copied_requirements", []),
            }
    assert not offenders, (
        f"{len(offenders)} distribution(s) declare dependencies as a bare `pip "
        f"install` literal instead of a requirements file, so no dependency "
        f"scanner sees them: {offenders}. Move the list into a requirements file "
        f"for that distribution and install it with `-r`."
    )


# ---------------------------------------------------------------------------
# PROVE THE CHECK CAN FAIL — derived, not hard-coded to a known-bad path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("scope", SCOPES, ids=lambda s: s.name)
def test_dropping_a_real_declaration_is_detected(scope):
    """
    The invariant above passes by finding an empty set, which is also what a broken
    derivation returns. So run the SAME gap function against a deliberately broken
    declared set for this scope — its real set minus one name that a checked file
    genuinely imports — and require the gap to be named.

    Derived from the scope's own data: no module name is written down here, so this
    control cannot rot into a test of a dependency that no longer matters. This is
    the mechanised form of the manual red-proof (remove `cryptography` from
    `proxy/requirements.txt`, watch the floor name it).
    """
    declared = _declared_with_inline(scope)
    imported_tops = {
        m.split(".")[0] for rel in scope.checked_files() for m in imported_modules(rel)
    }
    load_bearing = sorted(declared & imported_tops)
    assert load_bearing, (
        f"{scope.name}: no declared name is actually imported by a checked file, so "
        f"this control has nothing to break — the declared set and the import graph "
        f"are describing different things."
    )

    for name in load_bearing:
        gaps = scope.gaps(declared - {name})
        assert name in gaps, (
            f"{scope.name}: removing {name!r} from the declared set did NOT surface "
            f"it as a gap, so the check cannot see a missing declaration."
        )


@pytest.mark.parametrize("scope", SCOPES, ids=lambda s: s.name)
def test_an_empty_declared_set_is_detected(scope):
    """A scope that installs nothing must not read as fully declared."""
    gaps = scope.gaps(set())
    assert gaps, (
        f"{scope.name}: a declared set of NOTHING reported no undeclared imports — "
        f"the gap function is not looking at this scope's files."
    )


@pytest.mark.parametrize("scope", SCOPES, ids=lambda s: s.name)
def test_a_lazily_imported_undeclared_module_is_detected(scope):
    """
    THE REAL DEFECT, reproduced against this scope's own files.

    `proxy/main.py` reaches `proxy/crypto/profile_crypto.py` — and therefore
    `cryptography` — only through a function-level import inside a conditional
    branch. A floor that walked only module-level imports would have called this
    repo clean. Here that shape is synthesised against a REAL checked file of this
    scope: the file's own source is appended with a deferred, conditionally
    guarded, dotted import of a package nothing declares, and the gap function
    must name it.
    """
    checked = scope.checked_files()
    assert checked, f"{scope.name}: nothing to check — see the work-done guard"

    sentinel = "zzz_undeclared_sentinel_pkg"
    victim = checked[0]
    spliced = (_ROOT / victim).read_text(encoding="utf-8-sig") + (
        "\n\n"
        "def _floor_probe():\n"
        "    if False:\n"
        "        try:\n"
        f"            from {sentinel}.deep.mod import Thing\n"
        "        except ImportError:\n"
        "            raise\n"
    )

    tops = {m.split(".")[0] for m in imports_in_source(spliced, victim)}
    assert sentinel in tops, (
        f"{scope.name}: a function-level, conditionally guarded, dotted import of "
        f"{sentinel!r} spliced into {victim.as_posix()} was NOT extracted. The "
        f"extraction cannot see deferred imports, which is the exact mechanism "
        f"that hid both incidents this floor exists for."
    )
    assert sentinel not in _declared_with_inline(scope), (
        f"{scope.name}: the sentinel name collides with a real declaration"
    )


def test_floor_uses_only_stdlib_and_pytest():
    """
    The floor tier installs pytest and nothing else. A floor that needed a project
    dependency could not run in the tier whose job is to be independent of them —
    and would be unable to judge a repo whose dependencies do not install.
    """
    tops = {m.split(".")[0] for m in imported_modules(Path(__file__).relative_to(_ROOT))}
    extra = sorted(t for t in tops if t not in _STDLIB and t not in {"__future__", "pytest"})
    assert not extra, (
        f"the declared-dependency floor must import only the standard library and "
        f"pytest, but imports: {extra}"
    )
