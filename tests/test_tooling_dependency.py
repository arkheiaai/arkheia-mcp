"""
INVARIANT — every pytest option this repo passes is provided either by core pytest
or by a plugin whose distribution is DECLARED in a requirements file.

Runs in the `unit-tests` job, NOT the floor tier, and that placement is the
design. Answering "which distribution provides `--timeout`?" without writing down
a flag→package table means asking the real pytest, which means the plugins have to
be installed. The floor tier deliberately installs pytest and nothing else, so this
check would be structurally unable to answer there — and a check that cannot
observe must not be run somewhere it will fail for the wrong reason.

────────────────────────────────────────────────────────────────────────────────
THE DEFECT THAT EARNED THIS
────────────────────────────────────────────────────────────────────────────────
`tools/mutate_f18_integrity_manifest.py` runs its mutation harness with
`--timeout=180`. `requirements.txt` declared `pytest` and `pytest-asyncio` and
nothing else, so in an environment built from our own declared files the harness
refuses to start:

    pytest: error: unrecognized arguments: --timeout=180

It is not a runtime defect — nothing a customer runs is affected. It is an
EVIDENCE-REPRODUCIBILITY defect, which is worse in a specific way: the harness is
how we prove 19/19 mutants are killed, and that proof could not be re-derived from
the environment we declare. CI hid it, because both workflows carried a bare
`pip install … pytest-timeout` line beside the `-r requirements.txt` ones. That is
the same masking that hid the undeclared `cryptography` import — a green run that
says nothing about what a declared install would contain.

────────────────────────────────────────────────────────────────────────────────
WHY THIS IS A SEPARATE FLOOR, NOT AN EXTENSION OF #27
────────────────────────────────────────────────────────────────────────────────
`tests/test_declared_dependency_floor.py` (PR #27) owns the adjacent axis and
draws its boundary explicitly: *"Test-only dependencies are out of scope: test
files are not runtime code, so `pytest`, `respx` and `locust` are not required to
be declared here."* It asks whether a SHIPPED DISTRIBUTION declares what its
RUNTIME code imports. This defect is in neither half — the consumer is a tool, not
a distribution, and the dependency is used through a command-line flag, not an
import, so no import-graph walk can see it at all. Restating #27's axis here would
duplicate it; this covers the gap it names.

────────────────────────────────────────────────────────────────────────────────
WHAT IS DERIVED
────────────────────────────────────────────────────────────────────────────────
USED      — pytest invocations discovered across the repo: Python argv lists,
            workflow/shell command lines, and `pytest.ini` `addopts`.
CORE      — options core pytest accepts, probed with plugin autoload DISABLED.
            Nothing is written down about which options are built in.
PROVIDER  — for each non-core option, the installed `pytest11` plugin that makes
            pytest accept it, found by re-probing with that plugin alone. The
            distribution name comes from the entry point's own metadata.
DECLARED  — distribution names parsed out of every `requirements*.txt` in the
            tree, normalised per PEP 503.

Every unresolvable case FAILS: an option no core pytest and no installed plugin
accepts cannot be shown to be declared, and "not observed" must not land in the
pass bucket (DONE.md floor-ledger clause 9d).

FALSE-POSITIVE-FREE: the assertion is that a flag this repo actually passes comes
from a package this repo actually declares. A declared-but-unused plugin is never
flagged, and an option core pytest accepts needs no declaration beyond `pytest`.
"""

from __future__ import annotations

import ast
import os
import re
import shlex
import subprocess
import sys
from importlib.metadata import entry_points
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

_SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache"}
)

#: Files that can carry a pytest invocation. `.cfg`/`.toml` are included because
#: `addopts` can live in `setup.cfg` / `pyproject.toml` as well as `pytest.ini`.
_SCANNED_SUFFIXES = frozenset({".py", ".yml", ".yaml", ".ini", ".cfg", ".toml", ".sh"})


def _walk() -> list[Path]:
    found: list[Path] = []
    for path in _ROOT.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.relative_to(_ROOT).parts):
            continue
        if path.is_file() and (
            path.suffix in _SCANNED_SUFFIXES or path.name == "Makefile"
        ):
            found.append(path)
    return sorted(found)


def _options_from_tokens(tokens: list[str]) -> set[str]:
    """Long options from a token list, `--opt=value` reduced to `--opt`."""
    return {t.split("=", 1)[0] for t in tokens if t.startswith("--") and len(t) > 2}


def _logical_lines(text: str) -> list[tuple[int, str]]:
    """
    Physical lines joined across trailing backslashes, keyed by their FIRST line.

    Not a nicety. `unit-tests.yml` writes its run block as

        pytest \\
          proxy/tests \\
          -v --timeout=120

    so a per-physical-line scan sees `pytest` with no options and `--timeout=120`
    with no `pytest`, and reports a clean repo while missing the invocation that
    matters most. The first draft of this file did exactly that, and only the
    single-line smoke-test job was found — which is why the work-done guard below
    counts invocations rather than trusting an empty result.
    """
    joined: list[tuple[int, str]] = []
    buffer: list[str] = []
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not buffer:
            start = number
        if line.rstrip().endswith("\\"):
            buffer.append(line.rstrip()[:-1])
            continue
        buffer.append(line)
        joined.append((start, " ".join(part.strip() for part in buffer)))
        buffer = []
    if buffer:
        joined.append((start, " ".join(part.strip() for part in buffer)))
    return joined


def _invocations() -> dict[str, set[str]]:
    """
    Map `<file>:<line>` -> the long options that invocation passes.

    Three shapes, because this repo uses all three:
      * a Python list literal beginning `[sys.executable, "-m", "pytest", …]`
      * a command line whose first word is `pytest` (workflows, shell, Makefile)
      * `addopts = …` in an ini/cfg
    """
    found: dict[str, set[str]] = {}

    for path in _walk():
        rel = path.relative_to(_ROOT).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue

        if path.suffix == ".py":
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, (ast.List, ast.Tuple)):
                    continue
                literals = [
                    e.value for e in node.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                if "-m" in literals and "pytest" in literals:
                    options = _options_from_tokens(literals)
                    if options:
                        found[f"{rel}:{node.lineno}"] = options
            continue

        for number, line in _logical_lines(text):
            stripped = line.strip()

            if stripped.startswith("addopts"):
                _, _, value = stripped.partition("=")
                options = _options_from_tokens(shlex.split(value, comments=True))
                if options:
                    found[f"{rel}:{number}"] = options
                continue

            if not re.search(r"(^|[\s;&|])(python\S*\s+-m\s+)?pytest\s", stripped):
                continue
            body = stripped.lstrip("-").lstrip()
            body = re.sub(r"^run:\s*", "", body)
            try:
                tokens = shlex.split(body, comments=True)
            except ValueError:
                tokens = body.split()
            options = _options_from_tokens(tokens)
            if options:
                found[f"{rel}:{number}"] = options

    return found


def _probe(option: str, plugin: str | None, tmp: Path) -> bool:
    """
    Does a pytest with autoload DISABLED (plus `plugin`, if given) accept `option`?

    Autoload off is what makes the answer meaningful: with it on, every installed
    plugin is active and every option looks built in, which is precisely the
    illusion the ad-hoc `pip install` lines created in CI.
    """
    argv = [sys.executable, "-m", "pytest", "--collect-only", "-q"]
    if plugin:
        argv += ["-p", plugin]
    argv += [option, str(tmp)]

    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env.pop("PYTEST_ADDOPTS", None)

    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        argv, capture_output=True, text=True, timeout=180, env=env, cwd=str(tmp)
    )
    return "unrecognized arguments" not in (result.stderr + result.stdout)


def _declared_distributions() -> dict[str, str]:
    """Normalised distribution name -> the requirements file declaring it."""
    declared: dict[str, str] = {}
    for path in _ROOT.rglob("requirements*.txt"):
        if any(part in _SKIP_DIRS for part in path.relative_to(_ROOT).parts):
            continue
        rel = path.relative_to(_ROOT).as_posix()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith("-"):
                continue
            name = re.split(r"[<>=!~\[; ]", line, maxsplit=1)[0].strip()
            if name:
                declared.setdefault(re.sub(r"[-_.]+", "-", name).lower(), rel)
    return declared


def test_the_scan_found_pytest_invocations_to_check():
    """
    WORK-DONE GUARD. The invariant below passes by finding no undeclared option,
    which is also what a scan that matched nothing returns. Name the units first.
    """
    invocations = _invocations()
    assert invocations, (
        "no pytest invocation carrying a long option was found anywhere in the "
        "repo. The CI workflows alone pass several, so the scanner is matching "
        "nothing and this file is examining nothing."
    )
    options = set().union(*invocations.values())
    assert options, f"invocations found ({sorted(invocations)}) but no options in any"


def test_every_pytest_option_used_here_comes_from_a_declared_package(tmp_path):
    """
    THE INVARIANT. A flag we pass must come from a package we declare — otherwise
    the command works only in an environment nobody wrote down, and the evidence it
    produces cannot be re-derived.
    """
    invocations = _invocations()
    used: dict[str, list[str]] = {}
    for where, options in invocations.items():
        for option in options:
            used.setdefault(option, []).append(where)

    empty = tmp_path / "nothing-to-collect"
    empty.mkdir()

    core = {option for option in used if _probe(option, None, empty)}
    non_core = sorted(set(used) - core)

    plugins = {
        entry.value: getattr(getattr(entry, "dist", None), "name", None)
        for entry in entry_points(group="pytest11")
    }

    undeclared: list[str] = []
    unresolved: list[str] = []
    declared = _declared_distributions()

    for option in non_core:
        provider = next(
            (
                module
                for module in sorted(plugins)
                if _probe(option, module, empty)
            ),
            None,
        )
        if provider is None:
            unresolved.append(
                f"{option}  (passed at {', '.join(sorted(used[option]))}) — no core "
                f"pytest option and no installed plugin of "
                f"{sorted(plugins) or 'NONE'} accepts it"
            )
            continue

        distribution = plugins[provider]
        if distribution is None:
            unresolved.append(
                f"{option}  provided by plugin module {provider!r}, whose "
                f"distribution metadata is unreadable, so it cannot be matched "
                f"against any requirements file"
            )
            continue

        normalised = re.sub(r"[-_.]+", "-", distribution).lower()
        if normalised not in declared:
            undeclared.append(
                f"{option}  needs {distribution} (plugin {provider}) — declared in "
                f"NO requirements file; passed at {', '.join(sorted(used[option]))}"
            )

    assert not unresolved, (
        "a pytest option used in this repo could not be attributed to any package, "
        "so it cannot be shown to be declared:\n"
        + "\n".join(f"    {u}" for u in unresolved)
        + "\nAn unattributable flag is not a pass. If a plugin was removed, remove "
        "the flag with it; if this scanner is misreading a command line, teach it."
    )
    assert not undeclared, (
        f"{len(undeclared)} pytest option(s) come from packages this repo declares "
        f"nowhere:\n"
        + "\n".join(f"    {u}" for u in undeclared)
        + "\n\nIn an environment built only from our declared requirements the "
        "command fails with `unrecognized arguments`, so the evidence it produces "
        "cannot be re-derived from what we publish. Declare the package — a bare "
        "`pip install` line in a workflow masks the gap instead of closing it."
    )


def test_the_probe_can_tell_a_missing_plugin_from_a_present_one(tmp_path):
    """
    PROVE THE CHECK CAN FAIL. The invariant above rests entirely on `_probe`
    distinguishing "pytest accepts this" from "pytest rejects this". If the probe
    always returned True — a swallowed subprocess error, a changed pytest message —
    every option would look core and nothing could ever be reported.

    So drive it both ways with an option that cannot exist.
    """
    empty = tmp_path / "nothing-to-collect"
    empty.mkdir()

    impossible = "--arkheia-floor-option-that-does-not-exist"
    assert not _probe(impossible, None, empty), (
        f"the probe reported that core pytest accepts {impossible!r}. It cannot "
        f"distinguish a recognised option from an unrecognised one, so every "
        f"assertion built on it is vacuous."
    )
    assert _probe("--tb", None, empty), (
        "the probe reported that core pytest does NOT accept `--tb`, which is a "
        "built-in option. It is rejecting everything, so it would attribute core "
        "options to plugins."
    )
