"""
`--version` on the npm launcher prints the package version and exits.

Before this, `npx @arkheia/mcp-server --version` ignored the flag and started
the stdio MCP server, which reads standard input until it closes. A shell
script that called it while being read from standard input (`curl ... | bash`)
lost the rest of its own text to the server. `--version` (and `-v`) must print
the version from npm-wrapper/package.json, exit 0, and do nothing else: no
standard-input read, no Python lookup, no virtual environment, no runtime
directory.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import npm_bundle  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_PACKAGE = _ROOT / "npm-wrapper"
_LAUNCHER = _PACKAGE / "bin" / "arkheia-mcp.js"


def _version() -> str:
    return json.loads((_PACKAGE / "package.json").read_text(encoding="utf-8"))["version"]


def _fake_commands(tmp_path: Path) -> tuple[Path, Path]:
    """python3/python/pip that only record that they were run."""
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    log = tmp_path / "commands.log"
    for name in ("python3", "python", "pip", "pip3"):
        path = fakebin / name
        path.write_text(
            f"#!/bin/sh\necho \"{name} $*\" >> '{log}'\nexit 1\n", encoding="utf-8"
        )
        path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return fakebin, log


def _run(tmp_path: Path, *args: str) -> tuple[int, str, str, Path, Path]:
    fakebin, log = _fake_commands(tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "PATH": f"{fakebin}{os.pathsep}{os.environ.get('PATH', '')}",
    }
    env.pop("ARKHEIA_API_KEY", None)
    # Standard input is a pipe that this test never writes to and never closes
    # until the launcher has exited. A launcher that starts the server would
    # block on it, so the timeout below fails the test instead of hanging.
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, test-controlled paths
        [npm_bundle.require_node(), str(_LAUNCHER), *args],
        cwd=tmp_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        out, err = _wait(proc)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    return proc.returncode, out, err, home, log


def _wait(proc: subprocess.Popen) -> tuple[str, str]:
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        pytest.fail(
            "the launcher was still running 15 s after --version with standard input "
            f"held open (it started the server).\nstdout: {out!r}\nstderr: {err!r}"
        )
    return proc.stdout.read(), proc.stderr.read()


@pytest.mark.parametrize("flag", ["--version", "-v"])
def test_version_flag_prints_package_version_and_exits(tmp_path, flag):
    rc, out, err, home, log = _run(tmp_path, flag)

    assert rc == 0, f"exit {rc}; stderr: {err!r}"
    assert out == _version() + "\n"
    assert err == ""
    assert not log.exists(), f"--version ran Python or pip: {log.read_text()}"
    assert not (home / ".arkheia").exists(), "--version created the runtime directory"


def test_version_flag_wins_wherever_it_appears(tmp_path):
    rc, out, _err, _home, log = _run(tmp_path, "--stdio", "--version")

    assert rc == 0
    assert out == _version() + "\n"
    assert not log.exists()


def test_version_check_can_fail_without_the_flag(tmp_path):
    """Control: with no flag the launcher does NOT print the version and exit 0.

    Here the fake Python makes it stop with an error, so a check that passed by
    accident (for example, by matching any exit 0) would show up as a failure.
    """
    rc, out, _err, _home, log = _run(tmp_path)

    assert out != _version() + "\n"
    assert rc != 0
