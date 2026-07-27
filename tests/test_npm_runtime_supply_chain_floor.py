"""
Runtime floor for the npm launcher bootstrap path.

The packaging floor proves the tarball contains the bundled server. This file
checks the next step: the launcher must trust those package bytes, fail closed
when they are absent or tampered, and bound dependency installation to the
verified package-owned requirements file. No test here performs a real network
operation; fake commands are placed first on PATH and record any attempted use.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import import_closure, npm_bundle  # noqa: E402

_ROOT = import_closure.REPO_ROOT
_PROVENANCE = ".arkheia-bundle-provenance.json"


def _packed_package(tmp_path: Path) -> Path:
    package_dir = _ROOT / npm_bundle.PACKAGE_DIR
    bundle_root = npm_bundle.bundle_root(_ROOT)
    bundle_dir = package_dir / bundle_root
    entry_module = npm_bundle.launcher_entry_module(_ROOT)
    first_party = import_closure.first_party_roots(_ROOT)
    closure = import_closure.required_files((entry_module,), _ROOT, first_party)
    generated_roots = {p.parts[0] for p in closure}

    with npm_bundle.tree_restored(bundle_dir):
        npm_bundle.prune_generated(bundle_dir, generated_roots)
        tarball = npm_bundle.pack(package_dir, tmp_path / "tgz")
        return npm_bundle.extract(tarball, tmp_path / "extracted")


def _base_env(tmp_path: Path, fakebin: Path, log: Path) -> dict[str, str]:
    home = tmp_path / "home"
    return {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "ARKHEIA_API_KEY": "ak_test_runtime_floor",
        "ARKHEIA_TEST_LOG": str(log),
        "PATH": str(fakebin) + os.pathsep + os.environ.get("PATH", ""),
    }


def _write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _write_forbidden_git(fakebin: Path) -> None:
    script = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import json
        import os
        import pathlib
        import sys

        log = pathlib.Path(os.environ["ARKHEIA_TEST_LOG"])
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({{"kind": "forbidden_git", "argv": sys.argv[1:]}}) + "\\n")
        sys.exit(88)
        """
    )
    _write_executable(fakebin / "git", script)


def _write_fake_python(fakebin: Path) -> None:
    script = textwrap.dedent(
        f"""\
        #!{sys.executable}
        import json
        import os
        import pathlib
        import shutil
        import stat
        import sys

        def record(kind):
            log = pathlib.Path(os.environ["ARKHEIA_TEST_LOG"])
            log.parent.mkdir(parents=True, exist_ok=True)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({{
                    "kind": kind,
                    "argv": sys.argv[1:],
                    "cwd": os.getcwd(),
                    "env": {{
                        "PIP_DISABLE_PIP_VERSION_CHECK": os.environ.get("PIP_DISABLE_PIP_VERSION_CHECK"),
                        "PIP_NO_INPUT": os.environ.get("PIP_NO_INPUT"),
                        "PIP_REQUIRE_VIRTUALENV": os.environ.get("PIP_REQUIRE_VIRTUALENV"),
                        "PYTHONPATH": os.environ.get("PYTHONPATH"),
                        "PYTHONDONTWRITEBYTECODE": os.environ.get("PYTHONDONTWRITEBYTECODE"),
                    }},
                }}) + "\\n")

        argv = sys.argv[1:]
        if argv == ["--version"]:
            print("Python 3.11.8")
            sys.exit(0)

        if len(argv) == 3 and argv[:2] == ["-m", "venv"]:
            record("create_venv")
            venv = pathlib.Path(argv[2])
            bindir = venv / ("Scripts" if os.name == "nt" else "bin")
            bindir.mkdir(parents=True, exist_ok=True)
            target = bindir / ("python.exe" if os.name == "nt" else "python")
            shutil.copy2(pathlib.Path(__file__), target)
            target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            sys.exit(0)

        if len(argv) >= 3 and argv[:3] == ["-m", "pip", "install"]:
            record("pip_install")
            sys.exit(0)

        if argv == ["-m", "mcp_server.server"]:
            record("server")
            sys.stdin.read()
            sys.exit(0)

        record("unexpected_python")
        sys.exit(91)
        """
    )
    _write_executable(fakebin / "python3", script)
    shutil.copy2(fakebin / "python3", fakebin / "python")


def _run_launcher(package: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - node path and cwd are test-controlled
        [npm_bundle.require_node(), "bin/arkheia-mcp.js"],
        cwd=package,
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


def _events(log: Path) -> list[dict]:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


def test_launcher_fails_closed_when_bundled_server_code_is_absent(tmp_path):
    package = _packed_package(tmp_path)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    log = tmp_path / "events.jsonl"
    _write_forbidden_git(fakebin)

    (package / "python" / "mcp_server" / "server.py").unlink()
    result = _run_launcher(package, _base_env(tmp_path, fakebin, log))

    assert result.returncode != 0
    assert "bundled Python server code is missing" in result.stderr
    assert "refusing to fetch code at runtime" in result.stderr
    assert _events(log) == [], (
        "launcher executed a runtime bootstrap command instead of failing closed: "
        f"{_events(log)}"
    )
    assert not (tmp_path / "home" / ".arkheia" / "mcp").exists()
    assert not (tmp_path / "home" / ".arkheia" / "venv").exists()


def test_launcher_blocks_tampered_bundle_before_dependency_setup(tmp_path):
    package = _packed_package(tmp_path)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    log = tmp_path / "events.jsonl"
    _write_fake_python(fakebin)

    requirements = package / "python" / "requirements.txt"
    requirements.write_text(
        requirements.read_text(encoding="utf-8") + "\n# tampered\n",
        encoding="utf-8",
    )
    result = _run_launcher(package, _base_env(tmp_path, fakebin, log))

    assert result.returncode != 0
    assert "bundle provenance hash mismatch for requirements.txt" in result.stderr
    assert _events(log) == [], (
        "launcher reached Python setup before verifying package-content provenance: "
        f"{_events(log)}"
    )
    assert not (tmp_path / "home" / ".arkheia" / "venv").exists()


def test_dependency_install_is_bounded_to_verified_package_requirements(tmp_path):
    package = _packed_package(tmp_path)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    log = tmp_path / "events.jsonl"
    _write_fake_python(fakebin)
    _write_forbidden_git(fakebin)

    env = _base_env(tmp_path, fakebin, log)
    first = _run_launcher(package, env)
    second = _run_launcher(package, env)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr

    events = _events(log)
    assert [e["kind"] for e in events].count("forbidden_git") == 0
    assert [e["kind"] for e in events].count("create_venv") == 1
    assert [e["kind"] for e in events].count("pip_install") == 1
    assert [e["kind"] for e in events].count("server") == 2

    pip_event = next(e for e in events if e["kind"] == "pip_install")
    pip_args = pip_event["argv"]
    assert pip_args[:3] == ["-m", "pip", "install"]
    assert "git+https://github.com/arkheiaai/arkheia-mcp.git" not in pip_args
    assert "mcp_server/requirements.txt" not in " ".join(pip_args)
    req_index = pip_args.index("-r")
    assert Path(pip_args[req_index + 1]) == package / "python" / "requirements.txt"
    assert pip_event["env"]["PIP_DISABLE_PIP_VERSION_CHECK"] == "1"
    assert pip_event["env"]["PIP_NO_INPUT"] == "1"
    assert pip_event["env"]["PIP_REQUIRE_VIRTUALENV"] == "1"

    server_event = next(e for e in events if e["kind"] == "server")
    assert Path(server_event["cwd"]) == package / "python"
    assert Path(server_event["env"]["PYTHONPATH"]) == package / "python"
    assert server_event["env"]["PYTHONDONTWRITEBYTECODE"] == "1"

    provenance = json.loads(
        (package / "python" / _PROVENANCE).read_text(encoding="utf-8")
    )
    req_hash = next(
        entry["sha256"]
        for entry in provenance["files"]
        if entry["path"] == "requirements.txt"
    )
    marker = tmp_path / "home" / ".arkheia" / "venv" / ".arkheia-deps-installed.json"
    marker_data = json.loads(marker.read_text(encoding="utf-8"))
    assert marker_data["requirements_sha256"] == req_hash
    assert marker_data["package_name"] == provenance["package"]["name"]
    assert marker_data["package_version"] == provenance["package"]["version"]
