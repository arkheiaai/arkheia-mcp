"""
Installing the npm package must not change anything in the installing user's home.

WHY THIS EXISTS. `@arkheia/mcp-server` 1.2.1, as published, ran a `postinstall`
(`npm-wrapper/scripts/setup.js`) that, on every `npm install` / `npx`:

  * appended a "Fabrication Detection" section to the user's GLOBAL
    `~/.claude/CLAUDE.md`, which changes the instructions every Claude Code session
    on that machine follows; and
  * copied an exported `ARKHEIA_API_KEY` into `~/.arkheia/config.json`.

Neither was asked for, and the user was not asked. The current `setup.js` no longer
does either, and `tests/test_install_key_custody_floor.py` already runs `setup.js`
directly. What no check observed is the path a customer actually takes: npm
installing the PACKED tarball and running whatever lifecycle hook the manifest
declares. A hook re-pointed at another script, a second hook, or a build that packs
a stale `setup.js` would all pass a test that calls `node scripts/setup.js` by hand.

So this floor runs the REAL thing: `npm pack` on the package directory (which runs
the real `prepack` build), then `npm install` of that tarball into a throwaway
project with `HOME` pointed at a throwaway directory, lifecycle scripts enabled and
an API key exported. It fingerprints every file under that home before and after,
and fails on ANY addition, removal or change, and on the key appearing anywhere in
the home or in npm's output.

PROVED ABLE TO FAIL (DONE.md v1.19 / v1.22). A check that passes because it found
no change must show it can see one. `test_the_harness_sees_a_postinstall_that_edits_home`
packs a stand-in package whose postinstall does exactly what 1.2.1 did and asserts
this harness reports both edits and the key. The closure test was also run red
against the pre-fix `setup.js` (git `2165d1e^`) before being committed.

Stdlib + pytest only, so it runs in the floor tier. Needs `node`/`npm`, which the
floor workflow installs; if npm is missing it FAILS rather than skips.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:  # floor tier runs bare pytest from the repo root
    sys.path.insert(0, str(_TESTS_DIR))

from floor_support import import_closure, npm_bundle  # noqa: E402

_ROOT = import_closure.REPO_ROOT
KEY_ENV = "ARKHEIA" + "_API_KEY"
PERSIST_ENV = "ARKHEIA" + "_PERSIST_API_KEY"
FIXTURE_KEY = "home" + "_untouched_fixture_" + "k3y"
EXISTING_CLAUDE_MD = "# My own instructions\n\nNothing from a package belongs here.\n"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

def _fingerprint(home: Path) -> dict[str, str]:
    """Every file and directory under `home`, mapped to a content hash (or 'dir')."""
    seen: dict[str, str] = {}
    for path in sorted(home.rglob("*")):
        rel = path.relative_to(home).as_posix()
        if path.is_symlink():
            seen[rel] = "symlink:" + os.readlink(path)
        elif path.is_dir():
            seen[rel] = "dir"
        else:
            seen[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return seen


def _home_changes(before: dict[str, str], after: dict[str, str]) -> list[str]:
    changes = []
    for rel in sorted(after.keys() - before.keys()):
        changes.append(f"added {rel}")
    for rel in sorted(before.keys() - after.keys()):
        changes.append(f"removed {rel}")
    for rel in sorted(before.keys() & after.keys()):
        if before[rel] != after[rel]:
            changes.append(f"changed {rel}")
    return changes


def _files_containing(home: Path, needle: str) -> list[str]:
    hits = []
    raw = needle.encode("utf-8")
    for path in sorted(home.rglob("*")):
        if path.is_file() and not path.is_symlink() and raw in path.read_bytes():
            hits.append(path.relative_to(home).as_posix())
    return hits


def _seed_home(home: Path, *, existing_claude_md: bool) -> None:
    home.mkdir(parents=True)
    if existing_claude_md:
        (home / ".claude").mkdir()
        (home / ".claude" / "CLAUDE.md").write_text(EXISTING_CLAUDE_MD, encoding="utf-8")


def _install_env(work: Path, home: Path) -> dict[str, str]:
    """
    A minimal environment: the user's home is `home`, npm's own state lives OUTSIDE
    it (so npm's cache and logs are not mistaken for an edit by the package), and a
    runtime key plus the old persistence opt-in are exported, because those are the
    conditions under which 1.2.1 wrote the key to disk.
    """
    user_npmrc = work / "user-npmrc"
    global_npmrc = work / "global-npmrc"
    user_npmrc.write_text("", encoding="utf-8")
    global_npmrc.write_text("", encoding="utf-8")
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
        "USERPROFILE": str(home),
        "APPDATA": str(home / "AppData" / "Roaming"),
        "LOCALAPPDATA": str(home / "AppData" / "Local"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "TMPDIR": str(work / "tmp"),
        "npm_config_cache": str(work / "npm-cache"),
        "npm_config_userconfig": str(user_npmrc),
        "npm_config_globalconfig": str(global_npmrc),
        "npm_config_offline": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "npm_config_ignore_scripts": "false",
        "NO_COLOR": "1",
        KEY_ENV: FIXTURE_KEY,
        PERSIST_ENV: "1",
    }
    (work / "tmp").mkdir(exist_ok=True)
    for name in ("SystemRoot", "WINDIR", "COMSPEC"):  # Windows needs these to spawn node
        if os.environ.get(name):
            env[name] = os.environ[name]
    return env


def _npm_install(tarball: Path, work: Path, *, existing_claude_md: bool):
    """
    `npm install <tarball>` into a fresh project with lifecycle scripts ON.

    Returns (home, before, after, combined npm output, installed package dir).
    """
    npm = npm_bundle.require_npm()
    home = work / "home"
    _seed_home(home, existing_claude_md=existing_claude_md)
    project = work / "project"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "install-probe", "version": "0.0.0", "private": True}),
        encoding="utf-8",
    )

    before = _fingerprint(home)
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [npm, "install", "--foreground-scripts", "--no-save", str(tarball)],
        cwd=str(project),
        env=_install_env(work, home),
        capture_output=True,
        text=True,
        timeout=300,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise npm_bundle.ArtifactUnobservable(
            f"`npm install {tarball.name}` failed (exit {result.returncode}); the "
            f"install path was not observed.\n{output}"
        )
    after = _fingerprint(home)
    name = json.loads(
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["tar", "-xzOf", str(tarball), "package/package.json"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
    )["name"]
    installed = project / "node_modules" / name
    return home, before, after, output, installed


# ---------------------------------------------------------------------------
# The real package
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def packed_tarball(tmp_path_factory) -> Path:
    """The tarball a clean checkout publishes, produced by the real `npm pack`."""
    tmp = tmp_path_factory.mktemp("home-untouched-pack")
    package_dir = _ROOT / npm_bundle.PACKAGE_DIR
    bundle_dir = package_dir / npm_bundle.bundle_root(_ROOT)
    entry = npm_bundle.launcher_entry_module(_ROOT)
    first_party = import_closure.first_party_roots(_ROOT)
    closure = import_closure.required_files((entry,), _ROOT, first_party)
    # Packing runs the real build, which also rewrites the committed trust root
    # under `bin/`. Restore it byte-for-byte so this floor leaves the tree clean.
    trust_root = package_dir / "bin" / "bundle-provenance-root.json"
    trust_root_bytes = trust_root.read_bytes() if trust_root.exists() else None
    try:
        with npm_bundle.tree_restored(bundle_dir):
            npm_bundle.prune_generated(bundle_dir, {p.parts[0] for p in closure})
            tarball = npm_bundle.pack(package_dir, tmp / "tgz")
    finally:
        if trust_root_bytes is not None:
            trust_root.write_bytes(trust_root_bytes)
    return tarball


def test_the_package_declares_an_install_time_hook_this_floor_exercises(packed_tarball: Path):
    """
    Work-done guard. If the package stopped declaring an install-time hook, the
    floor below would pass trivially; that is fine for users but the floor must say
    so rather than look like it observed a script that never ran. Keep this in step
    with the manifest: if the hook is removed on purpose, change this test to assert
    there is none.
    """
    manifest = json.loads(
        subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["tar", "-xzOf", str(packed_tarball), "package/package.json"],
            capture_output=True, text=True, check=True, timeout=30,
        ).stdout
    )
    hooks = {k: v for k, v in manifest.get("scripts", {}).items()
             if k in ("preinstall", "install", "postinstall", "prepare")}
    assert hooks, "the packed manifest declares no install-time hook"


@pytest.mark.parametrize("existing_claude_md", [True, False], ids=["existing-CLAUDE.md", "empty-home"])
def test_npm_install_of_the_packed_package_leaves_home_untouched(
    packed_tarball: Path, tmp_path: Path, existing_claude_md: bool
):
    home, before, after, output, installed = _npm_install(
        packed_tarball, tmp_path, existing_claude_md=existing_claude_md
    )

    # Work done: the package really installed and its postinstall really ran.
    assert (installed / "package.json").is_file(), output
    assert "Arkheia MCP Server" in output, (
        "the postinstall banner is missing from npm's output, so this run did not "
        "observe the install hook executing:\n" + output
    )

    changes = _home_changes(before, after)
    assert changes == [], (
        "installing the package changed the user's home directory:\n  "
        + "\n  ".join(changes)
    )
    if existing_claude_md:
        assert (home / ".claude" / "CLAUDE.md").read_text(encoding="utf-8") == EXISTING_CLAUDE_MD
    assert _files_containing(home, FIXTURE_KEY) == []
    assert FIXTURE_KEY not in output


# ---------------------------------------------------------------------------
# Negative self-test: the harness can see the defect it exists to catch
# ---------------------------------------------------------------------------

_EDITING_POSTINSTALL = r"""
const fs = require("fs");
const os = require("os");
const path = require("path");
console.log("Arkheia MCP Server stand-in postinstall");
const claudeDir = path.join(os.homedir(), ".claude");
fs.mkdirSync(claudeDir, { recursive: true });
fs.appendFileSync(path.join(claudeDir, "CLAUDE.md"), "\n# Fabrication Detection\n");
const key = process.env["ARKHEIA" + "_API_KEY"];
if (key) {
  const dir = path.join(os.homedir(), ".arkheia");
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify({ api_key: key }));
}
"""


@pytest.mark.parametrize("existing_claude_md", [True, False], ids=["existing-CLAUDE.md", "empty-home"])
def test_the_harness_sees_a_postinstall_that_edits_home(tmp_path: Path, existing_claude_md: bool):
    stand_in = tmp_path / "stand-in"
    (stand_in / "scripts").mkdir(parents=True)
    (stand_in / "package.json").write_text(
        json.dumps(
            {
                "name": "home-edit-stand-in",
                "version": "0.0.0",
                "scripts": {"postinstall": "node scripts/setup.js"},
                "files": ["scripts/"],
            }
        ),
        encoding="utf-8",
    )
    (stand_in / "scripts" / "setup.js").write_text(_EDITING_POSTINSTALL, encoding="utf-8")
    tarball = npm_bundle.pack(stand_in, tmp_path / "tgz")

    run = tmp_path / "run"
    run.mkdir()
    home, before, after, output, installed = _npm_install(
        tarball, run, existing_claude_md=existing_claude_md
    )

    assert (installed / "package.json").is_file(), output
    changes = _home_changes(before, after)
    claude_change = "changed .claude/CLAUDE.md" if existing_claude_md else "added .claude/CLAUDE.md"
    assert claude_change in changes, changes
    assert "added .arkheia/config.json" in changes, changes
    assert _files_containing(home, FIXTURE_KEY) == [".arkheia/config.json"]
