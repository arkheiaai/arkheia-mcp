from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SETUP_JS = ROOT / "npm-wrapper" / "scripts" / "setup.js"
INSTALL_SH = ROOT / "install.sh"
KEY_ENV = "ARKHEIA" + "_API_KEY"
PERSIST_ENV = "ARKHEIA" + "_PERSIST_API_KEY"

def _fixture_key(label: str) -> str:
    return "custody" + "_fixture_" + label


PRIMARY_VALUE = _fixture_key("primary")
def _combined(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout + result.stderr


def _base_env(home: Path, *, api_key: str | None = PRIMARY_VALUE) -> dict[str, str]:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env.pop("APPDATA", None)
    env.pop(PERSIST_ENV, None)
    env.pop("ARKHEIA_SETUP_DRY_RUN", None)
    env.pop("npm_config_arkheia_persist_api_key", None)
    env.pop("ARKHEIA_INSTALL_TEST_FAIL_AFTER_WRITE", None)
    if api_key is None:
        env.pop(KEY_ENV, None)
    else:
        env[KEY_ENV] = api_key
    return env


def _run_setup(home: Path, *, env_extra: dict[str, str] | None = None, args: list[str] | None = None):
    env = _base_env(home)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["node", str(SETUP_JS), *(args or [])],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )


def _claude_desktop_config(home: Path) -> Path:
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    if os.environ.get("APPDATA"):
        return Path(os.environ["APPDATA"]) / "Claude" / "claude_desktop_config.json"
    return home / ".config" / "claude" / "claude_desktop_config.json"


def _python_310_or_newer() -> str:
    for name in ("python3.12", "python3.11", "python3.10", "python3"):
        candidate = shutil.which(name)
        if not candidate:
            continue
        result = subprocess.run(
            [
                candidate,
                "-c",
                "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return candidate
    raise AssertionError("install.sh tests require a Python 3.10+ interpreter")


def _fake_install_path(tmp_path: Path) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    python_cmd = _python_310_or_newer()

    (bin_dir / "npx").write_text(
        "#!/bin/sh\n"
        f"if [ -n \"${{{KEY_ENV}+x}}\" ]; then echo 'leaked runtime key to npx' >&2; exit 92; fi\n"
        "printf '1.3.0\\n'\n"
        "exit 0\n",
        encoding="utf-8",
    )

    (bin_dir / "curl").write_text(
        "#!/bin/sh\n"
        f"if [ -n \"${{{KEY_ENV}+x}}\" ]; then echo 'leaked runtime key to curl' >&2; exit 92; fi\n"
        "case \"$*\" in\n"
        "  */v1/provision*) printf '{\"api_key\":\"%s\"}\\n201' \"${ARKHEIA_FAKE_PROVISION_KEY:-custody_fixture_provisioned}\" ;;\n"
        "  *) printf '200' ;;\n"
        "esac\n",
        encoding="utf-8",
    )

    (bin_dir / "python3").write_text(
        "#!/bin/sh\n"
        f"if [ -n \"${{{KEY_ENV}+x}}\" ]; then echo 'leaked runtime key to python' >&2; exit 92; fi\n"
        f"exec {shlex.quote(python_cmd)} \"$@\"\n",
        encoding="utf-8",
    )

    for script in (bin_dir / "npx", bin_dir / "curl", bin_dir / "python3"):
        script.chmod(0o755)

    return bin_dir


def _run_install(
    home: Path,
    tmp_path: Path,
    *args: str,
    env_extra: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = _base_env(home, api_key=None)
    fake_bin = _fake_install_path(tmp_path)
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["ARKHEIA_HOSTED_URL"] = "https://arkheia.invalid"
    if env_extra:
        env.update(env_extra)

    return subprocess.run(
        ["bash", str(INSTALL_SH), *args],
        cwd=ROOT,
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )


def test_npm_postinstall_does_not_persist_keys_or_global_claude_md(tmp_path: Path):
    result = _run_setup(tmp_path)

    assert PRIMARY_VALUE not in _combined(result)
    assert not (tmp_path / ".arkheia" / "config.json").exists()
    assert not (tmp_path / ".claude" / "CLAUDE.md").exists()
    assert "Not persisted" in result.stdout
    assert "Global Claude instructions not modified" in result.stdout


def test_npm_persist_opt_in_is_noop_for_api_key_storage(tmp_path: Path):
    result = _run_setup(tmp_path, env_extra={PERSIST_ENV: "1"})

    assert PRIMARY_VALUE not in _combined(result)
    assert not (tmp_path / ".arkheia" / "config.json").exists()
    assert not (tmp_path / ".claude" / "CLAUDE.md").exists()


def test_npm_dry_run_writes_nothing_even_with_opt_ins(tmp_path: Path):
    result = _run_setup(
        tmp_path,
        env_extra={PERSIST_ENV: "1"},
        args=["--dry-run"],
    )

    assert PRIMARY_VALUE not in _combined(result)
    assert not (tmp_path / ".arkheia").exists()
    assert not (tmp_path / ".claude").exists()
    assert "Global Claude instructions not modified" in result.stdout


def test_install_sh_dry_run_writes_nothing_and_does_not_echo_key(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()

    result = _run_install(
        home,
        tmp_path,
        "--persist-api-key",
        "--dry-run",
        env_extra={KEY_ENV: PRIMARY_VALUE},
    )

    assert PRIMARY_VALUE not in _combined(result)
    assert not (home / ".arkheia").exists()
    assert not _claude_desktop_config(home).exists()
    assert "Dry run" in result.stdout


def test_install_sh_configures_clients_without_persisting_api_key(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    claude_code_dir = home / ".claude"
    claude_code_dir.mkdir()
    claude_settings = claude_code_dir / "settings.json"
    claude_settings.write_text('{"mcpServers": {}}\n', encoding="utf-8")

    first = _run_install(
        home,
        tmp_path,
        "--persist-api-key",
        env_extra={KEY_ENV: PRIMARY_VALUE},
    )

    desktop_config = _claude_desktop_config(home)

    assert PRIMARY_VALUE not in _combined(first)
    assert not (home / ".arkheia" / "config.json").exists()

    desktop = json.loads(desktop_config.read_text(encoding="utf-8"))
    code = json.loads(claude_settings.read_text(encoding="utf-8"))
    assert desktop["mcpServers"]["arkheia"] == {"command": "npx", "args": ["@arkheia/mcp-server"]}
    assert code["mcpServers"]["arkheia"] == {"command": "npx", "args": ["@arkheia/mcp-server"]}
    assert PRIMARY_VALUE not in desktop_config.read_text(encoding="utf-8")
    assert PRIMARY_VALUE not in claude_settings.read_text(encoding="utf-8")
    assert not (claude_code_dir / "CLAUDE.md").exists()

    first_desktop = desktop_config.read_text(encoding="utf-8")
    first_code = claude_settings.read_text(encoding="utf-8")

    second = _run_install(
        home,
        tmp_path,
        "--persist-api-key",
        env_extra={KEY_ENV: PRIMARY_VALUE},
    )

    assert PRIMARY_VALUE not in _combined(second)
    assert not (home / ".arkheia" / "config.json").exists()
    assert desktop_config.read_text(encoding="utf-8") == first_desktop
    assert claude_settings.read_text(encoding="utf-8") == first_code


def test_install_sh_rolls_back_claude_config_after_write_failure(tmp_path: Path):
    home = tmp_path / "home"
    home.mkdir()
    desktop_config = _claude_desktop_config(home)
    desktop_config.parent.mkdir(parents=True)
    original = {
        "mcpServers": {
            "other": {"command": "node", "args": ["server.js"]},
        }
    }
    desktop_config.write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8")

    result = _run_install(
        home,
        tmp_path,
        "--no-persist-api-key",
        env_extra={
            KEY_ENV: PRIMARY_VALUE,
            "ARKHEIA_INSTALL_TEST_FAIL_AFTER_WRITE": str(desktop_config),
        },
    )

    assert PRIMARY_VALUE not in _combined(result)
    assert json.loads(desktop_config.read_text(encoding="utf-8")) == original
    assert "Could not configure" in _combined(result)
