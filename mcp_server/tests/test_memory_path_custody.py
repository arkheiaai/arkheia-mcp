from __future__ import annotations

import os
from pathlib import Path, PureWindowsPath

import pytest

from mcp_server.tools import memory


pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="POSIX-only regression for Windows drive paths being treated as relative",
)


def test_default_memory_db_path_is_posix_absolute_and_not_cwd_c_drive(
    tmp_path,
    monkeypatch,
):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("MEMORY_DB_PATH", raising=False)

    conn = memory._get_conn()
    conn.close()

    db_path = Path(memory._db_path())
    assert db_path.is_absolute()
    assert db_path == home / ".arkheia-mcp" / "data" / "memory.db"
    assert db_path.is_file()
    assert not (cwd / "C:").exists(), (
        "default MEMORY_DB_PATH must not create a literal ./C: directory on POSIX"
    )


def test_explicit_windows_absolute_memory_db_path_is_rejected_before_mkdir(
    tmp_path,
    monkeypatch,
):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("MEMORY_DB_PATH", "C:/arkheia-mcp/data/memory.db")

    with pytest.raises(ValueError, match="Windows absolute path"):
        memory._get_conn()

    assert not (cwd / "C:").exists()


def test_negative_self_test_posix_pathlib_would_create_relative_c_drive():
    path = Path("C:/arkheia-mcp/data/memory.db")
    assert not path.is_absolute()
    assert path.parts[0] == "C:"
    assert PureWindowsPath("C:/arkheia-mcp/data/memory.db").is_absolute()
