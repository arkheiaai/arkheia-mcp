"""
FLOOR INVARIANT — the knowledge-graph DB path is absolute, so the graph cannot fork with cwd.

Runs in the required `floor-invariants` context: a bare `pytest` with NO project dependencies
installed. That is affordable here because mcp_server/tools/memory.py imports only stdlib
(os, sqlite3, uuid, datetime, pathlib) plus the stdlib-only audit rail, so this tier can
exercise the REAL FUNCTIONS rather than static-analyse them. It is an effect test, not a token
scan: a docstring, a comment or a plausible-looking constant cannot satisfy it.

THE DEFECT THIS ENCODES (live on origin/master 3037f0c, measured not hypothesised)
`_db_path()` returned the literal "C:/arkheia-mcp/data/memory.db". On Windows that is absolute;
on POSIX "C:" is an ordinary directory NAME, so the whole path is RELATIVE and every process
resolved it against its own current working directory. Two processes with identical environment
differing only in cwd each stored an entity, neither could see the other's, and nothing raised —
the knowledge graph split silently and a missing retrieve was indistinguishable from "not stored
yet". The repo ships THREE different working directories for the same server (README and
npm-wrapper/README say cwd `~/.arkheia/mcp`, AGENTS.md says `~/.arkheia-mcp`, and
npm-wrapper/bin/arkheia-mcp.js spawns with `cwd: PYTHON_DIR` inside the global node_modules
tree), so which graph an operator got depended on which install document they followed.

WHY IT IS WORTH A FLOOR SLOT rather than only a unit test: the failure is SILENT and produces no
error at any layer, the value is a one-token edit away from returning, and the same string appears
in this repo's install docs for genuinely-Windows reasons, so a future edit copying it back is a
plausible mistake rather than a far-fetched one. It also carries a security consequence — the
store's confidentiality boundary is the filesystem, so a cwd-relative path put a private graph
inside a shared, world-readable directory under the npm install.

FALSE-POSITIVE-FREE: a relative default is unambiguously the defect. There is no legitimate
configuration in which this store should resolve against the caller's working directory.

Also pinned here, from the other half of the same merge: NUL-byte refusal on the path and on the
entity name, the fact that a legacy NUL-bearing row is never handed back, and that the mode
enforcement NARROWS permissions without ever widening them.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcp_server.tools.memory import (  # noqa: E402
    DEFAULT_DB_PATH,
    _db_path,
    _enforce_mode,
    _get_conn,
    _init_schema,
    retrieve_entities,
    store_entity,
)
from mcp_server.tools import memory as memory_mod  # noqa: E402


def _resolve_with(env_value: str | None, home: Path) -> str:
    previous_db = os.environ.get("MEMORY_DB_PATH")
    previous_home = os.environ.get("HOME")
    try:
        if env_value is None:
            os.environ.pop("MEMORY_DB_PATH", None)
        else:
            os.environ["MEMORY_DB_PATH"] = env_value
        os.environ["HOME"] = str(home)
        return _db_path()
    finally:
        os.environ.pop("MEMORY_DB_PATH", None)
        if previous_db is not None:
            os.environ["MEMORY_DB_PATH"] = previous_db
        if previous_home is not None:
            os.environ["HOME"] = previous_home


def test_default_db_path_expands_to_an_absolute_path():
    """
    The shipped default expands to an absolute path.

    Asserted on the EXPANDED value: "~/..." is not absolute as a raw string, so testing the
    constant with is_absolute() alone would reject the correct value and accept nothing useful.
    """
    assert Path(DEFAULT_DB_PATH).expanduser().is_absolute()


def test_resolved_default_is_absolute_and_under_home():
    with tempfile.TemporaryDirectory() as home:
        home_path = Path(home)
        resolved = Path(_resolve_with(None, home_path))

    assert resolved.is_absolute()
    assert resolved.is_relative_to(home_path)


def test_relative_memory_db_path_is_refused():
    """
    Includes the EXACT defective literal from origin/master as a case, so this covers the real
    regression rather than a tidier stand-in. On Windows that literal is genuinely absolute and
    the defect never existed, so it is asserted only on POSIX.
    """
    candidates = ["data/memory.db", "./memory.db"]
    if os.name == "posix":
        candidates.append("C:/arkheia-mcp/data/memory.db")

    with tempfile.TemporaryDirectory() as home:
        for candidate in candidates:
            with pytest.raises(ValueError):
                _resolve_with(candidate, Path(home))


def test_nul_memory_db_path_is_refused_before_path_resolution(tmp_path, monkeypatch):
    monkeypatch.setattr(
        memory_mod.os,
        "environ",
        {"MEMORY_DB_PATH": f"{tmp_path}/bad\x00memory.db"},
    )

    with pytest.raises(ValueError) as exc:
        _db_path()

    assert "MEMORY_DB_PATH" in str(exc.value)
    assert "NUL" in str(exc.value)


def test_absolute_memory_db_path_is_accepted():
    """
    POSITIVE CONTROL for the refusal above. Without it, a `_db_path` that raised
    unconditionally — refusing every path, including valid ones — would pass the refusal test
    and leave the store completely broken. An absence assertion never stands alone.
    """
    with tempfile.TemporaryDirectory() as home:
        absolute = str(Path(home) / "explicit" / "memory.db")
        assert _resolve_with(absolute, Path(home)) == absolute


def test_nul_entity_name_is_rejected_without_creating_graph(tmp_path, monkeypatch):
    db = tmp_path / "graph" / "memory.db"
    monkeypatch.setenv("MEMORY_DB_PATH", str(db))

    with pytest.raises(ValueError) as exc:
        asyncio.run(store_entity("A\x00tail", "company", ["fact"]))

    assert "name" in str(exc.value)
    assert "NUL" in str(exc.value)
    assert not db.exists()


def test_legacy_nul_name_row_is_not_returned_from_graph_dump(tmp_path, monkeypatch):
    db = tmp_path / "graph" / "memory.db"
    monkeypatch.setenv("MEMORY_DB_PATH", str(db))

    conn = _get_conn()
    try:
        _init_schema(conn)
        conn.execute(
            "INSERT INTO entities (entity_id, name, entity_type, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("entity-1", "A\x00tail", "company", "2026-01-01T00:00:00"),
        )
        probe = conn.execute(
            "SELECT name, length(name) AS sql_len FROM entities"
        ).fetchone()
        assert probe["sql_len"] == 1
        assert len(probe["name"]) == 6
        conn.commit()
    finally:
        conn.close()

    result = asyncio.run(retrieve_entities("A"))

    # Asserted field-by-field rather than by whole-dict equality: retrieve_entities also
    # returns receipt_id / receipt, so `result == {...}` would now fail for a reason that
    # has nothing to do with the NUL row. The NUL check below still covers the WHOLE
    # result, receipt fields included.
    assert result["entities"] == []
    assert result["total"] == 0
    assert "\\u0000" not in json.dumps(result)


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_mode_enforcement_strips_group_world_bits_without_widening(tmp_path):
    directory = tmp_path / "graph"
    directory.mkdir()

    try:
        for starting_mode, final_mode in {
            0o755: 0o700,
            0o500: 0o500,
            0o400: 0o400,
            0o000: 0o000,
        }.items():
            os.chmod(directory, starting_mode)
            _enforce_mode(directory, 0o700)

            assert (directory.stat().st_mode & 0o777) == final_mode
    finally:
        os.chmod(directory, 0o700)


def test_store_from_one_cwd_is_visible_from_another():
    """
    THE EFFECT TEST — the invariant stated as behaviour, which is what actually failed on master.

    Store from one cwd, retrieve from another, with MEMORY_DB_PATH unset so the default is the
    thing under test. Asserts the exact entity set (not merely that something came back) and
    that neither working directory was written to.
    """
    previous_cwd = Path.cwd()
    previous_db = os.environ.get("MEMORY_DB_PATH")
    previous_home = os.environ.get("HOME")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        home = root / "home"
        cwd_a = root / "a"
        cwd_b = root / "b"
        for path in (home, cwd_a, cwd_b):
            path.mkdir()

        try:
            os.environ.pop("MEMORY_DB_PATH", None)
            os.environ["HOME"] = str(home)

            os.chdir(cwd_a)
            asyncio.run(store_entity("Acme Corp", "company", ["written from cwd A"]))

            os.chdir(cwd_b)
            found = asyncio.run(retrieve_entities("Acme Corp"))

            assert [entity["name"] for entity in found["entities"]] == ["Acme Corp"]
            assert [
                obs["content"] for obs in found["entities"][0]["observations"]
            ] == ["written from cwd A"]
            assert list(cwd_a.iterdir()) == []
            assert list(cwd_b.iterdir()) == []
            assert [
                path.relative_to(root).as_posix()
                for path in sorted(root.rglob("memory.db"))
            ] == ["home/.arkheia/mcp/memory.db"]
        finally:
            os.chdir(previous_cwd)
            os.environ.pop("MEMORY_DB_PATH", None)
            if previous_db is not None:
                os.environ["MEMORY_DB_PATH"] = previous_db
            if previous_home is not None:
                os.environ["HOME"] = previous_home
