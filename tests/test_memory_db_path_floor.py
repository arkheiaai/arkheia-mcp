"""
FLOOR INVARIANT — the knowledge-graph DB path is absolute, so the graph cannot fork with cwd.

Runs in the required `floor-invariants` context: a bare `pytest` with NO project dependencies
installed. That is affordable here because mcp_server/tools/memory.py imports only stdlib
(os, sqlite3, uuid, datetime, pathlib), so this tier can exercise the REAL FUNCTIONS rather than
static-analyse them. It is an effect test, not a token scan: a docstring, a comment or a
plausible-looking constant cannot satisfy it.

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
store's confidentiality boundary is the filesystem (observation text is deliberately NOT scrubbed;
see the module docstring), so a cwd-relative path put a private graph inside a shared, world
readable directory under the npm install.

FALSE-POSITIVE-FREE: a relative default is unambiguously the defect. There is no legitimate
configuration in which this store should resolve against the caller's working directory.
"""

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mcp_server.tools.memory import (  # noqa: E402
    DEFAULT_DB_PATH,
    _db_path,
    retrieve_entities,
    store_entity,
)


def _resolve_with(env_value, home):
    """Call _db_path() under a controlled environment, restoring it afterwards."""
    prev_db = os.environ.get("MEMORY_DB_PATH")
    prev_home = os.environ.get("HOME")
    try:
        if env_value is None:
            os.environ.pop("MEMORY_DB_PATH", None)
        else:
            os.environ["MEMORY_DB_PATH"] = env_value
        os.environ["HOME"] = str(home)
        return _db_path()
    finally:
        os.environ.pop("MEMORY_DB_PATH", None)
        if prev_db is not None:
            os.environ["MEMORY_DB_PATH"] = prev_db
        if prev_home is not None:
            os.environ["HOME"] = prev_home


def test_default_db_path_constant_is_not_cwd_relative():
    """
    The shipped default expands to an absolute path.

    Asserted on the EXPANDED value: "~/..." is not absolute as a raw string, so testing the
    constant with is_absolute() alone would reject the correct value and accept nothing useful.
    """
    assert Path(DEFAULT_DB_PATH).expanduser().is_absolute()


def test_resolved_default_is_absolute_and_under_home():
    with tempfile.TemporaryDirectory() as home:
        resolved = Path(_resolve_with(None, home))
        assert resolved.is_absolute()
        assert resolved.is_relative_to(Path(home))


def test_a_relative_memory_db_path_is_refused():
    """
    Includes the EXACT defective literal from origin/master as a case, so this covers the real
    regression rather than a tidier stand-in. On Windows that literal is genuinely absolute and
    the defect never existed, so it is asserted only on POSIX.
    """
    candidates = ["data/memory.db", "./memory.db"]
    if os.name == "posix":
        candidates.append("C:/arkheia-mcp/data/memory.db")

    with tempfile.TemporaryDirectory() as home:
        for value in candidates:
            with pytest.raises(ValueError):
                _resolve_with(value, home)


def test_an_absolute_memory_db_path_is_accepted():
    """
    POSITIVE CONTROL for the refusal above. Without it, a `_db_path` that raised
    unconditionally — refusing every path, including valid ones — would pass the refusal test
    and leave the store completely broken. An absence assertion never stands alone.
    """
    with tempfile.TemporaryDirectory() as home:
        absolute = str(Path(home) / "explicit" / "memory.db")
        assert _resolve_with(absolute, home) == absolute


def test_a_store_is_visible_from_a_different_working_directory():
    """
    THE EFFECT TEST — the invariant stated as behaviour, which is what actually failed on master.

    Store from one cwd, retrieve from another, with MEMORY_DB_PATH unset so the default is the
    thing under test. Asserts the exact entity set (not merely that something came back) and
    that neither working directory was written to.
    """
    prev_cwd = Path.cwd()
    prev_db = os.environ.get("MEMORY_DB_PATH")
    prev_home = os.environ.get("HOME")
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        home, cwd_a, cwd_b = tmp / "home", tmp / "a", tmp / "b"
        for d in (home, cwd_a, cwd_b):
            d.mkdir()
        try:
            os.environ.pop("MEMORY_DB_PATH", None)
            os.environ["HOME"] = str(home)

            os.chdir(cwd_a)
            asyncio.run(store_entity("Acme Corp", "company", ["written from cwd A"]))

            os.chdir(cwd_b)
            found = asyncio.run(retrieve_entities("Acme Corp"))

            assert [e["name"] for e in found["entities"]] == ["Acme Corp"]
            assert [o["content"] for o in found["entities"][0]["observations"]] == [
                "written from cwd A"
            ]
            assert list(cwd_a.iterdir()) == []
            assert list(cwd_b.iterdir()) == []
            assert [p.relative_to(tmp).as_posix() for p in sorted(tmp.rglob("memory.db"))] == [
                "home/.arkheia/mcp/memory.db"
            ]
        finally:
            os.chdir(prev_cwd)
            os.environ.pop("MEMORY_DB_PATH", None)
            if prev_db is not None:
                os.environ["MEMORY_DB_PATH"] = prev_db
            if prev_home is not None:
                os.environ["HOME"] = prev_home
