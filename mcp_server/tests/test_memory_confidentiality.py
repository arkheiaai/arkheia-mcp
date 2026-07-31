"""
F5 split: memory graph confidentiality and bounded read/write controls.

This is the non-overlapping part of the stale memory branch that can land on
current master without reopening the shared redactor decision:

* the graph path is absolute and user-private by default;
* the sqlite directory/file modes are asserted on every open;
* LIKE metacharacters in search input are literal, not wildcard queries;
* memory_relate enforces the documented "both endpoints already exist" rule;
* limit is bounded at the lower-level retrieve function, not only in server.py.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mcp_server.tools import memory as memory_mod
from mcp_server.tools.memory import (
    _db_path,
    _enforce_mode,
    _get_conn,
    _init_schema,
    _like_escape,
    retrieve_entities,
    store_entity,
    store_relation,
)


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "graph" / "memory.db"
    monkeypatch.setenv("MEMORY_DB_PATH", str(path))
    return path


class TestDbPath:
    def test_default_path_is_absolute_and_under_home(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        monkeypatch.delenv("MEMORY_DB_PATH", raising=False)
        monkeypatch.setenv("HOME", str(home))

        resolved = Path(_db_path())

        assert resolved == home / ".arkheia" / "mcp" / "memory.db"
        assert resolved.is_absolute()

    def test_relative_memory_db_path_is_refused(self, monkeypatch):
        monkeypatch.setenv("MEMORY_DB_PATH", "data/memory.db")

        with pytest.raises(ValueError) as exc:
            _db_path()

        assert "data/memory.db" in str(exc.value)
        assert "absolute" in str(exc.value).lower()

    def test_posix_refuses_the_old_windows_literal_default(self, monkeypatch):
        if os.name != "posix":
            pytest.skip("'C:/...' is absolute on Windows")

        monkeypatch.setenv("MEMORY_DB_PATH", "C:/arkheia-mcp/data/memory.db")

        with pytest.raises(ValueError):
            _db_path()

    def test_nul_memory_db_path_is_refused_before_path_resolution(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            memory_mod.os,
            "environ",
            {"MEMORY_DB_PATH": f"{tmp_path}/bad\x00memory.db"},
        )

        with pytest.raises(ValueError) as exc:
            _db_path()

        assert "MEMORY_DB_PATH" in str(exc.value)
        assert "NUL" in str(exc.value)

    @pytest.mark.asyncio
    async def test_two_working_directories_share_the_default_graph(
        self, tmp_path, monkeypatch
    ):
        home = tmp_path / "home"
        cwd_a = tmp_path / "a"
        cwd_b = tmp_path / "b"
        for path in (home, cwd_a, cwd_b):
            path.mkdir()
        monkeypatch.delenv("MEMORY_DB_PATH", raising=False)
        monkeypatch.setenv("HOME", str(home))

        monkeypatch.chdir(cwd_a)
        await store_entity("Acme Corp", "company", ["written from cwd A"])

        monkeypatch.chdir(cwd_b)
        found = await retrieve_entities("Acme Corp")

        assert [entity["name"] for entity in found["entities"]] == ["Acme Corp"]
        assert [
            obs["content"] for obs in found["entities"][0]["observations"]
        ] == ["written from cwd A"]
        assert list(cwd_a.iterdir()) == []
        assert list(cwd_b.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
class TestOwnerOnlyFilesystemBoundary:
    @pytest.mark.asyncio
    async def test_new_db_and_directory_are_owner_only(self, db):
        await store_entity("Acme Corp", "company", ["fact"])

        assert (db.parent.stat().st_mode & 0o777) == 0o700
        assert (db.stat().st_mode & 0o777) == 0o600

    @pytest.mark.asyncio
    async def test_existing_world_readable_artifacts_are_tightened(self, db):
        await store_entity("Acme Corp", "company", ["fact"])
        os.chmod(db.parent, 0o755)
        os.chmod(db, 0o644)

        await store_entity("Beta Ltd", "company", ["another fact"])

        assert (db.parent.stat().st_mode & 0o777) == 0o700
        assert (db.stat().st_mode & 0o777) == 0o600

    def test_get_conn_tightens_directory_without_a_store_call(self, db):
        _get_conn().close()
        os.chmod(db.parent, 0o755)

        _get_conn().close()

        assert (db.parent.stat().st_mode & 0o777) == 0o700

    def test_enforce_mode_strips_unsafe_bits_without_widening(self, tmp_path):
        directory = tmp_path / "graph"
        directory.mkdir()
        expected = {
            0o755: 0o700,
            0o500: 0o500,
            0o400: 0o400,
            0o000: 0o000,
        }

        try:
            for starting_mode, final_mode in expected.items():
                os.chmod(directory, starting_mode)
                _enforce_mode(directory, 0o700)

                assert (directory.stat().st_mode & 0o777) == final_mode
        finally:
            os.chmod(directory, 0o700)

    def test_enforce_mode_preserves_restrictive_db_file_modes(self, tmp_path):
        db_file = tmp_path / "memory.db"
        db_file.write_text("", encoding="utf-8")
        expected = {
            0o644: 0o600,
            0o400: 0o400,
            0o200: 0o200,
            0o000: 0o000,
        }

        try:
            for starting_mode, final_mode in expected.items():
                os.chmod(db_file, starting_mode)
                _enforce_mode(db_file, 0o600)

                assert (db_file.stat().st_mode & 0o777) == final_mode
        finally:
            os.chmod(db_file, 0o600)

    @pytest.mark.asyncio
    async def test_unenforceable_mode_warns_but_memory_still_works(
        self, db, monkeypatch, caplog
    ):
        def _refuse(*_args, **_kwargs):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr(memory_mod.os, "chmod", _refuse)

        with caplog.at_level("WARNING", logger=memory_mod.__name__):
            result = await store_entity("Acme Corp", "company", ["still stored"])

        assert result["observations_added"] == 1
        warnings = [record.getMessage() for record in caplog.records]
        assert warnings
        assert all("filesystem permissions" in msg for msg in warnings)


class TestNulSafety:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "kwargs,offending",
        [
            (
                {
                    "name": "Acme\x00Corp",
                    "entity_type": "company",
                    "observations": ["fact"],
                },
                "name",
            ),
            (
                {
                    "name": "Acme Corp",
                    "entity_type": "company\x00hidden",
                    "observations": ["fact"],
                },
                "entity_type",
            ),
            (
                {
                    "name": "Acme Corp",
                    "entity_type": "company",
                    "observations": ["fact\x00hidden"],
                },
                "observations",
            ),
        ],
    )
    async def test_store_rejects_nul_text_before_opening_db(
        self, db, kwargs, offending
    ):
        with pytest.raises(ValueError) as exc:
            await store_entity(**kwargs)

        assert offending in str(exc.value)
        assert "NUL" in str(exc.value)
        assert not db.exists()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "query,entity_type,offending",
        [
            ("Acme\x00Corp", None, "query"),
            ("Acme", "company\x00hidden", "entity_type"),
        ],
    )
    async def test_retrieve_rejects_nul_filters_before_opening_db(
        self, db, query, entity_type, offending
    ):
        with pytest.raises(ValueError) as exc:
            await retrieve_entities(query, entity_type=entity_type)

        assert offending in str(exc.value)
        assert "NUL" in str(exc.value)
        assert not db.exists()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "from_entity,relation_type,to_entity,offending",
        [
            ("Jane\x00Smith", "works_at", "Acme Corp", "from_entity"),
            ("Jane Smith", "works\x00at", "Acme Corp", "relation_type"),
            ("Jane Smith", "works_at", "Acme\x00Corp", "to_entity"),
        ],
    )
    async def test_relation_rejects_nul_text_before_opening_db(
        self, db, from_entity, relation_type, to_entity, offending
    ):
        with pytest.raises(ValueError) as exc:
            await store_relation(from_entity, relation_type, to_entity)

        assert offending in str(exc.value)
        assert "NUL" in str(exc.value)
        assert not db.exists()

    @pytest.mark.asyncio
    async def test_legacy_nul_entity_name_is_not_dumped(self, db):
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

        result = await retrieve_entities("A")

        assert result == {"entities": [], "total": 0}

    @pytest.mark.asyncio
    async def test_legacy_nul_observations_and_relations_are_not_dumped(self, db):
        conn = _get_conn()
        try:
            _init_schema(conn)
            conn.execute(
                "INSERT INTO entities (entity_id, name, entity_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                ("entity-1", "Acme Corp", "company", "2026-01-01T00:00:00"),
            )
            conn.execute(
                "INSERT INTO observations (obs_id, entity_id, content, created_at) "
                "VALUES (?, ?, ?, ?)",
                ("obs-1", "entity-1", "fact\x00hidden", "2026-01-01T00:00:01"),
            )
            conn.execute(
                "INSERT INTO relations "
                "(rel_id, from_entity, relation_type, to_entity, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    "rel-1",
                    "Acme Corp",
                    "owns\x00hidden",
                    "Beta Ltd",
                    "2026-01-01T00:00:02",
                ),
            )
            conn.commit()
        finally:
            conn.close()

        result = await retrieve_entities("Acme")

        assert result["total"] == 1
        assert result["entities"][0]["observations"] == []
        assert result["entities"][0]["relations"] == []
        assert "\\u0000" not in json.dumps(result)


class TestSearchIsLiteral:
    def test_like_escape_covers_sql_like_metacharacters(self):
        assert _like_escape("100%") == "100\\%"
        assert _like_escape("auth_middleware") == "auth\\_middleware"
        assert _like_escape("a\\b") == "a\\\\b"

    @pytest.mark.asyncio
    async def test_percent_query_does_not_return_the_whole_graph(self, db):
        await store_entity("Acme Corp", "company", ["x"])
        await store_entity("Beta Ltd", "company", ["y"])

        wildcard = await retrieve_entities("%")
        control = await retrieve_entities("Acme")

        assert wildcard == {"entities": [], "total": 0}
        assert [entity["name"] for entity in control["entities"]] == ["Acme Corp"]

    @pytest.mark.asyncio
    async def test_underscore_matches_only_literal_underscore(self, db):
        await store_entity("auth_middleware bug", "bug", ["real"])
        await store_entity("authXmiddleware bug", "bug", ["decoy"])

        result = await retrieve_entities("auth_middleware")
        filtered = await retrieve_entities("auth_middleware", entity_type="bug")

        assert [entity["name"] for entity in result["entities"]] == [
            "auth_middleware bug"
        ]
        assert [entity["name"] for entity in filtered["entities"]] == [
            "auth_middleware bug"
        ]


class TestRelationEndpoints:
    @pytest.mark.asyncio
    async def test_relation_between_existing_entities_succeeds(self, db):
        await store_entity("Jane Smith", "person", ["Sales lead"])
        await store_entity("Acme Corp", "company", ["Prospect"])

        result = await store_relation("Jane Smith", "works_at", "Acme Corp")

        assert result["from_entity"] == "Jane Smith"
        assert result["relation_type"] == "works_at"
        assert result["to_entity"] == "Acme Corp"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "from_entity,to_entity,offending",
        [
            ("Jane Smyth", "Acme Corp", "from_entity"),
            ("Jane Smith", "Acme Copr", "to_entity"),
        ],
    )
    async def test_unknown_endpoint_is_refused_before_insert(
        self, db, from_entity, to_entity, offending
    ):
        await store_entity("Jane Smith", "person", ["Sales lead"])
        await store_entity("Acme Corp", "company", ["Prospect"])

        with pytest.raises(ValueError) as exc:
            await store_relation(from_entity, "works_at", to_entity)

        assert offending in str(exc.value)
        conn = _get_conn()
        try:
            assert conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0] == 0
        finally:
            conn.close()


class TestRetrieveLimit:
    @pytest.mark.asyncio
    async def test_server_wrapper_caps_limit_at_fifty(self, db):
        from mcp_server import server as mcp_server_module

        for i in range(55):
            await store_entity(f"Node {i:03d}", "node", [f"obs {i}"])

        result = await mcp_server_module.memory_retrieve(query="Node", limit=9999)

        assert len(result["entities"]) == 50
        assert result["total"] == 55

    @pytest.mark.asyncio
    async def test_lower_level_function_refuses_zero_and_negative_limits(self, db):
        for i in range(3):
            await store_entity(f"Node {i}", "node", [f"obs {i}"])

        for bad in (0, -1):
            with pytest.raises(ValueError):
                await retrieve_entities("Node", limit=bad)

        control = await retrieve_entities("Node", limit=2)
        assert len(control["entities"]) == 2
        assert control["total"] == 3
