"""
F5 — Memory knowledge-graph store/retrieve/relate: the guards, and proof each can fail.

Runs in the REQUIRED `unit-tests` context (.github/workflows/unit-tests.yml, job `unit`,
`pytest ... mcp_server/tests ...` on push+pull_request to master), so every invariant here
gates a commit to the default branch.

WHY THESE TESTS EXIST — each is anchored to a defect that was live on origin/master
(3037f0c) and observed, not hypothesised:

  INV-1  The graph does not fork with the working directory.
         `_db_path()` returned the literal "C:/arkheia-mcp/data/memory.db". On POSIX "C:" is an
         ordinary directory NAME, so that string is RELATIVE. Measured on master: two processes
         with identical environment, differing only in cwd, each stored an entity and neither
         could see the other's; the files landed at <cwd>/C:/arkheia-mcp/data/memory.db. Nothing
         raised. A retrieve that misses is indistinguishable from "not stored yet".

  INV-2  The store's confidentiality boundary is ASSERTED, not assumed. Observation text is
         written verbatim (deliberately — see the module docstring's ACCESS CONTROL note), so the
         only control is the OS one. Measured on master: directory 0755, file 0644 — world
         readable — and under the npm install that directory sits inside the global node_modules
         tree.

  INV-3  A search string is matched LITERALLY. `f"%{query}%"` went straight into LIKE, so
         query="%" returned the entire graph and "auth_middleware" also matched "authXmiddleware".

  INV-4  memory_relate's published contract ("Both entities must already exist") is enforced.
         It was not, so a mistyped endpoint stored a dangling edge that memory_retrieve then
         reported to the agent as a real relation.

  INV-5  The documented `limit` cap is actually applied. The pre-existing test named
         `test_retrieve_limit_capped_at_50` asserted only `"entities" in result` and
         `"total" in result` — a PERMISSIVE assertion that passes against any dict-returning
         implementation, including one with no cap at all. It is superseded here by an assertion
         that pins the count positively.

ASSERTION DISCIPLINE (the permissive-assertion trap):
every assertion below pins a positive, exact value — a specific count, a specific set of names, a
specific mode integer. Where an ABSENCE is asserted (an entity NOT matched, a relation NOT
stored), it is paired in the same test with a POSITIVE CONTROL proving the query that should match
does match — otherwise "nothing came back" would pass against a store that returns nothing at all.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_server.tools import memory as memory_mod
from mcp_server.tools.memory import (
    _db_path,
    _get_conn,
    _like_escape,
    retrieve_entities,
    store_entity,
    store_relation,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def db(tmp_path, monkeypatch):
    """A per-test knowledge graph. Absolute, as _db_path() now requires."""
    path = tmp_path / "graph" / "memory.db"
    monkeypatch.setenv("MEMORY_DB_PATH", str(path))
    return path


# ---------------------------------------------------------------------------
# INV-1 — the graph does not fork with the working directory
# ---------------------------------------------------------------------------

class TestDbPathIsAbsolute:
    """
    The defect was a RELATIVE default, so the invariant is a property of the resolved
    path, and it is proved end-to-end (a store in one cwd is visible from another)
    rather than by inspecting the string alone.
    """

    def test_default_path_is_absolute_and_under_the_users_home(self, tmp_path, monkeypatch):
        """
        With no MEMORY_DB_PATH the resolved path is absolute AND inside $HOME.

        Absoluteness alone is not enough to pin this: an absolute path under the npm
        package tree would satisfy it while still putting a private graph in a shared
        directory, so the home-relative location is asserted too.
        """
        monkeypatch.delenv("MEMORY_DB_PATH", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path))

        resolved = Path(_db_path())

        assert resolved.is_absolute()
        assert resolved == tmp_path / ".arkheia" / "mcp" / "memory.db"

    def test_relative_memory_db_path_is_refused_loudly(self, monkeypatch):
        """
        An explicitly relative MEMORY_DB_PATH raises rather than silently forking the graph.

        Pinned on the exception TYPE and on the message naming the offending value, so a
        bare `raise` or a differently-worded refusal for another reason cannot satisfy it.
        """
        monkeypatch.setenv("MEMORY_DB_PATH", "data/memory.db")

        with pytest.raises(ValueError) as exc:
            _db_path()

        assert "data/memory.db" in str(exc.value)
        assert "absolute" in str(exc.value).lower()

    def test_the_exact_master_default_would_now_be_refused(self, monkeypatch):
        """
        Positive control for the test above, using the LITERAL defective value.

        `Path("C:/arkheia-mcp/data/memory.db").is_absolute()` is False on POSIX, so the
        refusal covers the real regression and not merely a tidier-looking relative path.
        Skipped on Windows, where that string genuinely IS absolute and the defect
        never existed.
        """
        if os.name != "posix":
            pytest.skip("'C:/...' is absolute on Windows; the defect is POSIX-only")

        monkeypatch.setenv("MEMORY_DB_PATH", "C:/arkheia-mcp/data/memory.db")

        with pytest.raises(ValueError):
            _db_path()

    @pytest.mark.asyncio
    async def test_two_working_directories_share_one_graph(self, tmp_path, monkeypatch):
        """
        THE regression test for the defect, asserted as an EFFECT.

        Store from cwd A, retrieve from cwd B, with MEMORY_DB_PATH unset so the default
        is exercised. On master this returned zero entities from B. The assertion is an
        exact entity set, not `len(...) > 0`: a store that returned everything in the
        graph would also satisfy a non-empty check.
        """
        home = tmp_path / "home"
        home.mkdir()
        cwd_a = tmp_path / "a"
        cwd_b = tmp_path / "b"
        cwd_a.mkdir()
        cwd_b.mkdir()

        monkeypatch.delenv("MEMORY_DB_PATH", raising=False)
        monkeypatch.setenv("HOME", str(home))

        monkeypatch.chdir(cwd_a)
        await store_entity("Acme Corp", "company", ["Written from cwd A"])

        monkeypatch.chdir(cwd_b)
        found = await retrieve_entities("Acme Corp")

        assert [e["name"] for e in found["entities"]] == ["Acme Corp"]
        assert [o["content"] for o in found["entities"][0]["observations"]] == [
            "Written from cwd A"
        ]

        # And nothing was written relative to either cwd.
        assert list(cwd_a.iterdir()) == []
        assert list(cwd_b.iterdir()) == []

    def test_source_carries_no_relative_default(self):
        """
        Belt-and-braces: the defective literal is gone from the resolver.

        This is a TOKEN check and is deliberately not the primary evidence for INV-1 —
        a token in a file is not an effect. It exists only so a future edit that
        reintroduces the string is noticed even if someone weakens the effect tests.
        Scoped to the resolver, because the module docstring names the old value on
        purpose and must stay free to do so.
        """
        src = (_REPO_ROOT / "mcp_server" / "tools" / "memory.py").read_text()
        resolver = src.split("def _db_path")[1].split("\ndef ")[0]
        assert "C:/arkheia-mcp" not in resolver


# ---------------------------------------------------------------------------
# INV-2 — the OS boundary is asserted
# ---------------------------------------------------------------------------

@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
class TestStoreIsOwnerPrivate:
    """
    The module's stated position is that observation content is NOT scrubbed and the
    control is the filesystem instead. That position is only honest if the filesystem
    permission is actually set, so it is pinned here in exact octal.
    """

    @pytest.mark.asyncio
    async def test_new_db_and_directory_are_owner_only(self, db):
        await store_entity("Acme Corp", "company", ["a fact"])

        assert (db.stat().st_mode & 0o777) == 0o600
        assert (db.parent.stat().st_mode & 0o777) == 0o700

    @pytest.mark.asyncio
    async def test_a_pre_existing_world_readable_db_is_tightened(self, db):
        """
        mkdir(mode=...) is a no-op on an existing directory and is masked by the umask,
        so the modes must be re-asserted on every connect. An install that already ran
        under the defective code has a 0644 file on disk; opening it must fix it, not
        inherit it.
        """
        await store_entity("Acme Corp", "company", ["a fact"])
        os.chmod(db, 0o644)
        os.chmod(db.parent, 0o755)

        await store_entity("Beta Ltd", "company", ["another fact"])

        assert (db.stat().st_mode & 0o777) == 0o600
        assert (db.parent.stat().st_mode & 0o777) == 0o700


# ---------------------------------------------------------------------------
# INV-3 — search strings are matched literally
# ---------------------------------------------------------------------------

class TestSearchIsLiteral:

    def test_like_escape_covers_all_three_metacharacters(self):
        assert _like_escape("100%") == "100\\%"
        assert _like_escape("auth_middleware") == "auth\\_middleware"
        # The escape character itself must be escaped first, or escaping is reversible.
        assert _like_escape("a\\b") == "a\\\\b"

    @pytest.mark.asyncio
    async def test_percent_query_does_not_return_the_whole_graph(self, db):
        """
        ABSENCE assertion + POSITIVE CONTROL in one test: the wildcard query must return
        nothing, AND a query that genuinely occurs must return exactly its entity — so a
        store that returns nothing at all cannot pass.
        """
        await store_entity("Acme Corp", "company", ["x"])
        await store_entity("Beta Ltd", "company", ["y"])

        wildcard = await retrieve_entities("%")
        assert wildcard["total"] == 0
        assert wildcard["entities"] == []

        control = await retrieve_entities("Acme")
        assert [e["name"] for e in control["entities"]] == ["Acme Corp"]

    @pytest.mark.asyncio
    async def test_underscore_matches_only_a_literal_underscore(self, db):
        """
        The realistic form of this bug: '_' is common in entity names, and unescaped it
        is LIKE's single-character wildcard.
        """
        await store_entity("auth_middleware bug", "bug", ["real"])
        await store_entity("authXmiddleware bug", "bug", ["decoy"])

        result = await retrieve_entities("auth_middleware")

        assert [e["name"] for e in result["entities"]] == ["auth_middleware bug"]
        assert result["total"] == 1

    @pytest.mark.asyncio
    async def test_escaping_survives_the_entity_type_filter_branch(self, db):
        """
        retrieve_entities has TWO SQL call sites — with and without entity_type — and an
        ESCAPE clause added to only one of them would leave the other defective while
        every other test in this class passed. This exercises the second branch.
        """
        await store_entity("auth_middleware bug", "bug", ["real"])
        await store_entity("authXmiddleware bug", "bug", ["decoy"])

        result = await retrieve_entities("auth_middleware", entity_type="bug")

        assert [e["name"] for e in result["entities"]] == ["auth_middleware bug"]


# ---------------------------------------------------------------------------
# INV-4 — the relate contract is enforced
# ---------------------------------------------------------------------------

class TestRelateRefusesDanglingEdges:

    @pytest.mark.asyncio
    async def test_relate_between_two_stored_entities_succeeds(self, db):
        """Positive control: enforcement must not simply refuse everything."""
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
            ("Nobody", "Nowhere", "from_entity"),
        ],
    )
    async def test_unknown_endpoint_raises_and_names_which_one(
        self, db, from_entity, to_entity, offending
    ):
        """
        Both endpoints are checked, not just the first. The message must name the
        offending side — an error that says only 'no such entity' leaves the agent
        unable to tell which name it mistyped.
        """
        await store_entity("Jane Smith", "person", ["Sales lead"])
        await store_entity("Acme Corp", "company", ["Prospect"])

        with pytest.raises(ValueError) as exc:
            await store_relation(from_entity, "works_at", to_entity)

        assert offending in str(exc.value)

    @pytest.mark.asyncio
    async def test_a_refused_relation_leaves_no_row_behind(self, db):
        """
        The refusal must happen BEFORE the insert. Asserting only that it raised would
        pass against an implementation that inserts and then raises.
        """
        await store_entity("Jane Smith", "person", ["Sales lead"])

        with pytest.raises(ValueError):
            await store_relation("Jane Smith", "works_at", "Acme Corp")

        conn = _get_conn()
        try:
            assert conn.execute("SELECT COUNT(*) FROM relations").fetchone()[0] == 0
        finally:
            conn.close()

    @pytest.mark.asyncio
    async def test_a_dangling_edge_planted_directly_is_still_reported(self, db):
        """
        Honest scope marker, asserted rather than described. Enforcement is at the WRITE
        path only; rows already on disk from before this fix (or written by any other
        client of the sqlite file) are still returned by memory_retrieve. This test pins
        that known limitation so it cannot be mistaken for coverage, and fails loudly if
        someone later adds read-side filtering without updating the flow's ledger entry.
        """
        await store_entity("Jane Smith", "person", ["Sales lead"])
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at)"
                " VALUES ('planted', 'Jane Smith', 'works_at', 'Ghost Corp', '2026-01-01')"
            )
            conn.commit()
        finally:
            conn.close()

        result = await retrieve_entities("Jane Smith")

        assert result["entities"][0]["relations"] == [
            {"relation_type": "works_at", "to_entity": "Ghost Corp"}
        ]


# ---------------------------------------------------------------------------
# INV-5 — the documented limit cap is applied (supersedes a permissive assertion)
# ---------------------------------------------------------------------------

class TestRetrieveLimit:

    @pytest.mark.asyncio
    async def test_limit_truncates_entities_but_total_reports_all_matches(self, db):
        """
        Exact counts in both directions. The superseded test asserted only that the
        result was a dict with two keys, which no cap regression could have failed.
        """
        for i in range(12):
            await store_entity(f"Node {i:02d}", "node", [f"obs {i}"])

        result = await retrieve_entities("Node", limit=5)

        assert len(result["entities"]) == 5
        assert result["total"] == 12

    @pytest.mark.asyncio
    async def test_server_wrapper_caps_limit_at_fifty(self, db):
        """
        The cap lives in mcp_server/server.py's wrapper, NOT in retrieve_entities, so it
        must be exercised through the wrapper. Called with limit=9999 against 55 stored
        entities: an uncapped path returns 55, the capped path returns 50.
        """
        from mcp_server import server as mcp_server_module

        for i in range(55):
            await store_entity(f"Node {i:03d}", "node", [f"obs {i}"])

        result = await mcp_server_module.memory_retrieve(query="Node", limit=9999)

        assert len(result["entities"]) == 50
        assert result["total"] == 55


# ---------------------------------------------------------------------------
# Cross-process proof — the defect's actual shape was two PROCESSES, not two calls
# ---------------------------------------------------------------------------

class TestCrossProcessGraphIdentity:
    """
    monkeypatch.chdir proves cwd-independence within one interpreter. The live defect
    was two separately spawned MCP servers (one per install doc), so it is also proved
    across real process boundaries.
    """

    @staticmethod
    def _run(cwd: Path, home: Path, script: str) -> str:
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "PYTHONPATH": str(_REPO_ROOT),
            "JWT_SECRET": "test-secret-for-pytest-not-for-production-use!!",
        }
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(cwd), env=env, capture_output=True, text=True, timeout=60,
        )
        assert proc.returncode == 0, f"child failed: {proc.stdout}\n{proc.stderr}"
        return proc.stdout.strip()

    def test_two_processes_in_different_cwds_see_one_graph(self, tmp_path):
        home = tmp_path / "home"
        home.mkdir()
        for name in ("a", "b"):
            (tmp_path / name).mkdir()

        writer = (
            "import asyncio;"
            "from mcp_server.tools.memory import store_entity;"
            "asyncio.run(store_entity('Acme Corp', 'company', ['from process A']));"
            "print('ok')"
        )
        reader = (
            "import asyncio, json;"
            "from mcp_server.tools.memory import retrieve_entities;"
            "r = asyncio.run(retrieve_entities('Acme Corp'));"
            "print(json.dumps([e['name'] for e in r['entities']]))"
        )

        assert self._run(tmp_path / "a", home, writer) == "ok"
        assert self._run(tmp_path / "b", home, reader) == '["Acme Corp"]'

        # The graph exists in exactly ONE place: under $HOME, and nowhere under either cwd.
        found = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("memory.db"))
        assert found == ["home/.arkheia/mcp/memory.db"]


# ---------------------------------------------------------------------------
# The scrub-vs-access-control decision, pinned as a test
# ---------------------------------------------------------------------------

class TestObservationsAreStoredVerbatim:
    """
    Defect 2 of this flow was "observation text reaches sqlite with no scrub". The
    ruling (argued in the PR body and in the module docstring) is that the remedy is
    ACCESS CONTROL, not redaction: observations are authored, not captured, and are read
    back by the principal that wrote them, so a silent lossy rewrite would destroy a fact
    the agent deliberately kept while telling it nothing.

    That ruling is pinned HERE so it is a decision with a test behind it rather than a
    comment. If a future change adds redaction on the write path, this test fails and
    forces the ledger entry and the threat model to be revisited rather than drifting.
    """

    @pytest.mark.asyncio
    async def test_content_round_trips_byte_identical(self, db):
        observation = "staging DSN is postgres://svc:hunter2@db.internal:5432/app"

        await store_entity("staging env", "environment", [observation])
        result = await retrieve_entities("staging env")

        assert [o["content"] for o in result["entities"][0]["observations"]] == [observation]

    @pytest.mark.asyncio
    async def test_no_redactor_is_imported_by_the_memory_module(self):
        """
        The companion half: the decision is 'no scrub', so the absence of a redaction
        import is asserted deliberately, with the reason on the record. Paired with the
        round-trip test above as its positive control.
        """
        src = (_REPO_ROOT / "mcp_server" / "tools" / "memory.py").read_text()
        assert "from proxy.audit.redactor import" not in src
        assert not hasattr(memory_mod, "redact")
