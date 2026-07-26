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

    def test_the_connection_path_tightens_the_directory_on_its_own(self, db):
        """
        `_get_conn` must assert the directory mode ITSELF, not rely on something else in
        the call doing it.

        Found by the mutation harness, not by review: once receipts landed, `_emit_receipt`
        also re-asserted the directory mode, so deleting `_get_conn`'s own
        `_enforce_mode(parent, _DIR_MODE)` left every store-driven test green. A second
        code path doing the right thing is not the same as this path doing it — an import
        site that opens a connection without emitting a receipt would have inherited a
        world-readable directory. So this drives `_get_conn` alone, with no receipt
        anywhere in the call.
        """
        memory_mod._get_conn().close()
        os.chmod(db.parent, 0o755)

        memory_mod._get_conn().close()

        assert (db.parent.stat().st_mode & 0o777) == 0o700

    @pytest.mark.asyncio
    async def test_an_unenforceable_mode_is_reported_not_swallowed(self, db, monkeypatch, caplog):
        """
        A permission control that cannot be applied must SAY SO.

        The store deliberately does not scrub observation text and names the filesystem as
        its only confidentiality control, so a chmod that fails silently would leave the
        operator believing in a boundary that was never set — the "guard wired but switched
        off" defect. Memory must still work (some filesystems cannot express 0600), so the
        contract is: proceed, and warn loudly.

        Pinned on the WARNING level and on the message actually naming the consequence, not
        merely on "something was logged".
        """
        def _refuse(*_args, **_kwargs):
            raise OSError(1, "Operation not permitted")

        monkeypatch.setattr(memory_mod.os, "chmod", _refuse)

        with caplog.at_level("WARNING", logger=memory_mod.__name__):
            result = await store_entity("Acme Corp", "company", ["still stored"])

        # The store still worked — a permission failure never breaks memory.
        assert result["observations_added"] == 1

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert all("filesystem permissions" in r.getMessage() for r in warnings)

        # Asserted as the SET OF TARGETS, not as a count. A bare `len(warnings) == 2` is the
        # count-guard shape this sweep keeps finding: it says nothing about WHICH artifacts
        # were covered, and it broke — correctly — the moment a third protected artifact
        # appeared. Every file this module asserts a mode on must be named here, so a future
        # artifact that is created and never chmod'ed fails this test rather than sliding
        # under a number that still happens to match.
        protected = {db.parent, db, db.parent / memory_mod.RECEIPT_LOG_NAME}
        warned_about = {
            Path(str(r.args[1]) if r.args else "")
            for r in warnings
        }
        assert warned_about == protected


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
    async def test_a_dangling_edge_planted_directly_is_no_longer_reported(self, db):
        """
        SUPERSEDES `test_a_dangling_edge_planted_directly_is_still_reported`, which pinned
        the write-path-only limitation and was written to "fail loudly if someone later
        adds read-side filtering". Read-side filtering has now been added — retrieve joins
        relations on from_entity_id — so that test failed by design and this replaces it.

        A legacy row carrying only names is migrated to ids when both names resolve
        uniquely (see _migrate_relations_to_ids). "Ghost Corp" resolves to NO entity, so
        this edge cannot be migrated, stays NULL-keyed, and is attached to nobody.

        Both halves are pinned, so this cannot pass by returning nothing at all: the
        dangling edge is absent AND a genuine edge on the same entity is present.
        """
        await store_entity("Jane Smith", "person", ["Sales lead"])
        await store_entity("Real Corp", "company", ["employer"])
        await store_relation("Jane Smith", "works_at", "Real Corp")

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

        # POSITIVE CONTROL + absence, in one assertion: exactly the real edge, and the
        # planted one nowhere in it.
        assert result["entities"][0]["relations"] == [
            {"relation_type": "works_at", "to_entity": "Real Corp"}
        ]

    @pytest.mark.asyncio
    async def test_a_legacy_name_keyed_edge_is_migrated_when_the_names_are_unique(self, db):
        """
        The other half of the migration contract: a pre-existing name-keyed row whose
        endpoints BOTH resolve to exactly one entity is back-filled and keeps working.
        Without this, "dangling edges disappear" could be satisfied by dropping every
        legacy edge, silently discarding real history.
        """
        await store_entity("Jane Smith", "person", ["Sales lead"])
        await store_entity("Real Corp", "company", ["employer"])

        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at)"
                " VALUES ('legacy', 'Jane Smith', 'works_at', 'Real Corp', '2026-01-01')"
            )
            conn.commit()
        finally:
            conn.close()

        result = await retrieve_entities("Jane Smith")
        assert result["entities"][0]["relations"] == [
            {"relation_type": "works_at", "to_entity": "Real Corp"}
        ]

        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT from_entity_id, to_entity_id FROM relations WHERE rel_id = 'legacy'"
            ).fetchone()
        finally:
            conn.close()
        assert row["from_entity_id"] is not None
        assert row["to_entity_id"] is not None

    @pytest.mark.asyncio
    async def test_an_ambiguous_legacy_edge_is_retained_but_attached_to_nobody(self, db):
        """
        The genuinely unrecoverable case, stated honestly. A legacy edge from "Mercury"
        when two Mercuries exist cannot be assigned to either — the information needed was
        never recorded. It must NOT be attached to both (the original defect) and must NOT
        be deleted (silent data loss). It is retained with NULL ids and attached to nobody.
        """
        await store_entity("Mercury", "person", ["god"])
        await store_entity("Mercury", "project", ["project"])
        await store_entity("Acme", "company", ["employer"])

        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at)"
                " VALUES ('ambig', 'Mercury', 'works_at', 'Acme', '2026-01-01')"
            )
            conn.commit()
        finally:
            conn.close()

        result = await retrieve_entities("Mercury", limit=10)
        assert len(result["entities"]) == 2
        for entity in result["entities"]:
            assert entity["relations"] == []

        # Retained, not deleted.
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT from_entity_id, to_entity_id FROM relations WHERE rel_id = 'ambig'"
            ).fetchone()
        finally:
            conn.close()
        assert row is not None
        assert row["from_entity_id"] is None
        assert row["to_entity_id"] is None


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


# ---------------------------------------------------------------------------
# INV-6 — the limit cap is bounded on BOTH sides (Codex finding A)
# ---------------------------------------------------------------------------

class TestLimitIsBoundedBothWays:
    """
    `min(limit, 50)` is a ONE-SIDED bound. It clamps the top and lets everything below
    through, including negatives, which Python's slice semantics then reinterpret:
    rows[:-1] is not "one row", it is "all rows but the last".

    Same defect family as the `-lt` count guards this sweep keeps finding — the guard is
    real, it is just only half a guard.
    """

    @pytest.mark.asyncio
    async def test_negative_limit_does_not_return_more_than_the_cap(self, db):
        """
        Codex finding A, reproduced at the reported shape: 60 rows, limit=-1.
        Observed on the unfixed path: 59 entities returned (rows[:-1]) against a
        documented maximum of 50.
        """
        from mcp_server import server as mcp_server_module

        for i in range(60):
            await store_entity(f"Node {i:03d}", "node", [f"obs {i}"])

        with pytest.raises(ValueError) as exc:
            await mcp_server_module.memory_retrieve(query="Node", limit=-1)

        assert "limit" in str(exc.value).lower()

    @pytest.mark.asyncio
    async def test_zero_limit_is_refused_rather_than_silently_emptying(self, db):
        """
        limit=0 slices to []. That is not a cap violation, but it is indistinguishable
        from "nothing matched" — the silent-degradation shape. Refuse it explicitly.

        Positive control in the same test: the identical query at a valid limit returns
        the rows, so the refusal above is about the limit and not about an empty store.
        """
        from mcp_server import server as mcp_server_module

        for i in range(5):
            await store_entity(f"Node {i:03d}", "node", [f"obs {i}"])

        with pytest.raises(ValueError):
            await mcp_server_module.memory_retrieve(query="Node", limit=0)

        control = await mcp_server_module.memory_retrieve(query="Node", limit=10)
        assert len(control["entities"]) == 5
        assert control["total"] == 5

    @pytest.mark.asyncio
    async def test_non_integer_limit_is_refused_not_coerced(self, db):
        """
        Reject invalid input explicitly rather than coercing silently. A bool is an int
        subclass in Python, so `limit=True` would otherwise slip through as limit=1 and
        return exactly one row while looking like a flag the caller set by mistake.
        """
        from mcp_server import server as mcp_server_module

        await store_entity("Node 001", "node", ["obs"])

        for bad in ("10", 3.5, True, None):
            with pytest.raises(ValueError):
                await mcp_server_module.memory_retrieve(query="Node", limit=bad)

    @pytest.mark.asyncio
    async def test_the_lower_level_function_also_refuses_a_negative_limit(self, db):
        """
        The wrapper is not the only caller of retrieve_entities. Clamping only in
        server.py would leave the defect reachable by any other import site, so the
        bound is asserted at the function that actually does the slicing.
        """
        for i in range(60):
            await store_entity(f"Node {i:03d}", "node", [f"obs {i}"])

        with pytest.raises(ValueError):
            await retrieve_entities("Node", limit=-1)

        control = await retrieve_entities("Node", limit=10)
        assert len(control["entities"]) == 10
        assert control["total"] == 60


# ---------------------------------------------------------------------------
# INV-7 — a relation is keyed by IDENTITY, not by display name (Codex finding B)
# ---------------------------------------------------------------------------

class TestRelationsAreKeyedByIdentity:
    """
    A NAME IS NOT AN IDENTITY. entity_id is already the primary key of `entities`, and
    `observations` correctly references it — but `relations` stored the NAME on both
    endpoints, and retrieve re-joined on `row["name"]`. Two entities may legitimately
    share a name (a person and a project both called Mercury), so one stored edge was
    reported as a fact about BOTH of them.

    Third appearance of this defect shape today: a truncated clause slug, a `setdefault`
    on a shared job name, and now an entity name used as a foreign key.

    The store deliberately permits duplicate names — "Mercury" the person and "Mercury"
    the project are different things that share a label, and forbidding that would be the
    wrong fix. So an ambiguous reference is REFUSED loudly at write time rather than
    silently resolved to whichever row sqlite returned first.
    """

    @pytest.mark.asyncio
    async def test_relation_attaches_to_only_the_named_entity_not_its_namesake(self, db):
        """
        Codex finding B at the reported shape. The relation is created against the
        PERSON (disambiguated by type); the PROJECT must not acquire it.

        Both directions are pinned: the person's relation list is exactly the one edge,
        and the project's is exactly empty. Asserting only `!= []` on the person would
        pass while the bleed continued.
        """
        person = await store_entity("Mercury", "person", ["the Roman god"])
        project = await store_entity("Mercury", "project", ["the internal project"])
        await store_entity("Acme", "company", ["employer"])

        assert person["entity_id"] != project["entity_id"]

        await store_relation(
            "Mercury", "works_at", "Acme", from_entity_type="person"
        )

        result = await retrieve_entities("Mercury", limit=10)
        by_type = {e["entity_type"]: e for e in result["entities"]}

        assert by_type["person"]["relations"] == [
            {"relation_type": "works_at", "to_entity": "Acme"}
        ]
        assert by_type["project"]["relations"] == []

    @pytest.mark.asyncio
    async def test_ambiguous_endpoint_is_refused_rather_than_guessed(self, db):
        """
        With two entities named Mercury and no disambiguator, there is no correct answer.
        Picking one silently is the defect; refusing names the problem to the agent.

        Positive control: the same call against an UNAMBIGUOUS name succeeds, so the
        refusal is about ambiguity and not about relate being broken outright.
        """
        await store_entity("Mercury", "person", ["god"])
        await store_entity("Mercury", "project", ["project"])
        await store_entity("Acme", "company", ["employer"])

        with pytest.raises(ValueError) as exc:
            await store_relation("Mercury", "works_at", "Acme")

        msg = str(exc.value).lower()
        assert "ambiguous" in msg
        assert "mercury" in msg

        await store_entity("Venus", "person", ["unique name"])
        rel = await store_relation("Venus", "works_at", "Acme")
        assert rel["from_entity"] == "Venus"

    @pytest.mark.asyncio
    async def test_relations_are_stored_against_entity_ids_on_disk(self, db):
        """
        Structural proof at the storage layer, not just through the read path: the
        relations row must carry the endpoint entity_ids. A read-path-only fix would
        leave the identity defect latent for any other consumer of the table.
        """
        person = await store_entity("Mercury", "person", ["god"])
        acme = await store_entity("Acme", "company", ["employer"])
        await store_relation("Mercury", "works_at", "Acme", from_entity_type="person")

        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT from_entity_id, to_entity_id FROM relations"
            ).fetchone()
        finally:
            conn.close()

        assert row["from_entity_id"] == person["entity_id"]
        assert row["to_entity_id"] == acme["entity_id"]

    @pytest.mark.asyncio
    async def test_same_name_different_type_each_keeps_its_own_edges(self, db):
        """
        The general case, not just the empty-vs-one case: give BOTH namesakes a distinct
        relation and prove neither sees the other's. If retrieve still joined on name,
        each would report both edges.
        """
        await store_entity("Mercury", "person", ["god"])
        await store_entity("Mercury", "project", ["project"])
        await store_entity("Acme", "company", ["employer"])
        await store_entity("Roadmap", "document", ["plan"])

        await store_relation("Mercury", "works_at", "Acme", from_entity_type="person")
        await store_relation(
            "Mercury", "documented_in", "Roadmap", from_entity_type="project"
        )

        result = await retrieve_entities("Mercury", limit=10)
        by_type = {e["entity_type"]: e for e in result["entities"]}

        assert by_type["person"]["relations"] == [
            {"relation_type": "works_at", "to_entity": "Acme"}
        ]
        assert by_type["project"]["relations"] == [
            {"relation_type": "documented_in", "to_entity": "Roadmap"}
        ]
