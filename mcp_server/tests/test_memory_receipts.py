"""
F5 `receipted` — the knowledge graph's decisions leave a durable, attributable record.

WHAT THIS SUITE HAS TO PROVE, and the three ways a "receipt test" fails to prove it
(discipline from `proxy/tests/_receipt_probe.py`, PR #18, and
`registry_server/tests/_auth_receipt_probe.py`):

1. **It drives a helper, not the writer.** Asserting on the dict `build_record()` returns
   proves what the tool HANDS the audit layer. It proves nothing about what reaches disk:
   `AuditWriter._writer_loop` redacts, chains and serialises after that point, and
   swallows its own write errors while still marking the queue item done. So every test
   here calls the REAL public tool function and reads the REAL file.

2. **It reads back *a* record, not *this* record.** A test that writes one record and then
   asserts something about "the record on disk" passes even when the id the caller was
   handed has nothing to do with the row that landed. So rows are looked up BY THE ID THE
   CALLER RECEIVED, and a fabricated id must find nothing — paired with a positive control
   so that a null result cannot just mean "the log was empty".

3. **It asserts permissively.** `assert row is not None` passes for any garbage. Every
   assertion below pins a positively-computed expected value — a fingerprint recomputed in
   the test from the text actually stored, an entity_id taken from the tool's own result —
   and never merely a truthy one.

FOLLOW-UP, named rather than quietly duplicated: `MemoryReceiptProbe` is the third copy of
this read-back discipline in the repo (proxy PR #18, registry PR #22-branch, here). They
differ only in the id field. Once those land, collapse the three into one generic probe
parameterised by id field. Duplicated here so this suite does not depend on an unmerged
branch.
"""

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from mcp_server import receipts
from mcp_server.tools import memory as memory_mod
from mcp_server.tools.memory import retrieve_entities, store_entity, store_relation
from proxy.audit.writer import _compute_hash


# ---------------------------------------------------------------------------
# Probe — read the artifact back off disk, by the id the caller was handed
# ---------------------------------------------------------------------------

class MemoryReceiptProbe:

    def __init__(self, log_path):
        self.log_path = Path(log_path)

    def raw_bytes(self) -> bytes:
        """The exact bytes on disk. Nothing parses or normalises them first."""
        if not self.log_path.exists():
            return b""
        return self.log_path.read_bytes()

    def rows(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.raw_bytes().decode("utf-8").splitlines()
            if line.strip()
        ]

    def find(self, receipt_id: str):
        matches = [r for r in self.rows() if r.get("receipt_id") == receipt_id]
        if not matches:
            return None
        assert len(matches) == 1, (
            f"{len(matches)} rows carry receipt_id={receipt_id!r}; an id that is not "
            f"unique cannot tie a record to the decision it describes"
        )
        return matches[0]

    def require(self, receipt_id: str) -> dict:
        row = self.find(receipt_id)
        if row is None:
            present = [r.get("receipt_id") for r in self.rows()]
            raise AssertionError(
                f"no receipt row for receipt_id={receipt_id!r}. {len(present)} row(s) on "
                f"disk carrying ids: {present!r}. Either the operation produced no record, "
                f"or the record is not tied to the id the caller was handed."
            )
        return row

    def recompute_this_hash(self, row: dict) -> str:
        body = {k: v for k, v in row.items() if k != "this_hash"}
        return _compute_hash(body, row["prev_hash"])


def fp(text: str) -> str:
    """Fingerprint recomputed independently of the module under test."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


@pytest.fixture
def graph(tmp_path, monkeypatch):
    """A per-test knowledge graph. Its receipt log is resolved beside it, not configured."""
    db = tmp_path / "graph" / "memory.db"
    monkeypatch.setenv("MEMORY_DB_PATH", str(db))
    monkeypatch.delenv("MEMORY_RECEIPT_LOG", raising=False)
    return db


@pytest.fixture
def probe(graph):
    return MemoryReceiptProbe(graph.parent / memory_mod.RECEIPT_LOG_NAME)


# ---------------------------------------------------------------------------
# INV-1 — a mutation is recorded, and the record is tied to the id the caller got
# ---------------------------------------------------------------------------

class TestAStoreIsEvidenced:

    @pytest.mark.asyncio
    async def test_the_surfaced_receipt_id_finds_the_row_that_describes_the_store(self, probe):
        result = await store_entity("Acme Corp", "company", ["In negotiation since 2026-03-01"])

        assert result["receipt"] == receipts.STATUS_RECORDED
        row = probe.require(result["receipt_id"])

        # Positively computed, field by field — nothing here passes for arbitrary content.
        assert row["tool"] == "memory_store"
        assert row["event_type"] == "mcp.memory_store"
        assert row["decision"] == receipts.DECISION_RECORDED
        assert row["entity_id"] == result["entity_id"]
        assert row["entity_type"] == "company"
        assert row["entity_created"] is True
        assert row["name_fingerprint"] == fp("Acme Corp")
        assert row["observations_submitted"] == 1
        assert row["observations_added"] == 1
        assert row["observation_fingerprints"] == [fp("In negotiation since 2026-03-01")]
        assert row["total_observations"] == 1

    @pytest.mark.asyncio
    async def test_a_fabricated_receipt_id_finds_nothing(self, probe):
        """
        The vacuity guard. Without it, a probe that returned "the only row" regardless of
        the id would make every read-back assertion above pass by accident.

        The positive control in the same test is what stops this being satisfied by an
        empty log: the REAL id must resolve in the very same file.
        """
        result = await store_entity("Acme Corp", "company", ["one fact"])

        assert probe.find("0" * 32) is None
        assert probe.find(result["receipt_id"]) is not None

    @pytest.mark.asyncio
    async def test_an_upsert_is_distinguishable_from_a_first_store(self, probe):
        """
        `entity_created` is the difference between "this call created the entity" and
        "this call added to one that already existed". Both return the same entity_id, so
        without this field the receipts for the two are identical and the record cannot
        answer when an entity came into existence.
        """
        first = await store_entity("Acme Corp", "company", ["one fact"])
        second = await store_entity("Acme Corp", "company", ["another fact"])

        assert probe.require(first["receipt_id"])["entity_created"] is True
        assert probe.require(second["receipt_id"])["entity_created"] is False
        assert second["entity_id"] == first["entity_id"]

    @pytest.mark.asyncio
    async def test_a_deduplicated_observation_is_recorded_as_added_nothing(self, probe):
        await store_entity("Acme Corp", "company", ["one fact"])
        again = await store_entity("Acme Corp", "company", ["one fact"])

        row = probe.require(again["receipt_id"])
        assert row["observations_submitted"] == 1
        assert row["observations_added"] == 0
        assert row["observation_fingerprints"] == []
        assert row["total_observations"] == 1


# ---------------------------------------------------------------------------
# INV-2 — the record is chained, and the chained form is the form on disk
# ---------------------------------------------------------------------------

class TestTheRecordIsTamperEvident:

    @pytest.mark.asyncio
    async def test_the_stored_hash_is_reproducible_from_the_row_as_it_sits_on_disk(self, probe):
        result = await store_entity("Acme Corp", "company", ["one fact"])
        row = probe.require(result["receipt_id"])

        assert row["seq"] == 1
        assert row["prev_hash"] == "0" * 64
        assert row["this_hash"] == probe.recompute_this_hash(row)

    @pytest.mark.asyncio
    async def test_the_chain_continues_across_calls_and_across_writers(self, graph, probe):
        """
        Each emit constructs its own `AuditWriter` (there is no lifespan to hold one), so
        the chain only holds if every writer recovers the tail before appending. Three
        separate calls, three separate writers, one unbroken chain.
        """
        ids = [
            (await store_entity("Acme Corp", "company", ["fact one"]))["receipt_id"],
            (await store_entity("Beta Ltd", "company", ["fact two"]))["receipt_id"],
            (await retrieve_entities("Acme"))["receipt_id"],
        ]

        rows = probe.rows()
        assert [r["receipt_id"] for r in rows] == ids
        assert [r["seq"] for r in rows] == [1, 2, 3]

        prev = "0" * 64
        for row in rows:
            assert row["prev_hash"] == prev
            assert row["this_hash"] == probe.recompute_this_hash(row)
            prev = row["this_hash"]

    @pytest.mark.asyncio
    async def test_an_edited_record_breaks_the_chain(self, probe):
        """
        POSITIVE CONTROL for the recomputation above: a hash check that could not detect a
        change would satisfy every assertion in this class. Rewrite one field on disk and
        require the recomputation to disagree.
        """
        result = await store_entity("Acme Corp", "company", ["one fact"])
        row = probe.require(result["receipt_id"])
        assert row["this_hash"] == probe.recompute_this_hash(row)

        tampered = dict(row)
        tampered["entity_id"] = "00000000-0000-0000-0000-000000000000"
        probe.log_path.write_text(json.dumps(tampered) + "\n", encoding="utf-8")

        after = probe.require(result["receipt_id"])
        assert after["this_hash"] != probe.recompute_this_hash(after)


# ---------------------------------------------------------------------------
# INV-3 — the receipt evidences the change without becoming a copy of the graph
# ---------------------------------------------------------------------------

class TestTheReceiptCarriesNoAuthoredText:
    """
    The ruling on this flow (module docstring, and `TestObservationsAreStoredVerbatim`) is
    that observation text is NOT scrubbed: it is authored rather than captured, and a
    silent lossy rewrite would destroy a fact the agent meant to keep.

    `AuditWriter` redacts everything it writes. So a receipt carrying observation text
    would subject that text to exactly the silent rewrite the ruling rejects, and would
    additionally make the receipt log a second, differently-retained copy of the graph.
    The design answer is that receipts carry identifiers, counts and fingerprints only —
    and that is asserted here against the RAW BYTES, not against a parsed view.
    """

    @pytest.mark.asyncio
    async def test_the_observation_text_reaches_the_db_and_not_the_receipt(self, graph, probe):
        secret_shaped = "staging DSN is postgres://svc:hunter2@db.internal:5432/app"

        result = await store_entity("staging env", "environment", [secret_shaped])

        # Positive control: the text really is in the store, byte-identical and unscrubbed.
        rows = sqlite3.connect(graph).execute("SELECT content FROM observations").fetchall()
        assert [r[0] for r in rows] == [secret_shaped]

        # And it is nowhere in the evidence file — asserted on raw bytes.
        assert secret_shaped.encode() not in probe.raw_bytes()
        assert b"hunter2" not in probe.raw_bytes()

        # What IS there is the fingerprint, which ties the record to that exact text.
        assert probe.require(result["receipt_id"])["observation_fingerprints"] == [
            fp(secret_shaped)
        ]

    @pytest.mark.asyncio
    async def test_the_entity_name_is_fingerprinted_not_copied(self, probe):
        name = "Project Mercury acquisition"
        result = await store_entity(name, "project", ["kick-off 2026-04-01"])

        assert name.encode() not in probe.raw_bytes()
        assert probe.require(result["receipt_id"])["name_fingerprint"] == fp(name)

    @pytest.mark.asyncio
    async def test_the_identifiers_survive_the_redactor_verbatim(self, probe):
        """
        The rail redacts every record on the way to disk. If a uuid4 or a `sha256:` prefix
        ever matched a secret pattern, the receipt would land carrying `[REDACTED:…]` where
        its primary key should be and would stop being attributable at all — silently.
        Pinned so a future pattern added to the redactor cannot eat the evidence.
        """
        result = await store_entity("Acme Corp", "company", ["one fact"])
        row = probe.require(result["receipt_id"])

        assert row["entity_id"] == result["entity_id"]
        assert "REDACTED" not in json.dumps(row)


# ---------------------------------------------------------------------------
# INV-4 — the refusals are receipted, because the refusal IS the control
# ---------------------------------------------------------------------------

class TestRefusalsAreEvidenced:
    """
    `memory_relate` refuses an unknown endpoint and refuses an ambiguous one; those
    refusals are the control that stops dangling and mis-attributed edges. A refusal that
    leaves no record is indistinguishable from a call that was never made — "the agent's
    memory is wrong" and "the agent tried to record it and was stopped" look identical.
    """

    @pytest.mark.asyncio
    async def test_an_unknown_endpoint_leaves_a_refusal_receipt(self, probe):
        await store_entity("Acme Corp", "company", ["exists"])

        with pytest.raises(ValueError) as exc:
            await store_relation("Acme Corp", "acquired", "Ghost Ltd")

        # The receipt id comes back through the only channel this tool has: the message.
        message = str(exc.value)
        assert "no such entity" in message
        receipt_id = message.split("[receipt ")[1].split(":")[0]

        row = probe.require(receipt_id)
        assert row["tool"] == "memory_relate"
        assert row["decision"] == receipts.DECISION_REFUSED
        assert row["reason"] == "unknown_endpoint"
        assert row["endpoint"] == "to_entity"
        assert row["endpoint_name_fingerprint"] == fp("Ghost Ltd")
        assert row["candidates"] == 0
        assert row["relation_type"] == "acquired"

    @pytest.mark.asyncio
    async def test_an_ambiguous_endpoint_leaves_a_refusal_receipt_naming_the_count(self, probe):
        await store_entity("Mercury", "person", ["a person"])
        await store_entity("Mercury", "project", ["a project"])
        await store_entity("Acme Corp", "company", ["exists"])

        with pytest.raises(ValueError) as exc:
            await store_relation("Mercury", "works_at", "Acme Corp")

        receipt_id = str(exc.value).split("[receipt ")[1].split(":")[0]
        row = probe.require(receipt_id)
        assert row["reason"] == "ambiguous_endpoint"
        assert row["endpoint"] == "from_entity"
        assert row["candidates"] == 2
        assert row["endpoint_name_fingerprint"] == fp("Mercury")

    @pytest.mark.asyncio
    async def test_a_refused_relation_records_the_refusal_and_no_success(self, graph, probe):
        """
        The refusal receipt must not be accompanied by a success one. Asserted as the
        exact decision sequence on disk, so an implementation that receipted the attempt
        AND the refusal — leaving a log that reads as though an edge was created — fails.
        """
        await store_entity("Acme Corp", "company", ["exists"])
        with pytest.raises(ValueError):
            await store_relation("Acme Corp", "acquired", "Ghost Ltd")

        relate_rows = [r for r in probe.rows() if r["tool"] == "memory_relate"]
        assert [r["decision"] for r in relate_rows] == [receipts.DECISION_REFUSED]
        assert sqlite3.connect(graph).execute("SELECT COUNT(*) FROM relations").fetchone()[0] == 0

    @pytest.mark.asyncio
    async def test_a_refused_retrieve_leaves_a_receipt_and_discloses_nothing(self, probe):
        await store_entity("Acme Corp", "company", ["one fact"])

        with pytest.raises(ValueError) as exc:
            await retrieve_entities("Acme", limit=-1)

        receipt_id = str(exc.value).split("[receipt ")[1].split(":")[0]
        row = probe.require(receipt_id)
        assert row["tool"] == "memory_retrieve"
        assert row["decision"] == receipts.DECISION_REFUSED
        assert row["reason"] == "limit_below_one"
        assert row["limit_requested"] == "-1"
        # A refused read disclosed nothing, so the record must not claim otherwise.
        assert "entity_ids" not in row


# ---------------------------------------------------------------------------
# INV-5 — a retrieval records WHAT WAS DISCLOSED
# ---------------------------------------------------------------------------

class TestARetrievalIsEvidenced:

    @pytest.mark.asyncio
    async def test_the_receipt_names_the_rows_actually_returned(self, probe):
        a = await store_entity("Acme Corp", "company", ["one"])
        b = await store_entity("Acme Holdings", "company", ["two"])
        await store_entity("Beta Ltd", "company", ["three"])

        result = await retrieve_entities("Acme", limit=10)
        row = probe.require(result["receipt_id"])

        assert row["query_fingerprint"] == fp("Acme")
        assert row["matched"] == 2
        assert row["returned"] == 2
        assert sorted(row["entity_ids"]) == sorted([a["entity_id"], b["entity_id"]])
        assert row["limit_requested"] == "10"
        assert row["limit_applied"] == 10

    @pytest.mark.asyncio
    async def test_a_clamped_limit_records_both_what_was_asked_and_what_was_applied(self, probe):
        """
        `limit=500` is clamped to the published maximum of 50. A receipt that recorded only
        the applied value would lose the fact that a caller asked for ten times the cap —
        which is the interesting half.
        """
        await store_entity("Acme Corp", "company", ["one"])
        result = await retrieve_entities("Acme", limit=500)

        row = probe.require(result["receipt_id"])
        assert row["limit_requested"] == "500"
        assert row["limit_applied"] == memory_mod.MAX_RETRIEVE_LIMIT

    @pytest.mark.asyncio
    async def test_a_search_that_matched_nothing_is_still_recorded(self, probe):
        """
        An empty result is a disclosure decision too, and it is the one an operator asks
        about ("did the agent even look?"). Zero rows must not mean zero records.
        """
        result = await retrieve_entities("nothing here")

        row = probe.require(result["receipt_id"])
        assert row["matched"] == 0
        assert row["returned"] == 0
        assert row["entity_ids"] == []


# ---------------------------------------------------------------------------
# INV-6 — the relate success path
# ---------------------------------------------------------------------------

class TestARelationIsEvidenced:

    @pytest.mark.asyncio
    async def test_the_receipt_carries_the_resolved_identities_not_just_the_names(self, probe):
        """
        The edge is keyed by entity_id precisely because a name is not an identity. The
        receipt has to carry the same keys, or it evidences an ambiguity the store went to
        some trouble to remove.
        """
        person = await store_entity("Mercury", "person", ["a person"])
        await store_entity("Mercury", "project", ["a project"])
        acme = await store_entity("Acme Corp", "company", ["exists"])

        result = await store_relation(
            "Mercury", "works_at", "Acme Corp", from_entity_type="person"
        )
        row = probe.require(result["receipt_id"])

        assert row["rel_id"] == result["rel_id"]
        assert row["relation_type"] == "works_at"
        assert row["from_entity_id"] == person["entity_id"]
        assert row["to_entity_id"] == acme["entity_id"]
        assert row["from_name_fingerprint"] == fp("Mercury")
        assert row["to_name_fingerprint"] == fp("Acme Corp")
        assert row["from_entity_type"] == "person"
        assert row["to_entity_type"] is None


# ---------------------------------------------------------------------------
# INV-7 — the evidence is protected exactly as well as the store it describes
# ---------------------------------------------------------------------------

class TestTheReceiptLogIsOwnerPrivate:

    @pytest.mark.asyncio
    async def test_the_log_sits_beside_the_db_and_is_owner_only(self, graph, probe):
        await store_entity("Acme Corp", "company", ["one fact"])

        assert probe.log_path.parent == graph.parent
        assert probe.log_path.exists()
        assert (probe.log_path.stat().st_mode & 0o777) == 0o600
        assert (probe.log_path.parent.stat().st_mode & 0o777) == 0o700

    @pytest.mark.asyncio
    async def test_redirecting_the_graph_redirects_its_evidence(self, tmp_path, monkeypatch):
        """
        One graph, one receipt log. If the receipt path did not follow MEMORY_DB_PATH, a
        second graph's evidence would land in the first graph's log and every id in it
        would resolve against the wrong store — or, worse, against a path in a shared tree.
        """
        other = tmp_path / "elsewhere" / "memory.db"
        monkeypatch.setenv("MEMORY_DB_PATH", str(other))
        monkeypatch.delenv("MEMORY_RECEIPT_LOG", raising=False)

        result = await store_entity("Acme Corp", "company", ["one fact"])

        expected = other.parent / memory_mod.RECEIPT_LOG_NAME
        assert MemoryReceiptProbe(expected).find(result["receipt_id"]) is not None
        assert list((tmp_path / "elsewhere").iterdir()) != []

    @pytest.mark.asyncio
    async def test_an_explicit_override_is_honoured(self, tmp_path, monkeypatch, graph):
        override = tmp_path / "audit" / "memory-receipts.jsonl"
        monkeypatch.setenv("MEMORY_RECEIPT_LOG", str(override))

        result = await store_entity("Acme Corp", "company", ["one fact"])

        assert MemoryReceiptProbe(override).find(result["receipt_id"]) is not None
        assert not (graph.parent / memory_mod.RECEIPT_LOG_NAME).exists()

    def test_a_relative_override_is_refused(self, monkeypatch):
        """
        Same rule as MEMORY_DB_PATH and for the same reason: a cwd-relative evidence path
        splits one graph's record across every process that runs from a different
        directory, and this repo ships three different working directories for one server.
        """
        monkeypatch.setenv("MEMORY_RECEIPT_LOG", "receipts.jsonl")
        with pytest.raises(ValueError, match="absolute"):
            memory_mod._receipt_log_path()

    def test_an_absolute_override_is_accepted(self, tmp_path, monkeypatch):
        """POSITIVE CONTROL: a resolver that refused everything would pass the test above."""
        monkeypatch.setenv("MEMORY_RECEIPT_LOG", str(tmp_path / "r.jsonl"))
        assert memory_mod._receipt_log_path() == str(tmp_path / "r.jsonl")


# ---------------------------------------------------------------------------
# INV-8 — fail-open on the receipt, never on the decision; never fail-silent
# ---------------------------------------------------------------------------

class TestAnUnwritableReceiptChangesNoOutcome:
    """
    The standing ruling is that a receipt failure must not block the operation. It must
    also not be invisible — an unrecorded change that reports itself as recorded is worse
    than no receipt at all, because it is a claim about evidence that does not exist.

    Both failures below are induced by REAL I/O, not by monkeypatching an exception into
    the receipt path: a directory occupies the log path, so the writer's `open(..., "a")`
    genuinely raises, exactly as it would on a full disk or a read-only mount.
    """

    @pytest.fixture
    def blocked_log(self, graph):
        path = graph.parent / memory_mod.RECEIPT_LOG_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir()
        return path

    @pytest.mark.asyncio
    async def test_the_store_still_happens_and_says_it_is_unrecorded(self, graph, blocked_log):
        result = await store_entity("Acme Corp", "company", ["still stored"])

        # The mutation stands.
        assert result["observations_added"] == 1
        rows = sqlite3.connect(graph).execute("SELECT content FROM observations").fetchall()
        assert [r[0] for r in rows] == ["still stored"]

        # And the caller is told, in the result, that it is not evidenced.
        assert result["receipt"] == receipts.STATUS_UNRECORDED
        assert result["receipt_id"]

    @pytest.mark.asyncio
    async def test_a_refusal_stays_a_refusal(self, graph, blocked_log):
        """
        The nastier half. If the receipt path raised on the refusal branch, the caller
        would receive a DIFFERENT error than the one the control produced — the registry
        found exactly this, where a failing receipt turned a 401 into a 500.
        """
        await store_entity("Acme Corp", "company", ["exists"])

        with pytest.raises(ValueError) as exc:
            await store_relation("Acme Corp", "acquired", "Ghost Ltd")

        message = str(exc.value)
        assert "no such entity" in message
        assert f": {receipts.STATUS_UNRECORDED}]" in message

    @pytest.mark.asyncio
    async def test_the_failure_is_logged_at_error_level(self, blocked_log, caplog):
        """
        Fail-open, never fail-silent. Nobody reads a tool result looking for a missing
        receipt; the operator reads logs. Pinned on ERROR and on the message naming the
        consequence, not merely on "something was logged".
        """
        with caplog.at_level("ERROR"):
            await store_entity("Acme Corp", "company", ["still stored"])

        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert errors, "an unrecorded decision was completely silent"
        assert any("UNRECORDED" in r.getMessage() for r in errors)


# ---------------------------------------------------------------------------
# INV-9 — coverage: no governed memory tool is left un-receipted
# ---------------------------------------------------------------------------

class TestEveryGovernedMemoryToolEmits:

    @pytest.mark.asyncio
    async def test_all_three_tools_leave_a_row(self, probe):
        """
        Coverage stated as an exact SET, not a count: a new tool added to this module
        without a receipt leaves the set short, and no total that merely "looks right" can
        cover for it.
        """
        await store_entity("Acme Corp", "company", ["one"])
        await store_entity("Beta Ltd", "company", ["two"])
        await store_relation("Acme Corp", "partners_with", "Beta Ltd")
        await retrieve_entities("Acme")

        assert {r["tool"] for r in probe.rows()} == {
            "memory_store",
            "memory_retrieve",
            "memory_relate",
        }

    @pytest.mark.asyncio
    async def test_every_row_carries_the_graph_it_describes(self, graph, probe):
        """
        The prior defect on this flow was a store that silently forked across working
        directories. A receipt that did not name its graph would be unable to tell two
        forks apart afterwards — the evidence would be as ambiguous as the bug.
        """
        await store_entity("Acme Corp", "company", ["one"])
        await retrieve_entities("Acme")

        assert {r["graph"] for r in probe.rows()} == {str(graph)}

    @pytest.mark.asyncio
    async def test_receipt_ids_are_unique_across_calls(self, probe):
        ids = [
            (await store_entity("Acme Corp", "company", ["one"]))["receipt_id"],
            (await store_entity("Acme Corp", "company", ["two"]))["receipt_id"],
            (await retrieve_entities("Acme"))["receipt_id"],
        ]
        assert len(set(ids)) == 3
        assert len({r["receipt_id"] for r in probe.rows()}) == 3


# ---------------------------------------------------------------------------
# INV-10 — the record builder refuses an unknown decision
# ---------------------------------------------------------------------------

def test_an_unknown_decision_is_refused_rather_than_recorded():
    """
    A typo'd decision would create a class of record that no query for "refused" ever
    finds — the receipt equivalent of an unregistered event type, which this estate has
    shipped three times. Cheap to make impossible.
    """
    with pytest.raises(ValueError, match="unknown decision"):
        receipts.build_record(receipt_id="x", tool="memory_store", decision="maybe")

    # POSITIVE CONTROL: the valid decisions really do build.
    for decision in (receipts.DECISION_RECORDED, receipts.DECISION_REFUSED):
        assert receipts.build_record(
            receipt_id="x", tool="memory_store", decision=decision
        )["decision"] == decision


def test_a_fingerprint_distinguishes_texts_and_passes_none_through():
    assert receipts.fingerprint("a") != receipts.fingerprint("b")
    assert receipts.fingerprint("a") == fp("a")
    # None and "" are different facts — an absent optional must not be recorded as the
    # fingerprint of the empty string.
    assert receipts.fingerprint(None) is None
    assert receipts.fingerprint("") is not None


@pytest.mark.asyncio
async def test_the_probe_is_not_reading_the_production_reader(probe):
    """
    The suite's own vacuity guard. Every read-back above goes through MemoryReceiptProbe,
    which parses the file itself. Check it agrees with the production reader on the same
    file — if they ever disagree, one of them is wrong and the tests would otherwise be
    grading the implementation with itself.
    """
    result = await store_entity("Acme Corp", "company", ["one fact"])

    assert receipts.find_receipt(probe.log_path, result["receipt_id"]) == probe.require(
        result["receipt_id"]
    )
    assert receipts.find_receipt(probe.log_path, "0" * 32) is None
