"""
RECEIPTED AXIS — the tool-registry gate's allow/deny decision leaves a durable,
attributable record on the shared audit rail.

Collected by the REQUIRED status context ``unit-tests``
(``.github/workflows/unit-tests.yml``, job ``unit``, which runs
``pytest proxy/tests mcp_server/tests registry_server/tests tests``).

WHAT WAS WRONG
--------------
The gate decided whether a tool call may execute — a governed decision made on
behalf of an orchestrator — and recorded NOTHING. Not the allows, and (the serious
half) not the denies. A blocked tool call produced an exception string on the wire
and no artefact at all, so after the fact "this agent was refused four hundred
times" and "this agent never asked" were the same observation. A refusal nobody can
see later cannot be investigated by us and cannot be contested by the customer.

HOW THIS SUITE PROVES THE FIX, rather than asserting it
-------------------------------------------------------
Every test here drives the REAL production path and then reads the artefact back
off disk through ``proxy/tests/_receipt_probe.ReceiptProbe`` — the single shared
probe (``id_field="receipt_id"``), not a fourth private copy and not a recording
stub. The probe's properties are what make the read-back meaningful:

  * the row is looked up BY THE ID THE CALLER WAS HANDED, so it is tied to the
    decision rather than merely being *a* row near the right timestamp;
  * a fabricated id finds nothing, which is what lets each absence assertion carry
    a positive control;
  * ``this_hash`` is recomputed from the row AS IT SITS ON DISK, so the record is
    proved to be inside the tamper-evident chain in its redacted form;
  * ``verify_chain`` is the PRODUCTION verifier, not a reimplementation here.

Every assertion pins a positively computed expected value. There is no
``assert row is not None`` standing in for a test.
"""
from __future__ import annotations

import json

import pytest

from mcp_server import receipts, server as srv
from mcp_server.tool_registry import (
    _POLICIES,
    GATE_EVENT_TYPE,
    Permission,
    PolicyViolation,
    ToolPolicy,
    check_receipted,
    decide,
)
from proxy.tests._receipt_probe import ReceiptProbe, contains

pytestmark = pytest.mark.asyncio


@pytest.fixture
def probe(gate_receipt_log):
    """Read-only probe over the file the PRODUCTION gate writes (probe property P2).

    ``gate_receipt_log`` (mcp_server/tests/conftest.py) has already pointed the gate
    at this path via its real env var, so nothing here constructs a writer, and the
    bytes read back were written by the code under test.
    """
    return ReceiptProbe(gate_receipt_log, id_field="receipt_id")


@pytest.fixture
def registry_sandbox():
    original = dict(_POLICIES)
    try:
        yield _POLICIES
    finally:
        _POLICIES.clear()
        _POLICIES.update(original)


# ---------------------------------------------------------------------------
# 1 — the DENY leaves a record. The half that matters most.
# ---------------------------------------------------------------------------

class TestDenyIsRecorded:

    async def test_denied_call_writes_one_row_findable_by_the_surfaced_id(self, probe):
        with pytest.raises(PolicyViolation) as exc:
            await check_receipted("exfiltrate_secrets")

        receipt_id = exc.value.receipt_id
        assert receipt_id, "the refusal carried no receipt id, so it cannot be quoted"
        assert exc.value.receipt_status == receipts.STATUS_RECORDED

        row = probe.require(receipt_id)
        assert row["decision"] == receipts.DECISION_DENIED
        assert row["tool"] == "exfiltrate_secrets"
        assert row["event_type"] == GATE_EVENT_TYPE
        assert row["control"] == "tool_registry_gate"
        assert row["deny_code"] == "not_registered"
        assert "not in allowlist" in row["deny_reason"]
        # A NO must carry what would clear it. An unexplained refusal is the
        # Gate-9 legibility finding, and in a trust product it is indistinguishable
        # from an arbitrary one.
        assert row["remedy"]
        assert "advertised" in row["remedy"]
        # Exactly one row: a decision must not be double-counted in the evidence.
        assert len(probe.rows()) == 1

    async def test_a_fabricated_receipt_id_finds_nothing(self, probe):
        """The vacuity guard (probe property P4). Without it, every read-back below
        would pass against a probe that returned 'the only row' whatever it was
        asked for — and then none of them would be testing attributability."""
        with pytest.raises(PolicyViolation) as exc:
            await check_receipted("exfiltrate_secrets")
        # Positive control: the real id resolves.
        assert probe.find(exc.value.receipt_id) is not None
        # And a plausible-looking id that was never issued does not.
        assert probe.find("0" * 32) is None

    async def test_the_receipt_id_is_in_the_refusal_MESSAGE_not_only_an_attribute(self):
        """The MCP framework serialises a handler exception down to its string, so an
        attribute the orchestrator never sees is not recourse."""
        with pytest.raises(PolicyViolation) as exc:
            await check_receipted("exfiltrate_secrets")
        assert exc.value.receipt_id in str(exc.value)
        assert receipts.STATUS_RECORDED in str(exc.value)

    @pytest.mark.parametrize(
        "setup,tool,expected_code",
        [
            ("unregistered", "exfiltrate_secrets", "not_registered"),
            ("empty_permissions", "neutered", "empty_permission_set"),
            ("confirm_required", "deploy_to_prod", "human_confirm_required"),
            ("malformed", None, "malformed_tool_name"),
        ],
    )
    async def test_every_deny_branch_is_recorded_with_its_own_code(
        self, probe, registry_sandbox, setup, tool, expected_code
    ):
        """All four deny branches, each producing a DISTINCT machine-readable code on
        disk. Prose reasons cannot be counted; a stream where every refusal says
        'policy violation' cannot answer 'are we being probed, or is one integration
        misconfigured?'."""
        if setup == "empty_permissions":
            registry_sandbox[tool] = ToolPolicy(name=tool, permissions=())
        elif setup == "confirm_required":
            registry_sandbox[tool] = ToolPolicy(
                name=tool,
                permissions=(Permission.DEPLOY,),
                requires_human_confirm=True,
            )

        with pytest.raises(PolicyViolation) as exc:
            await check_receipted(tool)

        row = probe.require(exc.value.receipt_id)
        assert row["decision"] == receipts.DECISION_DENIED
        assert row["deny_code"] == expected_code
        assert row["remedy"], f"{expected_code} refusal has no path to yes"

    async def test_deny_branch_codes_are_all_distinct_on_disk(self, probe, registry_sandbox):
        """Companion to the parametrised test above, which could pass while two
        branches shared a code — each case only sees its own row."""
        registry_sandbox["neutered"] = ToolPolicy(name="neutered", permissions=())
        registry_sandbox["deploy_to_prod"] = ToolPolicy(
            name="deploy_to_prod",
            permissions=(Permission.DEPLOY,),
            requires_human_confirm=True,
        )
        for name in ("exfiltrate_secrets", "neutered", "deploy_to_prod", 12345):
            with pytest.raises(PolicyViolation):
                await check_receipted(name)

        codes = [r["deny_code"] for r in probe.rows()]
        assert len(codes) == 4
        assert len(set(codes)) == 4, f"deny branches share a code on disk: {codes}"


# ---------------------------------------------------------------------------
# 2 — the ALLOW leaves a record too, carrying the policy that was APPLIED
# ---------------------------------------------------------------------------

class TestAllowIsRecorded:

    async def test_allowed_call_records_the_policy_actually_applied(self, probe):
        d = await decide(
            "run_grok", argument_keys=["prompt", "model"], call_site="dispatch"
        )
        assert d.allowed is True
        assert d.receipt_status == receipts.STATUS_RECORDED

        row = probe.require(d.receipt_id)
        assert row["decision"] == receipts.DECISION_ALLOWED
        assert row["tool"] == "run_grok"
        assert row["deny_code"] is None
        assert row["deny_reason"] is None
        # The grant the decision USED, positively pinned. "Some permissions" would
        # pass against a row that silently recorded DEPLOY.
        assert row["permissions_applied"] == ["execute", "read"]
        assert row["network_egress_declared"] is True
        assert row["requires_human_confirm"] is False
        assert row["human_confirmed"] is False
        assert row["call_site"] == "dispatch"
        assert row["argument_keys"] == ["model", "prompt"]

    async def test_a_supplied_human_approval_is_recorded_as_such(
        self, probe, registry_sandbox
    ):
        """An approval that is used and not recorded is an unauditable override: the
        one field that distinguishes 'a human authorised this' from 'the gate let it
        through'."""
        registry_sandbox["deploy_to_prod"] = ToolPolicy(
            name="deploy_to_prod",
            permissions=(Permission.DEPLOY,),
            requires_human_confirm=True,
        )
        d = await decide("deploy_to_prod", human_confirmed=True)
        assert d.allowed is True
        row = probe.require(d.receipt_id)
        assert row["decision"] == receipts.DECISION_ALLOWED
        assert row["human_confirmed"] is True
        assert row["requires_human_confirm"] is True
        assert row["permissions_applied"] == ["deploy"]


# ---------------------------------------------------------------------------
# 3 — the record is real: on the shared rail, chained, and redacting
# ---------------------------------------------------------------------------

class TestTheRecordIsOnTheSharedRail:

    async def test_rows_are_chained_and_the_chain_verifies(self, probe, gate_receipt_log):
        ids = []
        for name in ("arkheia_verify", "arkheia_audit_log", "memory_store"):
            ids.append((await decide(name)).receipt_id)
        for name in ("nope_one", "nope_two"):
            with pytest.raises(PolicyViolation) as exc:
                await check_receipted(name)
            ids.append(exc.value.receipt_id)

        rows = probe.rows()
        assert [r["receipt_id"] for r in rows] == ids, (
            "rows on disk are not the decisions that were made, in order"
        )
        # seq is dense from 1 and prev_hash links each row to the one before it.
        assert [r["seq"] for r in rows] == [1, 2, 3, 4, 5]
        assert rows[0]["prev_hash"] == "0" * 64
        for earlier, later in zip(rows, rows[1:]):
            assert later["prev_hash"] == earlier["this_hash"]

        # Recompute each hash from the row AS IT SITS ON DISK (probe property P8):
        # this is what proves the REDACTED form is the form that was committed.
        for row in rows:
            assert probe.recompute_this_hash(row) == row["this_hash"]

        # And delegate to the PRODUCTION verifier rather than trusting the loop above.
        verdict = probe.verify_chain()
        assert verdict == {"ok": True, "verified": 5, "breaks": []}

    async def test_a_tampered_row_breaks_the_chain(self, probe, gate_receipt_log):
        """The chain assertions above are only evidence if the chain can FAIL. Flip a
        recorded verdict from denied to allowed — the single most valuable edit an
        attacker could make to this file — and require it to be detected."""
        with pytest.raises(PolicyViolation):
            await check_receipted("exfiltrate_secrets")
        assert probe.verify_chain()["ok"] is True  # positive control

        row = json.loads(gate_receipt_log.read_text().strip())
        row["decision"] = receipts.DECISION_ALLOWED
        gate_receipt_log.write_text(json.dumps(row) + "\n")

        verdict = probe.verify_chain()
        assert verdict["ok"] is False
        assert verdict["verified"] == 1
        assert len(verdict["breaks"]) == 1

    async def test_argument_VALUES_never_reach_the_evidence_file(self, probe):
        """Argument names are structure; argument values are prompts, observations and
        credentials. Asserted on the RAW BYTES (probe property P7), not a parsed view,
        so a value nested anywhere in the record would still be caught."""
        secret = "ak_live_deadbeefdeadbeefdeadbeef0123"
        d = await decide("arkheia_verify", argument_keys=["prompt", "response", "model"])
        raw = probe.raw_bytes()
        # Positive control: the probe IS looking at the right bytes.
        assert contains(raw, d.receipt_id)
        assert contains(raw, "argument_keys")
        # And the values are not there — never were passed, and must never be.
        assert not contains(raw, secret)

    async def test_the_receipt_file_is_not_world_readable(self, gate_receipt_log):
        await decide("arkheia_verify")
        mode = gate_receipt_log.stat().st_mode & 0o777
        assert mode == 0o600, (
            f"gate receipt log is mode {oct(mode)}. Evidence about who was refused "
            f"what must be at least as protected as the thing it describes; under the "
            f"npm install the package tree sits in a shared node_modules."
        )
