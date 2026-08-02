"""
Decision receipts for the KNOWLEDGE-GRAPH tools — same rail as the proxy and the registry.

WHY THIS IS NOT `mcp_server/receipts.py`
----------------------------------------
It was, on this branch. `mcp_server/receipts.py` on master is the TOOL-GATE rail
(`tool_registry.py`; decisions allowed/denied/unrepresentable) and it confines every
receipt path to `~/.arkheia/mcp` or the OS temp dir. This module is the MEMORY rail
(decisions recorded/refused) and its first stated property is the opposite one — the log
path is supplied by the CALLER, because the receipt has to land inside the same 0700
directory as the graph it describes, wherever the operator put that graph. Fusing them
would have had to pick one path policy and one `emit`, silently dropping a control from
whichever side lost. So the two rails keep their own module and both survive intact.

WHY
---
`memory_store` and `memory_relate` MUTATE persistent state that outlives the session,
and `memory_retrieve` reads it back; every one of them is gated by the tool registry,
so each is a governed action. Before this module none of them left any record at all.
The knowledge graph could be added to, related across, and read from, and afterwards
there was no way to answer "what changed, when, and which graph" from anything but the
graph itself — which is the artifact under question. A store that can only be audited
by reading its own current contents has no evidence; it has state.

The refusals matter as much as the writes, for the same reason they do on the registry
auth gate. `memory_relate` refuses an unknown endpoint and refuses an ambiguous one —
those refusals ARE the control that stops dangling and mis-attributed edges. A refusal
nobody can see later is indistinguishable from a call that was never made, so "the
agent's memory is wrong" and "the agent tried to record it and was refused" look the
same from outside.

ONE RAIL, NOT A SECOND ONE
--------------------------
Records go through `proxy.audit.writer.AuditWriter`: JSONL, secrets redaction, and a
tamper-evident hash chain (seq / prev_hash / this_hash). That is the same rail the proxy
uses for detection events and `registry_server.receipts` uses for auth decisions. Both
files it needs are stdlib-only, which is why this import does not drag a dependency into
the floor tier or into the npm bundle.

THREE DELIBERATE DIVERGENCES FROM `registry_server/receipts.py`
---------------------------------------------------------------
1. **The log path is supplied by the caller, not defaulted here.** The registry defaults
   to a package-relative path — the repo root. For this flow that is the exact defect
   this branch just fixed: under the npm install the package tree is inside a shared,
   world-readable `node_modules`, and the memory store's local confidentiality boundary
   includes the filesystem. Caller-supplied fields are also redacted before sqlite writes.
   A receipt about a private graph must be at least as protected as the graph, so
   `mcp_server.tools.memory` resolves the path next to the DB, inside the same 0700
   directory, and chmods the file 0600. Path policy lives with the store that owns it;
   this module stays a rail.

2. **The write is drained before `emit` returns.** The registry is a long-lived HTTP
   server whose lifespan flushes the queue on shutdown, so fire-and-forget is safe there.
   This is a stdio server that an MCP client starts and kills at will, and the mutation
   has already been committed to sqlite by the time we get here. A receipt still sitting
   in an in-memory queue when the process is killed is the "writing a record is not the
   same as the record landing" failure with the state change already made permanent. So
   the writer is started, written, and stopped (which drains) per emit, and the record is
   then READ BACK BY ITS ID off disk before this returns success. `emit` reports what it
   observed, not what it attempted. (Durability is process-level — the writer closes the
   file handle, so the bytes survive a kill; it does not fsync, so it does not survive a
   power cut. Stated rather than implied.)

3. **No module-level writer singleton.** There is no lifespan hook to start or stop one,
   and a cached `AuditWriter` binds a queue and a background task to one event loop —
   which is wrong in a stdio process that may outlive several, and wrong in a test suite
   that builds a fresh loop per test. Starting per emit also re-reads the chain tail each
   time, so the chain continues correctly across processes sharing one graph.

FAILURE POSTURE
---------------
Fail-open on the RECEIPT, never on the DECISION; and never fail-silent. `emit` catches
everything and returns False. It cannot turn a stored entity into an error, and it cannot
turn a refusal into a 500 — the standing ruling is that a receipt failure must not block
the halt. But an unwritten receipt is logged at error level AND surfaced to the caller
(`receipt: "unrecorded"`), because "no record" and "no call" must not look the same to
the operator either.

WHAT IS RECORDED, AND WHAT IS NOT
---------------------------------
Identifiers, structure and counts — never authored free text. The record carries the
store's own primary keys (entity_id, rel_id), the caller-supplied *structural* fields
(entity_type, relation_type), counts, and a `sha256:`-prefixed 12-hex fingerprint of each
piece of free text (entity name, observation content, search query).

Two reasons, both load-bearing:

* The graph write path already applies `proxy.audit.redactor.redact` to caller-supplied
  fields before sqlite writes. The receipt must not re-copy the pre-redaction text into
  an audit log with a different lifecycle. Fingerprints are immune to the redactor by
  construction and tie the receipt to the stored value without making the receipt a second
  content store.
* A receipt log that contained the observations would be a second copy of the knowledge
  graph, with a different retention (`AuditWriter.purge_old_records`) and a different
  lifecycle from the DB it describes. The receipt's job is to evidence the change, not to
  duplicate it.

Attribution does not suffer: the record carries the entity_id/rel_id, which is the exact
primary key of the affected row. Someone with legitimate access to the graph can resolve
it to a name; someone without learns nothing. That is strictly stronger than logging the
name, which is neither unique (two entities may share one) nor resolvable to a row.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from proxy.audit.writer import AuditWriter

logger = logging.getLogger(__name__)

#: The two decisions any governed tool call ends in. A refusal is a decision.
DECISION_RECORDED = "recorded"
DECISION_REFUSED = "refused"

_DECISIONS = (DECISION_RECORDED, DECISION_REFUSED)

#: Surfaced to the caller alongside the receipt id, so an unwritten receipt is visible in
#: the tool result and not only in a log line the agent never sees.
STATUS_RECORDED = "recorded"
STATUS_UNRECORDED = "unrecorded"


def new_receipt_id() -> str:
    """A fresh id per governed call, derived from nothing about its inputs."""
    return uuid.uuid4().hex


def fingerprint(text: Optional[str]) -> Optional[str]:
    """
    Stable, non-reversible identifier for a piece of free text.

    Enough to correlate ("these six receipts all touched the same entity name", "this
    observation was stored twice"), not enough to recover the text. `None` in, `None`
    out, so an absent optional field is recorded as absent rather than as the
    fingerprint of the empty string — those are different facts.
    """
    if text is None:
        return None
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:12]


def build_record(
    *,
    receipt_id: str,
    tool: str,
    decision: str,
    **fields: Any,
) -> dict:
    """
    The decision record. Pure — no I/O — so it can be asserted on directly.

    `decision` is validated rather than accepted: a typo'd decision would silently create
    a class of record that no query for "refused" would ever find, which is the receipt
    equivalent of an unregistered event type.
    """
    if decision not in _DECISIONS:
        raise ValueError(f"unknown decision {decision!r}; expected one of {_DECISIONS}")
    return {
        "event_type": f"mcp.{tool}",
        "receipt_id": receipt_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "decision": decision,
        **fields,
    }


def read_rows(log_path: str | Path) -> list[dict]:
    """Every record on disk, parsed, in write order. Missing file reads as no rows."""
    path = Path(log_path)
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def find_receipt(log_path: str | Path, receipt_id: str) -> Optional[dict]:
    """
    The row carrying `receipt_id`, or None.

    Looking a record up BY THE ID THE CALLER WAS HANDED is what makes the evidence
    attributable: a read-back that returns "the last row" would pass even when the id in
    the tool result has nothing to do with the row that landed.
    """
    for row in read_rows(log_path):
        if row.get("receipt_id") == receipt_id:
            return row
    return None


async def emit(log_path: str | Path, record: dict) -> bool:
    """
    Write one decision record and confirm it landed. Returns True only if it did.

    NEVER RAISES. The caller is past the point of decision — the entity is stored, or the
    refusal is about to be raised — and a receipt failure may not change that outcome.
    NEVER SILENT: every failure path logs at error level naming the receipt id, so an
    unrecorded decision is visible to an operator reading logs and not just absent from a
    file nobody is watching.
    """
    receipt_id = record.get("receipt_id")
    writer = AuditWriter(str(log_path))
    try:
        await writer.start()
        try:
            await writer.write(record)
        finally:
            # stop() drains the queue (bounded wait) and cancels the loop task. Run it in
            # a finally so a failed write cannot leak the background task.
            await writer.stop()
    except Exception as exc:  # pragma: no cover — defensive; the paths above are guarded
        logger.error(
            "MCP receipt FAILED to write (%s): tool=%s decision=%s receipt_id=%s "
            "— this decision is UNRECORDED",
            exc, record.get("tool"), record.get("decision"), receipt_id,
        )
        return False

    # The writer's loop swallows its own write errors and marks the queue item done, so a
    # drained queue does NOT prove a row landed. Read it back by id, which does.
    if find_receipt(log_path, receipt_id) is None:
        logger.error(
            "MCP receipt was enqueued but is NOT on disk at %s: tool=%s decision=%s "
            "receipt_id=%s — this decision is UNRECORDED",
            log_path, record.get("tool"), record.get("decision"), receipt_id,
        )
        return False
    return True
