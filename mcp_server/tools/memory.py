"""
Persistent knowledge graph memory — SQLite backend.

Agents can store facts about entities (people, companies, bugs, decisions)
across sessions and retrieve them by name search.

Schema:
  entities     — entity_id, name, entity_type, created_at
  observations — obs_id, entity_id, content, created_at
  relations    — rel_id, from_entity, relation_type, to_entity, created_at

DB path: MEMORY_DB_PATH env var, default ~/.arkheia/mcp/memory.db (per-user, absolute).
The resolved path must be absolute; a relative graph path silently forks memory
by the server's current working directory. The DB directory is asserted 0700 and
the DB file 0600 on every open because this store persists caller-authored text.

WHY THE DEFAULT MUST BE ABSOLUTE AND USER-PRIVATE — do not "simplify" this back.
The previous default was the literal string "C:/arkheia-mcp/data/memory.db". On Windows that is
an absolute path; on POSIX "C:" is an ordinary directory NAME, so the path is RELATIVE and every
process resolved it against its own current working directory. Nothing errored — each caller got
a private, empty graph at <cwd>/C:/arkheia-mcp/data/memory.db and a store followed by a retrieve
from another cwd returned nothing, which is indistinguishable from "not stored yet". This repo
ships THREE different working directories for the same server (README/npm-wrapper README say
cwd `~/.arkheia/mcp`, AGENTS.md says `~/.arkheia-mcp`, npm-wrapper/bin/arkheia-mcp.js spawns with
`cwd: PYTHON_DIR` inside the package install tree), so which graph you got depended on which
install doc you followed.

The store's confidentiality boundary is the FILESYSTEM (see ACCESS CONTROL below), which makes the
location a security property, not a convenience: under the npm install PYTHON_DIR is inside the
global node_modules tree (e.g. /opt/homebrew/lib/node_modules), so the relative default put a
private knowledge graph in a shared, world-readable directory.

ACCESS CONTROL AND REDACTION.
The store has two confidentiality controls, both required:
  * the OS boundary — directory 0700 and database file 0600, because the npm install path may live
    under a shared node_modules tree; and
  * the shared audit redactor — every caller-supplied field that is persisted is passed through
    proxy.audit.redactor.redact() before it reaches sqlite. This is the same implementation pinned
    by tests/test_audit_redactor_floor.py, not a second memory-only scrubber.
Previously the directory and file inherited the umask (measured: dir 0755, file 0644 — world-readable).

PRECONDITION on that choice: this holds only while the store is single-tenant and local. There is
NO tenant or principal column on any table and `retrieve_entities` returns any name-matching row,
so if this store is ever put behind a shared transport (HTTP/SSE, a hosted multi-tenant server) the
filesystem stops being a boundary and this decision MUST be revisited — with per-principal scoping,
not with redaction, which would not help there either.

RECEIPTS — every call leaves a durable record, beside the graph it describes.
All three tools are governed actions: two of them MUTATE state that outlives the session, and the
third discloses it. Each one now emits a decision receipt through the estate's audit rail
(`mcp_server.memory_receipts` -> `proxy.audit.writer`: JSONL, redaction, tamper-evident hash chain), and
returns the `receipt_id` to the caller so the tool result, the log row and the DB row form one
chain. The REFUSALS are receipted too — an unknown or ambiguous relation endpoint is the control
that stops dangling and mis-attributed edges, and a refusal nobody can see later is
indistinguishable from a call that was never made.

Two properties of the receipt are consequences of the decisions above, not incidental:
  * The log lives NEXT TO THE DB (`memory-receipts.jsonl` in the same 0700 directory, itself 0600),
    because the confidentiality boundary of this store is the filesystem. A receipt about a private
    graph written to a package-relative or shared path — which is what the other services on this
    rail default to — would re-open the very hole the DB path fix closed.
  * It records IDENTIFIERS, COUNTS AND FINGERPRINTS, never the authored text. The graph is the only
    content store; the receipt is evidence about the graph, not a second copy of it.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import stat
import uuid
from datetime import datetime
from pathlib import Path

# The MEMORY receipt rail. mcp_server/receipts.py is the TOOL-GATE rail (different
# decision vocabulary, and it confines receipt paths); see memory_receipts.py.
from mcp_server import memory_receipts as receipts
from proxy.audit.redactor import redact

logger = logging.getLogger(__name__)

# Directory holding the knowledge graph: owner-only. The DB file itself: owner-only.
_DIR_MODE = 0o700
_FILE_MODE = 0o600

DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"
MAX_RETRIEVE_LIMIT = 50
_NUL = "\x00"


def _reject_windows_drive_path_on_posix(path: str) -> None:
    """Name the Windows-drive case before the generic absolute-path refusal.

    'C:/arkheia-mcp/data/memory.db' is *relative* to POSIX pathlib, so the
    absolute-path check below already refuses it -- but it refuses it with a
    message that reads as "you passed a relative path", which is exactly the
    confusion that let the old hard-coded default create a literal './C:'
    directory. Merged in from the branch side of this PR: the check is a
    strictly-narrower, better-named refusal in front of the master check, and
    it does not relax it.
    """
    if os.name != "nt" and len(path) >= 2 and path[1] == ":" and path[0].isalpha():
        raise ValueError(
            "MEMORY_DB_PATH uses a Windows drive path on this POSIX host: "
            f"{path!r}"
        )


def _db_path() -> str:
    """
    Resolve the knowledge-graph DB path. ALWAYS absolute.

    A relative path forks the graph per working directory with no error, so this
    function never returns one. `~` is expanded; a relative MEMORY_DB_PATH is
    REFUSED LOUDLY rather than silently resolved against whatever cwd the server
    happened to be spawned in — a silent fork is the defect being fixed, and a
    caller who supplies one would inherit it. A NUL byte and a Windows drive path
    are refused first, by their own names, so neither is reported as "relative".
    """
    raw = os.environ.get("MEMORY_DB_PATH") or DEFAULT_DB_PATH
    if _NUL in raw:
        raise ValueError("MEMORY_DB_PATH must not contain NUL bytes")
    _reject_windows_drive_path_on_posix(raw)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError(
            f"MEMORY_DB_PATH must be an absolute path (or start with '~'); got {raw!r}. "
            "A relative path resolves against the current working directory, which silently "
            "splits the knowledge graph across every process that uses a different cwd."
        )
    return str(path)


#: Receipt log filename, resolved beside the graph it describes.
RECEIPT_LOG_NAME = "memory-receipts.jsonl"


def _receipt_log_path() -> str:
    """
    Resolve the decision-receipt log. ALWAYS absolute, and by default beside the DB.

    Defaulting to the DB's own directory is the whole point, not a convenience: that
    directory is the one this module asserts to 0700, and the receipt describes a store
    whose only confidentiality control is that boundary. The sibling services on this
    audit rail default to a package-relative path (the repo root, and under the npm
    install a shared node_modules tree) — for this store that would be the defect
    `_db_path` was rewritten to prevent, one file across.

    It also means an operator or a test that redirects MEMORY_DB_PATH redirects the
    receipts with it: one graph, one receipt log, no way to end up evidencing graph A in
    the log belonging to graph B.

    MEMORY_RECEIPT_LOG overrides it, under the same absolute-or-refuse rule as
    MEMORY_DB_PATH and for the same reason.
    """
    raw = os.environ.get("MEMORY_RECEIPT_LOG")
    if raw:
        path = Path(raw).expanduser()
        if not path.is_absolute():
            raise ValueError(
                f"MEMORY_RECEIPT_LOG must be an absolute path (or start with '~'); got {raw!r}. "
                "A relative path resolves against the current working directory, which splits "
                "the evidence for one graph across every process that uses a different cwd."
            )
        return str(path)
    return str(Path(_db_path()).parent / RECEIPT_LOG_NAME)


async def _emit_receipt(tool: str, decision: str, **fields) -> tuple[str, str]:
    """
    Emit one decision receipt. Returns (receipt_id, status).

    NEVER RAISES, whatever happens — the caller has already committed its mutation or is
    about to raise its refusal, and neither outcome may be changed by the evidence path.
    NEVER SILENT either: a failure is logged at error level here and reported to the
    caller as `receipt: "unrecorded"`, so an agent acting on the result can see that the
    change it just made is not evidenced, rather than assuming it is.
    """
    receipt_id = receipts.new_receipt_id()
    ok = False
    try:
        log_path = Path(_receipt_log_path())
        log_path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
        _enforce_mode(log_path.parent, _DIR_MODE)
        # Create the file at 0600 BEFORE the writer opens it. Letting the writer create it
        # would leave it at the process umask (measured 0644 for the DB, which is the
        # defect this branch fixed) for the window before any chmod — and the receipt
        # carries fingerprints and ids for a store whose only control is this boundary.
        log_path.touch(exist_ok=True)
        _enforce_mode(log_path, _FILE_MODE)

        record = receipts.build_record(
            receipt_id=receipt_id,
            tool=tool,
            decision=decision,
            graph=_db_path(),
            **fields,
        )
        ok = await receipts.emit(log_path, record)
    except Exception:
        logger.error(
            "memory: receipt path FAILED for tool=%s decision=%s receipt_id=%s — the "
            "operation stands but is UNRECORDED",
            tool, decision, receipt_id, exc_info=True,
        )
        ok = False
    return receipt_id, receipts.STATUS_RECORDED if ok else receipts.STATUS_UNRECORDED


async def _receipt_refusal(tool: str, exc: ValueError, **fields) -> None:
    """
    Receipt a refusal and re-raise it, with the receipt id appended to the message.

    The message is the only channel this tool has back to the caller (the registry auth
    gate uses an `X-Arkheia-Receipt` header for the same purpose), so a refused agent can
    quote the id and an operator can find the exact row. The original message is left
    intact as the prefix — the exception object, its type and its traceback are unchanged.
    """
    reason = getattr(exc, "receipt_reason", "invalid_request")
    extra = dict(getattr(exc, "receipt_fields", {}))
    extra.update(fields)
    receipt_id, status = await _emit_receipt(
        tool, receipts.DECISION_REFUSED, reason=reason, **extra
    )
    if exc.args:
        exc.args = (f"{exc.args[0]} [receipt {receipt_id}: {status}]",) + exc.args[1:]


def _get_conn() -> sqlite3.Connection:
    path = _db_path()
    parent = Path(path).parent
    parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    # mkdir's mode is masked by the umask and is a no-op when the dir already
    # exists, so assert the mode explicitly rather than hoping for it.
    _enforce_mode(parent, _DIR_MODE)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _enforce_mode(Path(path), _FILE_MODE)
    return conn


def _enforce_mode(target: Path, mode: int) -> None:
    """
    Apply `mode` to `target`, and if that is not possible SAY SO.

    Memory is never broken over a permission failure — a store that refuses because
    the filesystem cannot express 0600 (Windows, some network and container mounts)
    would be a worse outcome than a readable file. But the failure is NOT swallowed:
    this module's stated position is that the filesystem IS the confidentiality
    control for unscrubbed observation text, so a control that could not be applied
    has to be visible. Silently passing here would be exactly the "guard wired but
    switched off" defect — the operator would believe in a boundary that was never set.

    `mode` is a CEILING, not an assignment: the new mode is `current & mode`, so this
    only ever REMOVES bits. A bare `chmod(target, mode)` would widen an already-tighter
    path — 0o400 becoming 0o700 — which is a privilege-granting side effect from a
    function whose entire job is to take privilege away. Pinned by
    tests/test_memory_db_path_floor.py.
    """
    try:
        current_mode = stat.S_IMODE(target.stat().st_mode)
        os.chmod(target, current_mode & mode)
    except OSError as exc:
        logger.warning(
            "memory: could not set mode %o on %s (%s). The knowledge graph relies on "
            "owner-only filesystem permissions as one confidentiality control; on this "
            "filesystem that control is NOT in effect and the graph may be readable by "
            "other local users.",
            mode, target, exc,
        )


def _like_escape(value: str) -> str:
    """
    Escape SQL LIKE metacharacters so a caller's search string is matched literally.

    Without this, `_` matches any single character and `%` matches anything, so
    memory_retrieve(query="%") returned the WHOLE graph and a search for an
    underscore-bearing name (e.g. "auth_middleware bug") over-matched. Paired with
    an explicit ESCAPE '\\' clause at every call site.
    """
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _refusal(message: str, *, reason: str, **fields) -> ValueError:
    """
    Build a refusal carrying the structured facts its receipt needs.

    A plain ValueError would force the receipt to be reconstructed from the message text
    at the catch site, which drifts the moment the wording changes. The exception TYPE is
    unchanged — callers (and every existing test) still see a ValueError — the extra
    attributes are only read by `_receipt_refusal`.
    """
    exc = ValueError(message)
    exc.receipt_reason = reason
    exc.receipt_fields = fields
    return exc


def _validate_limit(limit: int) -> int:
    """
    Bound `limit` on BOTH sides, and reject invalid input instead of coercing it.

    The cap used to be `min(limit, 50)` in the server wrapper alone — a ONE-SIDED bound.
    It clamped the top and let everything below through to a bare `rows[:limit]`, where
    Python's slice semantics reinterpret a negative: rows[:-1] is not "one row", it is
    "every row but the last". Measured: 60 stored entities, limit=-1, 59 returned against
    a documented maximum of 50.

    limit=0 is refused too. It is not a cap violation, but it slices to [] and so is
    indistinguishable from "nothing matched" — the silent-degradation shape.

    Note `bool` is a subclass of `int`, so it is excluded explicitly: limit=True would
    otherwise sail through as limit=1.

    ASYMMETRY, deliberate: an OVER-LARGE limit is clamped to the cap rather than refused,
    because "max 50" is the published contract (server.py memory_retrieve) — asking for
    more than the maximum is a request the contract already answers. A limit below 1 is
    not a request the contract can answer at all, so it is refused.
    """
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise _refusal(
            f"memory_retrieve: limit must be an int between 1 and {MAX_RETRIEVE_LIMIT}, "
            f"got {limit!r} ({type(limit).__name__})",
            reason="invalid_limit_type",
            limit_requested=repr(limit),
        )
    if limit < 1:
        raise _refusal(
            f"memory_retrieve: limit must be >= 1 (max {MAX_RETRIEVE_LIMIT}), got {limit}. "
            "A negative limit was previously passed straight to a list slice, where "
            "rows[:-1] returns every row but the last — 59 rows against a cap of 50.",
            reason="limit_below_one",
            limit_requested=repr(limit),
        )
    return min(limit, MAX_RETRIEVE_LIMIT)


def _validate_retrieve_query(query: str) -> str:
    """
    Refuse search strings SQLite LIKE cannot safely interpret literally.

    Python binds the full string, but SQLite's LIKE implementation treats NUL as a string
    terminator for pattern matching. Without this guard, "%\x00%" behaves as "%", so a
    query for a NUL byte discloses the whole graph while looking like a literal search.
    """
    if "\x00" in query:
        raise _refusal(
            "memory_retrieve: query contains a NUL byte. SQLite LIKE treats NUL as a "
            "terminator, so accepting it would turn a literal search into a whole-graph "
            "wildcard.",
            reason="query_contains_nul",
            query_fingerprint=receipts.fingerprint(query),
        )
    return query


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS entities (
            entity_id   TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS observations (
            obs_id      TEXT PRIMARY KEY,
            entity_id   TEXT NOT NULL REFERENCES entities(entity_id),
            content     TEXT NOT NULL,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS relations (
            rel_id        TEXT PRIMARY KEY,
            from_entity   TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            to_entity     TEXT NOT NULL,
            created_at    TEXT NOT NULL
        );
    """)

    # --- identity columns (added after the name-as-key defect) ----------------
    # from_entity/to_entity are retained as the DISPLAY labels the agent typed; the
    # *_entity_id columns are the actual foreign keys. See _migrate_relations_to_ids.
    existing = {r[1] for r in conn.execute("PRAGMA table_info(relations)")}
    for column in ("from_entity_id", "to_entity_id"):
        if column not in existing:
            conn.execute(f"ALTER TABLE relations ADD COLUMN {column} TEXT")

    conn.commit()
    _migrate_relations_to_ids(conn)


def _migrate_relations_to_ids(conn: sqlite3.Connection) -> None:
    """
    Back-fill entity_ids onto relations that were stored when the NAME was the key.

    WHAT CAN AND CANNOT BE RECOVERED. A legacy row recorded only a name, so it can be
    resolved only if that name identifies exactly one entity today:

      * exactly one match on both endpoints -> back-filled; the edge is now identity-keyed
        and behaves as if it had always been.
      * name matches SEVERAL entities -> genuinely ambiguous and NOT recoverable. The
        information needed to disambiguate was never written down. Guessing would
        re-introduce the defect, so the row keeps NULL ids.
      * name matches NO entity -> a dangling edge from before relate enforced its
        endpoints (INV-4).

    Unresolvable rows are RETAINED, never silently deleted, and never silently attached:
    because retrieve now joins on from_entity_id, a NULL-id row is attached to nobody,
    where before it was attached to EVERY namesake. That is the honest outcome — an edge
    whose subject was never recorded is not evidence about any particular entity — but it
    means such an edge stops being reported, so the count is logged at WARNING rather than
    passing in silence.
    """
    rows = conn.execute(
        "SELECT rel_id, from_entity, to_entity FROM relations WHERE from_entity_id IS NULL OR to_entity_id IS NULL"
    ).fetchall()
    if not rows:
        return

    unresolved = 0
    for row in rows:
        from_ids = _entity_ids_for_name(conn, row["from_entity"])
        to_ids = _entity_ids_for_name(conn, row["to_entity"])
        if len(from_ids) == 1 and len(to_ids) == 1:
            conn.execute(
                "UPDATE relations SET from_entity_id = ?, to_entity_id = ? WHERE rel_id = ?",
                (from_ids[0], to_ids[0], row["rel_id"]),
            )
        else:
            unresolved += 1
    conn.commit()

    if unresolved:
        logger.warning(
            "memory: %d legacy relation(s) could not be migrated to entity ids — the "
            "endpoint name is ambiguous or missing, so the edge's subject was never "
            "recorded. Rows are retained but are no longer attached to any entity "
            "(previously they were attached to every namesake). Re-create them with "
            "memory_relate to restore them.",
            unresolved,
        )


def _entity_ids_for_name(conn: sqlite3.Connection, name: str, entity_type: str | None = None) -> list[str]:
    """All entity_ids carrying `name` (optionally narrowed by type). Order is stable."""
    if entity_type:
        rows = conn.execute(
            "SELECT entity_id FROM entities WHERE name = ? AND entity_type = ? ORDER BY created_at, entity_id",
            (name, entity_type),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT entity_id FROM entities WHERE name = ? ORDER BY created_at, entity_id",
            (name,),
        ).fetchall()
    return [r["entity_id"] for r in rows]


def _resolve_endpoint(
    conn: sqlite3.Connection, label: str, name: str, entity_type: str | None
) -> str:
    """
    Resolve one relation endpoint to a single entity_id, or refuse.

    A name is not an identity: the store deliberately allows "Mercury" the person and
    "Mercury" the project to coexist. When a name is ambiguous there is no correct
    answer, so this refuses and names the candidates instead of taking whichever row
    sqlite happened to return first.
    """
    ids = _entity_ids_for_name(conn, name, entity_type)

    if not ids:
        qualifier = f" of type {entity_type!r}" if entity_type else ""
        raise _refusal(
            f"memory_relate: no such entity — {label}={name!r}{qualifier}. "
            "Store both endpoints with memory_store before relating them; "
            "storing the relation anyway would create a dangling edge that "
            "memory_retrieve reports as a real relation.",
            reason="unknown_endpoint",
            endpoint=label,
            endpoint_name_fingerprint=receipts.fingerprint(name),
            endpoint_entity_type=entity_type,
            candidates=0,
        )

    if len(ids) > 1:
        types = [
            r["entity_type"]
            for r in conn.execute(
                "SELECT entity_type FROM entities WHERE name = ? ORDER BY created_at, entity_id",
                (name,),
            ).fetchall()
        ]
        raise _refusal(
            f"memory_relate: ambiguous entity — {label}={name!r} matches "
            f"{len(ids)} entities of types {sorted(set(types))!r}. A name is not an "
            f"identity. Disambiguate with {label}_type=<entity_type>; relating to a "
            "guessed one would report the edge as a fact about the wrong entity.",
            reason="ambiguous_endpoint",
            endpoint=label,
            endpoint_name_fingerprint=receipts.fingerprint(name),
            endpoint_entity_type=entity_type,
            candidates=len(ids),
        )

    return ids[0]


def _reject_nul(field: str, value: str) -> str:
    if isinstance(value, str) and _NUL in value:
        raise ValueError(f"{field} must not contain NUL bytes")
    return value


def _redact_memory_text(field: str, value: str) -> str:
    _reject_nul(field, value)
    redacted = redact(value)
    return _reject_nul(field, redacted)


def _safe_sqlite_text(value: object) -> bool:
    return not isinstance(value, str) or _NUL not in value


def _row_has_only_safe_text(row: sqlite3.Row, fields: tuple[str, ...]) -> bool:
    return all(_safe_sqlite_text(row[field]) for field in fields)


# NOTE: master's `_entity_exists(conn, name)` was deliberately NOT carried over. It
# answered "does SOME entity have this name?", which is the weaker half of what
# `_resolve_endpoint` now does: resolve the name to ONE entity_id, refusing both the
# unknown endpoint (same guarantee master had) and the AMBIGUOUS one (two namesakes),
# and returning the id the edge is actually keyed by. Keeping a name-only existence
# check alongside it would re-offer the namesake bug this branch fixed.


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

async def store_entity(name: str, entity_type: str, observations: list[str]) -> dict:
    """
    Upsert an entity by name+type, then add any new observations (deduped by content).

    Returns:
        entity_id:           UUID of the entity
        name:                Entity name
        entity_type:         Entity type
        observations_added:  Number of new observations added this call
        total_observations:  Total observations stored for this entity
        receipt_id:          Id of the decision receipt for this call
        receipt:             "recorded" | "unrecorded" — whether that receipt reached disk
    """
    # Every caller-supplied field is scrubbed through the shared redactor
    # BEFORE it reaches sqlite -- this is the only redaction implementation in
    # the repo (proxy/audit/redactor.py), reused rather than re-implemented.
    # Redacting here (not just `observations`) also keeps the entity's lookup
    # key consistent between the SELECT below and the INSERT that follows it.
    name = _redact_memory_text("memory_store: name", name)
    entity_type = _redact_memory_text("memory_store: entity_type", entity_type)
    observations = [
        _redact_memory_text("memory_store: observations[]", raw_content)
        for raw_content in observations
    ]

    conn = _get_conn()
    try:
        _init_schema(conn)
        now = datetime.utcnow().isoformat()

        # Upsert entity — look up by name+type
        row = conn.execute(
            "SELECT entity_id FROM entities WHERE name = ? AND entity_type = ?",
            (name, entity_type),
        ).fetchone()

        if row:
            entity_id = row["entity_id"]
            created = False
        else:
            created = True
            entity_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO entities (entity_id, name, entity_type, created_at) VALUES (?, ?, ?, ?)",
                (entity_id, name, entity_type, now),
            )
            conn.commit()

        # Fetch existing observation contents to deduplicate
        existing = {
            r["content"]
            for r in conn.execute(
                "SELECT content FROM observations WHERE entity_id = ?",
                (entity_id,),
            ).fetchall()
        }

        added = 0
        added_fingerprints: list[str] = []
        # Already scrubbed above, before the connection was opened, so a NUL-bearing
        # observation is refused without the graph being created at all.
        for content in observations:
            if content not in existing:
                conn.execute(
                    "INSERT INTO observations (obs_id, entity_id, content, created_at) VALUES (?, ?, ?, ?)",
                    (str(uuid.uuid4()), entity_id, content, now),
                )
                existing.add(content)
                added += 1
                added_fingerprints.append(receipts.fingerprint(content))

        conn.commit()

        total = conn.execute(
            "SELECT COUNT(*) AS n FROM observations WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()["n"]

        result = {
            "entity_id": entity_id,
            "name": name,
            "entity_type": entity_type,
            "observations_added": added,
            "total_observations": total,
        }
    finally:
        conn.close()

    # AFTER the commit, and outside the connection: the receipt evidences a change that
    # has actually happened, and a receipt failure can neither roll it back nor block it.
    receipt_id, status = await _emit_receipt(
        "memory_store",
        receipts.DECISION_RECORDED,
        entity_id=entity_id,
        entity_type=entity_type,
        entity_created=created,
        name_fingerprint=receipts.fingerprint(name),
        observations_submitted=len(observations),
        observations_added=added,
        observation_fingerprints=added_fingerprints,
        total_observations=total,
    )
    result["receipt_id"] = receipt_id
    result["receipt"] = status
    return result


async def retrieve_entities(
    query: str,
    entity_type: str | None = None,
    limit: int = 10,
) -> dict:
    """
    Search entities whose names contain `query` (case-insensitive LIKE).
    Optionally filter by entity_type.

    Returns each entity with all its observations and outgoing relations.

    `query` is matched as a LITERAL substring: LIKE's own wildcards (`%`, `_`) are
    escaped, so searching for "auth_middleware" cannot also match "authXmiddleware"
    and searching for "%" cannot return the entire graph.

    Returns:
        entities:    List of matching entity dicts
        total:       Count of matches before limit
        receipt_id:  Id of the decision receipt for this call
        receipt:     "recorded" | "unrecorded" — whether that receipt reached disk
    """
    limit_requested = repr(limit)
    try:
        limit = _validate_limit(limit)
        query = _validate_retrieve_query(query)
        # Scrubbed as well as validated: the query and the type filter are
        # caller-authored text that reaches the receipt and the LIKE pattern.
        query = _redact_memory_text("memory_retrieve: query", query)
        if entity_type is not None:
            entity_type = _redact_memory_text("memory_retrieve: entity_type", entity_type)
    except ValueError as exc:
        # A refused read is a decision this tool made and must be evidenced, not just
        # raised. Without it, "the agent never searched" and "the agent searched and was
        # refused" leave the same trace: none.
        await _receipt_refusal("memory_retrieve", exc)
        raise

    conn = _get_conn()
    try:
        _init_schema(conn)
        pattern = f"%{_like_escape(query)}%"

        if entity_type:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ? ESCAPE '\\' AND entity_type = ?",
                (pattern, entity_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ? ESCAPE '\\'",
                (pattern,),
            ).fetchall()

        rows = [
            row
            for row in rows
            if _row_has_only_safe_text(row, ("entity_id", "name", "entity_type", "created_at"))
        ]
        total = len(rows)
        rows = rows[:limit]

        entities = []
        for row in rows:
            eid = row["entity_id"]

            obs_rows = conn.execute(
                "SELECT content, created_at FROM observations WHERE entity_id = ? ORDER BY created_at",
                (eid,),
            ).fetchall()
            obs_rows = [
                row
                for row in obs_rows
                if _row_has_only_safe_text(row, ("content", "created_at"))
            ]

            # Join on IDENTITY, not on the display name. Joining on row["name"] gave
            # every namesake the same edges (see store_relation).
            rel_rows = conn.execute(
                "SELECT relation_type, to_entity FROM relations WHERE from_entity_id = ? ORDER BY created_at",
                (eid,),
            ).fetchall()
            rel_rows = [
                row
                for row in rel_rows
                if _row_has_only_safe_text(row, ("relation_type", "to_entity"))
            ]

            entities.append({
                "entity_id": eid,
                "name": row["name"],
                "entity_type": row["entity_type"],
                "created_at": row["created_at"],
                "observations": [
                    {"content": o["content"], "created_at": o["created_at"]}
                    for o in obs_rows
                ],
                "relations": [
                    {"relation_type": r["relation_type"], "to_entity": r["to_entity"]}
                    for r in rel_rows
                ],
            })

        result = {"entities": entities, "total": total}
    finally:
        conn.close()

    receipt_id, status = await _emit_receipt(
        "memory_retrieve",
        receipts.DECISION_RECORDED,
        query_fingerprint=receipts.fingerprint(query),
        entity_type=entity_type,
        limit_requested=limit_requested,
        limit_applied=limit,
        matched=total,
        returned=len(entities),
        # WHICH rows were disclosed, by primary key. A retrieval is the disclosure of a
        # store that has no principal scoping, so "what was read" is the fact worth
        # keeping; the ids resolve against the graph and reveal nothing without it.
        entity_ids=[e["entity_id"] for e in entities],
    )
    result["receipt_id"] = receipt_id
    result["receipt"] = status
    return result


async def store_relation(
    from_entity: str,
    relation_type: str,
    to_entity: str,
    from_entity_type: str | None = None,
    to_entity_type: str | None = None,
) -> dict:
    """
    Store a directional named relationship between two entities.

    Both endpoints MUST already exist as entities — the published tool contract
    (mcp_server/server.py, memory_relate) has always said so, and until now nothing
    enforced it. An unenforced endpoint produced a DANGLING EDGE: the relation was
    stored, returned a rel_id, and then surfaced through memory_retrieve as a real
    relation pointing at an entity that does not exist. A typo in a name was
    indistinguishable from a fact. Refusing is loud; a dangling edge is silent.

    A NAME IS NOT AN IDENTITY. Endpoints are given by name because that is what an agent
    knows, but they are RESOLVED to entity_id and the edge is stored against the id.
    Previously the name itself was the key, and retrieve re-joined on it, so a single
    "Mercury works_at Acme" was reported as a fact about BOTH the person named Mercury
    and the project named Mercury. Duplicate names are legitimate and are still allowed;
    what is no longer allowed is silently guessing which one was meant.

    Args:
        from_entity:      Name of the source entity
        relation_type:    Relation label
        to_entity:        Name of the target entity
        from_entity_type: Optional entity_type narrowing an ambiguous `from_entity`
        to_entity_type:   Optional entity_type narrowing an ambiguous `to_entity`

    Raises:
        ValueError: if an endpoint names no existing entity, or names more than one and
                    no *_entity_type was supplied to disambiguate it.

    Returns:
        rel_id, from_entity, relation_type, to_entity,
        from_entity_id, to_entity_id — the resolved identities the edge is keyed by
        receipt_id — id of the decision receipt for this call
        receipt     — "recorded" | "unrecorded", whether that receipt reached disk
    """
    # Scrub before the INSERT, same as store_entity above.
    from_entity = _redact_memory_text("memory_relate: from_entity", from_entity)
    relation_type = _redact_memory_text("memory_relate: relation_type", relation_type)
    to_entity = _redact_memory_text("memory_relate: to_entity", to_entity)
    # The two disambiguators are caller-supplied too, and they are matched against
    # stored entity_type values that were scrubbed on the way in.
    if from_entity_type is not None:
        from_entity_type = _redact_memory_text("memory_relate: from_entity_type", from_entity_type)
    if to_entity_type is not None:
        to_entity_type = _redact_memory_text("memory_relate: to_entity_type", to_entity_type)

    conn = _get_conn()
    refusal: ValueError | None = None
    try:
        _init_schema(conn)
        conn.execute("BEGIN IMMEDIATE")

        try:
            from_id = _resolve_endpoint(conn, "from_entity", from_entity, from_entity_type)
            to_id = _resolve_endpoint(conn, "to_entity", to_entity, to_entity_type)
        except ValueError as exc:
            # Held, not receipted here: the emit is async and the refusal must be
            # evidenced with the connection already closed, so nothing about the receipt
            # path can hold a transaction open on the graph.
            refusal = exc
            conn.rollback()
        else:
            rel_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()
            conn.execute(
                "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at, from_entity_id, to_entity_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (rel_id, from_entity, relation_type, to_entity, now, from_id, to_id),
            )
            conn.commit()
            result = {
                "rel_id": rel_id,
                "from_entity": from_entity,
                "relation_type": relation_type,
                "to_entity": to_entity,
                "from_entity_id": from_id,
                "to_entity_id": to_id,
            }
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()

    if refusal is not None:
        # The refusal IS the control that stops a dangling or mis-attributed edge. It is
        # the outcome most worth evidencing, and the one that previously left no trace.
        await _receipt_refusal("memory_relate", refusal, relation_type=relation_type)
        raise refusal

    receipt_id, status = await _emit_receipt(
        "memory_relate",
        receipts.DECISION_RECORDED,
        rel_id=rel_id,
        relation_type=relation_type,
        from_entity_id=from_id,
        to_entity_id=to_id,
        from_name_fingerprint=receipts.fingerprint(from_entity),
        to_name_fingerprint=receipts.fingerprint(to_entity),
        from_entity_type=from_entity_type,
        to_entity_type=to_entity_type,
    )
    result["receipt_id"] = receipt_id
    result["receipt"] = status
    return result
