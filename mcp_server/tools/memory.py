"""
Persistent knowledge graph memory — SQLite backend.

Agents can store facts about entities (people, companies, bugs, decisions)
across sessions and retrieve them by name search.

Schema:
  entities     — entity_id, name, entity_type, created_at
  observations — obs_id, entity_id, content, created_at
  relations    — rel_id, from_entity, relation_type, to_entity, created_at

DB path: MEMORY_DB_PATH env var, default ~/.arkheia/mcp/memory.db (per-user, absolute).

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

ACCESS CONTROL, not scrubbing — the deliberate choice for observation content.
Observation text is written to sqlite verbatim; there is no secret-redaction pass equivalent to
proxy/audit/redactor.py, and that asymmetry with the audit log is intentional:
  * An audit record is CAPTURED traffic that exists to be read by a principal who did not write it,
    so its reader cannot be restricted and redaction is the only available control.
  * A memory observation is AUTHORED — a statement an agent deliberately chose to persist — and it
    is retrieved by the same principal that wrote it, from the same local stdio server. Redaction
    here is lossy, irreversible and SILENT: it would mutilate a fact the agent meant to keep while
    returning no indication that it had done so, which is the silent-degradation failure the
    loud-failure invariant exists to forbid.
So the control is the OS boundary — and it is now ASSERTED rather than assumed: the directory is
created 0700 and the database file is chmod'ed 0600. Previously both inherited the umask (measured:
dir 0755, file 0644 — world-readable).

PRECONDITION on that choice: this holds only while the store is single-tenant and local. There is
NO tenant or principal column on any table and `retrieve_entities` returns any name-matching row,
so if this store is ever put behind a shared transport (HTTP/SSE, a hosted multi-tenant server) the
filesystem stops being a boundary and this decision MUST be revisited — with per-principal scoping,
not with redaction, which would not help there either.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory holding the knowledge graph: owner-only. The DB file itself: owner-only.
_DIR_MODE = 0o700
_FILE_MODE = 0o600

DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"


def _db_path() -> str:
    """
    Resolve the knowledge-graph DB path. ALWAYS absolute.

    A relative path forks the graph per working directory with no error, so this
    function never returns one. `~` is expanded; a relative MEMORY_DB_PATH is
    REFUSED LOUDLY rather than silently resolved against whatever cwd the server
    happened to be spawned in — a silent fork is the defect being fixed, and a
    caller who supplies one would inherit it.
    """
    raw = os.environ.get("MEMORY_DB_PATH") or DEFAULT_DB_PATH
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError(
            f"MEMORY_DB_PATH must be an absolute path (or start with '~'); got {raw!r}. "
            "A relative path resolves against the current working directory, which silently "
            "splits the knowledge graph across every process that uses a different cwd."
        )
    return str(path)


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
    """
    try:
        os.chmod(target, mode)
    except OSError as exc:
        logger.warning(
            "memory: could not set mode %o on %s (%s). The knowledge graph stores "
            "observation text unredacted and relies on filesystem permissions as its "
            "only confidentiality control; on this filesystem that control is NOT in "
            "effect and the graph may be readable by other local users.",
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


MAX_RETRIEVE_LIMIT = 50


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
        raise ValueError(
            f"memory_retrieve: limit must be an int between 1 and {MAX_RETRIEVE_LIMIT}, "
            f"got {limit!r} ({type(limit).__name__})"
        )
    if limit < 1:
        raise ValueError(
            f"memory_retrieve: limit must be >= 1 (max {MAX_RETRIEVE_LIMIT}), got {limit}. "
            "A negative limit was previously passed straight to a list slice, where "
            "rows[:-1] returns every row but the last — 59 rows against a cap of 50."
        )
    return min(limit, MAX_RETRIEVE_LIMIT)


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
        raise ValueError(
            f"memory_relate: no such entity — {label}={name!r}{qualifier}. "
            "Store both endpoints with memory_store before relating them; "
            "storing the relation anyway would create a dangling edge that "
            "memory_retrieve reports as a real relation."
        )

    if len(ids) > 1:
        types = [
            r["entity_type"]
            for r in conn.execute(
                "SELECT entity_type FROM entities WHERE name = ? ORDER BY created_at, entity_id",
                (name,),
            ).fetchall()
        ]
        raise ValueError(
            f"memory_relate: ambiguous entity — {label}={name!r} matches "
            f"{len(ids)} entities of types {sorted(set(types))!r}. A name is not an "
            f"identity. Disambiguate with {label}_type=<entity_type>; relating to a "
            "guessed one would report the edge as a fact about the wrong entity."
        )

    return ids[0]


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
    """
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
        else:
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
        for content in observations:
            if content not in existing:
                conn.execute(
                    "INSERT INTO observations (obs_id, entity_id, content, created_at) VALUES (?, ?, ?, ?)",
                    (str(uuid.uuid4()), entity_id, content, now),
                )
                existing.add(content)
                added += 1

        conn.commit()

        total = conn.execute(
            "SELECT COUNT(*) AS n FROM observations WHERE entity_id = ?",
            (entity_id,),
        ).fetchone()["n"]

        return {
            "entity_id": entity_id,
            "name": name,
            "entity_type": entity_type,
            "observations_added": added,
            "total_observations": total,
        }
    finally:
        conn.close()


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
        entities:  List of matching entity dicts
        total:     Count of matches before limit
    """
    limit = _validate_limit(limit)

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

        total = len(rows)
        rows = rows[:limit]

        entities = []
        for row in rows:
            eid = row["entity_id"]

            obs_rows = conn.execute(
                "SELECT content, created_at FROM observations WHERE entity_id = ? ORDER BY created_at",
                (eid,),
            ).fetchall()

            # Join on IDENTITY, not on the display name. Joining on row["name"] gave
            # every namesake the same edges (see store_relation).
            rel_rows = conn.execute(
                "SELECT relation_type, to_entity FROM relations WHERE from_entity_id = ? ORDER BY created_at",
                (eid,),
            ).fetchall()

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

        return {"entities": entities, "total": total}
    finally:
        conn.close()


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
    """
    conn = _get_conn()
    try:
        _init_schema(conn)

        from_id = _resolve_endpoint(conn, "from_entity", from_entity, from_entity_type)
        to_id = _resolve_endpoint(conn, "to_entity", to_entity, to_entity_type)

        rel_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at, from_entity_id, to_entity_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (rel_id, from_entity, relation_type, to_entity, now, from_id, to_id),
        )
        conn.commit()
        return {
            "rel_id": rel_id,
            "from_entity": from_entity,
            "relation_type": relation_type,
            "to_entity": to_entity,
            "from_entity_id": from_id,
            "to_entity_id": to_id,
        }
    finally:
        conn.close()
