"""
Persistent knowledge graph memory — SQLite backend.

Agents can store facts about entities (people, companies, bugs, decisions)
across sessions and retrieve them by name search.

Schema:
  entities     — entity_id, name, entity_type, created_at
  observations — obs_id, entity_id, content, created_at
  relations    — rel_id, from_entity, relation_type, to_entity, created_at

DB path: MEMORY_DB_PATH env var, default ~/.arkheia/mcp/memory.db.
The resolved path must be absolute; a relative graph path silently forks memory
by the server's current working directory. The DB directory is asserted 0700 and
the DB file 0600 on every open because this store persists caller-authored text.

Every caller-supplied string field (entity name/type, observation content,
relation endpoints/type) is passed through proxy.audit.redactor.redact()
before it reaches sqlite -- the SAME redaction implementation the audit log
uses, not a second one. See tests/test_audit_redactor_floor.py::DISK_SINKS
for the sink's classification and tests/test_memory_store_does_not_persist_
secrets_unredacted / test_memory_relate_does_not_persist_secrets_unredacted
for the pinned regression coverage.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

from proxy.audit.redactor import redact

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"
MAX_RETRIEVE_LIMIT = 50
_DIR_MODE = 0o700
_FILE_MODE = 0o600


# ---------------------------------------------------------------------------
# DB setup
# ---------------------------------------------------------------------------

def _db_path() -> str:
    raw = os.environ.get("MEMORY_DB_PATH") or DEFAULT_DB_PATH
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError(
            f"MEMORY_DB_PATH must be an absolute path (or start with '~'); got {raw!r}. "
            "A relative path resolves against the current working directory and "
            "silently splits the knowledge graph across processes."
        )
    return str(path)


def _enforce_mode(target: Path, mode: int) -> None:
    try:
        os.chmod(target, mode)
    except OSError as exc:
        logger.warning(
            "memory: could not set filesystem permissions %o on %s (%s). "
            "The knowledge graph stores redacted but caller-authored memory on disk; "
            "on this filesystem the owner-only boundary may not be in effect.",
            mode,
            target,
            exc,
        )


def _get_conn() -> sqlite3.Connection:
    path = _db_path()
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True, mode=_DIR_MODE)
    _enforce_mode(db_path.parent, _DIR_MODE)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    _enforce_mode(db_path, _FILE_MODE)
    return conn


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
    conn.commit()


def _like_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _validate_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError(
            f"memory_retrieve: limit must be an int between 1 and {MAX_RETRIEVE_LIMIT}; "
            f"got {limit!r} ({type(limit).__name__})"
        )
    if limit < 1:
        raise ValueError(
            f"memory_retrieve: limit must be >= 1 (max {MAX_RETRIEVE_LIMIT}); got {limit}"
        )
    return min(limit, MAX_RETRIEVE_LIMIT)


def _entity_exists(conn: sqlite3.Connection, name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM entities WHERE name = ? LIMIT 1",
        (name,),
    ).fetchone()
    return row is not None


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
    # Every caller-supplied field is scrubbed through the shared redactor
    # BEFORE it reaches sqlite -- this is the only redaction implementation in
    # the repo (proxy/audit/redactor.py), reused rather than re-implemented.
    # Redacting here (not just `observations`) also keeps the entity's lookup
    # key consistent between the SELECT below and the INSERT that follows it.
    name = redact(name)
    entity_type = redact(entity_type)

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
        for raw_content in observations:
            content = redact(raw_content)
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

            rel_rows = conn.execute(
                "SELECT relation_type, to_entity FROM relations WHERE from_entity = ? ORDER BY created_at",
                (row["name"],),
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


async def store_relation(from_entity: str, relation_type: str, to_entity: str) -> dict:
    """
    Store a directional named relationship between two entities (referenced by name).

    Returns:
        rel_id:        UUID of the stored relation
        from_entity:   Source entity name
        relation_type: Relation label
        to_entity:     Target entity name
    """
    # Scrub before the INSERT, same as store_entity above.
    from_entity = redact(from_entity)
    relation_type = redact(relation_type)
    to_entity = redact(to_entity)

    conn = _get_conn()
    try:
        _init_schema(conn)
        if not _entity_exists(conn, from_entity):
            raise ValueError(
                "memory_relate: no such entity - "
                f"from_entity={from_entity!r}. Store both endpoints with memory_store first."
            )
        if not _entity_exists(conn, to_entity):
            raise ValueError(
                "memory_relate: no such entity - "
                f"to_entity={to_entity!r}. Store both endpoints with memory_store first."
            )

        rel_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()
        conn.execute(
            "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at) VALUES (?, ?, ?, ?, ?)",
            (rel_id, from_entity, relation_type, to_entity, now),
        )
        conn.commit()
        return {
            "rel_id": rel_id,
            "from_entity": from_entity,
            "relation_type": relation_type,
            "to_entity": to_entity,
        }
    finally:
        conn.close()
