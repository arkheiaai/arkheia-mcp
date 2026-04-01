"""
Persistent knowledge graph memory — SQLite backend.

Agents can store facts about entities (people, companies, bugs, decisions)
across sessions and retrieve them by name search.

Schema:
  entities     — entity_id, name, entity_type, created_at
  observations — obs_id, entity_id, content, created_at
  relations    — rel_id, from_entity, relation_type, to_entity, created_at

DB path: MEMORY_DB_PATH env var, default C:/arkheia-mcp/data/memory.db
"""

from __future__ import annotations

import os
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# DB setup
# ---------------------------------------------------------------------------

def _db_path() -> str:
    return os.environ.get("MEMORY_DB_PATH", "C:/arkheia-mcp/data/memory.db")


def _get_conn() -> sqlite3.Connection:
    path = _db_path()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
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

    Returns:
        entities:  List of matching entity dicts
        total:     Count of matches before limit
    """
    conn = _get_conn()
    try:
        _init_schema(conn)
        pattern = f"%{query}%"

        if entity_type:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ? AND entity_type = ?",
                (pattern, entity_type),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities WHERE name LIKE ?",
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
    conn = _get_conn()
    try:
        _init_schema(conn)
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
