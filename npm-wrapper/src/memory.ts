import initSqlJs, { type Database } from 'sql.js';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as os from 'os';

const logger = console;

// ---------------------------------------------------------------------------
// DB setup — sql.js (pure JS, no native module)
// ---------------------------------------------------------------------------

function _db_path(): string {
    return process.env.MEMORY_DB_PATH || path.join(os.homedir(), '.arkheia', 'memory.db');
}

let _db: Database | null = null;
let _dbReady: Promise<Database> | null = null;

function _getDb(): Promise<Database> {
    if (_dbReady) return _dbReady;
    _dbReady = (async () => {
        const SQL = await initSqlJs();
        const dbPath = _db_path();
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        // Load existing DB or create new
        if (fs.existsSync(dbPath)) {
            const buffer = fs.readFileSync(dbPath);
            _db = new SQL.Database(buffer);
        } else {
            _db = new SQL.Database();
        }

        // Init schema
        _db.run(`
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
        `);
        _save(_db);
        return _db;
    })();
    return _dbReady;
}

function _save(db: Database): void {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(_db_path(), buffer);
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

export async function store_entity(name: string, entity_type: string, observations: string[]): Promise<any> {
    const db = await _getDb();
    const now = new Date().toISOString();

    // Upsert entity — look up by name+type
    let entity_id: string;
    const existing = db.exec("SELECT entity_id FROM entities WHERE name = ? AND entity_type = ?", [name, entity_type]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        entity_id = existing[0].values[0][0] as string;
    } else {
        entity_id = crypto.randomUUID();
        db.run("INSERT INTO entities (entity_id, name, entity_type, created_at) VALUES (?, ?, ?, ?)",
            [entity_id, name, entity_type, now]);
    }

    // Fetch existing observation contents to deduplicate
    const existingObs = db.exec("SELECT content FROM observations WHERE entity_id = ?", [entity_id]);
    const existingContentSet = new Set<string>();
    if (existingObs.length > 0) {
        for (const row of existingObs[0].values) {
            existingContentSet.add(row[0] as string);
        }
    }

    let added = 0;
    for (const content of observations) {
        if (!existingContentSet.has(content)) {
            db.run("INSERT INTO observations (obs_id, entity_id, content, created_at) VALUES (?, ?, ?, ?)",
                [crypto.randomUUID(), entity_id, content, now]);
            existingContentSet.add(content);
            added++;
        }
    }

    const countResult = db.exec("SELECT COUNT(*) AS n FROM observations WHERE entity_id = ?", [entity_id]);
    const totalObservations = countResult.length > 0 ? countResult[0].values[0][0] as number : 0;

    _save(db);

    return {
        entity_id,
        name,
        entity_type,
        observations_added: added,
        total_observations: totalObservations,
    };
}

export async function retrieve_entities(
    query: string,
    entity_type: string | undefined = undefined,
    limit: number = 10,
): Promise<any> {
    const db = await _getDb();
    const pattern = `%${query}%`;

    let rows: any[];
    if (entity_type) {
        const result = db.exec("SELECT entity_id, name, entity_type, created_at FROM entities WHERE name LIKE ? AND entity_type = ?", [pattern, entity_type]);
        rows = result.length > 0 ? result[0].values.map(r => ({ entity_id: r[0], name: r[1], entity_type: r[2], created_at: r[3] })) : [];
    } else {
        const result = db.exec("SELECT entity_id, name, entity_type, created_at FROM entities WHERE name LIKE ?", [pattern]);
        rows = result.length > 0 ? result[0].values.map(r => ({ entity_id: r[0], name: r[1], entity_type: r[2], created_at: r[3] })) : [];
    }

    const total = rows.length;
    rows = rows.slice(0, Math.min(limit, 50));

    const entities = [];
    for (const row of rows) {
        const obsResult = db.exec("SELECT content, created_at FROM observations WHERE entity_id = ? ORDER BY created_at", [row.entity_id]);
        const obs = obsResult.length > 0 ? obsResult[0].values.map(o => ({ content: o[0], created_at: o[1] })) : [];

        const relResult = db.exec("SELECT relation_type, to_entity FROM relations WHERE from_entity = ? ORDER BY created_at", [row.name]);
        const rels = relResult.length > 0 ? relResult[0].values.map(r => ({ relation_type: r[0], to_entity: r[1] })) : [];

        entities.push({
            entity_id: row.entity_id,
            name: row.name,
            entity_type: row.entity_type,
            created_at: row.created_at,
            observations: obs,
            relations: rels,
        });
    }

    return { entities, total };
}

export async function store_relation(from_entity: string, relation_type: string, to_entity: string): Promise<any> {
    const db = await _getDb();
    const rel_id = crypto.randomUUID();
    const now = new Date().toISOString();
    db.run("INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at) VALUES (?, ?, ?, ?, ?)",
        [rel_id, from_entity, relation_type, to_entity, now]);
    _save(db);

    return { rel_id, from_entity, relation_type, to_entity };
}
