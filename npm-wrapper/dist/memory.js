"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.store_entity = store_entity;
exports.retrieve_entities = retrieve_entities;
exports.store_relation = store_relation;
const sql_js_1 = __importDefault(require("sql.js"));
const path = __importStar(require("path"));
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const os = __importStar(require("os"));
const logger = console;
// ---------------------------------------------------------------------------
// DB setup — sql.js (pure JS, no native module)
// ---------------------------------------------------------------------------
function _db_path() {
    return process.env.MEMORY_DB_PATH || path.join(os.homedir(), '.arkheia', 'memory.db');
}
let _db = null;
let _dbReady = null;
function _getDb() {
    if (_dbReady)
        return _dbReady;
    _dbReady = (async () => {
        const SQL = await (0, sql_js_1.default)();
        const dbPath = _db_path();
        const dir = path.dirname(dbPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        // Load existing DB or create new
        if (fs.existsSync(dbPath)) {
            const buffer = fs.readFileSync(dbPath);
            _db = new SQL.Database(buffer);
        }
        else {
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
function _save(db) {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(_db_path(), buffer);
}
// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------
async function store_entity(name, entity_type, observations) {
    const db = await _getDb();
    const now = new Date().toISOString();
    // Upsert entity — look up by name+type
    let entity_id;
    const existing = db.exec("SELECT entity_id FROM entities WHERE name = ? AND entity_type = ?", [name, entity_type]);
    if (existing.length > 0 && existing[0].values.length > 0) {
        entity_id = existing[0].values[0][0];
    }
    else {
        entity_id = crypto.randomUUID();
        db.run("INSERT INTO entities (entity_id, name, entity_type, created_at) VALUES (?, ?, ?, ?)", [entity_id, name, entity_type, now]);
    }
    // Fetch existing observation contents to deduplicate
    const existingObs = db.exec("SELECT content FROM observations WHERE entity_id = ?", [entity_id]);
    const existingContentSet = new Set();
    if (existingObs.length > 0) {
        for (const row of existingObs[0].values) {
            existingContentSet.add(row[0]);
        }
    }
    let added = 0;
    for (const content of observations) {
        if (!existingContentSet.has(content)) {
            db.run("INSERT INTO observations (obs_id, entity_id, content, created_at) VALUES (?, ?, ?, ?)", [crypto.randomUUID(), entity_id, content, now]);
            existingContentSet.add(content);
            added++;
        }
    }
    const countResult = db.exec("SELECT COUNT(*) AS n FROM observations WHERE entity_id = ?", [entity_id]);
    const totalObservations = countResult.length > 0 ? countResult[0].values[0][0] : 0;
    _save(db);
    return {
        entity_id,
        name,
        entity_type,
        observations_added: added,
        total_observations: totalObservations,
    };
}
async function retrieve_entities(query, entity_type = undefined, limit = 10) {
    const db = await _getDb();
    const pattern = `%${query}%`;
    let rows;
    if (entity_type) {
        const result = db.exec("SELECT entity_id, name, entity_type, created_at FROM entities WHERE name LIKE ? AND entity_type = ?", [pattern, entity_type]);
        rows = result.length > 0 ? result[0].values.map(r => ({ entity_id: r[0], name: r[1], entity_type: r[2], created_at: r[3] })) : [];
    }
    else {
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
async function store_relation(from_entity, relation_type, to_entity) {
    const db = await _getDb();
    const rel_id = crypto.randomUUID();
    const now = new Date().toISOString();
    db.run("INSERT INTO relations (rel_id, from_entity, relation_type, to_entity, created_at) VALUES (?, ?, ?, ?, ?)", [rel_id, from_entity, relation_type, to_entity, now]);
    _save(db);
    return { rel_id, from_entity, relation_type, to_entity };
}
