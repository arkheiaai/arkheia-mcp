#!/usr/bin/env node
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
Object.defineProperty(exports, "__esModule", { value: true });
const mcp_js_1 = require("@modelcontextprotocol/sdk/server/mcp.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const zod_1 = require("zod");
const path = __importStar(require("path"));
const os = __importStar(require("os"));
const fs = __importStar(require("fs"));
const proxy_client_js_1 = require("./proxy-client.js");
const tool_registry_js_1 = require("./tool-registry.js");
const providers_js_1 = require("./providers.js");
const memory_js_1 = require("./memory.js");
// ---------------------------------------------------------------------------
// Config Loading
// ---------------------------------------------------------------------------
function loadConfig() {
    const configPath = path.join(os.homedir(), '.arkheia', 'config.json');
    if (!fs.existsSync(configPath))
        return;
    try {
        const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
        if (config.api_key && !process.env.ARKHEIA_API_KEY) {
            process.env.ARKHEIA_API_KEY = config.api_key;
            process.stderr.write(`[arkheia] API key loaded from ${configPath}\n`);
        }
        if (config.proxy_url && !process.env.ARKHEIA_HOSTED_URL) {
            process.env.ARKHEIA_HOSTED_URL = config.proxy_url;
            process.stderr.write(`[arkheia] Hosted URL: ${config.proxy_url}\n`);
        }
    }
    catch (e) {
        process.stderr.write(`[arkheia] Warning: Could not read ${configPath}\n`);
    }
}
function checkCRLF() {
    for (const k of ['ARKHEIA_API_KEY', 'ARKHEIA_PROXY_URL', 'ARKHEIA_HOSTED_URL']) {
        const v = process.env[k];
        if (v && /[\r\n]/.test(v)) {
            process.stderr.write(`[arkheia] WARNING: ${k} contains whitespace/newline characters. Run 'dos2unix' on your env file.\n`);
            process.env[k] = v.trim();
        }
    }
}
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function wrapResult(result) {
    return { content: [{ type: "text", text: JSON.stringify(result) }] };
}
function handleError(toolName, e) {
    if (e instanceof tool_registry_js_1.PolicyViolation) {
        return wrapResult({ error: e.reason, risk_level: "UNKNOWN" });
    }
    process.stderr.write(`[arkheia] ${toolName} error: ${e.message}\n`);
    return wrapResult({ error: e.message, risk_level: "UNKNOWN" });
}
// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
    loadConfig();
    checkCRLF();
    const ARKHEIA_PROXY_URL = process.env.ARKHEIA_PROXY_URL || "http://localhost:8098";
    const ARKHEIA_HOSTED_URL = process.env.ARKHEIA_HOSTED_URL || "https://arkheia-proxy-production.up.railway.app";
    const ARKHEIA_API_KEY = process.env.ARKHEIA_API_KEY;
    if (!ARKHEIA_API_KEY) {
        process.stderr.write("[arkheia] Warning: ARKHEIA_API_KEY not set.\n" +
            "Get a free API key at https://arkheia.ai/mcp\n" +
            "Then set: export ARKHEIA_API_KEY=ak_live_...\n\n");
    }
    const proxy = new proxy_client_js_1.ProxyClient(ARKHEIA_PROXY_URL, 10.0, ARKHEIA_HOSTED_URL, ARKHEIA_API_KEY);
    const server = new mcp_js_1.McpServer({ name: "arkheia-trust", version: "0.1.6" });
    // ── Detection & audit ──────────────────────────────────────────
    server.tool("arkheia_verify", "Verify whether an AI response shows signs of fabrication. Call this on EVERY model response before acting on it.", { prompt: zod_1.z.string(), response: zod_1.z.string(), model: zod_1.z.string() }, async ({ prompt, response, model }) => {
        try {
            (0, tool_registry_js_1.check)("arkheia_verify");
            const result = await proxy.verify(prompt, response, model);
            return wrapResult(result);
        }
        catch (e) {
            return handleError("arkheia_verify", e);
        }
    });
    server.tool("arkheia_audit_log", "Retrieve structured audit evidence for compliance review.", { session_id: zod_1.z.string().optional(), limit: zod_1.z.number().int().min(1).max(500).default(50) }, async ({ session_id, limit }) => {
        try {
            (0, tool_registry_js_1.check)("arkheia_audit_log");
            const result = await proxy.get_audit_log(session_id, Math.min(limit, 500));
            return wrapResult(result);
        }
        catch (e) {
            return handleError("arkheia_audit_log", e);
        }
    });
    // ── Provider wrappers ──────────────────────────────────────────
    server.tool("run_grok", "Call xAI Grok and screen the response through Arkheia for fabrication.", { prompt: zod_1.z.string(), model: zod_1.z.string().default("grok-4-fast-non-reasoning") }, async ({ prompt, model }) => {
        try {
            (0, tool_registry_js_1.check)("run_grok");
            const pr = await (0, providers_js_1.call_grok)(prompt, model);
            if (pr.error)
                return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
            const risk = await proxy.verify(prompt, pr.response, model);
            return wrapResult({ ...pr, arkheia: risk });
        }
        catch (e) {
            return handleError("run_grok", e);
        }
    });
    server.tool("run_gemini", "Call Google Gemini and screen the response through Arkheia for fabrication.", { prompt: zod_1.z.string(), model: zod_1.z.string().default("gemini-2.5-flash") }, async ({ prompt, model }) => {
        try {
            (0, tool_registry_js_1.check)("run_gemini");
            const pr = await (0, providers_js_1.call_gemini)(prompt, model);
            if (pr.error)
                return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
            const risk = await proxy.verify(prompt, pr.response, model);
            return wrapResult({ ...pr, arkheia: risk });
        }
        catch (e) {
            return handleError("run_gemini", e);
        }
    });
    server.tool("run_ollama", "Call a local Ollama model and screen the response through Arkheia. No network egress.", { prompt: zod_1.z.string(), model: zod_1.z.string().default("phi4:14b") }, async ({ prompt, model }) => {
        try {
            (0, tool_registry_js_1.check)("run_ollama");
            const pr = await (0, providers_js_1.call_ollama)(prompt, model);
            if (pr.error)
                return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
            const risk = await proxy.verify(prompt, pr.response, model);
            return wrapResult({ ...pr, arkheia: risk });
        }
        catch (e) {
            return handleError("run_ollama", e);
        }
    });
    server.tool("run_together", "Call Together AI (Kimi K2.5, DeepSeek, etc.) and screen the response through Arkheia.", { prompt: zod_1.z.string(), model: zod_1.z.string().default("moonshotai/Kimi-K2.5") }, async ({ prompt, model }) => {
        try {
            (0, tool_registry_js_1.check)("run_together");
            const pr = await (0, providers_js_1.call_together)(prompt, model);
            if (pr.error)
                return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
            const risk = await proxy.verify(prompt, pr.response, model);
            return wrapResult({ ...pr, arkheia: risk });
        }
        catch (e) {
            return handleError("run_together", e);
        }
    });
    // ── Memory / Knowledge Graph ───────────────────────────────────
    server.tool("memory_store", "Store an entity and its observations in the persistent knowledge graph. Entities are upserted by name+type.", { name: zod_1.z.string(), entity_type: zod_1.z.string(), observations: zod_1.z.array(zod_1.z.string()) }, async ({ name, entity_type, observations }) => {
        try {
            (0, tool_registry_js_1.check)("memory_store");
            const result = await (0, memory_js_1.store_entity)(name, entity_type, observations);
            return wrapResult(result);
        }
        catch (e) {
            return handleError("memory_store", e);
        }
    });
    server.tool("memory_retrieve", "Search entities in the persistent knowledge graph by name (case-insensitive).", { query: zod_1.z.string(), entity_type: zod_1.z.string().optional(), limit: zod_1.z.number().int().min(1).max(50).default(10) }, async ({ query, entity_type, limit }) => {
        try {
            (0, tool_registry_js_1.check)("memory_retrieve");
            const result = await (0, memory_js_1.retrieve_entities)(query, entity_type, Math.min(limit, 50));
            return wrapResult(result);
        }
        catch (e) {
            return handleError("memory_retrieve", e);
        }
    });
    server.tool("memory_relate", "Store a named relationship between two entities in the knowledge graph.", { from_entity: zod_1.z.string(), relation_type: zod_1.z.string(), to_entity: zod_1.z.string() }, async ({ from_entity, relation_type, to_entity }) => {
        try {
            (0, tool_registry_js_1.check)("memory_relate");
            const result = await (0, memory_js_1.store_relation)(from_entity, relation_type, to_entity);
            return wrapResult(result);
        }
        catch (e) {
            return handleError("memory_relate", e);
        }
    });
    // ── Start ──────────────────────────────────────────────────────
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
}
main().catch((err) => {
    process.stderr.write(`[arkheia] Fatal error: ${err}\n`);
    process.exit(1);
});
