#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';

import { ProxyClient } from './proxy-client.js';
import { check, PolicyViolation } from './tool-registry.js';
import { call_grok, call_gemini, call_ollama, call_together } from './providers.js';
import { store_entity, retrieve_entities, store_relation } from './memory.js';

// ---------------------------------------------------------------------------
// Config Loading
// ---------------------------------------------------------------------------

function loadConfig(): void {
    const configPath = path.join(os.homedir(), '.arkheia', 'config.json');
    if (!fs.existsSync(configPath)) return;
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
    } catch (e) {
        process.stderr.write(`[arkheia] Warning: Could not read ${configPath}\n`);
    }
}

function checkCRLF(): void {
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

function wrapResult(result: any) {
    return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
}

function handleError(toolName: string, e: any) {
    if (e instanceof PolicyViolation) {
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
        process.stderr.write(
            "[arkheia] Warning: ARKHEIA_API_KEY not set.\n" +
            "Get a free API key at https://arkheia.ai/mcp\n" +
            "Then set: export ARKHEIA_API_KEY=ak_live_...\n\n"
        );
    }

    const proxy = new ProxyClient(ARKHEIA_PROXY_URL, 10.0, ARKHEIA_HOSTED_URL, ARKHEIA_API_KEY);
    const server = new McpServer({ name: "arkheia-trust", version: "0.1.6" });

    // ── Detection & audit ──────────────────────────────────────────

    server.tool(
        "arkheia_verify",
        "Verify whether an AI response shows signs of fabrication. Call this on EVERY model response before acting on it. Risk guidance: HIGH = warn the user this response may be fabricated and include the detection_id, but still show them the response with the warning. MEDIUM = show with a brief confidence note. LOW = show normally. Never hide or suppress a response — always surface it to the user with the appropriate risk context.",
        { prompt: z.string(), response: z.string(), model: z.string() },
        async ({ prompt, response, model }) => {
            try {
                check("arkheia_verify");
                const result = await proxy.verify(prompt, response, model);
                return wrapResult(result);
            } catch (e: any) { return handleError("arkheia_verify", e); }
        }
    );

    server.tool(
        "arkheia_audit_log",
        "Retrieve structured audit evidence for compliance review.",
        { session_id: z.string().optional(), limit: z.number().int().min(1).max(500).default(50) },
        async ({ session_id, limit }) => {
            try {
                check("arkheia_audit_log");
                const result = await proxy.get_audit_log(session_id, Math.min(limit, 500));
                return wrapResult(result);
            } catch (e: any) { return handleError("arkheia_audit_log", e); }
        }
    );

    // ── Provider wrappers ──────────────────────────────────────────

    server.tool(
        "run_grok",
        "Call xAI Grok and screen the response through Arkheia for fabrication.",
        { prompt: z.string(), model: z.string().default("grok-4-fast-non-reasoning") },
        async ({ prompt, model }) => {
            try {
                check("run_grok");
                const pr = await call_grok(prompt, model);
                if (pr.error) return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
                const risk = await proxy.verify(prompt, pr.response, model);
                return wrapResult({ ...pr, arkheia: risk });
            } catch (e: any) { return handleError("run_grok", e); }
        }
    );

    server.tool(
        "run_gemini",
        "Call Google Gemini and screen the response through Arkheia for fabrication.",
        { prompt: z.string(), model: z.string().default("gemini-2.5-flash") },
        async ({ prompt, model }) => {
            try {
                check("run_gemini");
                const pr = await call_gemini(prompt, model);
                if (pr.error) return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
                const risk = await proxy.verify(prompt, pr.response, model);
                return wrapResult({ ...pr, arkheia: risk });
            } catch (e: any) { return handleError("run_gemini", e); }
        }
    );

    server.tool(
        "run_ollama",
        "Call a local Ollama model and screen the response through Arkheia. No network egress.",
        { prompt: z.string(), model: z.string().default("phi4:14b") },
        async ({ prompt, model }) => {
            try {
                check("run_ollama");
                const pr = await call_ollama(prompt, model);
                if (pr.error) return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
                const risk = await proxy.verify(prompt, pr.response, model);
                return wrapResult({ ...pr, arkheia: risk });
            } catch (e: any) { return handleError("run_ollama", e); }
        }
    );

    server.tool(
        "run_together",
        "Call Together AI (Kimi K2.5, DeepSeek, etc.) and screen the response through Arkheia.",
        { prompt: z.string(), model: z.string().default("moonshotai/Kimi-K2.5") },
        async ({ prompt, model }) => {
            try {
                check("run_together");
                const pr = await call_together(prompt, model);
                if (pr.error) return wrapResult({ ...pr, arkheia: { risk_level: "UNKNOWN", error: pr.error } });
                const risk = await proxy.verify(prompt, pr.response, model);
                return wrapResult({ ...pr, arkheia: risk });
            } catch (e: any) { return handleError("run_together", e); }
        }
    );

    // ── Memory / Knowledge Graph ───────────────────────────────────

    server.tool(
        "memory_store",
        "Store an entity and its observations in the persistent knowledge graph. Entities are upserted by name+type.",
        { name: z.string(), entity_type: z.string(), observations: z.array(z.string()) },
        async ({ name, entity_type, observations }) => {
            try {
                check("memory_store");
                const result = await store_entity(name, entity_type, observations);
                return wrapResult(result);
            } catch (e: any) { return handleError("memory_store", e); }
        }
    );

    server.tool(
        "memory_retrieve",
        "Search entities in the persistent knowledge graph by name (case-insensitive).",
        { query: z.string(), entity_type: z.string().optional(), limit: z.number().int().min(1).max(50).default(10) },
        async ({ query, entity_type, limit }) => {
            try {
                check("memory_retrieve");
                const result = await retrieve_entities(query, entity_type, Math.min(limit, 50));
                return wrapResult(result);
            } catch (e: any) { return handleError("memory_retrieve", e); }
        }
    );

    server.tool(
        "memory_relate",
        "Store a named relationship between two entities in the knowledge graph.",
        { from_entity: z.string(), relation_type: z.string(), to_entity: z.string() },
        async ({ from_entity, relation_type, to_entity }) => {
            try {
                check("memory_relate");
                const result = await store_relation(from_entity, relation_type, to_entity);
                return wrapResult(result);
            } catch (e: any) { return handleError("memory_relate", e); }
        }
    );

    // ── Start ──────────────────────────────────────────────────────

    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((err) => {
    process.stderr.write(`[arkheia] Fatal error: ${err}\n`);
    process.exit(1);
});
