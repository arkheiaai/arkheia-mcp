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
import { FeedbackClient, feedbackShape, reportShape, reportsShape } from './feedback.js';
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

const CURRENT_VERSION = "1.3.0";

async function checkForUpdate(): Promise<void> {
    // Check once per day — skip if checked recently
    const markerPath = path.join(os.homedir(), '.arkheia', '.update-check');
    try {
        if (fs.existsSync(markerPath)) {
            const age = Date.now() - fs.statSync(markerPath).mtimeMs;
            if (age < 24 * 60 * 60 * 1000) return; // checked within 24h
        }
    } catch {}

    try {
        const resp = await fetch('https://registry.npmjs.org/@arkheia/mcp-server/latest', {
            signal: AbortSignal.timeout(5000),
        });
        if (resp.ok) {
            const data = await resp.json() as { version?: string };
            if (data.version && data.version !== CURRENT_VERSION) {
                process.stderr.write(
                    `[arkheia] Update available: ${CURRENT_VERSION} → ${data.version}\n` +
                    `[arkheia] Run: npm update -g @arkheia/mcp-server\n`
                );
            }
        }
        // Touch marker regardless of result
        const dir = path.dirname(markerPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(markerPath, new Date().toISOString());
    } catch {
        // Network failure — silently skip, don't block startup
    }
}

async function main() {
    // --setup flag: install protocol + register MCP with all detected CLIs, then exit
    if (process.argv.includes('--setup')) {
        const { execSync } = await import('child_process');
        const setupScript = path.join(__dirname, '..', 'scripts', 'setup-claude.js');
        execSync(`node "${setupScript}"`, { stdio: 'inherit', env: process.env });
        process.exit(0);
    }

    loadConfig();
    checkCRLF();
    // Opt-in only: the check writes ~/.arkheia/.update-check, and a default run must change nothing in the user's
    // home (B-288, Codex R1). Set ARKHEIA_UPDATE_CHECK=1 to enable it.
    if (process.env.ARKHEIA_UPDATE_CHECK === "1") checkForUpdate(); // fire-and-forget, never blocks startup

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
    const feedback = new FeedbackClient(ARKHEIA_HOSTED_URL, ARKHEIA_API_KEY);
    const server = new McpServer({ name: "arkheia-trust", version: "1.3.0" });

    // ── Detection & audit ──────────────────────────────────────────

    server.tool(
        "arkheia_verify",
        "Verify whether an AI response shows signs of fabrication. Call this on EVERY model response before acting on it. Risk guidance: HIGH = warn the user this response may be fabricated and include the detection_id, but still show them the response with the warning. MEDIUM = show with a brief confidence note. LOW = show normally. Never hide or suppress a response — always surface it to the user with the appropriate risk context. The result's detection_id can be passed to arkheia_report to say whether the checked response was really right or wrong.",
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

    // ── Feedback & reports ─────────────────────────────────────────
    // These return only whether the server stored the item, and its id. They never carry a verdict.

    function wrapFeedback(result: any) {
        const failed = result.recorded === false || result.deleted === false || (result.ok === false);
        return { ...wrapResult(result), ...(failed ? { isError: true } : {}) };
    }

    function feedbackError(toolName: string, e: any) {
        process.stderr.write(`[arkheia] ${toolName} failed unexpectedly\n`);
        return wrapFeedback({ recorded: false, retryable: true, error: "Nothing was recorded: the request failed unexpectedly inside the tool. It is safe to try again." });
    }

    server.tool(
        "arkheia_feedback",
        "Send short feedback about Arkheia to its makers: a bug, a false alarm, a missed problem, a feature request, or praise. Use it when the user asks to give feedback, or when you hit a problem with Arkheia itself. Only what you pass here is sent. The email is optional, is used only to reply, and should be left out unless the user gives it. Do not include secrets or API keys. Success is reported only with an id from the server.",
        feedbackShape,
        async (args) => {
            try {
                check("arkheia_feedback");
                return wrapFeedback(await feedback.send_feedback(args));
            } catch (e: any) { return feedbackError("arkheia_feedback", e); }
        }
    );

    server.tool(
        "arkheia_report",
        "Say whether a response that arkheia_verify checked was really wrong or fine. Pass the detection_id field from that arkheia_verify result. outcome 'wrong' means the model's response was fabricated or incorrect, 'fine' means it was correct; this grades the model's response, not Arkheia's score. Give one line of evidence if you checked, and reporter_kind 'human' only when the user is reporting. One report per detection; success is reported only with a report_id from the server.",
        reportShape,
        async (args) => {
            try {
                check("arkheia_report");
                return wrapFeedback(await feedback.send_report(args));
            } catch (e: any) { return feedbackError("arkheia_report", e); }
        }
    );

    server.tool(
        "arkheia_reports",
        "List your own reports made with arkheia_report (action 'list'), or delete one by its report_id (action 'delete') so you can report that response again.",
        reportsShape,
        async ({ action, report_id, limit }) => {
            try {
                check("arkheia_reports");
                return wrapFeedback(action === "list"
                    ? await feedback.list_reports(limit)
                    : await feedback.delete_report(report_id));
            } catch (e: any) { return feedbackError("arkheia_reports", e); }
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
