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
const feedback_js_1 = require("./feedback.js");
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
const CURRENT_VERSION = "1.3.0";
async function checkForUpdate() {
    // Check once per day — skip if checked recently
    const markerPath = path.join(os.homedir(), '.arkheia', '.update-check');
    try {
        if (fs.existsSync(markerPath)) {
            const age = Date.now() - fs.statSync(markerPath).mtimeMs;
            if (age < 24 * 60 * 60 * 1000)
                return; // checked within 24h
        }
    }
    catch { }
    try {
        const resp = await fetch('https://registry.npmjs.org/@arkheia/mcp-server/latest', {
            signal: AbortSignal.timeout(5000),
        });
        if (resp.ok) {
            const data = await resp.json();
            if (data.version && data.version !== CURRENT_VERSION) {
                process.stderr.write(`[arkheia] Update available: ${CURRENT_VERSION} → ${data.version}\n` +
                    `[arkheia] Run: npm update -g @arkheia/mcp-server\n`);
            }
        }
        // Touch marker regardless of result
        const dir = path.dirname(markerPath);
        if (!fs.existsSync(dir))
            fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(markerPath, new Date().toISOString());
    }
    catch {
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
    if (process.env.ARKHEIA_UPDATE_CHECK === "1")
        checkForUpdate(); // fire-and-forget, never blocks startup
    const ARKHEIA_PROXY_URL = process.env.ARKHEIA_PROXY_URL || "http://localhost:8098";
    const ARKHEIA_HOSTED_URL = process.env.ARKHEIA_HOSTED_URL || "https://arkheia-proxy-production.up.railway.app";
    const ARKHEIA_API_KEY = process.env.ARKHEIA_API_KEY;
    if (!ARKHEIA_API_KEY) {
        process.stderr.write("[arkheia] Warning: ARKHEIA_API_KEY not set.\n" +
            "Get a free API key at https://arkheia.ai/mcp\n" +
            "Then set: export ARKHEIA_API_KEY=ak_live_...\n\n");
    }
    const proxy = new proxy_client_js_1.ProxyClient(ARKHEIA_PROXY_URL, 10.0, ARKHEIA_HOSTED_URL, ARKHEIA_API_KEY);
    const feedback = new feedback_js_1.FeedbackClient(ARKHEIA_HOSTED_URL, ARKHEIA_API_KEY);
    const server = new mcp_js_1.McpServer({ name: "arkheia-trust", version: "1.3.0" });
    // ── Detection & audit ──────────────────────────────────────────
    server.tool("arkheia_verify", "Verify whether an AI response shows signs of fabrication. Call this on EVERY model response before acting on it. Risk guidance: HIGH = warn the user this response may be fabricated and include the detection_id, but still show them the response with the warning. MEDIUM = show with a brief confidence note. LOW = show normally. Never hide or suppress a response — always surface it to the user with the appropriate risk context. The result's detection_id can be passed to arkheia_report to say whether the checked response was really right or wrong.", { prompt: zod_1.z.string(), response: zod_1.z.string(), model: zod_1.z.string() }, async ({ prompt, response, model }) => {
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
    // ── Feedback & reports ─────────────────────────────────────────
    // These return only whether the server stored the item, and its id. They never carry a verdict.
    function wrapFeedback(result) {
        const failed = result.recorded === false || result.deleted === false || (result.ok === false);
        return { ...wrapResult(result), ...(failed ? { isError: true } : {}) };
    }
    function feedbackError(toolName, e) {
        process.stderr.write(`[arkheia] ${toolName} failed unexpectedly\n`);
        return wrapFeedback({ recorded: false, retryable: true, error: "Nothing was recorded: the request failed unexpectedly inside the tool. It is safe to try again." });
    }
    server.tool("arkheia_feedback", "Send short feedback about Arkheia to its makers: a bug, a false alarm, a missed problem, a feature request, or praise. Use it when the user asks to give feedback, or when you hit a problem with Arkheia itself. Only what you pass here is sent. The email is optional, is used only to reply, and should be left out unless the user gives it. Do not include secrets or API keys. Success is reported only with an id from the server.", feedback_js_1.feedbackShape, async (args) => {
        try {
            (0, tool_registry_js_1.check)("arkheia_feedback");
            return wrapFeedback(await feedback.send_feedback(args));
        }
        catch (e) {
            return feedbackError("arkheia_feedback", e);
        }
    });
    server.tool("arkheia_report", "Say whether a response that arkheia_verify checked was really wrong or fine. Pass the detection_id field from that arkheia_verify result. outcome 'wrong' means the model's response was fabricated or incorrect, 'fine' means it was correct; this grades the model's response, not Arkheia's score. Give one line of evidence if you checked, and reporter_kind 'human' only when the user is reporting. One report per detection; success is reported only with a report_id from the server.", feedback_js_1.reportShape, async (args) => {
        try {
            (0, tool_registry_js_1.check)("arkheia_report");
            return wrapFeedback(await feedback.send_report(args));
        }
        catch (e) {
            return feedbackError("arkheia_report", e);
        }
    });
    server.tool("arkheia_reports", "List your own reports made with arkheia_report (action 'list'), or delete one by its report_id (action 'delete') so you can report that response again.", feedback_js_1.reportsShape, async ({ action, report_id, limit }) => {
        try {
            (0, tool_registry_js_1.check)("arkheia_reports");
            return wrapFeedback(action === "list"
                ? await feedback.list_reports(limit)
                : await feedback.delete_report(report_id));
        }
        catch (e) {
            return feedbackError("arkheia_reports", e);
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
