// Release pack Change A, client half: an unscored check never reads as LOW.
// Spec: the public MCP release pack, section 2, with its corrections.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ProxyClient } from '../src/proxy-client';
import {
    ALL_REASONS, CLIENT_REASONS, SERVER_REASONS, assessmentFromDetector, finishFromGemini,
    finishFromOllama, finishFromOpenAICompatible, normaliseAuditLog,
} from '../src/assessment';

const ASSESSED_LOW = { risk: "LOW", assessed: true, evidence_depth_limited: false, not_assessed_reason: null, candidate_alert: null };

// ---------------------------------------------------------------------------
// 1. Reading the service's answer
// ---------------------------------------------------------------------------

test("an assessed LOW from the service is LOW", () => {
    assert.deepEqual(assessmentFromDetector(ASSESSED_LOW, "risk"), { risk_level: "LOW", assessed: true });
});

for (const reason of SERVER_REASONS) {
    test(`service reason ${reason} is passed through as NOT_ASSESSED`, () => {
        const a = assessmentFromDetector({ risk: "LOW", assessed: false, not_assessed_reason: reason, evidence_depth_limited: true }, "risk");
        assert.deepEqual(a, { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: reason });
    });
}

for (const edl of [true, undefined]) {
    test(`hosted LOW with evidence_depth_limited ${edl} and no assessment fields is not LOW`, () => {
        const a = assessmentFromDetector({ risk: "LOW", evidence_depth_limited: edl }, "risk");
        assert.deepEqual(a, { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

test("a reason is never derived on the client from evidence_depth_limited alone", () => {
    // Corrections P3-1: limited_evidence is only ever the service's word.
    const a = assessmentFromDetector({ risk: "LOW", evidence_depth_limited: true }, "risk");
    assert.equal(a.not_assessed_reason, "unknown");
});

const contradictions: Array<[string, any]> = [
    ["assessed true with evidence_depth_limited true", { ...ASSESSED_LOW, evidence_depth_limited: true }],
    ["assessed true with evidence_depth_limited absent", { risk: "LOW", assessed: true }],
    ["assessed true with a reason", { ...ASSESSED_LOW, not_assessed_reason: "limited_evidence" }],
    ["assessed true with a candidate", { ...ASSESSED_LOW, candidate_alert: "HIGH" }],
    ["assessed true with no band", { ...ASSESSED_LOW, risk: "UNKNOWN" }],
    ["assessed false with an unlisted reason", { risk: "LOW", assessed: false, not_assessed_reason: "feature_x_missing" }],
    ["assessed false with a client-only reason", { risk: "LOW", assessed: false, not_assessed_reason: "provider_error" }],
    ["assessed false with no reason", { risk: "LOW", assessed: false }],
    ["assessed false with a LOW candidate", { risk: "LOW", assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: "LOW" }],
    ["assessed as a string", { ...ASSESSED_LOW, assessed: "true" }],
];
for (const [name, body] of contradictions) {
    test(`contradictory service flags fail closed: ${name}`, () => {
        assert.deepEqual(assessmentFromDetector(body, "risk"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

for (const level of ["MEDIUM", "HIGH"] as const) {
    test(`an unassessed ${level} keeps the service's candidate_alert`, () => {
        const a = assessmentFromDetector({ risk: "MEDIUM", ...(level === "HIGH" ? { risk_demoted_from: "HIGH" } : {}), assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: level }, "risk");
        assert.deepEqual(a, { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: level });
    });
}

test("the reason vocabulary is exactly the spec's closed list", () => {
    assert.deepEqual([...ALL_REASONS].sort(), [
        "borrowed_profile", "incomplete_response", "limited_evidence", "no_profile",
        "provider_error", "screening_disabled", "service_unavailable", "unknown"]);
    assert.deepEqual([...CLIENT_REASONS], ["screening_disabled", "provider_error", "incomplete_response", "service_unavailable", "unknown"]);
});

test("no reason string outside the closed list appears in the public source", () => {
    const src = ["assessment.ts", "proxy-client.ts", "index.ts", "providers.ts"]
        .map((f) => fs.readFileSync(path.join(__dirname, "..", "..", "src", f), "utf8")).join("\n");
    const used = new Set<string>();
    for (const m of src.matchAll(/notAssessed\("([a-z_]+)"/g)) used.add(m[1]);
    for (const r of used) assert.ok((ALL_REASONS as readonly string[]).includes(r), `unlisted reason ${r}`);
    assert.deepEqual([...used].sort(), ["incomplete_response", "provider_error", "service_unavailable", "unknown"]);
});

// ---------------------------------------------------------------------------
// 2. The client end to end against a stubbed service (no network)
// ---------------------------------------------------------------------------

function withFetch(handler: (url: string) => Response | Promise<Response>) {
    const orig = globalThis.fetch;
    globalThis.fetch = (async (u: any) => handler(String(u))) as any;
    return () => { globalThis.fetch = orig; };
}
const json = (status: number, body: any) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const LOCAL_DOWN = (u: string) => { if (u.startsWith("http://localhost")) throw new TypeError("fetch failed"); };

async function verifyWith(handler: (url: string) => Response | Promise<Response>) {
    const restore = withFetch(handler);
    try {
        return await new ProxyClient("http://localhost:8098", 1.0, "https://hosted.example.test", "ak_live_DUMMYDUMMYDUMMY00").verify("p", "r", "m") as any;
    } finally { restore(); }
}

test("hosted unassessed LOW: NOT_ASSESSED, the service's reason, and the word LOW nowhere", async () => {
    const r = await verifyWith((u) => { LOCAL_DOWN(u); return json(200, { risk: "LOW", assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: null, evidence_depth_limited: true, detection_id: "det_0123456789abcdef" }); });
    assert.equal(r.risk_level, "NOT_ASSESSED");
    assert.equal(r.assessed, false);
    assert.equal(r.not_assessed_reason, "limited_evidence");
    assert.equal("candidate_alert" in r, false);
    assert.doesNotMatch(JSON.stringify(r), /LOW/);
    assert.equal(r.detection_id, "det_0123456789abcdef");
});

test("hosted assessed LOW: LOW", async () => {
    const r = await verifyWith((u) => { LOCAL_DOWN(u); return json(200, { ...ASSESSED_LOW, confidence: 0.8, detection_id: "det_0123456789abcdef" }); });
    assert.equal(r.risk_level, "LOW");
    assert.equal(r.assessed, true);
    assert.equal("not_assessed_reason" in r, false);
});

test("hosted unassessed HIGH candidate survives to the caller", async () => {
    const r = await verifyWith((u) => { LOCAL_DOWN(u); return json(200, { risk: "MEDIUM", risk_demoted_from: "HIGH", assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: "HIGH", evidence_depth_limited: true }); });
    assert.deepEqual([r.risk_level, r.not_assessed_reason, r.candidate_alert], ["NOT_ASSESSED", "borrowed_profile", "HIGH"]);
});

test("an older service with no assessment fields: NOT_ASSESSED unknown, never LOW", async () => {
    const r = await verifyWith((u) => { LOCAL_DOWN(u); return json(200, { risk: "LOW", confidence: 0.1, evidence_depth_limited: false }); });
    assert.deepEqual([r.risk_level, r.assessed, r.not_assessed_reason], ["NOT_ASSESSED", false, "unknown"]);
});

const transportFailures: Array<[string, (u: string) => Response | Promise<Response>]> = [
    ["timeout", (u) => { LOCAL_DOWN(u); const e: any = new Error("aborted"); e.name = "AbortError"; throw e; }],
    ["connection failure", (u) => { LOCAL_DOWN(u); throw new TypeError("fetch failed"); }],
    ["HTTP error", (u) => { LOCAL_DOWN(u); return json(503, { detail: "down" }); }],
];
for (const [name, handler] of transportFailures) {
    test(`hosted ${name}: service_unavailable`, async () => {
        const r = await verifyWith(handler);
        assert.deepEqual([r.risk_level, r.assessed, r.not_assessed_reason], ["NOT_ASSESSED", false, "service_unavailable"]);
        assert.ok(r.error);
    });
}

test("audit rows: unassessed LOW and legacy rows are NOT_ASSESSED; the summary counts them apart", () => {
    const out = normaliseAuditLog({ events: [
        { source: "proxy", risk_level: "LOW", assessed: false, not_assessed_reason: "limited_evidence", evidence_depth_limited: true },
        { source: "proxy", risk_level: "LOW", confidence: 0.2 },  // legacy row, no assessment fields
        { source: "proxy", risk_level: "LOW", assessed: true, evidence_depth_limited: false },
        { source: "proxy", risk_level: "MEDIUM", risk_demoted_from: "HIGH", assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: "HIGH", evidence_depth_limited: true },
    ] });
    assert.deepEqual(out.events.map((e: any) => e.risk_level), ["NOT_ASSESSED", "NOT_ASSESSED", "LOW", "NOT_ASSESSED"]);
    assert.deepEqual(out.events.map((e: any) => e.not_assessed_reason), ["limited_evidence", "unknown", undefined, "borrowed_profile"]);
    assert.deepEqual(out.summary, { LOW: 1, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 3, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 1 });
});

test("finish states read each provider's documented field", () => {
    assert.equal(finishFromOpenAICompatible({ choices: [{ finish_reason: "stop" }] }), "complete");
    assert.equal(finishFromOpenAICompatible({ choices: [{ finish_reason: "length" }] }), "incomplete");
    assert.equal(finishFromOpenAICompatible({ choices: [{}] }), "unknown");
    assert.equal(finishFromGemini({ candidates: [{ finishReason: "STOP" }] }), "complete");
    assert.equal(finishFromGemini({ candidates: [{ finishReason: "MAX_TOKENS" }] }), "incomplete");
    assert.equal(finishFromOllama({ done: true, done_reason: "stop" }), "complete");
    assert.equal(finishFromOllama({ done: true, done_reason: "length" }), "incomplete");
    assert.equal(finishFromOllama({ done: false }), "incomplete");
    assert.equal(finishFromOllama({ response: "x" }), "unknown");
});

// ---------------------------------------------------------------------------
// 3. Through the npm-launched server over stdio (the release tests run here)
// ---------------------------------------------------------------------------

async function withServer(extraEnv: Record<string, string>, fn: (c: Client, log: () => string[]) => Promise<void>) {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-changea-"));
    const logFile = path.join(home, "requests.log");
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")],
        env: {
            PATH: process.env.PATH || "", HOME: home,
            ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00",
            ARKHEIA_HOSTED_URL: "https://hosted.example.test",
            ARKHEIA_PROXY_URL: "http://localhost:8098",
            XAI_API_KEY: "xai-dummy-key-0000", GOOGLE_API_KEY: "g-dummy-key-0000", TOGETHER_API_KEY: "t-dummy-key-0000",
            OLLAMA_BASE_URL: "http://ollama.example.test",
            ARKHEIA_TEST_REQUEST_LOG: logFile,
            ...extraEnv,
        },
        stderr: "pipe",
    });
    const client = new Client({ name: "changea-test", version: "0" });
    try {
        await client.connect(transport);
        await fn(client, () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8").split("\n").filter(Boolean) : []));
    } finally {
        await client.close();
        fs.rmSync(home, { recursive: true, force: true });
    }
}
const call = async (c: Client, name: string, args: any) => JSON.parse(((await c.callTool({ name, arguments: args })) as any).content[0].text);

test("stdio: arkheia_verify on an unassessed hosted LOW returns NOT_ASSESSED with no LOW anywhere", async () => {
    await withServer({ ARKHEIA_TEST_DETECT_BODY: JSON.stringify({ risk: "LOW", assessed: false, not_assessed_reason: "no_profile", candidate_alert: null, evidence_depth_limited: true }) }, async (c) => {
        const v = await call(c, "arkheia_verify", { prompt: "p", response: "r", model: "m" });
        assert.deepEqual([v.risk_level, v.assessed, v.not_assessed_reason], ["NOT_ASSESSED", false, "no_profile"]);
        assert.doesNotMatch(JSON.stringify(v), /LOW/);
    });
});

test("stdio: arkheia_verify on an assessed hosted LOW returns LOW", async () => {
    await withServer({ ARKHEIA_TEST_DETECT_BODY: JSON.stringify({ ...ASSESSED_LOW, confidence: 0.8 }) }, async (c) => {
        const v = await call(c, "arkheia_verify", { prompt: "p", response: "r", model: "m" });
        assert.deepEqual([v.risk_level, v.assessed], ["LOW", true]);
    });
});

test("stdio: the verify tool's guidance names NOT_ASSESSED and candidate_alert", async () => {
    await withServer({}, async (c) => {
        const t = (await c.listTools()).tools.find((x) => x.name === "arkheia_verify")!;
        assert.match(t.description!, /NOT_ASSESSED -- detection could not score this response\. It is not a clean result\. Verify by other means/);
        assert.match(t.description!, /candidate_alert -- an unqualified warning on a response we could not properly assess\. Treat MEDIUM or HIGH here as a reason to check the specific claims now\./);
    });
});

const RUNNERS: Array<[string, string]> = [
    ["run_grok", "https://api.x.ai/"], ["run_gemini", "https://generativelanguage.googleapis.com/"],
    ["run_together", "https://api.together.xyz/"], ["run_ollama", "http://ollama.example.test/"],
];
for (const [tool, origin] of RUNNERS) {
    test(`stdio: ${tool} reply cut off at the length limit is NOT_ASSESSED incomplete_response and is not screened`, async () => {
        await withServer({ ARKHEIA_TEST_FINISH: "length" }, async (c, log) => {
            const out = await call(c, tool, { prompt: "p" });
            assert.deepEqual([out.arkheia.risk_level, out.arkheia.assessed, out.arkheia.not_assessed_reason], ["NOT_ASSESSED", false, "incomplete_response"]);
            assert.ok(log().some((u) => u.startsWith(origin)), "the provider was called");
            assert.ok(!log().some((u) => u.endsWith("/v1/detect") || u.endsWith("/detect/verify")), "no screening call was made");
        });
    });
    test(`stdio: ${tool} normal reply is screened`, async () => {
        await withServer({ ARKHEIA_TEST_DETECT_BODY: JSON.stringify({ ...ASSESSED_LOW }) }, async (c, log) => {
            const out = await call(c, tool, { prompt: "p" });
            assert.ok(log().some((u) => u.endsWith("/v1/detect") || u.endsWith("/detect/verify")), "a screening call was made");
            if (tool === "run_ollama") {
                // local-only: the local verifier is down in the stub, so this is not assessed, never hosted
                assert.deepEqual([out.arkheia.risk_level, out.arkheia.not_assessed_reason], ["NOT_ASSESSED", "service_unavailable"]);
                assert.ok(!log().some((u) => u.endsWith("/v1/detect")));
            } else {
                assert.deepEqual([out.arkheia.risk_level, out.arkheia.assessed], ["LOW", true]);
            }
        });
    });
    test(`stdio: ${tool} provider error is NOT_ASSESSED provider_error and is not screened`, async () => {
        await withServer({ ARKHEIA_TEST_FINISH: "error" }, async (c, log) => {
            const out = await call(c, tool, { prompt: "p" });
            assert.deepEqual([out.arkheia.risk_level, out.arkheia.not_assessed_reason], ["NOT_ASSESSED", "provider_error"]);
            assert.ok(!log().some((u) => u.endsWith("/v1/detect") || u.endsWith("/detect/verify")));
        });
    });
}

test("stdio: arkheia_audit_log normalises rows and counts NOT_ASSESSED apart", async () => {
    const body = { events: [
        { source: "proxy", risk_level: "LOW", assessed: false, not_assessed_reason: "limited_evidence", evidence_depth_limited: true },
        { source: "proxy", risk_level: "LOW" },
        { source: "proxy", risk_level: "LOW", assessed: true, evidence_depth_limited: false },
    ], summary: { LOW: 3, MEDIUM: 0, HIGH: 0, UNKNOWN: 0 } };
    await withServer({ ARKHEIA_TEST_AUDIT_BODY: JSON.stringify(body) }, async (c) => {
        const out = await call(c, "arkheia_audit_log", {});
        assert.deepEqual(out.events.map((e: any) => e.risk_level), ["NOT_ASSESSED", "NOT_ASSESSED", "LOW"]);
        assert.deepEqual(out.summary, { LOW: 1, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 2, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0 });
    });
});


// ---------------------------------------------------------------------------
// 4. Review round 1 probes: contradictions, finish shapes, multi-part replies, malformed rows
// ---------------------------------------------------------------------------

const moreContradictions: Array<[string, any]> = [
    ["assessed LOW with a borrowed profile", { ...ASSESSED_LOW, profile_fingerprint_borrowed: true }],
    ["assessed LOW with model_supported false", { ...ASSESSED_LOW, model_supported: false }],
    ["assessed MEDIUM with a recorded demotion", { ...ASSESSED_LOW, risk: "MEDIUM", risk_demoted_from: "HIGH" }],
    ["a HIGH candidate beside a live LOW with no demotion", { risk: "LOW", assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: "HIGH" }],
    ["a MEDIUM candidate beside a HIGH band", { risk: "HIGH", assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: "MEDIUM" }],
];
for (const [name, body] of moreContradictions) {
    test(`fails closed: ${name}`, () => {
        assert.deepEqual(assessmentFromDetector(body, "risk"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

test("a demoted verdict keeps its pre-demotion level as the candidate", () => {
    assert.deepEqual(
        assessmentFromDetector({ risk: "MEDIUM", risk_demoted_from: "HIGH", assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: "HIGH" }, "risk"),
        { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "borrowed_profile", candidate_alert: "HIGH" });
});

for (const level of ["MEDIUM", "HIGH"] as const) {
    test(`an old row with no assessment fact keeps a service-supplied ${level} candidate with reason unknown`, () => {
        assert.deepEqual(assessmentFromDetector({ risk_level: level, candidate_alert: level }, "risk_level"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown", candidate_alert: level });
    });
}

test("Ollama counts as complete only with done: true and done_reason: stop", () => {
    assert.equal(finishFromOllama({ done: true, done_reason: "stop" }), "complete");
    assert.equal(finishFromOllama({ done_reason: "stop" }), "unknown");
    assert.equal(finishFromOllama({ done: "false", done_reason: "stop" }), "unknown");
    assert.equal(finishFromOllama({ done: "true", done_reason: "stop" }), "unknown");
    assert.equal(finishFromOllama({ done: true }), "unknown");
});

async function geminiWith(body: any) {
    const { call_gemini } = await import('../src/providers.js');
    const saved = process.env.GOOGLE_API_KEY;
    process.env.GOOGLE_API_KEY = "g-dummy-key-0000";
    const restore = withFetch(() => json(200, body));
    try { return await call_gemini("p", "gemini-2.5-flash") as any; }
    finally { restore(); if (saved === undefined) delete process.env.GOOGLE_API_KEY; else process.env.GOOGLE_API_KEY = saved; }
}

test("Gemini: a finished reply in two text parts is screened whole", async () => {
    const pr = await geminiWith({ candidates: [{ content: { parts: [{ text: "first. " }, { text: "second." }] }, finishReason: "STOP" }] });
    assert.equal(pr.response, "first. second.");
    assert.equal(pr.finish, "complete");
    assert.equal(pr.error, null);
});

test("Gemini: a finished reply with a non-text part is a provider error, not screened", async () => {
    const pr = await geminiWith({ candidates: [{ content: { parts: [{ text: "a" }, { functionCall: { name: "f" } }] }, finishReason: "STOP" }] });
    assert.ok(pr.error);
});

for (const reason of ["MAX_TOKENS", "SAFETY"]) {
    test(`Gemini: ${reason} with no text is incomplete, not a provider error`, async () => {
        const pr = await geminiWith({ candidates: [{ finishReason: reason }] });
        assert.deepEqual([pr.finish, pr.error, pr.response], ["incomplete", null, ""]);
    });
}

test("audit: a malformed row between two warnings costs neither warning", async () => {
    const restore = withFetch(() => json(200, { events: [
        { source: "proxy", risk_level: "MEDIUM", candidate_alert: "MEDIUM" },
        "not a row",
        null,
        { source: "proxy", risk_level: "HIGH", candidate_alert: "HIGH" },
    ] }));
    try {
        const out: any = await new ProxyClient("http://localhost:8098", 1.0, "https://hosted.example.test", "ak_live_DUMMYDUMMYDUMMY00").get_audit_log();
        assert.deepEqual(out.events.map((e: any) => e.candidate_alert), ["MEDIUM", "HIGH"]);
        assert.deepEqual(out.summary, { LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 2, CANDIDATE_MEDIUM: 1, CANDIDATE_HIGH: 1, INVALID_ROWS: 2 });
        assert.equal(out.error, undefined);
    } finally { restore(); }
});


// ---------------------------------------------------------------------------
// 5. Review round 2 probes
// ---------------------------------------------------------------------------

const LOCAL_ASSESSED = { risk_level: "LOW", assessed: true, evidence_depth_limited: false,
    not_assessed_reason: null, candidate_alert: null, model_id: "phi4:14b", profile_model_id: "phi4:14b",
    gate_reason: null, error: null, detection_method: "profile_ensemble" };

test("a consistent local own-profile verdict stays assessed and keeps detection_method", () => {
    assert.deepEqual(assessmentFromDetector(LOCAL_ASSESSED, "risk_level"), { risk_level: "LOW", assessed: true });
});

const localContradictions: Array<[string, any]> = [
    ["a suppression gate", { ...LOCAL_ASSESSED, gate_reason: "token_count_below_80" }],
    ["another model's profile", { ...LOCAL_ASSESSED, profile_model_id: "phi4:latest" }],
    ["a detector error", { ...LOCAL_ASSESSED, error: "engine_error" }],
    ["an impossible demotion", { ...LOCAL_ASSESSED, risk_level: "LOW", assessed: false, not_assessed_reason: "limited_evidence", risk_demoted_from: "HIGH", candidate_alert: "HIGH" }],
];
for (const [name, body] of localContradictions) {
    test(`local verdict fails closed on ${name}`, () => {
        assert.deepEqual(assessmentFromDetector(body, "risk_level"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

test("applyAssessment keeps detection_method on assessed results only", async () => {
    const { applyAssessment } = await import('../src/assessment.js');
    assert.equal(applyAssessment(LOCAL_ASSESSED, { risk_level: "LOW", assessed: true }).detection_method, "profile_ensemble");
    assert.equal("detection_method" in applyAssessment(LOCAL_ASSESSED, { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" }), false);
});

test("Gemini: a thought part is neither shown nor screened", async () => {
    const pr = await geminiWith({ candidates: [{ content: { parts: [{ text: "thinking...", thought: true }, { text: "answer." }] }, finishReason: "STOP" }] });
    assert.deepEqual([pr.response, pr.finish, pr.error], ["answer.", "complete", null]);
});

test("Gemini: an incomplete reply keeps its visible text beside a non-text part", async () => {
    const pr = await geminiWith({ candidates: [{ content: { parts: [{ text: "partial" }, { functionCall: { name: "f" } }] }, finishReason: "MAX_TOKENS" }] });
    assert.deepEqual([pr.response, pr.finish, pr.error], ["partial", "incomplete", null]);
});

for (const [name, fn, key] of [["grok", "call_grok", "XAI_API_KEY"], ["together", "call_together", "TOGETHER_API_KEY"]] as const) {
    test(`${name}: a content-filtered reply with null text is incomplete, not a provider error`, async () => {
        const mod: any = await import('../src/providers.js');
        const saved = process.env[key];
        process.env[key] = "dummy-key-00000000";
        const restore = withFetch(() => json(200, { choices: [{ message: { content: null }, finish_reason: "content_filter" }] }));
        try {
            const pr = await mod[fn]("p");
            assert.deepEqual([pr.finish, pr.error, pr.response], ["incomplete", null, ""]);
        } finally { restore(); if (saved === undefined) delete process.env[key]; else process.env[key] = saved; }
    });
}

test("audit: a delivery receipt is passed through and not counted", () => {
    const out = normaliseAuditLog({ events: [
        { source: "proxy", risk_level: "HIGH", assessed: true, evidence_depth_limited: false, model_id: "m", profile_model_id: "m" },
        { source: "governance_push", event_type: "governance_detection_push", risk_level: "HIGH" },
    ] });
    assert.deepEqual(out.events[1], { source: "governance_push", event_type: "governance_detection_push", record_kind: "delivery_receipt" });
    assert.deepEqual(out.summary, { LOW: 0, MEDIUM: 0, HIGH: 1, NOT_ASSESSED: 0, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 0 });
});


// ---------------------------------------------------------------------------
// 6. Review round 3 probes
// ---------------------------------------------------------------------------

test("audit: the service's assessment object is used, and stored fields keep their digest scope", () => {
    const out = normaliseAuditLog({ events: [
        { source: "passthrough", detection_id: "pt", risk_level: "HIGH", this_hash: "h1", prev_hash: "h0",
          record_kind: "detection", assessment: { assessed: false, not_assessed_reason: "unknown", candidate_alert: "HIGH" },
          read_time_fields: ["record_kind", "assessment", "read_time_fields"] },
        { source: "passthrough", detection_id: "rf", risk_level: "HIGH", action_taken: "refuse", record_kind: "refusal" },
        { source: "governance_push", detection_id: "pt", risk_level: "LOW", record_kind: "delivery_receipt", delivery_status: "delivered" },
    ] });
    const [det, refusal, receipt] = out.events;
    assert.deepEqual([det.risk_level, det.not_assessed_reason, det.candidate_alert], ["NOT_ASSESSED", "unknown", "HIGH"]);
    assert.equal(det.stored_this_hash, "h1");
    assert.match(det.hash_scope, /stored record, not this view/);
    assert.equal("this_hash" in det, false);
    assert.equal("assessment" in det, false);
    for (const r of [refusal, receipt]) assert.equal("risk_level" in r, false, "no band on a non-detection row");
    assert.equal(receipt.delivery_status, "delivered");
    assert.doesNotMatch(JSON.stringify(out.events), /"LOW"/);
    assert.deepEqual(out.summary, { LOW: 0, MEDIUM: 0, HIGH: 0, NOT_ASSESSED: 1, CANDIDATE_MEDIUM: 0, CANDIDATE_HIGH: 1 });
});

test("audit: an incoherent service assessment fails closed", () => {
    const out = normaliseAuditLog({ events: [
        { source: "proxy", risk_level: "LOW", record_kind: "detection", assessment: { assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: "HIGH" } },
        { source: "proxy", risk_level: "HIGH", record_kind: "detection", assessment: { assessed: true, not_assessed_reason: "limited_evidence" } },
    ] });
    assert.deepEqual(out.events.map((e: any) => [e.risk_level, e.not_assessed_reason, e.candidate_alert ?? null]),
                     [["NOT_ASSESSED", "unknown", null], ["NOT_ASSESSED", "unknown", null]]);
});

test("audit raw: the stored records come back unchanged", async () => {
    const body = { events: [{ source: "proxy", risk_level: "HIGH", this_hash: "h1" }], summary: { HIGH: 1 } };
    const restore = withFetch(() => json(200, body));
    try {
        const out: any = await new ProxyClient("http://localhost:8098", 1.0, "https://hosted.example.test", "ak_live_DUMMYDUMMYDUMMY00").get_audit_log(undefined, 50, true);
        assert.deepEqual(out, body);
    } finally { restore(); }
});

const identityContradictions: Array<[string, any]> = [
    ["an explicit null profile id", { ...LOCAL_ASSESSED, profile_model_id: null }],
    ["a model other than the one requested", { ...LOCAL_ASSESSED, model_id: "llama3:8b", profile_model_id: "llama3:8b" }],
];
for (const [name, body] of identityContradictions) {
    test(`local verdict fails closed on ${name}`, () => {
        assert.deepEqual(assessmentFromDetector(body, "risk_level", "phi4:14b"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

test("a verdict about the requested model, in another case, stays assessed", () => {
    assert.deepEqual(assessmentFromDetector({ ...LOCAL_ASSESSED, model_id: "PHI4:14B", profile_model_id: "phi4:14b" }, "risk_level", "phi4:14b"),
                     { risk_level: "LOW", assessed: true });
});

test("the capped-HIGH shape the local verifier now sends keeps its HIGH candidate", () => {
    assert.deepEqual(assessmentFromDetector({ risk_level: "MEDIUM", risk_demoted_from: "HIGH", assessed: false,
        not_assessed_reason: "limited_evidence", candidate_alert: "HIGH", evidence_depth_limited: true, source: "local" }, "risk_level", "gpt-4"),
        { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "limited_evidence", candidate_alert: "HIGH" });
});


// ---------------------------------------------------------------------------
// 7. Review round 4 probes
// ---------------------------------------------------------------------------

const NESTED_OK = { source: "proxy", risk_level: "LOW", model_id: "phi4:14b", profile_model_id: "phi4:14b",
    evidence_depth_limited: false, gate_reason: null, error: null, record_kind: "detection",
    assessment: { assessed: true, not_assessed_reason: null, candidate_alert: null } };

test("audit: a clean nested assessment stays assessed", () => {
    assert.equal(normaliseAuditLog({ events: [NESTED_OK] }).events[0].risk_level, "LOW");
});

for (const [name, change] of [
    ["limited evidence", { evidence_depth_limited: true }],
    ["a suppression gate", { gate_reason: "token_count_below_80" }],
    ["a detector error", { error: "engine_error" }],
    ["another model's profile", { profile_model_id: "phi4:latest" }],
] as const) {
    test(`audit: a nested affirmative assessment beside ${name} fails closed`, () => {
        const row = normaliseAuditLog({ events: [{ ...NESTED_OK, ...change }] }).events[0];
        assert.deepEqual([row.risk_level, row.not_assessed_reason], ["NOT_ASSESSED", "unknown"]);
    });
}

test("audit: an interception refusal is a refusal, even if labelled a detection", () => {
    const out = normaliseAuditLog({ events: [
        { source: "interception", risk_level: "REFUSED", action_taken: "refused", record_kind: "detection" },
        { source: "interception", risk_level: "REFUSED", action_taken: "refused" },
    ] });
    assert.deepEqual(out.events.map((e: any) => e.record_kind), ["refusal", "refusal"]);
    assert.equal(out.summary.NOT_ASSESSED, 0);
});

test("a scoring profile for another model fails closed even with no model echo", () => {
    const { model_id: _m, ...noEcho } = LOCAL_ASSESSED as any; void _m;
    assert.deepEqual(assessmentFromDetector({ ...noEcho, profile_model_id: "llama3:8b" }, "risk_level", "phi4:14b"),
                     { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
});

test("audit raw asks the service for its raw mode", async () => {
    let seen = "";
    const restore = withFetch((u) => { seen = u; return json(200, { events: [] }); });
    try {
        await new ProxyClient("http://localhost:8098", 1.0, "https://hosted.example.test", "ak_live_DUMMYDUMMYDUMMY00").get_audit_log(undefined, 10, true);
        assert.match(seen, /[?&]raw=true\b/);
    } finally { restore(); }
});


// ---------------------------------------------------------------------------
// 8. Review round 5 probes
// ---------------------------------------------------------------------------

for (const [name, value] of [["null", null], ["a string", "yes"], ["an array", []]] as const) {
    test(`audit: an unreadable assessment (${name}) fails closed even beside an affirmative top-level flag`, () => {
        const row = normaliseAuditLog({ events: [{ ...NESTED_OK, assessed: true, assessment: value }] }).events[0];
        assert.deepEqual([row.risk_level, row.not_assessed_reason], ["NOT_ASSESSED", "unknown"]);
    });
}

test("audit: an omitted assessment is read the old way (legacy producer)", () => {
    const { assessment: _a, record_kind: _k, ...legacy } = NESTED_OK as any; void _a; void _k;
    const row = normaliseAuditLog({ events: [{ ...legacy, assessed: true }] }).events[0];
    assert.deepEqual([row.risk_level, row.assessed], ["LOW", true]);
});

for (const key of ["model_id", "model", "profile_model_id"]) {
    test(`an explicit null ${key} fails closed`, () => {
        assert.deepEqual(assessmentFromDetector({ ...LOCAL_ASSESSED, [key]: null }, "risk_level", "phi4:14b"),
                         { risk_level: "NOT_ASSESSED", assessed: false, not_assessed_reason: "unknown" });
    });
}

test("audit raw against an older producer that ignores raw reports raw as unavailable", async () => {
    const restore = withFetch(() => json(200, { events: [{ source: "proxy", risk_level: "HIGH", this_hash: "h",
        record_kind: "detection", assessment: { assessed: false, not_assessed_reason: "unknown", candidate_alert: "HIGH" } }] }));
    try {
        const out: any = await new ProxyClient("http://localhost:8098", 1.0, "https://hosted.example.test", "ak_live_DUMMYDUMMYDUMMY00").get_audit_log(undefined, 10, true);
        assert.deepEqual(out, { events: [], summary: {}, error: "raw_unavailable_from_this_local_proxy" });
    } finally { restore(); }
});


for (const [name, change] of [
    ["a model alias that disagrees with the scoring profile", { model: "phi4:14b", profile_model_id: "llama3:8b", model_id: undefined }],
    ["a model alias that disagrees with matching model_id and profile", { model: "llama3:8b" }],
] as const) {
    test(`audit: ${name} fails closed with no requested model`, () => {
        const row = normaliseAuditLog({ events: [{ ...NESTED_OK, ...change }] }).events[0];
        assert.deepEqual([row.risk_level, row.not_assessed_reason], ["NOT_ASSESSED", "unknown"]);
    });
}
