import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import {
    FeedbackClient, withReportability, feedbackShape, reportShape, reportsShape, looksLikeCredential,
} from '../src/feedback.js';
import { call_grok, call_gemini, call_together, call_ollama } from '../src/providers.js';
import { ProxyClient } from '../src/proxy-client.js';
import { check, REGISTRY } from '../src/tool-registry.js';

const BASE = "https://api.example.test";
const KEY = "ak_live_TESTKEYTESTKEY1234";
const realFetch = globalThis.fetch;
let calls: { url: string; init: any }[] = [];

function mockFetch(handler: (url: string, init: any, n: number) => Response | Promise<Response>) {
    calls = [];
    (globalThis as any).fetch = async (url: any, init: any) => {
        calls.push({ url: String(url), init });
        return handler(String(url), init, calls.length);
    };
}
const json = (status: number, body: any, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const client = () => new FeedbackClient(BASE, KEY, 200);
beforeEach(() => { calls = []; });
afterEach(() => { (globalThis as any).fetch = realFetch; });

const FID = "11111111-2222-3333-4444-555555555555";
const DID = "det_0123456789abcdef";
const FB = { feedback_id: FID, status: "received" };
const RP = { report_id: FID, status: "recorded" };
// one reply that is a valid acknowledgement for whichever endpoint was called
const ackFor = (url: string) => (url.includes("/report") ? RP : FB);

// ---- success ---------------------------------------------------------------

test("feedback: success returns the server id; both documented reply shapes work", async () => {
    for (const echo of [false, true]) {
        mockFetch((_u, init) => json(201, echo
            ? { feedback_id: FID, submission_id: JSON.parse(init.body).submission_id, status: "received", message: "Your feedback was saved." }
            : { feedback_id: FID, status: "received", message: "Thank you for your feedback. We read every message." }));
        const r: any = await client().send_feedback({ message: "The check flagged a correct answer.", kind: "false_alarm" });
        assert.equal(r.recorded, true);
        assert.equal(r.feedback_id, FID);
        assert.deepEqual(Object.keys(r).sort(), ["feedback_id", "note", "recorded", "submission_id"]);
        assert.ok(!/Recorded by the Arkheia service/.test(r.note));
        assert.match(r.note, /acknowledged/);
    }
});

test("feedback: request body has exactly the expected fields, key only in header", async () => {
    mockFetch(() => json(201, FB));
    await client().send_feedback({ message: "hello there", kind: "bug", email: "a@b.co" });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, `${BASE}/v1/feedback`);
    assert.equal(calls[0].init.method, "POST");
    assert.equal(calls[0].init.headers["X-Arkheia-Key"], KEY);
    assert.equal(calls[0].init.redirect, "error");
    const body = JSON.parse(calls[0].init.body);
    assert.deepEqual(Object.keys(body).sort(), ["context", "email", "message", "submission_id"]);
    assert.equal(body.context, "bug");
    assert.equal(body.email, "a@b.co");
    assert.ok(!calls[0].init.body.includes(KEY));
});

test("feedback: optional fields are omitted when not supplied", async () => {
    mockFetch(() => json(201, FB));
    await client().send_feedback({ message: "hello there", email: "  " });
    assert.deepEqual(Object.keys(JSON.parse(calls[0].init.body)).sort(), ["message", "submission_id"]);
});

test("report: body has exactly the expected fields and goes to the id's path", async () => {
    mockFetch(() => json(201, { report_id: FID, status: "recorded", message: "Thanks." }));
    const r: any = await client().send_report({ detection_id: DID, outcome: "wrong", evidence: "no such function", category: "invented_api", reporter_kind: "human" });
    assert.equal(r.recorded, true);
    assert.equal(r.report_id, FID);
    assert.equal(calls[0].url, `${BASE}/v1/detections/${DID}/report`);
    assert.deepEqual(JSON.parse(calls[0].init.body), { outcome: "wrong", reporter_kind: "human", evidence: "no such function", category: "invented_api" });
    mockFetch(() => json(201, RP));
    await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.deepEqual(JSON.parse(calls[0].init.body), { outcome: "fine", reporter_kind: "agent" });
});

// ---- failures: three honest outcomes ---------------------------------------

const refusals: [string, () => Response | Promise<Response>][] = [
    ["400", () => json(400, { detail: "Feedback message too short" })],
    ["401", () => json(401, { detail: "bad key" })],
    ["429", () => json(429, { detail: "slow down" })],
];
const uncertain: [string, () => Response | Promise<Response>][] = [
    ["500", () => json(500, { detail: "boom" })],
    ["503 with a structured body", () => json(503, { detail: { feedback_id: FID, status: "unavailable" } }, { "Retry-After": "30" })],
    ["malformed json", () => new Response("<html>", { status: 201 })],
    ["201 without id", () => json(201, { status: "received" })],
    ["201 with empty id", () => json(201, { feedback_id: "" })],
    ["201 with non-string id", () => json(201, { feedback_id: 5 })],
    ["201 with a non-UUID id", () => json(201, { feedback_id: "all done, thanks", report_id: "all done, thanks" })],
    ["202 pending with a valid id", () => json(202, { feedback_id: FID, report_id: FID })],
    ["200 with a valid id", () => json(200, { feedback_id: FID, report_id: FID })],
];
for (const [name, h] of refusals) {
    test(`feedback: ${name} -> recorded:false, no retry`, async () => {
        mockFetch(h);
        const r: any = await client().send_feedback({ message: "hello there" });
        assert.equal(r.recorded, false);
        assert.match(r.error, /NOT recorded/);
        assert.equal(r.feedback_id, undefined);
        assert.match(r.submission_id, /^[0-9a-f-]{36}$/);
        assert.equal(calls.length, 1);
    });
}
for (const [name, h] of uncertain) {
    test(`feedback: ${name} -> recorded:"unknown" with the submission_id, no retry`, async () => {
        mockFetch(h);
        const r: any = await client().send_feedback({ message: "hello there" });
        assert.equal(r.recorded, "unknown");
        assert.equal(r.feedback_id, undefined);
        assert.match(r.error, /may or may not have been recorded/);
        assert.ok(r.error.includes(r.submission_id), "advice names the same submission_id");
        assert.match(r.error, /same submission_id/);
        assert.equal(calls.length, 1, "no automatic retry after a possibly-sent write");
    });
}
for (const [name, h] of [...refusals, ...uncertain]) {
    test(`report: ${name} -> never success, no retry`, async () => {
        mockFetch(h);
        const r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
        assert.notEqual(r.recorded, true);
        assert.equal(r.report_id, undefined);
        assert.equal(calls.length, 1);
    });
}

test("a caller-supplied submission_id is reused in the body and returned", async () => {
    const sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    mockFetch(() => json(500, {}));
    const r: any = await client().send_feedback({ message: "hello there", submission_id: sid });
    assert.equal(JSON.parse(calls[0].init.body).submission_id, sid);
    assert.equal(r.submission_id, sid);
    mockFetch(() => json(201, FB));
    const ok: any = await client().send_feedback({ message: "hello there", submission_id: sid });
    assert.equal(ok.recorded, true);
    assert.equal(ok.submission_id, sid);
    assert.equal(((await client().send_feedback({ message: "hello there", submission_id: "nope" })) as any).recorded, false);
    assert.ok(z.object(feedbackShape).safeParse({ message: "hello there", submission_id: sid }).success);
    assert.ok(!z.object(feedbackShape).safeParse({ message: "hello there", submission_id: "x" }).success);
});

const refusedConn = () => { throw new TypeError("fetch failed", { cause: Object.assign(new Error("x"), { code: "ECONNREFUSED" }) }); };

test("provably unsent (connection refused): one retry with the same body, then recorded:false", async () => {
    mockFetch(refusedConn);
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    assert.match(r.error, /nothing was sent/);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init.body, calls[1].init.body);
});

test("provably unsent, then success on the retry", async () => {
    mockFetch((_u, _i, n) => { if (n === 1) return refusedConn(); return json(201, FB); });
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, true);
    assert.equal(calls.length, 2);
});

test("connection error that may follow sending: unknown, NO retry (feedback and report)", async () => {
    mockFetch(() => { throw new TypeError("fetch failed", { cause: Object.assign(new Error("x"), { code: "ECONNRESET" }) }); });
    let r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, "unknown");
    assert.equal(calls.length, 1);
    r = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.equal(r.recorded, "unknown");
    assert.match(r.error, /arkheia_reports/);
    assert.equal(calls.length, 2, "one call each, no retries");
    mockFetch(() => { throw new TypeError("fetch failed"); });
    assert.equal(((await client().send_feedback({ message: "hello there" })) as any).recorded, "unknown");
    assert.equal(calls.length, 1);
});

test("timeout while waiting for headers: unknown, no retry", async () => {
    mockFetch((_u, init) => new Promise((_res, rej) => {
        init.signal.addEventListener("abort", () => { const e: any = new Error("aborted"); e.name = "AbortError"; rej(e); });
    }));
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, "unknown");
    assert.match(r.error, /did not answer in time/);
    assert.equal(calls.length, 1);
});

test("deadline covers the body: headers arrive, body never does -> unknown within the deadline", async () => {
    const hang = { ok: true, status: 201, text: () => new Promise<string>(() => { /* never */ }) };
    mockFetch(() => hang as any);
    const t0 = Date.now();
    const r: any = await new FeedbackClient(BASE, KEY, 100).send_feedback({ message: "hello there" });
    assert.ok(Date.now() - t0 < 1000, "returned promptly");
    assert.equal(r.recorded, "unknown");
    assert.equal(r.feedback_id, undefined);
    assert.equal(calls.length, 1);
    const l: any = await new FeedbackClient(BASE, KEY, 100).list_reports();
    assert.equal(l.recorded, false);
});

test("a body that stalls on a real stream is also cut off", async () => {
    mockFetch(() => new Response(new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("{")); } }), { status: 201 }));
    const r: any = await new FeedbackClient(BASE, KEY, 100).send_feedback({ message: "hello there" });
    assert.equal(r.recorded, "unknown");
});

test("server error text is never passed through: a 500 reflecting the key and a token yields neither", async () => {
    const token = "Bearer abcdefghijklmnopqrstuvwx";
    mockFetch(() => json(500, { detail: `failed for key ${KEY} with ${token}` }));
    for (const r of [
        await client().send_feedback({ message: "hello there" }),
        await client().send_report({ detection_id: DID, outcome: "fine" }),
        await client().delete_report(FID),
        await client().list_reports(),
    ]) {
        const out = JSON.stringify(r);
        assert.ok(!out.includes(KEY) && !out.includes("abcdefghijklmnop") && !/failed for key/.test(out), out);
        assert.match(out, /HTTP 500/);
    }
    mockFetch(() => json(422, { detail: `reflects ${KEY}` }));
    assert.ok(!JSON.stringify(await client().send_feedback({ message: "hello there" })).includes(KEY));
});

test("report 404 gives a fixed message; 409 says a report already exists and points to list, not delete", async () => {
    mockFetch(() => json(404, { detail: "No detection with that id for this key." }));
    let r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.match(r.error, /NOT recorded.*no record of that detection id/);
    mockFetch(() => json(409, { detail: "Already reported." }));
    r = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.equal(r.already_reported, true);
    assert.match(r.error, /already exists/);
    assert.match(r.error, /arkheia_reports \(action: list\)/);
    assert.ok(!/delete/i.test(r.error));
    assert.equal(calls.length, 1);
});

test("no key or non-https URL: nothing is sent", async () => {
    mockFetch(() => json(201, FB));
    let r: any = await new FeedbackClient(BASE, undefined).send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    r = await new FeedbackClient("http://example.test", KEY).send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    assert.equal(calls.length, 0);
});

// ---- validation ------------------------------------------------------------

test("input limits", () => {
    const f = z.object(feedbackShape);
    assert.ok(f.safeParse({ message: "abcde" }).success);
    assert.ok(!f.safeParse({ message: "abcd" }).success);
    assert.ok(f.safeParse({ message: "a".repeat(2000) }).success);
    assert.ok(!f.safeParse({ message: "a".repeat(2001) }).success);
    assert.ok(!f.safeParse({ message: "hello there", kind: "nonsense" }).success);
    for (const kind of ["bug", "false_alarm", "missed_problem", "feature_request", "praise", "other"]) {
        assert.ok(f.safeParse({ message: "hello there", kind }).success);
    }
    const r = z.object(reportShape);
    assert.ok(r.safeParse({ detection_id: DID, outcome: "wrong" }).success);
    assert.equal(r.parse({ detection_id: DID, outcome: "fine" }).reporter_kind, "agent");
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "maybe" }).success);
    assert.ok(!r.safeParse({ detection_id: "../x", outcome: "fine" }).success);
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "fine", evidence: "e".repeat(501) }).success);
    assert.ok(r.safeParse({ detection_id: DID, outcome: "fine", evidence: "e".repeat(500) }).success);
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "fine", category: "bogus" }).success);
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "fine", reporter_kind: "bot" }).success);
    assert.ok(!z.object(reportsShape).safeParse({ action: "purge" }).success);
});

test("module also enforces limits, bad email, multi-line evidence (no request sent)", async () => {
    mockFetch((u) => json(201, ackFor(u)));
    const c = client();
    assert.equal(((await c.send_feedback({ message: "   a   " })) as any).recorded, false);
    assert.equal(((await c.send_feedback({ message: "a".repeat(2001) })) as any).recorded, false);
    assert.equal(((await c.send_feedback({ message: "hello there", email: "not-an-email" })) as any).recorded, false);
    assert.equal(((await c.send_report({ detection_id: DID, outcome: "fine", evidence: "a\nb" })) as any).recorded, false);
    assert.equal(((await c.send_report({ detection_id: "a/b", outcome: "fine" })) as any).recorded, false);
    assert.equal(calls.length, 0);
});

test("credential-shaped text is refused and never sent or echoed", async () => {
    mockFetch((u) => json(201, ackFor(u)));
    const secrets = [
        "my key is ak_live_abcdefgh12345678",
        "Authorization: Bearer abcdefghijklmnop12345678",
        "sk-abcdefghijklmnopqrstuvwx",
        "ghp_" + "a".repeat(36),
        "AKIAABCDEFGHIJKLMNOP",
        "eyJhbGciOiJI.eyJzdWIiOiIx.abcdefghijk",
        "-----BEGIN RSA PRIVATE KEY-----",
        `contains my configured key ${KEY}`,
    ];
    for (const s of secrets) {
        const a: any = await client().send_feedback({ message: s });
        assert.equal(a.recorded, false, s);
        assert.match(a.error, /API key or token/);
        assert.ok(!a.error.includes(s));
        const b: any = await client().send_report({ detection_id: DID, outcome: "wrong", evidence: s });
        assert.equal(b.recorded, false, s);
    }
    const e: any = await client().send_feedback({ message: "hello there", email: "ak_live_abcdefgh12345678@x.co" });
    assert.equal(e.recorded, false);
    assert.equal(calls.length, 0);
    assert.ok(!looksLikeCredential("The verdict was wrong about src/index.ts and the bearer of bad news"));
    assert.ok(!looksLikeCredential("please make the sk- prefix shorter"));
});

// ---- list / delete -----------------------------------------------------------

test("list returns only whitelisted report fields; delete needs a 204", async () => {
    mockFetch(() => json(200, { reports: [{ report_id: FID, event_id: DID, outcome: "wrong", category: null, evidence: "e", reporter_kind: "agent", created_at: "2026-01-01T00:00:00Z", extra_internal: "x" }] }));
    const l: any = await client().list_reports(5);
    assert.equal(calls[0].url, `${BASE}/v1/reports?limit=5`);
    assert.deepEqual(Object.keys(l.reports[0]).sort(), ["category", "created_at", "detection_id", "evidence", "outcome", "report_id", "reporter_kind"]);
    mockFetch(() => json(200, { nope: 1 }));
    assert.match(((await client().list_reports()) as any).error, /could not be fetched/);
    mockFetch(() => new Response(null, { status: 204 }));
    const d: any = await client().delete_report(FID);
    assert.deepEqual(d, { deleted: true, report_id: FID });
    assert.equal(calls[0].init.method, "DELETE");
    mockFetch(() => json(404, { detail: "No such report for this key." }));
    const d2: any = await client().delete_report(FID);
    assert.equal(d2.deleted, false);
    assert.match(d2.error, /NOT deleted/);
    assert.equal(((await client().delete_report("nope")) as any).deleted, false);
    mockFetch(() => json(200, { ok: true }));
    const d3: any = await client().delete_report(FID);
    assert.equal(d3.deleted, "unknown", "a 2xx other than 204 is not a confirmed delete");
    mockFetch(() => json(202, {}));
    assert.equal(((await client().delete_report(FID)) as any).deleted, "unknown");
    mockFetch(() => { throw new TypeError("fetch failed"); });
    assert.equal(((await client().delete_report(FID)) as any).deleted, "unknown");
    assert.equal(calls.length, 1, "no automatic retry of a delete");
});

test("results never carry risk or detection detail", async () => {
    mockFetch(() => json(201, { feedback_id: FID, risk: "HIGH", features_triggered: ["x"], confidence: 0.9 }));
    const r = JSON.stringify(await client().send_feedback({ message: "hello there" }));
    assert.ok(!/risk|feature|confidence|HIGH/i.test(r));
});

// ---- registry and verify output ------------------------------------------------

test("tools are in the allowlist", () => {
    for (const t of ["arkheia_feedback", "arkheia_report", "arkheia_reports"]) {
        assert.equal(check(t).name, t);
        assert.equal(REGISTRY[t].network_egress, true);
    }
});

test("arkheia_verify output carries detection_id (hosted result)", async () => {
    mockFetch((url) => {
        if (url.startsWith("http://localhost")) throw new TypeError("fetch failed");
        return json(200, { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: DID });
    });
    const p = new ProxyClient("http://localhost:8098", 1.0, BASE, KEY);
    const out: any = await p.verify("p", "r", "m");
    assert.equal(out.detection_id, DID);
    assert.equal(out.source, "hosted");
});

// ---- inherited fixes ---------------------------------------------------------

test("no source file writes to stdout (the MCP protocol stream)", () => {
    const dir = path.join(__dirname, "..", "..", "src");
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ts"));
    assert.ok(files.length >= 6);
    for (const f of files) {
        const text = fs.readFileSync(path.join(dir, f), "utf8");
        assert.ok(!/console\.(log|info|debug)\b/.test(text), `${f} uses console.log/info/debug`);
        assert.ok(!/process\.stdout/.test(text), `${f} uses process.stdout`);
        assert.ok(!/=\s*console\s*;/.test(text), `${f} aliases console`);
    }
});

test("ProxyClient logging goes to stderr, not stdout", async () => {
    const out: string[] = [];
    const origOut = process.stdout.write.bind(process.stdout);
    (process.stdout as any).write = (c: any, ...rest: any[]) => { out.push(String(c)); return (origOut as any)(c, ...rest); };
    try {
        mockFetch((url) => {
            if (url.startsWith("http://localhost")) throw new TypeError("fetch failed");
            return json(200, { risk: "LOW", detection_id: DID });
        });
        await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m");
    } finally { (process.stdout as any).write = origOut; }
    assert.ok(!out.join("").includes("falling back"), "fallback notice must not be on stdout");
});

test("hosted verification refuses a redirect: key is never sent to the target", async () => {
    let targetHits = 0;
    const target = http.createServer((_q, res) => { targetHits++; res.end("{}"); });
    await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
    const tport = (target.address() as any).port;
    let sourceHits = 0;
    const source = http.createServer((_q, res) => {
        sourceHits++;
        res.writeHead(307, { Location: `http://127.0.0.1:${tport}/v1/detect` }); res.end();
    });
    await new Promise<void>((r) => source.listen(0, "127.0.0.1", r));
    const sport = (source.address() as any).port;
    try {
        // real fetch here: no mock
        const p = new ProxyClient("http://127.0.0.1:1", 2.0, `http://127.0.0.1:${sport}`, KEY);
        const out: any = await p.verify("p", "r", "m");
        assert.equal(out.risk_level, "UNKNOWN");
        assert.ok(out.error);
        assert.equal(sourceHits, 1);
        assert.equal(targetHits, 0, "the redirect target received nothing");
    } finally { source.close(); target.close(); }
});

test("hosted verify requests set redirect: error", async () => {
    mockFetch((url) => {
        if (url.startsWith("http://localhost")) throw new TypeError("fetch failed");
        return json(200, { risk: "LOW", detection_id: DID });
    });
    await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m");
    const hosted = calls.find((c) => c.url.startsWith(BASE))!;
    assert.equal(hosted.init.redirect, "error");
});

test("README does not promise automatic retry or a durable guarantee", () => {
    const readme = fs.readFileSync(path.join(__dirname, "..", "..", "README.md"), "utf8");
    assert.ok(!/you can try again/i.test(readme));
    assert.ok(!/Recorded by the Arkheia service/.test(readme));
    assert.match(readme, /unknown/);
});

test("every provider call that carries a key is built with redirect: error", async () => {
    const saved = { x: process.env.XAI_API_KEY, g: process.env.GOOGLE_API_KEY, t: process.env.TOGETHER_API_KEY };
    process.env.XAI_API_KEY = "dummy-x"; process.env.GOOGLE_API_KEY = "dummy-g"; process.env.TOGETHER_API_KEY = "dummy-t";
    try {
        mockFetch(() => json(200, {}));
        const table: [string, () => Promise<any>][] = [
            ["grok", () => call_grok("p")], ["gemini", () => call_gemini("p")],
            ["together", () => call_together("p")], ["ollama", () => call_ollama("p")],
        ];
        for (const [name, fn] of table) {
            calls = [];
            await fn();
            assert.equal(calls.length, 1, name);
            assert.equal(calls[0].init.redirect, "error", `${name} must refuse redirects`);
        }
    } finally {
        for (const [k, v] of [["XAI_API_KEY", saved.x], ["GOOGLE_API_KEY", saved.g], ["TOGETHER_API_KEY", saved.t]] as const) {
            if (v === undefined) delete process.env[k]; else process.env[k] = v;
        }
    }
});

test("a real 307 on a provider call is refused and the second server receives nothing", async () => {
    let targetHits = 0;
    const target = http.createServer((_q, res) => { targetHits++; res.end("{}"); });
    await new Promise<void>((r) => target.listen(0, "127.0.0.1", r));
    const tport = (target.address() as any).port;
    const source = http.createServer((_q, res) => { res.writeHead(307, { Location: `http://127.0.0.1:${tport}/x` }); res.end(); });
    await new Promise<void>((r) => source.listen(0, "127.0.0.1", r));
    const sport = (source.address() as any).port;
    const prevKey = process.env.XAI_API_KEY;
    process.env.XAI_API_KEY = "dummy-x";
    // Send the real provider call to the loopback source, keeping every option the code set (including redirect).
    (globalThis as any).fetch = (_u: any, init: any) => realFetch(`http://127.0.0.1:${sport}/v1/chat/completions`, init);
    try {
        const r: any = await call_grok("p");
        assert.ok(r.error, "the redirected call failed");
        assert.equal(targetHits, 0, "the redirect target received nothing, so no Authorization header");
    } finally {
        if (prevKey === undefined) delete process.env.XAI_API_KEY; else process.env.XAI_API_KEY = prevKey;
        source.close(); target.close();
    }
});

// ---- round 2 -----------------------------------------------------------------

test("retry hint names every original argument (names, not values) and the same submission_id", async () => {
    mockFetch(() => json(500, {}));
    const r: any = await client().send_feedback({ message: "private words here", kind: "bug", email: "a@b.co" });
    assert.deepEqual(r.repeat_arguments, ["message", "kind", "email"]);
    assert.match(r.error, /EVERY original argument \(message, kind, email\)/);
    assert.ok(r.error.includes(r.submission_id));
    assert.ok(!r.error.includes("private words here") && !r.error.includes("a@b.co"), "values are not echoed");
    const r2: any = await client().send_feedback({ message: "private words here" });
    assert.deepEqual(r2.repeat_arguments, ["message"]);
});

test("feedback 409 is a conflict on an existing submission, worded apart from a first-time refusal", async () => {
    mockFetch(() => json(409, { detail: { status: "conflict" } }));
    const r: any = await client().send_feedback({ message: "hello there", kind: "bug" });
    assert.equal(r.recorded, false);
    assert.equal(r.conflict, true);
    assert.match(r.error, /already exists with different content/);
    assert.ok(!/NOT recorded/.test(r.error));
    assert.ok(r.submission_id);
    mockFetch(() => json(400, {}));
    const first: any = await client().send_feedback({ message: "hello there" });
    assert.equal(first.conflict, undefined);
    assert.match(first.error, /NOT recorded/);
});

test("only exactly 201 with a UUID id is recorded:true", async () => {
    for (const [status, id] of [[201, FID], [201, "not-a-uuid"], [202, FID], [200, FID], [204, FID]] as const) {
        mockFetch((u) => json(status as number, u.includes("/report") ? { report_id: id, status: "recorded" } : { feedback_id: id, status: "received" }));
        const f: any = await client().send_feedback({ message: "hello there" });
        const r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
        const ok = status === 201 && id === FID;
        assert.equal(f.recorded, ok ? true : "unknown", `${status} ${id}`);
        assert.equal(r.recorded, ok ? true : "unknown", `${status} ${id}`);
    }
});

test("phase: 401 whose body cannot be read is still reported as the 401 refusal", async () => {
    const resp = { ok: false, status: 401, text: async () => { throw new TypeError("terminated"); }, body: null };
    mockFetch(() => resp as any);
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    assert.match(r.error, /HTTP 401/);
    assert.equal(calls.length, 1);
});

test("phase: 201 headers then a body error with a connection-refused code is unknown, one request, no replay", async () => {
    const bodyErr = Object.assign(new TypeError("terminated"), { cause: { code: "ECONNREFUSED" } });
    const resp = { ok: true, status: 201, text: async () => { throw bodyErr; } };
    mockFetch(() => resp as any);
    for (const run of [
        () => client().send_feedback({ message: "hello there" }),
        () => client().send_report({ detection_id: DID, outcome: "fine" }),
    ]) {
        calls = [];
        const r: any = await run();
        assert.equal(r.recorded, "unknown");
        assert.equal(calls.length, 1, "exactly one request");
    }
});

test("phase: a connection-refused failure before any headers is the only retryable case", async () => {
    mockFetch(refusedConn);
    const r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.equal(r.recorded, false);
    assert.equal(calls.length, 2);
});

test("reports list: every row is validated against the public shape", async () => {
    const good = { report_id: FID, event_id: DID, outcome: "fine", category: null, evidence: null, reporter_kind: "human", created_at: "2026-01-01T00:00:00Z" };
    mockFetch(() => json(200, { reports: [good] }));
    assert.equal(((await client().list_reports()) as any).reports.length, 1);
    const bad: any[] = [
        null, "x", { ...good, report_id: { nested: 1 } }, { ...good, report_id: "nope" }, { ...good, event_id: "../x" },
        { ...good, outcome: "maybe" }, { ...good, reporter_kind: "bot" }, { ...good, category: "bogus" },
        { ...good, evidence: 5 }, { ...good, evidence: "e".repeat(501) },
    ];
    for (const row of bad) {
        mockFetch(() => json(200, { reports: [good, row] }));
        const l: any = await client().list_reports();
        assert.equal(l.reports, undefined, JSON.stringify(row));
        assert.equal(l.recorded, false);
        assert.match(l.error, /could not be fetched|not in the expected shape/);
    }
    mockFetch(() => json(201, { reports: [good] }));
    assert.equal(((await client().list_reports()) as any).reports, undefined, "list needs exactly 200");
});

test("every request with a JSON body sets Content-Type: application/json", async () => {
    const saved = { x: process.env.XAI_API_KEY, g: process.env.GOOGLE_API_KEY, t: process.env.TOGETHER_API_KEY };
    process.env.XAI_API_KEY = "dummy-x"; process.env.GOOGLE_API_KEY = "dummy-g"; process.env.TOGETHER_API_KEY = "dummy-t";
    const ctype = (init: any) => Object.entries(init.headers ?? {}).find(([k]) => k.toLowerCase() === "content-type")?.[1];
    try {
        mockFetch((url) => url.includes("localhost:8098") ? (() => { throw new TypeError("fetch failed"); })() : json(201, { feedback_id: FID, report_id: FID, risk: "LOW" }));
        const table: [string, () => Promise<any>][] = [
            ["feedback", () => client().send_feedback({ message: "hello there" })],
            ["report", () => client().send_report({ detection_id: DID, outcome: "fine" })],
            ["verify hosted (and local)", () => new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m")],
            ["grok", () => call_grok("p")], ["gemini", () => call_gemini("p")],
            ["together", () => call_together("p")], ["ollama", () => call_ollama("p")],
        ];
        for (const [name, fn] of table) {
            calls = [];
            await fn();
            const withBody = calls.filter((c) => c.init.body !== undefined);
            assert.ok(withBody.length >= 1, name);
            for (const c of withBody) assert.equal(ctype(c.init), "application/json", `${name}: ${c.url}`);
        }
        // local proxy verify path alone
        calls = [];
        mockFetch(() => json(200, { risk_level: "LOW", confidence: 0, features_triggered: [] }));
        await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m");
        assert.equal(ctype(calls[0].init), "application/json");
        // requests without a body (list, delete, audit log) carry none
        calls = [];
        mockFetch(() => json(200, { events: [], summary: {} }));
        await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).get_audit_log();
        assert.equal(calls[0].init.body, undefined);
    } finally {
        for (const [k, v] of [["XAI_API_KEY", saved.x], ["GOOGLE_API_KEY", saved.g], ["TOGETHER_API_KEY", saved.t]] as const) {
            if (v === undefined) delete process.env[k]; else process.env[k] = v;
        }
    }
});

test("no source or test file carries an internal reference (this file included)", () => {
    const root = path.join(__dirname, "..", "..");
    // Built from parts so this file's own text does not match what it forbids.
    const banned = new RegExp([
        "#\\d{3}", "\\bB-\\d+", "\\bB\\d{3}\\b", "\\bCod" + "ex\\b", "\\bDav" + "id\\b", "proxy" + " #",
    ].join("|"));
    let scanned = 0;
    for (const dir of ["src", "test"]) {
        for (const f of fs.readdirSync(path.join(root, dir))) {
            const full = path.join(root, dir, f);
            if (!fs.statSync(full).isFile()) continue;
            scanned++;
            assert.ok(!banned.test(fs.readFileSync(full, "utf8")), `${full} has an internal reference`);
        }
    }
    assert.ok(fs.readdirSync(path.join(root, "test")).includes("feedback.test.ts"));
    assert.ok(scanned >= 9);
    assert.ok(banned.test("see #" + "123") && banned.test("B-" + "42"), "the pattern still matches what it should");
});

// ---- round 3 -----------------------------------------------------------------

test("404 on a report points to arkheia_feedback, not to re-verifying", async () => {
    mockFetch(() => json(404, { detail: "x" }));
    const r: any = await client().send_report({ detection_id: DID, outcome: "wrong" });
    assert.match(r.error, /checked by a local proxy cannot be linked to a hosted record/);
    assert.match(r.error, /arkheia_feedback \(kind false_alarm or missed_problem\)/);
    assert.ok(!/verify (it )?again|re-?verif/i.test(r.error));
});

test("verify result says whether it is reportable: hosted yes, local no, no check no", async () => {
    // hosted
    mockFetch((url) => {
        if (url.startsWith("http://localhost")) throw new TypeError("fetch failed");
        return json(200, { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: DID });
    });
    let out: any = withReportability(await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m"));
    assert.equal(out.reportable, true);
    assert.equal(out.report_with, "arkheia_report");
    assert.equal(out.detection_id, DID);
    assert.equal(out.report_note, undefined);
    // local proxy answered (its id is not a hosted id)
    mockFetch(() => json(200, { risk_level: "LOW", confidence: 0, features_triggered: [], detection_id: "local-abc" }));
    out = withReportability(await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m"));
    assert.equal(out.reportable, false);
    assert.equal(out.report_with, undefined);
    assert.match(out.report_note, /checked locally and cannot be linked to a hosted record/);
    assert.match(out.report_note, /arkheia_feedback/);
    // nothing checked
    mockFetch(() => { throw new TypeError("fetch failed"); });
    out = withReportability(await new ProxyClient("http://localhost:8098", 1.0, BASE, KEY).verify("p", "r", "m"));
    assert.equal(out.reportable, false);
    assert.match(out.report_note, /nothing to report/);
});

test("lengths count code points: 500 supplementary characters pass, 501 code points are refused", async () => {
    const astral = (n: number) => "\u{1F600}".repeat(n);
    assert.equal(astral(251).length, 502);
    const r = z.object(reportShape);
    assert.ok(r.safeParse({ detection_id: DID, outcome: "fine", evidence: astral(500) }).success);
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "fine", evidence: astral(501) }).success);
    assert.ok(!r.safeParse({ detection_id: DID, outcome: "fine", evidence: "e".repeat(501) }).success);
    const f = z.object(feedbackShape);
    assert.ok(f.safeParse({ message: astral(2000) }).success);
    assert.ok(!f.safeParse({ message: astral(2001) }).success);
    assert.ok(f.safeParse({ message: astral(5) }).success);
    assert.ok(!f.safeParse({ message: astral(4) }).success);
    // the client enforces the same count
    mockFetch((u) => json(201, ackFor(u)));
    assert.equal(((await client().send_report({ detection_id: DID, outcome: "fine", evidence: astral(500) })) as any).recorded, true);
    assert.equal(((await client().send_report({ detection_id: DID, outcome: "fine", evidence: astral(501) })) as any).recorded, false);
    assert.equal(((await client().send_feedback({ message: astral(2000) })) as any).recorded, true);
    assert.equal(((await client().send_feedback({ message: astral(2001) })) as any).recorded, false);
    assert.equal(((await client().send_feedback({ message: astral(4) })) as any).recorded, false);
    // list readback: 251 supplementary characters (502 UTF-16 units) is valid
    const row = { report_id: FID, event_id: DID, outcome: "wrong", category: null, evidence: astral(251), reporter_kind: "agent", created_at: null };
    mockFetch(() => json(200, { reports: [row] }));
    assert.equal(((await client().list_reports()) as any).reports.length, 1);
    mockFetch(() => json(200, { reports: [{ ...row, evidence: astral(501) }] }));
    assert.equal(((await client().list_reports()) as any).reports, undefined);
});

test("created_at must be an ISO datetime or null", async () => {
    const row = { report_id: FID, event_id: DID, outcome: "fine", category: null, evidence: null, reporter_kind: "human" };
    for (const [value, ok] of [["2026-11-12T17:40:00Z", true], ["2026-11-12T17:40:00.123456", true], ["2026-11-12T17:40:00+01:00", true], [null, true],
        ["t", false], ["yesterday", false], ["2026-13-45T99:00:00Z", false], [20260101, false]] as const) {
        mockFetch(() => json(200, { reports: [{ ...row, created_at: value }] }));
        const l: any = await client().list_reports();
        assert.equal(l.reports !== undefined, ok, String(value));
    }
});

test("contradictory acknowledgements are unknown; consistent ones are recorded", async () => {
    const run = async (fbBody: any, rpBody: any) => [
        (await client().send_feedback({ message: "hello there" })) as any,
        (await client().send_report({ detection_id: DID, outcome: "fine" })) as any,
    ].map((x, i) => ({ x, body: i ? rpBody : fbBody }));
    // pending / wrong status
    mockFetch((u) => json(201, u.includes("/report") ? { report_id: FID, status: "pending" } : { feedback_id: FID, status: "pending" }));
    for (const { x } of await run(0, 0)) assert.equal(x.recorded, "unknown");
    // status absent: both contracts always send it, so absence is not accepted
    mockFetch((u) => json(201, u.includes("/report") ? { report_id: FID } : { feedback_id: FID }));
    for (const { x } of await run(0, 0)) assert.equal(x.recorded, "unknown");
    // the other endpoint's status is wrong for this one
    mockFetch((u) => json(201, u.includes("/report") ? { report_id: FID, status: "received" } : { feedback_id: FID, status: "recorded" }));
    for (const { x } of await run(0, 0)) assert.equal(x.recorded, "unknown");
    // echoed submission_id that is not the caller's
    mockFetch(() => json(201, { feedback_id: FID, status: "received", submission_id: "99999999-9999-9999-9999-999999999999" }));
    const bad: any = await client().send_feedback({ message: "hello there" });
    assert.equal(bad.recorded, "unknown");
    assert.ok(bad.submission_id, "the caller's own id is returned for the retry");
    // echoed id equal to the caller's (any case) is accepted; absent echo is accepted
    const sid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    mockFetch(() => json(201, { feedback_id: FID, status: "received", submission_id: sid.toUpperCase() }));
    assert.equal(((await client().send_feedback({ message: "hello there", submission_id: sid })) as any).recorded, true);
    mockFetch((u) => json(201, ackFor(u)));
    assert.equal(((await client().send_feedback({ message: "hello there" })) as any).recorded, true);
    assert.equal(((await client().send_report({ detection_id: DID, outcome: "fine" })) as any).recorded, true);
});

test("a known refusal survives a cancellation that never finishes", async () => {
    const resp = { ok: false, status: 401, body: { cancel: () => new Promise<void>(() => { /* never */ }) } };
    mockFetch(() => resp as any);
    const t0 = Date.now();
    const r: any = await new FeedbackClient(BASE, KEY, 300).send_feedback({ message: "hello there" });
    assert.ok(Date.now() - t0 < 250, "returned at once, not at the deadline");
    assert.equal(r.recorded, false);
    assert.match(r.error, /HTTP 401/);
    assert.equal(calls.length, 1);
    // a cancellation that rejects is also harmless
    mockFetch(() => ({ ok: false, status: 429, body: { cancel: () => Promise.reject(new Error("x")) } }) as any);
    assert.match(((await client().send_feedback({ message: "hello there" })) as any).error, /HTTP 429/);
});

test("engines.node is >=20 and the README says Node 20+", () => {
    const root = path.join(__dirname, "..", "..");
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.equal(pkg.engines.node, ">=20.0.0");
    assert.match(fs.readFileSync(path.join(root, "README.md"), "utf8"), /Node 20\+/);
});

// ---- round 4 -----------------------------------------------------------------

test("local-only verify never contacts the hosted service", async () => {
    mockFetch((url) => { if (url.startsWith("http://localhost")) throw new TypeError("fetch failed"); return json(200, { risk: "LOW", detection_id: DID }); });
    const p = new ProxyClient("http://localhost:8098", 1.0, BASE, KEY);
    const r: any = await p.verify("p", "r", "m", undefined, { allowHosted: false });
    assert.equal(r.risk_level, "UNKNOWN");
    assert.ok(r.error);
    assert.ok(calls.every((c) => c.url.startsWith("http://localhost")), "only the local verifier was contacted");
    // it does not flip the shared flag: the ordinary path still tries local first, then hosted
    calls = [];
    const h: any = await p.verify("p", "r", "m");
    assert.equal(h.source, "hosted");
});

test("provider errors and unidentifiable hosted results carry the right reportability", () => {
    const err: any = withReportability({ risk_level: "UNKNOWN", error: "XAI_API_KEY not set" });
    assert.equal(err.reportable, false);
    assert.match(err.report_note, /nothing to report/);
    const noId: any = withReportability({ risk_level: "LOW", source: "hosted" });
    assert.equal(noId.reportable, false);
    assert.match(noId.report_note, /no usable detection id/);
    assert.ok(!/checked locally/.test(noId.report_note));
    const badId: any = withReportability({ risk_level: "LOW", source: "hosted", detection_id: "../x" });
    assert.match(badId.report_note, /no usable detection id/);
});

test("report-conflict advice does not promise the earlier report is in the list", async () => {
    mockFetch(() => json(409, {}));
    const r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.match(r.error, /most recent reports/);
    assert.match(r.error, /may not appear/);
    assert.ok(!/See it with/.test(r.error));
});

test("created_at must be a real calendar datetime or explicit null; missing is invalid", async () => {
    const row: any = { report_id: FID, event_id: DID, outcome: "fine", category: null, evidence: null, reporter_kind: "human" };
    const cases: [any, boolean][] = [
        ["2024-02-29T10:00:00Z", true], ["2025-02-29T10:00:00Z", false], ["2026-02-30T10:00:00Z", false],
        ["2026-04-31T00:00:00Z", false], ["2026-06-15T24:00:00Z", false], ["2026-06-15T23:59:59Z", true],
        ["2026-06-15T10:00:00+25:00", false], [null, true],
    ];
    for (const [v, ok] of cases) {
        mockFetch(() => json(200, { reports: [{ ...row, created_at: v }] }));
        assert.equal(((await client().list_reports()) as any).reports !== undefined, ok, String(v));
    }
    mockFetch(() => json(200, { reports: [row] }));
    assert.equal(((await client().list_reports()) as any).reports, undefined, "a missing created_at is invalid");
});

test("root README points to the npm package, says Node 20+ and describes the Python server accurately", () => {
    const readme = fs.readFileSync(path.join(__dirname, "..", "..", "..", "README.md"), "utf8");
    assert.match(readme, /npm install -g @arkheia\/mcp-server/);
    assert.match(readme, /Node\.js 20\+/);
    assert.ok(!/Node\.js 18/.test(readme));
    assert.match(readme, /npm-wrapper\/README\.md/);
    assert.match(readme, /does \*\*not\*\* include `arkheia_feedback`/);
    assert.ok(!/"args": \["-m", "mcp_server\.server"\]/.test(readme), "no Python registration snippet as the main route");
});

// ---- round 5 -----------------------------------------------------------------

test("a key pasted into any string that reaches a URL (or the body id) is refused locally, with zero transport calls", async () => {
    mockFetch((u) => json(201, ackFor(u)));
    const keyShaped = ["ak_live_" + "A".repeat(24), "ak_test_" + "b1".repeat(12), KEY, "sk-" + "a".repeat(30)];
    for (const k of keyShaped) {
        const r: any = await client().send_report({ detection_id: k, outcome: "wrong" });
        assert.equal(r.recorded, false, k);
        assert.ok(!r.error.includes(k), "the error does not repeat the input");
        const d: any = await client().delete_report(k);
        assert.equal(d.deleted, false);
        assert.ok(!d.error.includes(k));
        const f: any = await client().send_feedback({ message: "hello there", submission_id: k });
        assert.equal(f.recorded, false);
        assert.ok(!JSON.stringify(f).includes(k));
    }
    assert.equal(calls.length, 0, "no request was made");
    // the error for a key-shaped id is its own fixed message
    const r: any = await client().send_report({ detection_id: KEY, outcome: "wrong" });
    assert.match(r.error, /looks like an API key or token, not a detection id/);
    // ordinary ids still work
    assert.equal(((await client().send_report({ detection_id: DID, outcome: "wrong" })) as any).recorded, true);
    mockFetch(() => new Response(null, { status: 204 }));
    assert.equal(((await client().delete_report(FID)) as any).deleted, true);
    mockFetch((u) => json(201, ackFor(u)));
    assert.equal(((await client().send_feedback({ message: "hello there", submission_id: FID })) as any).recorded, true);
});

test("the client rejects values outside the closed lists without sending", async () => {
    mockFetch((u) => json(201, ackFor(u)));
    assert.equal(((await client().send_feedback({ message: "hello there", kind: "ak_live_" + "A".repeat(24) })) as any).recorded, false);
    assert.equal(((await client().send_report({ detection_id: DID, outcome: "wrong", category: "nope" })) as any).recorded, false);
    assert.equal(calls.length, 0);
});

test("list rows must carry evidence and category (possibly null); years 0001-0099 are valid dates", async () => {
    const base: any = { report_id: FID, event_id: DID, outcome: "fine", reporter_kind: "human", created_at: null };
    const run = async (row: any) => ((await client().list_reports()) as any).reports !== undefined;
    for (const [row, ok] of [
        [{ ...base, evidence: null, category: null }, true],
        [{ ...base, category: null }, false],
        [{ ...base, evidence: null }, false],
        [{ ...base }, false],
    ] as const) {
        mockFetch(() => json(200, { reports: [row] }));
        assert.equal(await run(row), ok, JSON.stringify(Object.keys(row)));
    }
    const full = { ...base, evidence: null, category: null };
    for (const [value, ok] of [["0001-01-01T00:00:00Z", true], ["0099-12-31T23:59:59Z", true], ["0004-02-29T00:00:00Z", true],
        ["0100-02-29T00:00:00Z", false], ["0000-01-01T00:00:00Z", false], ["1900-02-29T00:00:00Z", false], ["2000-02-29T00:00:00Z", true]] as const) {
        mockFetch(() => json(200, { reports: [{ ...full, created_at: value }] }));
        assert.equal(await run(full), ok, value);
    }
});

test("AGENTS.md points to the npm instructions and names the feedback tools; the root README needs no Python for npm", () => {
    const root = path.join(__dirname, "..", "..", "..");
    const agents = fs.readFileSync(path.join(root, "AGENTS.md"), "utf8");
    assert.ok(!/single source of truth/i.test(agents));
    assert.match(agents, /npm install -g @arkheia\/mcp-server/);
    for (const t of ["arkheia_feedback", "arkheia_report", "arkheia_reports"]) assert.ok(agents.includes(t), t);
    const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
    assert.ok(!/Python 3\.10-3\.13/.test(readme));
    assert.match(readme, /needs no Python/);
    assert.match(readme, /press Confirm/);
    assert.match(readme, /arkheia_feedback/);
});
