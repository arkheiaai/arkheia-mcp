import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { z } from 'zod';
import {
    FeedbackClient, feedbackShape, reportShape, reportsShape, looksLikeCredential,
} from '../src/feedback.js';
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

// ---- success ---------------------------------------------------------------

test("feedback: success returns the server id; current and #230-style replies both work", async () => {
    for (const reply of [
        { feedback_id: FID, status: "received", message: "Thank you for your feedback. We read every message." },
        { feedback_id: FID, submission_id: "x", status: "received", message: "Your feedback was saved." },
    ]) {
        mockFetch(() => json(201, reply));
        const r: any = await client().send_feedback({ message: "The check flagged a correct answer.", kind: "false_alarm" });
        assert.equal(r.recorded, true);
        assert.equal(r.feedback_id, FID);
        assert.deepEqual(Object.keys(r).sort(), ["feedback_id", "note", "recorded"]);
    }
});

test("feedback: request body has exactly the expected fields, key only in header", async () => {
    mockFetch(() => json(201, { feedback_id: FID }));
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
    mockFetch(() => json(201, { feedback_id: FID }));
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
    mockFetch(() => json(201, { report_id: FID }));
    await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.deepEqual(JSON.parse(calls[0].init.body), { outcome: "fine", reporter_kind: "agent" });
});

// ---- failures --------------------------------------------------------------

const failures: [string, () => Response | Promise<Response>][] = [
    ["400", () => json(400, { detail: "Feedback message too short" })],
    ["401", () => json(401, { detail: "bad key" })],
    ["429", () => json(429, { detail: "slow down" })],
    ["500", () => json(500, { detail: "boom" })],
    ["503 (#230 shape)", () => json(503, { detail: { feedback_id: FID, status: "unavailable", code: "feedback_unavailable", message: "Retry." } }, { "Retry-After": "30" })],
    ["409 (#230 shape)", () => json(409, { detail: { status: "conflict", message: "used" } })],
    ["malformed json", () => new Response("<html>", { status: 201 })],
    ["201 without id", () => json(201, { status: "received" })],
    ["201 with empty id", () => json(201, { feedback_id: "" })],
    ["201 with non-string id", () => json(201, { feedback_id: 5 })],
];
for (const [name, h] of failures) {
    test(`feedback: ${name} -> NOT recorded, never success`, async () => {
        mockFetch(h);
        const r: any = await client().send_feedback({ message: "hello there" });
        assert.equal(r.recorded, false);
        assert.match(r.error, /NOT recorded/);
        assert.equal(r.feedback_id, undefined);
        assert.ok(!/thank/i.test(r.error));
        assert.equal(calls.length, 1, "no automatic retry on an HTTP answer");
    });
    test(`report: ${name} -> NOT recorded, never success`, async () => {
        mockFetch(h);
        const r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
        assert.equal(r.recorded, false);
        assert.match(r.error, /NOT recorded/);
        assert.equal(r.report_id, undefined);
    });
}

test("network error: one retry with the same body, then NOT recorded", async () => {
    mockFetch(() => { throw new TypeError("fetch failed"); });
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    assert.equal(r.retryable, true);
    assert.match(r.error, /NOT recorded/);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init.body, calls[1].init.body);
});

test("network error then success on the retry is recorded", async () => {
    mockFetch((_u, _i, n) => { if (n === 1) throw new TypeError("fetch failed"); return json(201, { feedback_id: FID }); });
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, true);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].init.body, calls[1].init.body);
});

test("timeout: aborts, retries once, then NOT recorded", async () => {
    mockFetch((_u, init) => new Promise((_res, rej) => {
        init.signal.addEventListener("abort", () => { const e: any = new Error("aborted"); e.name = "AbortError"; rej(e); });
    }));
    const r: any = await client().send_feedback({ message: "hello there" });
    assert.equal(r.recorded, false);
    assert.match(r.error, /did not answer in time/);
    assert.equal(calls.length, 2);
});

test("4xx is never retried", async () => {
    mockFetch(() => json(422, { detail: [{ msg: "x" }] }));
    await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.equal(calls.length, 1);
});

test("report 404 and 409 give specific not-recorded messages", async () => {
    mockFetch(() => json(404, { detail: "No detection with that id for this key." }));
    let r: any = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.match(r.error, /NOT recorded.*no detection with that id/);
    mockFetch(() => json(409, { detail: "Already reported." }));
    r = await client().send_report({ detection_id: DID, outcome: "fine" });
    assert.match(r.error, /NOT recorded.*already has a report/);
});

test("no key or non-https URL: nothing is sent", async () => {
    mockFetch(() => json(201, { feedback_id: FID }));
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
    mockFetch(() => json(201, { feedback_id: FID, report_id: FID }));
    const c = client();
    assert.equal(((await c.send_feedback({ message: "   a   " })) as any).recorded, false);
    assert.equal(((await c.send_feedback({ message: "a".repeat(2001) })) as any).recorded, false);
    assert.equal(((await c.send_feedback({ message: "hello there", email: "not-an-email" })) as any).recorded, false);
    assert.equal(((await c.send_report({ detection_id: DID, outcome: "fine", evidence: "a\nb" })) as any).recorded, false);
    assert.equal(((await c.send_report({ detection_id: "a/b", outcome: "fine" })) as any).recorded, false);
    assert.equal(calls.length, 0);
});

test("credential-shaped text is refused and never sent or echoed", async () => {
    mockFetch(() => json(201, { feedback_id: FID, report_id: FID }));
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
    mockFetch(() => json(200, { reports: [{ report_id: FID, event_id: DID, outcome: "wrong", category: null, evidence: "e", reporter_kind: "agent", created_at: "t", extra_internal: "x" }] }));
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
