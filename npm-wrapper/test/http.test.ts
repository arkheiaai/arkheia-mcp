import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'http';
import { AddressInfo } from 'net';
import { ProxyClient } from '../src/proxy-client.js';
import { call_grok, call_gemini, call_together, call_ollama } from '../src/providers.js';

type Seen = { url: string; init: any };
const realFetch = globalThis.fetch;
function stubFetch(seen: Seen[]) {
    (globalThis as any).fetch = async (url: any, init: any = {}) => {
        seen.push({ url: String(url), init });
        const u = String(url);
        if (u.startsWith("http://localhost:1")) throw new TypeError("fetch failed");
        const body = u.endsWith("/v1/detect") ? { risk: "LOW", confidence: 0.1, features_triggered: [], detection_id: "det_x" }
            : u.includes("generateContent") ? { candidates: [{ content: { parts: [{ text: "ok" }] } }] }
            : u.includes("/api/generate") ? { response: "ok" }
            : { choices: [{ message: { content: "ok" } }] };
        return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    };
}
const ctype = (init: any) => new Headers(init.headers || {}).get("content-type");

test("every call that sends a JSON body sends the JSON content type", async () => {
    const seen: Seen[] = [];
    stubFetch(seen);
    process.env.XAI_API_KEY = "k"; process.env.GEMINI_API_KEY = "k"; process.env.GOOGLE_API_KEY = "k"; process.env.TOGETHER_API_KEY = "k";
    process.env.OLLAMA_BASE_URL = "http://ollama.example.test";
    try {
        const c = new ProxyClient("http://localhost:1", 2, "https://hosted.example.test", "ak_test");
        await c.verify("p", "r", "m");           // local /detect/verify, then hosted /v1/detect
        await call_grok("p"); await call_gemini("p"); await call_together("p"); await call_ollama("p");
    } finally { (globalThis as any).fetch = realFetch; }
    const withBody = seen.filter((s) => s.init.body !== undefined);
    assert.equal(withBody.length, 6, "local verify, hosted verify, grok, gemini, together, ollama");
    for (const s of withBody) assert.equal(ctype(s.init), "application/json", `Content-Type on ${s.url.replace(/\?.*/, "")}`);
});

test("every call that carries a key refuses redirects", async () => {
    const seen: Seen[] = [];
    stubFetch(seen);
    process.env.XAI_API_KEY = "k"; process.env.GEMINI_API_KEY = "k"; process.env.GOOGLE_API_KEY = "k"; process.env.TOGETHER_API_KEY = "k";
    process.env.OLLAMA_BASE_URL = "http://ollama.example.test";
    try {
        const c = new ProxyClient("http://localhost:1", 2, "https://hosted.example.test", "ak_test");
        await c.verify("p", "r", "m");
        await call_grok("p"); await call_gemini("p"); await call_together("p"); await call_ollama("p");
    } finally { (globalThis as any).fetch = realFetch; }
    const hosted = seen.filter((s) => s.url.endsWith("/v1/detect"));
    const providers = seen.filter((s) => /x\.ai|generativelanguage|together|ollama\.example/.test(s.url));
    assert.equal(hosted.length, 1);
    assert.equal(providers.length, 4);
    for (const s of [...hosted, ...providers]) assert.equal(s.init.redirect, "error", `redirect policy on ${s.url.replace(/\?.*/, "")}`);
});

function listen(handler: http.RequestListener): Promise<http.Server> {
    return new Promise((res) => { const s = http.createServer(handler); s.listen(0, "127.0.0.1", () => res(s)); });
}
const port = (s: http.Server) => (s.address() as AddressInfo).port;

test("a real 307 redirect does not carry the key: the second server receives nothing", async () => {
    let received = 0;
    const target = await listen((req, res) => { received++; req.resume(); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
    const redirector = await listen((req, res) => {
        req.resume();
        res.writeHead(307, { location: `http://127.0.0.1:${port(target)}/v1/detect` });
        res.end();
    });
    const hostedUrl = `http://127.0.0.1:${port(redirector)}`;
    process.env.OLLAMA_BASE_URL = hostedUrl;
    try {
        const c = new ProxyClient("http://127.0.0.1:1", 3, hostedUrl, "ak_test_dummy");
        const r = await c.verify("p", "r", "m");
        assert.equal(r.risk_level, "UNKNOWN");
        const o = await call_ollama("p");
        assert.ok(o.error, "the redirected provider call fails");
        assert.equal(received, 0, "the redirect target received no request");
    } finally {
        redirector.close(); target.close();
    }
});

test("the Ollama tool call site asks for local-only verification", () => {
    const src = require("fs").readFileSync(require("path").join(__dirname, "..", "..", "src", "index.ts"), "utf8");
    const m = src.match(/"run_ollama",[\s\S]*?handleError\("run_ollama"/);
    assert.ok(m, "found the run_ollama handler");
    assert.match(m[0], /proxy\.verify\([^)]*\{ allowHosted: false \}\)/);
    for (const other of ["run_grok", "run_gemini", "run_together"]) {
        const o = src.match(new RegExp(`"${other}",[\\s\\S]*?handleError\\("${other}"`));
        assert.doesNotMatch(o![0], /allowHosted/);
    }
});

test("ProxyClient.verify with allowHosted false never contacts the hosted URL", async () => {
    const seen: string[] = [];
    (globalThis as any).fetch = async (url: any) => { seen.push(String(url)); throw new TypeError("fetch failed"); };
    try {
        const c = new ProxyClient("http://localhost:1", 2, "https://hosted.example.test", "ak_test");
        const r = await c.verify("p", "r", "m", undefined, { allowHosted: false });
        assert.equal(r.error, "not_checked_local_verification_unavailable");
        assert.equal(r.risk_level, "UNKNOWN");
        assert.deepEqual(seen, ["http://localhost:1/detect/verify"]);
    } finally { (globalThis as any).fetch = realFetch; }
});
