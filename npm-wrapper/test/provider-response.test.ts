import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import * as http from 'http';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { ProxyClient } from '../src/proxy-client.js';
import { checkProviderResponse, MAX_PROVIDER_RESPONSE_BYTES } from '../src/provider-response.js';

const realFetch = globalThis.fetch;
afterEach(() => { (globalThis as any).fetch = realFetch; });

const REPLY = { id: "chatcmpl-x", choices: [{ message: { role: "assistant", content: "hi" }, finish_reason: "stop", extra: { n: [1, 2, { z: null }] } }], usage: { total_tokens: 3 } };
const HOSTED_OK = { risk: "LOW", assessed: true, evidence_depth_limited: false, confidence: 0.1, detection_id: "det_0123456789abcdef" };

function hostedFetch(bodies: any[]) {
    (globalThis as any).fetch = async (url: any, init: any) => {
        if (String(url).startsWith("http://localhost")) throw new TypeError("fetch failed");
        bodies.push(JSON.parse(init.body));
        return new Response(JSON.stringify(HOSTED_OK), { status: 200, headers: { "content-type": "application/json" } });
    };
}
const client = () => new ProxyClient("http://localhost:8098", 1.0, "https://api.example.test", "ak_live_TESTKEYTESTKEY1234");

test("provider_response is forwarded unchanged in the hosted request body", async () => {
    const bodies: any[] = [];
    hostedFetch(bodies);
    await client().verify("p", "r", "m", undefined, { provider_response: REPLY });
    assert.deepEqual(bodies[0].provider_response, REPLY);
    assert.deepEqual(Object.keys(bodies[0]).sort(), ["model", "prompt", "provider_response", "response"]);
});

test("verify without provider_response sends exactly the earlier body", async () => {
    const bodies: any[] = [];
    hostedFetch(bodies);
    await client().verify("p", "r", "m");
    assert.deepEqual(bodies[0], { model: "m", response: "r", prompt: "p" });
});

test("a JSON string is parsed to an object; anything else is rejected", () => {
    const ok = checkProviderResponse(JSON.stringify(REPLY));
    assert.deepEqual(ok, { ok: true, value: REPLY });
    assert.deepEqual(checkProviderResponse(REPLY), { ok: true, value: REPLY });
    assert.deepEqual(checkProviderResponse(undefined), { ok: true, value: undefined });
    for (const bad of [42, true, [1, 2], "not json", "[1,2]", "42", '"str"', "null"]) {
        const r = checkProviderResponse(bad);
        assert.equal(r.ok, false, String(bad));
    }
});

test("an oversize provider_response is rejected, as object or string", () => {
    const big = { blob: "x".repeat(MAX_PROVIDER_RESPONSE_BYTES + 10) };
    const a = checkProviderResponse(big);
    assert.equal(a.ok, false);
    assert.match((a as any).error, /too large/);
    assert.equal(checkProviderResponse(JSON.stringify(big)).ok, false);
});

// ---- real stdio child against a local stand-in for the hosted service ----
async function withHosted<T>(fn: (client: Client, seen: any[], logs: () => string) => Promise<T>): Promise<T> {
    const seen: any[] = [];
    const srv = http.createServer((req, res) => {
        let b = ""; req.on("data", (c) => (b += c));
        req.on("end", () => { try { seen.push(JSON.parse(b)); } catch { seen.push(null); } res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify(HOSTED_OK)); });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as any).port;
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-pr-"));
    const transport = new StdioClientTransport({
        command: process.execPath, args: [path.join(root, "dist", "index.js")], stderr: "pipe",
        env: { PATH: process.env.PATH || "", HOME: home, ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00", ARKHEIA_HOSTED_URL: `http://127.0.0.1:${port}`, ARKHEIA_PROXY_URL: "http://127.0.0.1:1" },
    });
    let err = "";
    transport.stderr?.on("data", (d) => (err += d));
    const c = new Client({ name: "pr-test", version: "0" });
    try { await c.connect(transport); return await fn(c, seen, () => err); }
    finally { await c.close(); srv.close(); fs.rmSync(home, { recursive: true, force: true }); }
}

test("through the tool: forwarded, never echoed or logged; bad input gets a plain error and no request", async () => {
    const marker = "SENTINEL-" + "q7".repeat(8);
    const reply = { ...REPLY, note: marker };
    await withHosted(async (c, seen, logs) => {
        const call = async (args: any): Promise<any> => JSON.parse(((await c.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m", ...args } })) as any).content[0].text);
        const o1 = await call({ provider_response: reply });
        assert.equal(o1.risk_level, "LOW");
        assert.deepEqual(seen[0].provider_response, reply);
        const o2 = await call({ provider_response: JSON.stringify(reply) });
        assert.deepEqual(seen[1].provider_response, reply);
        const bad = await call({ provider_response: "{" + marker });
        const arr = await call({ provider_response: [marker] });
        assert.match(bad.error, /must be a JSON object/);
        assert.match(arr.error, /must be a JSON object/);
        const others: any[] = [];
        for (const v of [[{ note: marker }], [[marker]], JSON.stringify([marker]), JSON.stringify([{ note: marker }]), 42, -1.5, true, false]) {
            const raw: any = await c.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m", provider_response: v } });
            assert.notEqual(raw.isError, true, JSON.stringify(v));
            const o = JSON.parse(raw.content[0].text);
            assert.match(o.error, /must be a JSON object/, JSON.stringify(v));
            others.push(raw);
        }
        assert.equal(seen.length, 2, "rejected input sent nothing");
        for (const raw of others) assert.ok(!JSON.stringify(raw).includes(marker));
        const huge = await call({ provider_response: { blob: marker + "x".repeat(MAX_PROVIDER_RESPONSE_BYTES) } });
        assert.match(huge.error, /too large/);
        assert.equal(seen.length, 2);
        await call({});
        assert.equal("provider_response" in seen[2], false);
        for (const out of [o1, o2, bad, arr, huge]) assert.ok(!JSON.stringify(out).includes(marker));
        assert.ok(!logs().includes(marker));
    });
});

// ---- guidance: only an exact known public string passes ----
const G = "For a full assessment, ask your model provider to include detailed output in its response.";
test("guidance: the allowed message passes; any other message, including one containing it, is dropped", async () => {
    const run = async (message: any): Promise<any> => {
        (globalThis as any).fetch = async (url: any) => {
            if (String(url).startsWith("http://localhost")) throw new TypeError("fetch failed");
            return new Response(JSON.stringify({ ...HOSTED_OK, message }), { status: 200, headers: { "content-type": "application/json" } });
        };
        return client().verify("p", "r", "m");
    };
    assert.equal((await run(G)).guidance, G);
    for (const bad of [G + " ", " " + G, G + " Also: secret.", "Note: " + G, G.toLowerCase(), G.slice(0, -1), "other", "", null, 5, [G], { m: G }]) {
        const out = await run(bad);
        assert.equal("guidance" in out, false, JSON.stringify(bad));
        assert.ok(!JSON.stringify(out).includes("secret"));
    }
    assert.equal("guidance" in (await run(undefined)), false);
});
