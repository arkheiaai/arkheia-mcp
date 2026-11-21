import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as http from 'http';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { AddressInfo } from 'net';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { isArkheiaHostedOrigin, isLoopbackOrigin, computeEgress, applyEgress } from '../src/egress.js';
import { REGISTRY } from '../src/tool-registry.js';
import { ProxyClient } from '../src/proxy-client.js';
import { call_grok, call_gemini, call_together, call_ollama } from '../src/providers.js';

test("isLoopbackOrigin: table", () => {
    for (const v of ["http://localhost:11434", "HTTP://LOCALHOST", "http://LocalHost:8098/x", "http://127.0.0.1:1", "http://127.1.2.3", "https://127.255.255.255:9", "http://[::1]:8098", "http://[0:0:0:0:0:0:0:1]/"]) {
        assert.equal(isLoopbackOrigin(v), true, v);
    }
    for (const v of ["http://192.168.1.5:11434", "http://10.0.0.2", "http://172.16.0.1", "https://api.example.com", "http://localhost.evil.example", "http://127.0.0.1.evil.example", "http://0.0.0.0:8098",
        "http://[::ffff:127.0.0.1]", "http://localhost.", "http://128.0.0.1", "ftp://localhost", "", "garbage", "localhost:11434", undefined as any, null as any]) {
        assert.equal(isLoopbackOrigin(v), false, String(v));
    }
});

test("egress flags and descriptions for the three configurations; userinfo and query are never shown", () => {
    const both = computeEgress({});
    assert.equal(both.run_ollama.network_egress, false);
    assert.equal(both.run_ollama.description, "Uses local addresses: calls the Ollama address and the verifier address configured here (both recognised local addresses). Never contacts the Arkheia hosted service. If the local verifier is unavailable the response is returned unchecked.");
    assert.equal(both.arkheia_audit_log.network_egress, false);

    const remoteOllama = computeEgress({ OLLAMA_BASE_URL: "http://user:secret@gpu.lan:11434/api?token=abc" });
    assert.equal(remoteOllama.run_ollama.network_egress, true);
    assert.equal(remoteOllama.run_ollama.description, "Calls the Ollama address and verifier address you configured (outside the recognised local addresses: Ollama at gpu.lan:11434). Never contacts the Arkheia hosted service.");
    assert.equal(remoteOllama.arkheia_audit_log.network_egress, false, "audit uses only the verifier address");

    const remoteVerifier = computeEgress({ ARKHEIA_PROXY_URL: "https://u:p@verify.corp.example:8443/x?k=1" });
    assert.equal(remoteVerifier.run_ollama.network_egress, true);
    assert.equal(remoteVerifier.run_ollama.description, "Calls the Ollama address and verifier address you configured (outside the recognised local addresses: verifier at verify.corp.example:8443). Never contacts the Arkheia hosted service.");
    assert.equal(remoteVerifier.arkheia_audit_log.network_egress, true);
    for (const e of [remoteOllama, remoteVerifier]) {
        const all = JSON.stringify(e);
        assert.doesNotMatch(all, /secret|token|abc|u:p|k=1/);
    }

    applyEgress({ ARKHEIA_PROXY_URL: "http://10.1.1.1:8098" });
    assert.equal(REGISTRY.run_ollama.network_egress, true);
    assert.equal(REGISTRY.arkheia_audit_log.network_egress, true);
    applyEgress({});
    assert.equal(REGISTRY.run_ollama.network_egress, false);
});

// ---- every call site refuses redirects ----
test("redirect policy is error on every fetch call site (table-driven)", async () => {
    const real = globalThis.fetch;
    const seen: { url: string; redirect: any }[] = [];
    (globalThis as any).fetch = async (url: any, init: any = {}) => {
        seen.push({ url: String(url), redirect: init.redirect });
        if (String(url).startsWith("http://localhost:1")) throw new TypeError("fetch failed");
        return new Response(JSON.stringify({ risk: "LOW", response: "ok", choices: [{ message: { content: "ok" } }], candidates: [{ content: { parts: [{ text: "ok" }] } }] }), { status: 200 });
    };
    process.env.XAI_API_KEY = "k"; process.env.GEMINI_API_KEY = "k"; process.env.GOOGLE_API_KEY = "k"; process.env.TOGETHER_API_KEY = "k";
    try {
        const c = new ProxyClient("http://localhost:1", 2, "https://hosted.example.test", "ak_test");
        await c.verify("p", "r", "m");                                  // local verify + hosted verify
        await c.get_audit_log();                                         // audit log
        await c.verify("p", "r", "m", undefined, { allowHosted: false }); // local verify, local-only
        await call_grok("p"); await call_gemini("p"); await call_together("p"); await call_ollama("p");
    } finally { (globalThis as any).fetch = real; }
    const table: [string, RegExp][] = [["local verify", /localhost:1\/detect\/verify/], ["audit log", /\/audit\/log/], ["hosted verify", /hosted\.example\.test\/v1\/detect/],
        ["grok", /x\.ai/], ["gemini", /generativelanguage/], ["together", /together/], ["ollama", /\/api\/generate/]];
    for (const [name, re] of table) {
        const hits = seen.filter((s) => re.test(s.url));
        assert.ok(hits.length > 0, `${name} was exercised`);
        for (const h of hits) assert.equal(h.redirect, "error", name);
    }
    assert.ok(seen.every((s) => s.redirect === "error"), "no request without the policy");
});

function listen(handler: http.RequestListener): Promise<http.Server> {
    return new Promise((res) => { const s = http.createServer(handler); s.listen(0, "127.0.0.1", () => res(s)); });
}
const port = (s: http.Server) => (s.address() as AddressInfo).port;

test("a real 307 on the local verification and audit requests: the second server receives nothing", async () => {
    let received = 0;
    const target = await listen((req, res) => { received++; req.resume(); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
    const redirector = await listen((req, res) => { req.resume(); res.writeHead(307, { location: `http://127.0.0.1:${port(target)}/x` }); res.end(); });
    try {
        const c = new ProxyClient(`http://127.0.0.1:${port(redirector)}`, 3, "https://hosted.example.test", "ak_test");
        const v = await c.verify("p", "r", "m", undefined, { allowHosted: false });
        assert.equal(v.risk_level, "UNKNOWN");
        const a = await c.get_audit_log();
        assert.ok(a.error, "the audit request fails instead of following");
        assert.equal(received, 0);
    } finally { redirector.close(); target.close(); }
});

// ---- real stdio child ----
async function withChild<T>(extra: Record<string, string>, fn: (client: Client, requests: () => string[]) => Promise<T>): Promise<T> {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-egress-"));
    const log = path.join(home, "requests.log");
    const env: Record<string, string> = {
        PATH: process.env.PATH || "", HOME: home, ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00",
        ARKHEIA_HOSTED_URL: "https://hosted.example.test", ARKHEIA_TEST_REQUEST_LOG: log, ...extra,
    };
    const transport = new StdioClientTransport({ command: process.execPath, args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")], env, stderr: "pipe" });
    const client = new Client({ name: "egress-test", version: "0" });
    try {
        await client.connect(transport);
        return await fn(client, () => (fs.existsSync(log) ? fs.readFileSync(log, "utf8").split("\n").filter(Boolean) : []));
    } finally { await client.close(); fs.rmSync(home, { recursive: true, force: true }); }
}

test("tools/list shows the egress wording for each of the three configurations", async () => {
    const desc = async (extra: Record<string, string>) => withChild(extra, async (c) => {
        const t = (await c.listTools()).tools;
        return { ollama: t.find((x) => x.name === "run_ollama")!.description, audit: t.find((x) => x.name === "arkheia_audit_log")!.description };
    });
    const a = await desc({});
    assert.equal(a.ollama, computeEgress({}).run_ollama.description);
    const b = await desc({ OLLAMA_BASE_URL: "http://gpu.lan:11434" });
    assert.match(b.ollama!, /outside the recognised local addresses: Ollama at gpu\.lan:11434\)/);
    assert.match(b.audit!, /a recognised local address/);
    const c = await desc({ ARKHEIA_PROXY_URL: "http://u:p@verify.corp.example:8443/?q=1" });
    assert.match(c.ollama!, /outside the recognised local addresses: verifier at verify\.corp\.example:8443\)/);
    assert.match(c.audit!, /outside the recognised local addresses: verify\.corp\.example:8443\)/);
    assert.doesNotMatch(JSON.stringify([a, b, c]), /u:p|q=1/);
});

test("ARKHEIA_PROXY_URL equal to the hosted origin: the Ollama path sends nothing there; ordinary verify still reaches hosted", async () => {
    await withChild({ OLLAMA_BASE_URL: "http://127.0.0.1:11434", ARKHEIA_PROXY_URL: "https://hosted.example.test" }, async (client, requests) => {
        const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
        const out = JSON.parse(o.content[0].text);
        assert.equal(out.arkheia.error, "not_checked_local_verification_unavailable");
        assert.deepEqual(requests(), ["http://127.0.0.1:11434/api/generate"], "nothing was sent to the hosted origin");
    });
    await withChild({}, async (client, requests) => {
        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        assert.equal(JSON.parse(v.content[0].text).source, "hosted");
        assert.ok(requests().includes("https://hosted.example.test/v1/detect"));
    });
});

test("isArkheiaHostedOrigin: table", () => {
    const custom = "https://hosted.example.test";
    for (const v of ["https://arkheia-proxy-production.up.railway.app", "HTTPS://Arkheia-Proxy-Production.Up.Railway.App:443/x?y=1", "https://u:p@arkheia-proxy-production.up.railway.app",
        "https://hosted.example.test", "https://HOSTED.example.test:443/api", "garbage", "", "localhost:1"]) {
        assert.equal(isArkheiaHostedOrigin(v, custom), true, v);
    }
    for (const v of ["http://127.0.0.1:11434", "http://gpu.lan:11434", "https://hosted.example.test:8443", "http://hosted.example.test", "https://hosted.example.test.evil.example"]) {
        assert.equal(isArkheiaHostedOrigin(v, custom), false, v);
    }
    assert.equal(isArkheiaHostedOrigin("https://hosted.example.test", undefined), false, "no custom URL configured");
});

test("Ollama and verifier addresses that are the hosted service: zero requests to it; remote Ollama host still works; ordinary verify still hosted", async () => {
    const builtin = "https://arkheia-proxy-production.up.railway.app";
    const custom = "https://hosted.example.test";
    const isHosted = (u: string) => u.startsWith(builtin) || u.startsWith(custom);
    // Ollama address = built-in hosted origin, then = the custom hosted URL: no model call, no verification
    for (const addr of [builtin, "HTTPS://Arkheia-Proxy-Production.Up.Railway.App:443", custom, custom + "/"]) {
        await withChild({ OLLAMA_BASE_URL: addr }, async (client, requests) => {
            const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
            const out = JSON.parse(o.content[0].text);
            assert.match(out.error, /configuration_error/);
            assert.equal(out.arkheia.risk_level, "UNKNOWN");
            assert.deepEqual(requests(), [], `nothing sent for OLLAMA_BASE_URL=${addr}`);
        });
    }
    // verifier address = built-in hosted origin, then = custom: the model request goes to local Ollama, nothing to hosted
    for (const addr of [builtin, custom]) {
        await withChild({ OLLAMA_BASE_URL: "http://127.0.0.1:11434", ARKHEIA_PROXY_URL: addr }, async (client, requests) => {
            const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
            assert.equal(JSON.parse(o.content[0].text).arkheia.error, "not_checked_local_verification_unavailable");
            assert.deepEqual(requests().filter(isHosted), [], `nothing to hosted for ARKHEIA_PROXY_URL=${addr}`);
        });
    }
    // a distinct remote Ollama host still works (model answered; verifier unavailable -> unchecked, still nothing hosted)
    await withChild({ OLLAMA_BASE_URL: "http://127.0.0.1:11434" }, async (client, requests) => {
        const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
        assert.equal(JSON.parse(o.content[0].text).response, "local answer");
        assert.deepEqual(requests().filter(isHosted), []);
    });
    await withChild({ OLLAMA_BASE_URL: "http://gpu.lan:11434" }, async (client, requests) => {
        await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
        assert.ok(requests().includes("http://gpu.lan:11434/api/generate"), "the distinct remote host was attempted");
        assert.deepEqual(requests().filter(isHosted), []);
    });
    await withChild({}, async (client, requests) => {
        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        assert.equal(JSON.parse(v.content[0].text).source, "hosted");
        assert.ok(requests().includes(custom + "/v1/detect"));
    });
});
