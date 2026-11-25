import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { displayOrigin } from '../src/egress.js';
import { ProxyClient } from '../src/proxy-client.js';
import { call_grok, call_gemini, call_together, call_ollama, modelNameError } from '../src/providers.js';

const realFetch = globalThis.fetch;
let calls: string[] = [];
afterEach(() => { (globalThis as any).fetch = realFetch; });
function mockFetch() {
    calls = [];
    (globalThis as any).fetch = async (url: any) => {
        calls.push(String(url));
        const u = String(url);
        const body = u.includes("generateContent") ? { candidates: [{ content: { parts: [{ text: "ok" }] }, finishReason: "STOP" }] }
            : u.includes("/api/generate") ? { response: "ok", done: true, done_reason: "stop" } : { choices: [{ message: { content: "ok" }, finish_reason: "stop" }] };
        return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    };
}

const SECRET_URL = "https://user:s3cretpass@hosted.example.test:8443/base/path?token=abc123&x=1";

test("displayOrigin prints scheme, host and port only", () => {
    assert.equal(displayOrigin(SECRET_URL), "https://hosted.example.test:8443");
    assert.equal(displayOrigin("http://localhost:8098/detect?k=v"), "http://localhost:8098");
    assert.equal(displayOrigin("HTTPS://Example.COM/x"), "https://example.com");
    for (const bad of ["not a url", "", undefined, null, "file:///etc/passwd", "javascript:alert(1)"]) {
        assert.equal(displayOrigin(bad as any), "an address that is not valid");
    }
});

test("start-up diagnostic prints the origin only, never userinfo, path or query", async () => {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-redact-"));
    fs.mkdirSync(path.join(home, ".arkheia"));
    fs.writeFileSync(path.join(home, ".arkheia", "config.json"), JSON.stringify({ proxy_url: SECRET_URL }));
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")],
        env: { PATH: process.env.PATH || "", HOME: home, ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00", ARKHEIA_PROXY_URL: "http://localhost:8098" },
        stderr: "pipe",
    });
    const client = new Client({ name: "redact-test", version: "0" });
    const err: string[] = [];
    try {
        await client.connect(transport);
        transport.stderr?.on("data", (d) => err.push(String(d)));
        await client.listTools();
        // trigger the fallback diagnostic against the configured hosted URL
        await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
    } finally { await client.close(); fs.rmSync(home, { recursive: true, force: true }); }
    // stderr is collected after connect; the start-up line was written before, so also capture via a second run below
    const text = err.join("");
    for (const leak of ["s3cretpass", "user:", "token=abc123", "/base/path"]) assert.ok(!text.includes(leak), `stderr leaks ${leak}`);
});

test("the start-up Hosted URL line itself is origin-only", async () => {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-redact-"));
    fs.mkdirSync(path.join(home, ".arkheia"));
    fs.writeFileSync(path.join(home, ".arkheia", "config.json"), JSON.stringify({ proxy_url: SECRET_URL }));
    const { spawn } = await import("child_process");
    const child = spawn(process.execPath, [path.join(root, "dist", "index.js")], {
        env: { PATH: process.env.PATH || "", HOME: home, ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00" }, stdio: ["pipe", "ignore", "pipe"],
    });
    let err = "";
    child.stderr.on("data", (d) => { err += String(d); });
    await new Promise((r) => setTimeout(r, 1500));
    child.kill();
    fs.rmSync(home, { recursive: true, force: true });
    assert.match(err, /\[arkheia\] Hosted URL: https:\/\/hosted\.example\.test:8443\n/);
    for (const leak of ["s3cretpass", "user:", "token=abc123", "/base/path"]) assert.ok(!err.includes(leak), `stderr leaks ${leak}`);
});

test("transport diagnostics print origins only", async () => {
    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as any).write = (c: any) => { lines.push(String(c)); return true; };
    try {
        (globalThis as any).fetch = async () => { throw new TypeError("fetch failed"); };
        const p = new ProxyClient("http://user:pw@localhost:8098/p?q=1", 1.0, SECRET_URL, "ak_test_dummy");
        await p.verify("p", "r", "m");
        process.env.OLLAMA_BASE_URL = "http://user:pw@ollama.example.test:11434/x?y=1";
        await call_ollama("p");
    } finally { (process.stderr as any).write = orig; delete process.env.OLLAMA_BASE_URL; }
    const text = lines.join("");
    assert.ok(text.length > 0);
    for (const leak of ["s3cretpass", "user:", "pw@", "token=abc123", "q=1", "y=1", "/base/path"]) assert.ok(!text.includes(leak), `diagnostic leaks ${leak}`);
    assert.match(text, /https:\/\/hosted\.example\.test:8443/);
});

// ---- model names -----------------------------------------------------------

const KEYISH = ["ak_live_" + "A".repeat(24), "sk-" + "a".repeat(30), "Bearer abcdefghijklmnopqrstuvwx"];
const BAD_SHAPES = ["a b", "x/../y", "model\n", "a?key=1", "a#b", "", " ", "../etc", "/abs", "a//b", "x".repeat(129), "é"];

test("a key-shaped or malformed model name is refused with a fixed error and zero transport calls", async () => {
    process.env.XAI_API_KEY = "k"; process.env.GOOGLE_API_KEY = "k"; process.env.TOGETHER_API_KEY = "k";
    try {
        mockFetch();
        const fns: [string, (m: string) => Promise<any>][] = [
            ["grok", (m) => call_grok("p", m)], ["gemini", (m) => call_gemini("p", m)],
            ["together", (m) => call_together("p", m)], ["ollama", (m) => call_ollama("p", m)],
        ];
        for (const [name, fn] of fns) {
            for (const bad of [...KEYISH, ...BAD_SHAPES]) {
                const r: any = await fn(bad);
                assert.equal(r.error, "invalid_model_name", `${name}: ${JSON.stringify(bad)}`);
                assert.equal(r.model, "", "the refused name is not echoed");
                if (KEYISH.includes(bad)) assert.ok(!JSON.stringify(r).includes(bad), "a key-shaped name never appears in the result");
            }
        }
        assert.deepEqual(calls, [], "nothing was sent");
    } finally { delete process.env.XAI_API_KEY; delete process.env.GOOGLE_API_KEY; delete process.env.TOGETHER_API_KEY; }
});

test("ordinary model names still work for each provider", async () => {
    process.env.XAI_API_KEY = "k"; process.env.GOOGLE_API_KEY = "k"; process.env.TOGETHER_API_KEY = "k";
    try {
        mockFetch();
        for (const [fn, model] of [
            [call_grok, "grok-4-fast-non-reasoning"], [call_gemini, "gemini-2.5-flash"],
            [call_together, "moonshotai/Kimi-K2.5"], [call_ollama, "phi4:14b"], [call_ollama, "library/llama3.1:8b-instruct-q4_K_M"],
        ] as const) {
            calls = [];
            const r: any = await (fn as any)("p", model);
            assert.equal(r.error, null, model);
            assert.equal(r.model, model);
            assert.equal(calls.length, 1, model);
        }
        // Gemini puts the name in the path: encoded, and no slash or colon allowed
        assert.ok(calls.length === 1);
        assert.equal(modelNameError("gemini-2.5-flash", true), null);
        assert.equal(modelNameError("a/b", true), "invalid_model_name");
        assert.equal(modelNameError("a:b", true), "invalid_model_name");
    } finally { delete process.env.XAI_API_KEY; delete process.env.GOOGLE_API_KEY; delete process.env.TOGETHER_API_KEY; }
});

test("the configured Arkheia key as a model name is refused", () => {
    process.env.ARKHEIA_API_KEY = "ak_live_CONFIGURED1234";
    try { assert.equal(modelNameError("ak_live_CONFIGURED1234"), "invalid_model_name"); }
    finally { delete process.env.ARKHEIA_API_KEY; }
});

// ---- packaging -------------------------------------------------------------

test("the Python launcher is not shipped and is not the published binary", () => {
    const root = path.join(__dirname, "..", "..");
    const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    assert.deepEqual(pkg.bin, { "mcp-server": "dist/index.js" });
    for (const f of pkg.files as string[]) assert.ok(!/^bin\b/.test(f), `files lists ${f}`);
});

test("READMEs and the installer agree: Node 20+, Python only for the separate Python server", () => {
    const top = path.join(__dirname, "..", "..", "..");
    const root = fs.readFileSync(path.join(top, "README.md"), "utf8");
    const req = root.slice(root.indexOf("## Requirements"));
    assert.match(req, /Node\.js 20\+\. The npm package needs no Python/);
    assert.match(req, /Only for the separate Python server/);
    const pkgReadme = fs.readFileSync(path.join(top, "npm-wrapper", "README.md"), "utf8");
    const pre = pkgReadme.slice(pkgReadme.indexOf("## Prerequisites"), pkgReadme.indexOf("## Install"));
    assert.ok(!/python/i.test(pre.replace("needs no Python", "")), "the prerequisites do not require Python");
    assert.match(pkgReadme, /## The separate Python server/);
    const sh = fs.readFileSync(path.join(top, "install.sh"), "utf8");
    assert.ok(!/Node\.js 18/.test(sh) && /-lt 20/.test(sh));
    assert.match(sh.slice(0, 900), /needs no Python/);
});

// ---- round 1 review: real failure shapes, secrets in the model field ---------------------------

const LEAKS = ["s3cretpass", "user:", "pw@", "token=abc123", "y=1", "/base/path", "/secret/path", "x?token"];
const noLeak = (text: string, label: string) => { for (const l of LEAKS) assert.ok(!text.includes(l), `${label} leaks ${l}: ${text.slice(0, 200)}`); };

function captureStderr() {
    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    (process.stderr as any).write = (c: any) => { lines.push(String(c)); return true; };
    return { text: () => lines.join(""), restore: () => { (process.stderr as any).write = orig; } };
}

test("the real Node failure shapes (embedded credentials, unparseable address) leak nothing in logs or results", async () => {
    // The shapes Node's own fetch throws; checked here so the test fails if a future Node changes them silently.
    const probe: string[] = [];
    for (const u of ["https://user:s3cretpass@host.example.test/secret/path?token=abc123", "not a url/ x?token=abc123"]) {
        try { await fetch(u); } catch (e: any) { probe.push(e.message); }
    }
    assert.equal(probe.length, 2);
    assert.ok(probe.some((m) => m.includes("s3cretpass")) || probe.some((m) => m.includes("token=abc123")), "the raw exception text really does contain the input");

    const cap = captureStderr();
    let results: any[] = [];
    try {
        const bad = ["https://user:s3cretpass@host.example.test:8443/base/path?token=abc123", "not a url/ x?token=abc123"];
        for (const url of bad) {
            const p = new ProxyClient(url, 1.0, url, "ak_test_dummy");
            results.push(await p.verify("p", "r", "m"));
            results.push(await p.get_audit_log());
            results.push(await new ProxyClient("http://localhost:1", 1.0, url, "ak_test_dummy").verify("p", "r", "m"));
            process.env.OLLAMA_BASE_URL = url;
            results.push(await call_ollama("p", "phi4:14b"));
        }
    } finally { cap.restore(); delete process.env.OLLAMA_BASE_URL; }
    noLeak(cap.text(), "log");
    noLeak(JSON.stringify(results), "result");
    assert.ok(cap.text().length > 0, "something was logged");
    assert.match(cap.text() + JSON.stringify(results), /address|connection|request failed/i);
});

test("a thrown exception with the address in its text is described by class, never by its text", async () => {
    const { describeTransportError } = await import("../src/egress.js");
    for (const [e, code] of [
        [Object.assign(new TypeError("Request cannot be constructed from a URL that includes credentials: https://u:p@h/x?y=1")), "address_has_credentials"],
        [Object.assign(new TypeError("Failed to parse URL from https://u:p@h/x?y=1"), { cause: { code: "ERR_INVALID_URL" } }), "invalid_address"],
        [Object.assign(new TypeError("fetch failed"), { cause: { code: "ECONNREFUSED" } }), "network_error"],
        [Object.assign(new Error("anything with https://u:p@h/x?y=1 in it")), "request_failed"],
        [Object.assign(new Error("x"), { name: "AbortError" }), "timeout"],
    ] as const) {
        const d = describeTransportError(e);
        assert.equal(d.code, code);
        assert.ok(!/u:p|h\/x|y=1/.test(d.text + d.code));
    }
});

test("direct verify timeout diagnostics do not include the caller's model", async () => {
    const cap = captureStderr();
    try {
        (globalThis as any).fetch = (_u: any, init: any) => new Promise((_res, rej) => init.signal.addEventListener("abort", () => rej(Object.assign(new Error("a"), { name: "AbortError" }))));
        const p = new ProxyClient("http://localhost:1", 0.05, "https://hosted.example.test", "ak_test_dummy");
        await p.verify("p", "r", "my-private-model-name");
    } finally { cap.restore(); }
    assert.match(cap.text(), /timed out/);
    assert.ok(!cap.text().includes("my-private-model-name"));
});

test("every configured secret pasted as (or into) a model name is refused: zero transport calls, never echoed", async () => {
    const secrets: Record<string, string> = {
        XAI_API_KEY: "xai-PLACEHOLDER-secret-1234", GOOGLE_API_KEY: "gkey_PLACEHOLDER_9876543210", TOGETHER_API_KEY: "tog.PLACEHOLDER.value.5555",
        ARKHEIA_API_KEY: "arkheia-PLACEHOLDER-token-77",
    };
    const saved: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(secrets)) { saved[k] = process.env[k]; process.env[k] = v; }
    try {
        mockFetch();
        const fns: [string, (m: string) => Promise<any>][] = [
            ["grok", (m) => call_grok("p", m)], ["gemini", (m) => call_gemini("p", m)],
            ["together", (m) => call_together("p", m)], ["ollama", (m) => call_ollama("p", m)],
        ];
        for (const [name, fn] of fns) {
            for (const [envName, secret] of Object.entries(secrets)) {
                for (const model of [secret, `prefix-${secret}`, `${secret}-suffix`]) {
                    const r: any = await fn(model);
                    assert.equal(r.error, "invalid_model_name", `${name} / ${envName}`);
                    assert.equal(r.model, "");
                    assert.ok(!JSON.stringify(r).includes(secret), "not echoed");
                }
            }
        }
        assert.deepEqual(calls, [], "nothing was sent");
        // a short unrelated model name is not caught by a longer secret
        assert.equal((await call_ollama("p", "phi4:14b") as any).error, null);
    } finally {
        for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    }
});
