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
        const body = u.includes("generateContent") ? { candidates: [{ content: { parts: [{ text: "ok" }] } }] }
            : u.includes("/api/generate") ? { response: "ok" } : { choices: [{ message: { content: "ok" } }] };
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
