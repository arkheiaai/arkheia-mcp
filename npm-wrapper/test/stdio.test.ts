import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// Real child process over stdio with the MCP SDK's own client. fetch is replaced by a preload,
// so no network is used, and the key is a dummy.
test("built server over stdio: fallback verify, tools/list and feedback, with no protocol errors", async () => {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-stdio-"));
    const env: Record<string, string> = {
        PATH: process.env.PATH || "", HOME: home,
        ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00",
        ARKHEIA_HOSTED_URL: "https://hosted.example.test",
        ARKHEIA_PROXY_URL: "http://localhost:8098",
    };
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")],
        env, stderr: "pipe",
    });
    const errors: unknown[] = [];
    const client = new Client({ name: "stdio-test", version: "0" });
    client.onerror = (e) => errors.push(e);
    const stderr: string[] = [];
    try {
        await client.connect(transport);
        transport.stderr?.on("data", (d) => stderr.push(String(d)));

        const tools = (await client.listTools()).tools.map((t) => t.name);
        for (const t of ["arkheia_verify", "arkheia_feedback", "arkheia_report", "arkheia_reports"]) {
            assert.ok(tools.includes(t), `tools/list has ${t}`);
        }
        assert.equal(tools.length, 12);

        // local proxy "down" -> falls back to hosted: the path that used to log to stdout
        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        const verdict = JSON.parse(v.content[0].text);
        assert.equal(verdict.detection_id, "det_0123456789abcdef");
        assert.equal(verdict.source, "hosted");
        assert.equal(verdict.reportable, true);
        assert.equal(verdict.report_with, "arkheia_report");

        const f: any = await client.callTool({ name: "arkheia_feedback", arguments: { message: "Works well for me.", kind: "praise" } });
        const fb = JSON.parse(f.content[0].text);
        assert.equal(fb.recorded, true);
        assert.equal(fb.feedback_id, "11111111-2222-3333-4444-555555555555");
        assert.ok(!f.isError);

        assert.deepEqual(errors, [], "the client saw no protocol/parse errors");
        assert.match(stderr.join(""), /falling back to hosted/, "the fallback notice went to stderr");
    } finally {
        await client.close();
        fs.rmSync(home, { recursive: true, force: true });
    }
});

async function withServer(extraEnv: Record<string, string>, fn: (c: Client, log: () => string[]) => Promise<void>) {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-stdio-"));
    const logFile = path.join(home, "requests.log");
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")],
        env: {
            PATH: process.env.PATH || "", HOME: home,
            ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00",
            ARKHEIA_HOSTED_URL: "https://hosted.example.test",
            ARKHEIA_PROXY_URL: "http://localhost:8098",
            ARKHEIA_TEST_REQUEST_LOG: logFile,
            ...extraEnv,
        },
        stderr: "pipe",
    });
    const client = new Client({ name: "stdio-test", version: "0" });
    try {
        await client.connect(transport);
        await fn(client, () => (fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8").split("\n").filter(Boolean) : []));
    } finally {
        await client.close();
        fs.rmSync(home, { recursive: true, force: true });
    }
}

// The Ollama tool promises no network egress: with the local verifier down and a hosted key set,
// nothing may be sent to the hosted origin, and the result says it was not checked.
test("run_ollama is local-only: local verifier down + hosted key set -> no hosted request, marked not checked", async () => {
    await withServer({ OLLAMA_BASE_URL: "http://ollama.example.test" }, async (client, log) => {
        const r: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p" } });
        const body = JSON.parse(r.content[0].text);
        assert.equal(body.response, "an answer");
        assert.equal(body.arkheia.risk_level, "UNKNOWN");
        assert.ok(body.arkheia.error, "says it was not checked");
        assert.equal(body.arkheia.reportable, false);
        assert.match(body.arkheia.report_note, /No check was completed/);
        const hosted = log().filter((u) => u.startsWith("https://hosted.example.test"));
        assert.deepEqual(hosted, [], "no request reached the hosted origin");
        assert.ok(log().some((u) => u.startsWith("http://localhost:8098")), "the local verifier was tried");
        // contrast: the ordinary verify tool still falls back to hosted
        await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        assert.ok(log().some((u) => u.startsWith("https://hosted.example.test/v1/detect")));
    });
});

test("tools/list advertises the true bounds and tools/call enforces them in code points", async () => {
    await withServer({}, async (client) => {
        const tools: any[] = (await client.listTools()).tools;
        const props = (n: string) => tools.find((t) => t.name === n).inputSchema.properties;
        const fb = props("arkheia_feedback");
        assert.equal(fb.message.minLength, 5);
        assert.equal(fb.message.maxLength, 2000);
        assert.equal(fb.email.maxLength, 200);
        assert.equal(props("arkheia_report").evidence.maxLength, 500);

        const call = async (name: string, args: any) => {
            try {
                const r: any = await client.callTool({ name, arguments: args });
                return { error: !!r.isError, text: r.content?.[0]?.text as string };
            } catch (e: any) { return { error: true, text: String(e.message) }; }
        };
        const bad = await call("arkheia_feedback", { message: "a".repeat(2001) });
        assert.ok(bad.error, "2,001 ASCII letters are refused");
        const short = await call("arkheia_feedback", { message: "abcd" });
        assert.ok(short.error, "4 characters are refused");
        const astral = await call("arkheia_report", { detection_id: "det_0123456789abcdef", outcome: "wrong", evidence: "\u{1F600}".repeat(500) });
        assert.ok(!astral.error, `500 supplementary-plane characters are accepted: ${astral.text}`);
        assert.equal(JSON.parse(astral.text).recorded, true);
        const tooMany = await call("arkheia_report", { detection_id: "det_0123456789abcdef", outcome: "wrong", evidence: "\u{1F600}".repeat(501) });
        assert.ok(tooMany.error, "501 code points are refused");
        const ok = await call("arkheia_feedback", { message: "\u{1F600}".repeat(2000) });
        assert.equal(JSON.parse(ok.text).recorded, true, "2,000 code points of message are accepted");
    });
});

// Exact-address version: with the default local Ollama address and the local verifier down, nothing may reach the hosted origin.
test("run_ollama with the local verifier down sends nothing to the hosted service and says the response was not checked", async () => {
    await withServer({ OLLAMA_BASE_URL: "http://127.0.0.1:11434" }, async (client, log) => {
        const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
        const out = JSON.parse(o.content[0].text);
        assert.equal(out.response, "local answer");
        assert.equal(out.arkheia.risk_level, "UNKNOWN");
        assert.match(out.arkheia.error, /not_checked_local_verification_unavailable/);
        assert.equal(out.arkheia.detection_id, undefined);
        assert.equal(out.arkheia.reportable, false);
        assert.deepEqual(log(), ["http://127.0.0.1:11434/api/generate", "http://localhost:8098/detect/verify"],
            "only the local Ollama and local verifier addresses were attempted");

        // the ordinary verify tool still falls back to hosted
        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        assert.equal(JSON.parse(v.content[0].text).source, "hosted");
        assert.equal(log().filter((u) => u.startsWith("https://hosted.example.test")).length, 1, "only the ordinary verify reached the hosted origin");
    });
});

test("published schemas express the enforced rules, and calls enforce them", async () => {
    await withServer({}, async (client) => {
        const tools: any[] = (await client.listTools()).tools;
        const props = (n: string) => tools.find((t) => t.name === n).inputSchema.properties;
        const fb = props("arkheia_feedback");
        assert.match(fb.message.description, /at least 5 after leading and trailing spaces are removed/);
        assert.equal(fb.email.format, "email");
        assert.match(fb.email.description, /Leave the field out/);
        assert.equal(fb.submission_id.format, "uuid");
        const ev = props("arkheia_report").evidence;
        assert.ok(ev.pattern, "evidence has a single-line pattern");
        assert.equal(new RegExp(ev.pattern).test("one line"), true);
        assert.equal(new RegExp(ev.pattern).test("two\nlines"), false);
        assert.equal(props("arkheia_reports").report_id.format, "uuid");

        const refused = async (name: string, args: any) => {
            try { const r: any = await client.callTool({ name, arguments: args }); return !!r.isError; } catch { return true; }
        };
        assert.ok(await refused("arkheia_feedback", { message: "hello there", email: "not-an-email" }));
        assert.ok(await refused("arkheia_report", { detection_id: "det_0123456789abcdef", outcome: "fine", evidence: "a\nb" }));
        assert.ok(await refused("arkheia_reports", { action: "delete", report_id: "x" }));
        assert.ok(await refused("arkheia_report", { detection_id: "ak_live_" + "A".repeat(24), outcome: "fine" }), "key-shaped detection_id refused through the tool");
        assert.ok(!(await refused("arkheia_feedback", { message: "hello there", email: "a@b.co" })));
    });
});
