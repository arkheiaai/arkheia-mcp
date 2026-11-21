import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

// Real child process over stdio with the MCP SDK's own client. fetch is replaced by a preload that answers 422
// to any JSON body sent without a JSON content type, so no network is used, and the key is a dummy.
test("built server over stdio: local-to-hosted fallback verify succeeds with no protocol errors", async () => {
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

        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        const verdict = JSON.parse(v.content[0].text);
        assert.equal(verdict.detection_id, "det_0123456789abcdef");
        assert.equal(verdict.source, "hosted");

        assert.deepEqual(errors, [], "the client saw no protocol/parse errors");
        assert.match(stderr.join(""), /falling back to hosted/, "the fallback notice went to stderr");
    } finally {
        await client.close();
        fs.rmSync(home, { recursive: true, force: true });
    }
});

// The Ollama tool promises no network egress: with the local verifier down and a hosted key set, nothing may reach the hosted origin.
test("run_ollama with the local verifier down sends nothing to the hosted service and says the response was not checked", async () => {
    const root = path.join(__dirname, "..", "..");
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-stdio-"));
    const log = path.join(home, "requests.log");
    const env: Record<string, string> = {
        PATH: process.env.PATH || "", HOME: home,
        ARKHEIA_API_KEY: "ak_live_DUMMYDUMMYDUMMY00",
        ARKHEIA_HOSTED_URL: "https://hosted.example.test",
        ARKHEIA_PROXY_URL: "http://localhost:8098",
        OLLAMA_BASE_URL: "http://127.0.0.1:11434",
        ARKHEIA_TEST_REQUEST_LOG: log,
    };
    const transport = new StdioClientTransport({
        command: process.execPath,
        args: ["--require", path.join(root, "test", "stdio-preload.cjs"), path.join(root, "dist", "index.js")],
        env, stderr: "pipe",
    });
    const client = new Client({ name: "stdio-test", version: "0" });
    try {
        await client.connect(transport);
        const o: any = await client.callTool({ name: "run_ollama", arguments: { prompt: "p", model: "m" } });
        const out = JSON.parse(o.content[0].text);
        assert.equal(out.response, "local answer");
        assert.equal(out.arkheia.risk_level, "UNKNOWN");
        assert.match(out.arkheia.error, /not_checked_local_verification_unavailable/);
        assert.equal(out.arkheia.detection_id, undefined);

        const read = () => fs.readFileSync(log, "utf8").split("\n").filter(Boolean);
        assert.deepEqual(read(), ["http://127.0.0.1:11434/api/generate", "http://localhost:8098/detect/verify"],
            "only the local Ollama and local verifier addresses were attempted");

        // the ordinary verify tool still falls back to hosted
        const v: any = await client.callTool({ name: "arkheia_verify", arguments: { prompt: "p", response: "r", model: "m" } });
        assert.equal(JSON.parse(v.content[0].text).source, "hosted");
        assert.equal(read().filter((u) => u.startsWith("https://hosted.example.test")).length, 1, "only the ordinary verify reached the hosted origin");
    } finally {
        await client.close();
        fs.rmSync(home, { recursive: true, force: true });
    }
});
