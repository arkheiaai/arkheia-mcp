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
