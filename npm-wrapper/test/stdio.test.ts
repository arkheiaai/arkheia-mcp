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
