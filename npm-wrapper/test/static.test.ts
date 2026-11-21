import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';

// stdout carries the MCP protocol: nothing under src/ may write to it.
test("no file under src/ writes to stdout", () => {
    const dir = path.join(__dirname, "..", "..", "src");
    const files = fs.readdirSync(dir).filter((f) => f.endsWith(".ts"));
    assert.ok(files.length > 0);
    for (const f of files) {
        const text = fs.readFileSync(path.join(dir, f), "utf8");
        assert.doesNotMatch(text, /console\s*\.\s*(log|info|debug)\b/, `${f} uses console.log/info/debug`);
        assert.doesNotMatch(text, /process\s*\.\s*stdout/, `${f} uses process.stdout`);
        assert.doesNotMatch(text, /(?:=|:)\s*console\s*[;,)]/, `${f} aliases console (its info/log would reach stdout)`);
    }
});
