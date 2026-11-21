import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { spawnSync } from 'child_process';

// Runs the real install.sh under /bin/bash (macOS: bash 3.2) with a restricted PATH made of stubs
// plus /usr/bin:/bin (macOS: BSD grep). Nothing is installed or provisioned: npm, claude, curl and
// node are stubs that log their arguments.
const SCRIPT = path.join(__dirname, "..", "..", "..", "install.sh");
const BASH = fs.existsSync("/bin/bash") ? "/bin/bash" : "bash";

function realPython(): string {
    for (const c of ["/opt/homebrew/bin/python3.12", "/opt/homebrew/bin/python3", "/usr/bin/python3", "/usr/local/bin/python3"]) {
        if (!fs.existsSync(c)) continue;
        const r = spawnSync(c, ["-c", "import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)"]);
        if (r.status === 0) return c;
    }
    const w = spawnSync("sh", ["-c", "command -v python3"]).stdout.toString().trim();
    return w;
}

type Opts = { npm?: number; claude?: number | "absent"; mcpServer?: boolean; verify?: string; provision?: "ok" | "fail"; hosted?: string; args?: string[]; desktop?: boolean };

function run(o: Opts = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "arkheia-install-"));
    const bin = path.join(root, "bin"); const home = path.join(root, "home"); const log = path.join(root, "calls.log");
    fs.mkdirSync(bin); fs.mkdirSync(home);
    const stub = (name: string, body: string) => { fs.writeFileSync(path.join(bin, name), `#!/bin/sh\n${body}\n`); fs.chmodSync(path.join(bin, name), 0o755); };
    stub("node", 'echo v20.1.0');
    stub("npm", `echo "npm $*" >> "${log}"; [ "$1" = "prefix" ] && { echo /stub/prefix; exit 0; }; exit ${o.npm ?? 0}`);
    if (o.mcpServer !== false) stub("mcp-server", "exit 0");
    if (o.claude !== "absent") stub("claude", `echo "claude $*" >> "${log}"; exit ${o.claude ?? 0}`);
    stub("curl", `
case "$*" in
  *"/v1/provision"*) ${o.provision === "fail" ? "exit 6" : `printf '{"api_key": "ak_live_NEWKEY123"}\\n201'`} ;;
  *"/v1/detect"*) printf '%s' "${o.verify ?? "200"}" ;;
  *) exit 7 ;;
esac`);
    fs.symlinkSync(realPython(), path.join(bin, "python3"));
    if (o.desktop) {
        const dir = process.platform === "darwin" ? path.join(home, "Library", "Application Support", "Claude") : path.join(home, ".config", "Claude");
        fs.mkdirSync(dir, { recursive: true });
    }
    const r = spawnSync(BASH, [SCRIPT, ...(o.args ?? ["--api-key", "ak_live_TESTKEY0001"])], {
        env: { PATH: `${bin}:/usr/bin:/bin`, HOME: home, TMPDIR: root, ...(o.hosted ? { ARKHEIA_HOSTED_URL: o.hosted } : {}) },
        input: "", encoding: "utf8", timeout: 30000,
    });
    const calls = fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "";
    return { r, out: `${r.stdout}${r.stderr}`, calls, home, root };
}
const SUCCESS = /installed and registered/;

test("install.sh: syntax is valid, and it uses no GNU-only grep or bare mktemp", () => {
    const sh = fs.readFileSync(SCRIPT, "utf8");
    assert.equal(spawnSync(BASH, ["-n", SCRIPT]).status, 0);
    assert.ok(!/grep\s+-\w*P/.test(sh), "no grep -P");
    assert.ok(!/mktemp\s*\)/.test(sh), "no bare mktemp");
    assert.ok(!/npx @arkheia\/mcp-server --version/.test(sh));
});

test("install.sh: everything succeeds -> exit 0, npm install -g and the documented claude command, success banner", () => {
    const { r, out, calls } = run();
    assert.equal(r.status, 0, out);
    assert.match(calls, /npm install -g @arkheia\/mcp-server/);
    assert.match(calls, /claude mcp add arkheia -s user -e ARKHEIA_API_KEY=ak_live_TESTKEY0001 -- mcp-server/);
    assert.match(out, SUCCESS);
});

test("install.sh: provisioning and parsing work under stock bash and BSD grep (no network, nothing installed)", () => {
    const { r, out, calls } = run({ args: ["--email", "you@example.com"] });
    assert.equal(r.status, 0, out);
    assert.match(calls, /ARKHEIA_API_KEY=ak_live_NEWKEY123/, "the key was parsed from the provisioning response");
    assert.match(out, /press Confirm|Confirm/);
    const bad = run({ args: ["--email", "not an email"] });
    assert.notEqual(bad.r.status, 0);
    assert.match(bad.out, /Invalid email format/);
});

test("install.sh: npm failing -> non-zero exit, no success banner, nothing registered", () => {
    const { r, out, calls } = run({ npm: 17 });
    assert.equal(r.status, 1, out);
    assert.ok(!SUCCESS.test(out) && !/installed successfully/i.test(out));
    assert.match(out, /npm could not install/);
    assert.ok(!/claude mcp add/.test(calls));
});

test("install.sh: npm succeeds but the mcp-server command is not found -> failure, no banner", () => {
    const { r, out, calls } = run({ mcpServer: false });
    assert.equal(r.status, 1, out);
    assert.match(out, /'mcp-server' command is not on your PATH/);
    assert.ok(!SUCCESS.test(out));
    assert.ok(!/claude mcp add/.test(calls));
});

test("install.sh: no claude command -> exit 10, says registration was NOT done and prints the exact command", () => {
    const { r, out, calls } = run({ claude: "absent" });
    assert.equal(r.status, 10, out);
    assert.match(out, /NOT registered/);
    assert.match(out, /Registration was NOT done/);
    assert.match(out, /claude mcp add arkheia -s user -e ARKHEIA_API_KEY="\$ARKHEIA_API_KEY" -- mcp-server/);
    assert.ok(!SUCCESS.test(out));
    assert.match(calls, /npm install -g/);
    assert.ok(!out.includes("ak_live_TESTKEY0001"), "the key is not printed again");
});

test("install.sh: claude mcp add failing -> exit 1, says it is NOT registered, no banner", () => {
    const { r, out } = run({ claude: 3 });
    assert.equal(r.status, 1, out);
    assert.match(out, /failed \(exit status 3\).*NOT registered/);
    assert.ok(!SUCCESS.test(out));
});

test("install.sh: a pending (unconfirmed) key's 403 gives the confirmation instruction and stops before installing", () => {
    const { r, out, calls } = run({ verify: "403" });
    assert.equal(r.status, 3, out);
    assert.match(out, /not confirmed yet/);
    assert.match(out, /click the link/);
    assert.match(out, /Press Confirm/);
    assert.match(out, /--api-key/);
    assert.equal(calls, "", "nothing was installed or registered");
    assert.ok(!SUCCESS.test(out));
});

test("install.sh: an invalid key (401) fails", () => {
    const { r, out, calls } = run({ verify: "401" });
    assert.equal(r.status, 1, out);
    assert.equal(calls, "");
});

test("install.sh: a configured hosted address is printed as an origin only", () => {
    const { r, out } = run({ args: ["--email", "you@example.com"], provision: "fail", hosted: "https://user:s3cretpass@host.example.test:8443/base?token=abc123" });
    assert.notEqual(r.status, 0);
    assert.match(out, /Failed to reach https:\/\/host\.example\.test:8443/);
    for (const leak of ["s3cretpass", "user:", "token=abc123", "/base"]) assert.ok(!out.includes(leak), `leaks ${leak}`);
});

test("install.sh: never writes Claude Code settings.json, and writes the Desktop config only when Desktop is installed", () => {
    const a = run();
    assert.ok(!fs.existsSync(path.join(a.home, ".claude")), "no ~/.claude was created");
    assert.ok(!fs.existsSync(path.join(a.home, "Library")) && !fs.existsSync(path.join(a.home, ".config")), "no Desktop config dir was created");
    const b = run({ desktop: true });
    assert.equal(b.r.status, 0, b.out);
    const file = process.platform === "darwin"
        ? path.join(b.home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
        : path.join(b.home, ".config", "Claude", "claude_desktop_config.json");
    const cfg = JSON.parse(fs.readFileSync(file, "utf8"));
    assert.equal(cfg.mcpServers.arkheia.env.ARKHEIA_API_KEY, "ak_live_TESTKEY0001");
});
