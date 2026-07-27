#!/usr/bin/env node
/**
 * Post-install script: verifies Python is available and prints setup instructions.
 * Does NOT auto-install Python dependencies (that happens on first run).
 */

const { execFileSync } = require("child_process");

const KEY_ENV = "ARKHEIA" + "_API_KEY";

function truthy(value) {
  return /^(1|true|yes|y|on)$/i.test(String(value || ""));
}

function parseOptions(argv = process.argv.slice(2), env = process.env) {
  return {
    dryRun: argv.includes("--dry-run") || truthy(env.ARKHEIA_SETUP_DRY_RUN),
  };
}

function childEnvWithoutApiKey(env = process.env) {
  const childEnv = { ...env };
  delete childEnv[KEY_ENV];
  return childEnv;
}

function checkPython() {
  const candidates = ["python3", "python"];
  for (const cmd of candidates) {
    try {
      const version = execFileSync(cmd, ["--version"], {
        encoding: "utf-8",
        timeout: 5000,
        stdio: ["ignore", "pipe", "pipe"],
        env: childEnvWithoutApiKey(),
      }).trim();
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (!match) continue;

      const major = parseInt(match[1], 10);
      const minor = parseInt(match[2], 10);
      if (major > 3 || (major === 3 && minor >= 10)) {
        return { cmd, version };
      }
    } catch {
      // Try next.
    }
  }
  return null;
}

function main() {
  parseOptions();
  const python = checkPython();

  if (!python) {
    console.log(`
  ============================================================
  Arkheia MCP Server requires Python 3.10+

  Install Python from: https://python.org
  Then run: npx @arkheia/mcp-server
  ============================================================
  `);
  } else {
    console.log(`
  ============================================================
  Arkheia MCP Server installed successfully.
  Python: ${python.version}
  ============================================================
  `);
  }

  console.log(`
  ============================================================
  Runtime credentials are not inspected by postinstall.

  To enable hosted detection and encrypted profiles:

    1. Get a free API key at: https://arkheia.ai/mcp
    2. Set the Arkheia runtime key in your environment
    3. Start your MCP client with that environment present

  This postinstall does not read, verify, persist, or print API keys.
  The server will work without a key, but encrypted profiles
  and hosted detection will be unavailable.
  ============================================================
  `);

  console.log("  [arkheia] Global Claude instructions not modified by postinstall.");
}

module.exports = {
  childEnvWithoutApiKey,
  checkPython,
  main,
  parseOptions,
};

if (require.main === module) {
  main();
}
