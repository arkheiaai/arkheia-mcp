#!/usr/bin/env node
/**
 * Post-install script: verifies Python is available and prints setup instructions.
 * Does NOT auto-install Python dependencies (that happens on first run).
 */

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const CONFIG_FILE_NAME = "config.json";
const ARKHEIA_DIR_MODE = 0o700;
const ARKHEIA_CONFIG_MODE = 0o600;
const KEY_ENV = "ARKHEIA" + "_API_KEY";

function homeDir(env = process.env) {
  return env.HOME || env.USERPROFILE || "/tmp";
}

function pathsForHome(home) {
  const arkheiaDir = path.join(home, ".arkheia");
  return {
    arkheiaDir,
    configFile: path.join(arkheiaDir, CONFIG_FILE_NAME),
    claudeDir: path.join(home, ".claude"),
    claudeMdPath: path.join(home, ".claude", "CLAUDE.md"),
  };
}

function truthy(value) {
  return /^(1|true|yes|y|on)$/i.test(String(value || ""));
}

function parseOptions(argv = process.argv.slice(2), env = process.env) {
  return {
    dryRun: argv.includes("--dry-run") || truthy(env.ARKHEIA_SETUP_DRY_RUN),
  };
}

function chmodIfPossible(target, mode) {
  try {
    fs.chmodSync(target, mode);
  } catch (err) {
    if (process.platform !== "win32") {
      throw err;
    }
  }
}

function childEnvWithoutApiKey(env = process.env) {
  const childEnv = { ...env };
  delete childEnv[KEY_ENV];
  return childEnv;
}

function readJsonFile(file) {
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, "utf-8"));
}

function hasExistingApiKey(configFile) {
  try {
    const config = readJsonFile(configFile);
    if (config.api_key && config.api_key.length > 0) {
      chmodIfPossible(path.dirname(configFile), ARKHEIA_DIR_MODE);
      chmodIfPossible(configFile, ARKHEIA_CONFIG_MODE);
      return true;
    }
  } catch {
    // Corrupt config: treat as missing.
  }
  return false;
}

function checkApiKey(options = {}) {
  const env = options.env || process.env;
  const home = options.home || homeDir(env);
  const { configFile } = pathsForHome(home);

  if (hasExistingApiKey(configFile)) {
    return { hasApiKey: true, source: "config", persisted: true, configFile };
  }

  if (!env[KEY_ENV]) {
    return { hasApiKey: false, source: null, persisted: false, configFile };
  }

  return {
    hasApiKey: true,
    source: "environment",
    persisted: false,
    configFile,
  };
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
  const options = parseOptions();
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

  const keyState = checkApiKey(options);

  if (keyState.hasApiKey) {
    const persistence = keyState.persisted
      ? `Config: ${keyState.configFile}`
      : "Not persisted by postinstall. Start your MCP client with the Arkheia runtime key set.";
    console.log(`
  ============================================================
  API key configured.
  ${persistence}
  ============================================================
  `);
  } else {
    console.log(`
  ============================================================
  No Arkheia API key configured.

  To enable hosted detection and encrypted profiles:

    1. Get a free API key at: https://arkheia.ai/mcp
    2. Set the Arkheia runtime key in your environment
    3. Start your MCP client with that environment present

  This postinstall does not write API keys to ${keyState.configFile}.
  The server will work without a key, but encrypted profiles
  and hosted detection will be unavailable.
  ============================================================
  `);
  }

  console.log("  [arkheia] Global Claude instructions not modified by postinstall.");
}

module.exports = {
  ARKHEIA_CONFIG_MODE,
  ARKHEIA_DIR_MODE,
  checkApiKey,
  main,
  parseOptions,
  pathsForHome,
};

if (require.main === module) {
  main();
}
