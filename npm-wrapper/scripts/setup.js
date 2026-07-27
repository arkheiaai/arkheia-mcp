#!/usr/bin/env node
/**
 * Post-install script: verifies Python is available and prints setup instructions.
 * Does NOT auto-install Python dependencies (that happens on first run).
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const DEFAULT_PROXY_URL = "https://arkheia-proxy-production.up.railway.app";
const CONFIG_FILE_NAME = "config.json";
const ARKHEIA_DIR_MODE = 0o700;
const ARKHEIA_CONFIG_MODE = 0o600;

const CLAUDE_MD_MARKERS = [
  "Fabrication Detection - Arkheia",
  "Fabrication Detection — Arkheia",
];

const CLAUDE_MD_SECTION = `
# Fabrication Detection - Arkheia

This project uses Arkheia for runtime fabrication detection.
The \`arkheia_verify\` MCP tool is available in every conversation.

## Verification Protocol

Before presenting any substantive response to the user:
1. Call \`arkheia_verify\` with the model name, prompt, and response
2. Check the \`risk\` field in the result

### Risk Handling
- **LOW**: Present normally
- **MEDIUM**: Present with caveat: "Detection flagged medium confidence on this response. Key claims should be verified."
- **HIGH**: Do not present as-is. Investigate the specific claims against known sources. If claims cannot be verified, regenerate or escalate to the user with the detection result.

### Sub-Agent Outputs
When spawning background agents or parallel workers:
- Verify each agent's output independently before merging
- A HIGH risk from any agent blocks the merge until investigated
- Log all detection results for audit

### What NOT to Do
- Do not skip verification because the response "looks correct"
- Do not suppress HIGH findings; the user needs to know
- Do not retry the same prompt expecting a different risk score; the fingerprint is consistent
`;

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
    persistApiKey:
      argv.includes("--persist-api-key") ||
      truthy(env.ARKHEIA_PERSIST_API_KEY) ||
      truthy(env.npm_config_arkheia_persist_api_key),
    installClaudeMd:
      argv.includes("--install-claude-md") ||
      truthy(env.ARKHEIA_INSTALL_CLAUDE_MD) ||
      truthy(env.npm_config_arkheia_install_claude_md),
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

function ensurePrivateArkheiaDir(arkheiaDir, { dryRun = false } = {}) {
  if (dryRun) return;
  if (!fs.existsSync(arkheiaDir)) {
    fs.mkdirSync(arkheiaDir, { recursive: true, mode: ARKHEIA_DIR_MODE });
  }
  chmodIfPossible(arkheiaDir, ARKHEIA_DIR_MODE);
}

function readJsonFile(file) {
  if (!fs.existsSync(file)) return {};
  return JSON.parse(fs.readFileSync(file, "utf-8"));
}

function writeFileAtomicWithRollback(file, data, mode, { failAfterWrite = false } = {}) {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.tmp`);
  const existed = fs.existsSync(file);
  const previous = existed ? fs.readFileSync(file) : null;

  try {
    fs.writeFileSync(tmp, data, { encoding: "utf-8", mode });
    chmodIfPossible(tmp, mode);
    fs.renameSync(tmp, file);
    chmodIfPossible(file, mode);

    if (failAfterWrite) {
      throw new Error("simulated write failure after replace");
    }
  } catch (err) {
    try {
      if (fs.existsSync(tmp)) fs.rmSync(tmp, { force: true });
    } catch {
      // Best effort cleanup; preserve the original error.
    }

    try {
      if (previous !== null) {
        fs.writeFileSync(tmp, previous, { mode });
        chmodIfPossible(tmp, mode);
        fs.renameSync(tmp, file);
        chmodIfPossible(file, mode);
      } else if (fs.existsSync(file)) {
        fs.rmSync(file, { force: true });
      }
    } catch {
      // Preserve the original write failure. A failed rollback is surfaced by
      // the remaining filesystem state in tests and by the original warning.
    }

    throw err;
  }
}

function stableConfigString(config) {
  return `${JSON.stringify(config, null, 2)}\n`;
}

function saveConfig(apiKey, options = {}) {
  const home = options.home || homeDir(options.env);
  const { arkheiaDir, configFile } = pathsForHome(home);

  if (options.dryRun) {
    return { changed: false, dryRun: true, configFile };
  }

  ensurePrivateArkheiaDir(arkheiaDir);

  const existing = readJsonFile(configFile);
  const next = {
    ...existing,
    api_key: apiKey,
    proxy_url: existing.proxy_url || DEFAULT_PROXY_URL,
    provisioned_at:
      existing.api_key === apiKey && existing.provisioned_at
        ? existing.provisioned_at
        : new Date().toISOString(),
  };

  const current = fs.existsSync(configFile)
    ? fs.readFileSync(configFile, "utf-8")
    : null;
  const serialized = stableConfigString(next);

  if (current === serialized) {
    chmodIfPossible(configFile, ARKHEIA_CONFIG_MODE);
    return { changed: false, dryRun: false, configFile };
  }

  writeFileAtomicWithRollback(configFile, serialized, ARKHEIA_CONFIG_MODE, {
    failAfterWrite: options.failAfterWrite,
  });

  return { changed: true, dryRun: false, configFile };
}

function readExistingApiKey(configFile) {
  try {
    const config = readJsonFile(configFile);
    if (config.api_key && config.api_key.length > 0) {
      chmodIfPossible(path.dirname(configFile), ARKHEIA_DIR_MODE);
      chmodIfPossible(configFile, ARKHEIA_CONFIG_MODE);
      return config.api_key;
    }
  } catch {
    // Corrupt config: treat as missing.
  }
  return null;
}

function checkApiKey(options = {}) {
  const env = options.env || process.env;
  const home = options.home || homeDir(env);
  const { configFile } = pathsForHome(home);

  const existingKey = readExistingApiKey(configFile);
  if (existingKey) {
    return { apiKey: existingKey, source: "config", persisted: true, configFile };
  }

  if (!env.ARKHEIA_API_KEY) {
    return { apiKey: null, source: null, persisted: false, configFile };
  }

  if (!options.persistApiKey) {
    return {
      apiKey: env.ARKHEIA_API_KEY,
      source: "environment",
      persisted: false,
      configFile,
    };
  }

  try {
    const result = saveConfig(env.ARKHEIA_API_KEY, {
      home,
      dryRun: options.dryRun,
      failAfterWrite: options.failAfterWrite,
    });
    return {
      apiKey: env.ARKHEIA_API_KEY,
      source: "environment",
      persisted: !result.dryRun,
      dryRun: result.dryRun,
      changed: result.changed,
      configFile,
    };
  } catch (err) {
    console.error(`  [arkheia] Warning: Could not save config: ${err.message}`);
    return {
      apiKey: env.ARKHEIA_API_KEY,
      source: "environment",
      persisted: false,
      error: err,
      configFile,
    };
  }
}

function checkPython() {
  const candidates = ["python3", "python"];
  for (const cmd of candidates) {
    try {
      const version = execSync(`${cmd} --version 2>&1`, {
        encoding: "utf-8",
        timeout: 5000,
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

function installClaudeMd(options = {}) {
  const home = options.home || homeDir(options.env);
  const { claudeDir, claudeMdPath } = pathsForHome(home);

  if (options.dryRun) {
    return { changed: false, dryRun: true, claudeMdPath };
  }

  if (fs.existsSync(claudeMdPath)) {
    const existing = fs.readFileSync(claudeMdPath, "utf-8");
    if (CLAUDE_MD_MARKERS.some((marker) => existing.includes(marker))) {
      return { changed: false, dryRun: false, claudeMdPath };
    }
  }

  if (!fs.existsSync(claudeDir)) {
    fs.mkdirSync(claudeDir, { recursive: true });
  }

  fs.appendFileSync(claudeMdPath, CLAUDE_MD_SECTION, "utf-8");
  return { changed: true, dryRun: false, claudeMdPath };
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

  if (keyState.apiKey) {
    const persistence = keyState.persisted
      ? `Config: ${keyState.configFile}`
      : `Not persisted. Set ARKHEIA_PERSIST_API_KEY=1 to save it to ${keyState.configFile}.`;
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
    2. Set it in your environment:
       export ARKHEIA_API_KEY=<arkheia-api-key>
    3. To save it locally, opt in explicitly:
       ARKHEIA_PERSIST_API_KEY=1 npx @arkheia/mcp-server

  Saved keys are written to ${keyState.configFile} with private file modes.
  The server will work without a key, but encrypted profiles
  and hosted detection will be unavailable.
  ============================================================
  `);
  }

  if (options.installClaudeMd) {
    const result = installClaudeMd(options);
    const action = result.dryRun ? "Would install" : result.changed ? "Installed" : "Already installed";
    console.log(`  [arkheia] ${action} Claude protocol at ${result.claudeMdPath}`);
  } else {
    const { claudeMdPath } = pathsForHome(homeDir());
    console.log(
      `  [arkheia] Global Claude instructions not modified. ` +
        `Set ARKHEIA_INSTALL_CLAUDE_MD=1 to append ${claudeMdPath}.`
    );
  }
}

module.exports = {
  ARKHEIA_CONFIG_MODE,
  ARKHEIA_DIR_MODE,
  checkApiKey,
  installClaudeMd,
  main,
  parseOptions,
  pathsForHome,
  saveConfig,
  writeFileAtomicWithRollback,
};

if (require.main === module) {
  main();
}
