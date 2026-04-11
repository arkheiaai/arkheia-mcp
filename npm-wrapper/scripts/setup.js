#!/usr/bin/env node
/**
 * Post-install script — verifies Python is available and prints setup instructions.
 * Does NOT auto-install Python dependencies (that happens on first run).
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const ARKHEIA_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".arkheia"
);
const CONFIG_FILE = path.join(ARKHEIA_DIR, "config.json");

function checkApiKey() {
  // Check if config.json exists and has api_key
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
      if (config.api_key && config.api_key.length > 0) {
        return config.api_key;
      }
    }
  } catch {
    // Corrupt config — treat as missing
  }

  // Check environment variable
  if (process.env.ARKHEIA_API_KEY) {
    // Save env-provided key to config for future runs
    saveConfig(process.env.ARKHEIA_API_KEY);
    return process.env.ARKHEIA_API_KEY;
  }

  return null;
}

function saveConfig(apiKey) {
  try {
    if (!fs.existsSync(ARKHEIA_DIR)) {
      fs.mkdirSync(ARKHEIA_DIR, { recursive: true });
    }
    const config = {
      api_key: apiKey,
      proxy_url: "https://arkheia-proxy-production.up.railway.app",
      provisioned_at: new Date().toISOString(),
    };
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2), "utf-8");
  } catch (err) {
    console.error(`  [arkheia] Warning: Could not save config: ${err.message}`);
  }
}

function checkPython() {
  // Try versioned interpreters first — on Homebrew, keg-only formulae like
  // python@3.12 only expose python3.12, not python3.
  const candidates = ["python3.13", "python3.12", "python3.11", "python3", "python"];
  for (const cmd of candidates) {
    try {
      // Verify version AND that pyexpat + ensurepip work.
      // Python 3.14 on macOS has broken pyexpat (missing libexpat symbol).
      const output = execSync(
        `${cmd} -c "import sys,pyexpat,ensurepip; print(f'{sys.version_info.major}.{sys.version_info.minor}')"`,
        { encoding: "utf-8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] }
      ).trim();
      const match = output.match(/^(\d+)\.(\d+)$/);
      if (match) {
        const major = parseInt(match[1]);
        const minor = parseInt(match[2]);
        if (major === 3 && minor >= 10 && minor <= 13) {
          const version = execSync(`${cmd} --version 2>&1`, {
            encoding: "utf-8", timeout: 5000,
          }).trim();
          return { cmd, version };
        }
      }
    } catch {
      // Try next
    }
  }
  return null;
}

const python = checkPython();

if (!python) {
  console.error(`
  ============================================================
  ERROR: Arkheia MCP Server requires Python 3.10–3.13
         with working pyexpat and ensurepip.

  macOS (Homebrew):
    brew install python@3.12

  NOTE: Homebrew's current default 'brew install python'
  installs 3.14, which has a broken pyexpat link on macOS
  as of April 2026. Use python@3.12 until Homebrew ships a fix.

  After installing, verify with:
    python3.12 -c "import pyexpat, ensurepip"

  Other platforms: https://python.org
  ============================================================
  `);
  process.exit(1);
} else {
  console.log(`
  ============================================================
  Arkheia MCP Server installed successfully.
  Python: ${python.version} (${python.cmd})
  ============================================================
  `);
}

// ── API key provisioning check ──────────────────────────────────
const existingKey = checkApiKey();

if (existingKey) {
  const maskedKey =
    existingKey.substring(0, 8) + "..." + existingKey.substring(existingKey.length - 4);
  console.log(`
  ============================================================
  API key found: ${maskedKey}
  Config: ${CONFIG_FILE}
  ============================================================
  `);
} else {
  console.log(`
  ============================================================
  No Arkheia API key configured.

  To enable hosted detection and encrypted profiles:

    1. Get a free API key at: https://arkheia.ai/mcp
    2. Set it in your environment:
       export ARKHEIA_API_KEY=ak_live_...

    Or save it directly to ${CONFIG_FILE}:
    {
      "api_key": "ak_live_...",
      "proxy_url": "https://arkheia-proxy-production.up.railway.app",
      "provisioned_at": "..."
    }

  The server will work without a key, but encrypted profiles
  and hosted detection will be unavailable.
  ============================================================
  `);
}
