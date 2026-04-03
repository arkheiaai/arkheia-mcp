#!/usr/bin/env node
/**
 * Arkheia MCP Server — thin Node wrapper that spawns the Python MCP server.
 *
 * This wrapper exists so that MCP clients can install via:
 *   npx @arkheia/mcp-server
 *   npm install -g @arkheia/mcp-server
 *
 * It:
 *   1. Locates a Python 3.10+ interpreter
 *   2. Ensures mcp_server dependencies are installed (pip install)
 *   3. Spawns `python -m mcp_server.server` with stdio transport
 *   4. Forwards stdin/stdout/stderr (MCP uses stdio)
 *
 * Environment variables:
 *   ARKHEIA_API_KEY     — API key for hosted detection (required)
 *   ARKHEIA_PROXY_URL   — Local proxy URL (optional, for enterprise)
 *   ARKHEIA_HOSTED_URL  — Hosted API URL (default: https://arkheia-proxy-production.up.railway.app)
 */

const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ARKHEIA_HOME = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".arkheia"
);
const REPO_DIR = path.join(ARKHEIA_HOME, "mcp");
const BUNDLED_PYTHON_DIR = path.join(__dirname, "..", "python");
const VENV_DIR = path.join(ARKHEIA_HOME, "venv");

// Determine the real Python source: cloned repo > bundled package
function getServerDir() {
  // If repo already cloned, use it
  if (fs.existsSync(path.join(REPO_DIR, "mcp_server", "server.py"))) {
    return REPO_DIR;
  }
  // If bundled package has the server code, use it
  if (fs.existsSync(path.join(BUNDLED_PYTHON_DIR, "mcp_server", "server.py"))) {
    return BUNDLED_PYTHON_DIR;
  }
  // Neither exists — clone the repo
  process.stderr.write("[arkheia] Server code not found. Cloning from GitHub...\n");
  try {
    if (!fs.existsSync(ARKHEIA_HOME)) fs.mkdirSync(ARKHEIA_HOME, { recursive: true });
    execSync(`git clone --depth 1 https://github.com/arkheiaai/arkheia-mcp.git "${REPO_DIR}"`, {
      stdio: "inherit",
      timeout: 60000,
    });
    process.stderr.write("[arkheia] Repository cloned successfully.\n");
    return REPO_DIR;
  } catch (err) {
    process.stderr.write(
      `[arkheia] Error: Could not clone repository: ${err.message}\n` +
      "Manual install: git clone https://github.com/arkheiaai/arkheia-mcp.git ~/.arkheia/mcp\n"
    );
    process.exit(1);
  }
}

const PYTHON_DIR = getServerDir();
const REQUIREMENTS = fs.existsSync(path.join(PYTHON_DIR, "mcp_server", "requirements.txt"))
  ? path.join(PYTHON_DIR, "mcp_server", "requirements.txt")
  : path.join(PYTHON_DIR, "requirements.txt");

function findPython() {
  const candidates = ["python3", "python"];
  for (const cmd of candidates) {
    try {
      const version = execSync(`${cmd} --version 2>&1`, {
        encoding: "utf-8",
        timeout: 5000,
      }).trim();
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (match && parseInt(match[1]) >= 3 && parseInt(match[2]) >= 10) {
        return cmd;
      }
    } catch {
      // Try next candidate
    }
  }
  return null;
}

function ensureVenv(python) {
  const venvPython =
    process.platform === "win32"
      ? path.join(VENV_DIR, "Scripts", "python.exe")
      : path.join(VENV_DIR, "bin", "python");

  if (!fs.existsSync(venvPython)) {
    process.stderr.write("[arkheia] Creating virtual environment...\n");
    execSync(`${python} -m venv "${VENV_DIR}"`, { stdio: "inherit" });
  }

  return venvPython;
}

function installDeps(venvPython) {
  const marker = path.join(VENV_DIR, ".arkheia-deps-installed");
  if (fs.existsSync(marker)) {
    return; // Already installed
  }

  process.stderr.write("[arkheia] Installing dependencies...\n");
  execSync(`"${venvPython}" -m pip install --quiet -r "${REQUIREMENTS}"`, {
    stdio: "inherit",
    timeout: 120000,
  });

  fs.writeFileSync(marker, new Date().toISOString());
}

function main() {
  const python = findPython();
  if (!python) {
    process.stderr.write(
      "[arkheia] Error: Python 3.10+ is required but not found.\n" +
        "Install Python from https://python.org and try again.\n"
    );
    process.exit(1);
  }

  // ── Load config from ~/.arkheia/config.json ──────────────────
  const configPath = path.join(
    process.env.HOME || process.env.USERPROFILE || "/tmp",
    ".arkheia",
    "config.json"
  );
  let arkheiaConfig = {};
  try {
    if (fs.existsSync(configPath)) {
      arkheiaConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
      process.stderr.write(`[arkheia] Loaded config from ${configPath}\n`);
    }
  } catch (err) {
    process.stderr.write(
      `[arkheia] Warning: Could not read ${configPath}: ${err.message}\n`
    );
  }

  // Inject API key from config if not already in env
  if (!process.env.ARKHEIA_API_KEY && arkheiaConfig.api_key) {
    process.env.ARKHEIA_API_KEY = arkheiaConfig.api_key;
    process.stderr.write("[arkheia] API key loaded from config.json\n");
  }

  // Inject hosted URL from config if not already in env
  if (!process.env.ARKHEIA_HOSTED_URL && arkheiaConfig.proxy_url) {
    process.env.ARKHEIA_HOSTED_URL = arkheiaConfig.proxy_url;
    process.stderr.write(`[arkheia] Hosted URL: ${arkheiaConfig.proxy_url}\n`);
  }

  // Check for API key
  if (!process.env.ARKHEIA_API_KEY) {
    process.stderr.write(
      "[arkheia] Warning: ARKHEIA_API_KEY not set.\n" +
        "Get a free API key at https://arkheia.ai/mcp\n" +
        "Then set: export ARKHEIA_API_KEY=ak_live_...\n\n"
    );
  }

  let venvPython;
  try {
    venvPython = ensureVenv(python);
    installDeps(venvPython);
  } catch (err) {
    process.stderr.write(
      `[arkheia] Error setting up Python environment: ${err.message}\n`
    );
    process.exit(1);
  }

  // Spawn the MCP server with stdio transport
  const child = spawn(
    venvPython,
    ["-m", "mcp_server.server"],
    {
      cwd: PYTHON_DIR,
      stdio: ["pipe", "pipe", "inherit"], // stdin/stdout piped, stderr inherited
      env: {
        ...process.env,
        PYTHONPATH: PYTHON_DIR,
      },
    }
  );

  // Forward stdio for MCP protocol
  process.stdin.pipe(child.stdin);
  child.stdout.pipe(process.stdout);

  child.on("error", (err) => {
    process.stderr.write(`[arkheia] Failed to start MCP server: ${err.message}\n`);
    process.exit(1);
  });

  child.on("exit", (code) => {
    process.exit(code || 0);
  });

  // Forward signals
  process.on("SIGINT", () => child.kill("SIGINT"));
  process.on("SIGTERM", () => child.kill("SIGTERM"));
}

main();
