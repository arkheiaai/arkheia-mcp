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

const PYTHON_DIR = path.join(__dirname, "..", "python");
const REQUIREMENTS = path.join(PYTHON_DIR, "requirements.txt");
const VENV_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".arkheia",
  "venv"
);

function findPython() {
  // Try versioned interpreters first — on Homebrew, keg-only formulae like
  // python@3.12 only expose the versioned binary (python3.12), not python3.
  // Exclude 3.14: Homebrew's build has broken pyexpat on macOS as of Apr 2026.
  const candidates = ["python3.13", "python3.12", "python3.11", "python3", "python"];
  for (const cmd of candidates) {
    try {
      // Check version AND that pyexpat + ensurepip actually work.
      // Python 3.14 on macOS crashes on `import pyexpat` due to a missing
      // libexpat symbol — this import check catches it at discovery time.
      const output = execSync(
        `${cmd} -c "import sys,pyexpat,ensurepip; print(f'{sys.version_info.major}.{sys.version_info.minor}')"`,
        { encoding: "utf-8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"] }
      ).trim();
      const match = output.match(/^(\d+)\.(\d+)$/);
      if (match) {
        const major = parseInt(match[1]);
        const minor = parseInt(match[2]);
        if (major === 3 && minor >= 10 && minor <= 13) {
          return cmd;
        }
      }
    } catch {
      // Try next candidate
    }
  }
  return null;
}

function venvIsHealthy(venvPython) {
  if (!fs.existsSync(venvPython)) return false;
  try {
    execSync(`"${venvPython}" -m pip --version`, {
      encoding: "utf-8", timeout: 10000, stdio: ["pipe", "pipe", "pipe"],
    });
    return true;
  } catch {
    return false;
  }
}

function ensureVenv(python) {
  const venvPython =
    process.platform === "win32"
      ? path.join(VENV_DIR, "Scripts", "python.exe")
      : path.join(VENV_DIR, "bin", "python");

  if (!venvIsHealthy(venvPython)) {
    if (fs.existsSync(VENV_DIR)) {
      process.stderr.write("[arkheia] Existing venv is unhealthy (pip broken or missing). Recreating...\n");
      fs.rmSync(VENV_DIR, { recursive: true, force: true });
    }
    process.stderr.write("[arkheia] Creating virtual environment...\n");
    execSync(`${python} -m venv "${VENV_DIR}"`, { stdio: "inherit" });
    // Force-reinstall deps after venv recreation
    const marker = path.join(VENV_DIR, ".arkheia-deps-installed");
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
  }

  return venvPython;
}

function installDeps(venvPython) {
  const marker = path.join(VENV_DIR, ".arkheia-deps-installed");
  if (fs.existsSync(marker)) {
    return; // Already installed
  }

  const logFile = path.join(ARKHEIA_HOME, "install.log");
  process.stderr.write("[arkheia] Installing Python dependencies (first run)...\n");
  const start = Date.now();
  try {
    const output = execSync(`"${venvPython}" -m pip install -r "${REQUIREMENTS}" 2>&1`, {
      encoding: "utf-8",
      timeout: 300000, // 5 min — slow networks exist
    });
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    // Count installed packages from pip output
    const installed = (output.match(/Successfully installed/g) || []).length;
    process.stderr.write(`[arkheia] Dependencies installed in ${elapsed}s\n`);
    fs.writeFileSync(marker, new Date().toISOString());
  } catch (err) {
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    // Save full pip output for debugging
    const pipOutput = err.stdout || err.stderr || err.message || "unknown error";
    fs.writeFileSync(logFile, pipOutput);
    process.stderr.write(
      `[arkheia] Dependency install failed after ${elapsed}s.\n` +
      `[arkheia] Full output saved to: ${logFile}\n` +
      `[arkheia] Try: "${venvPython}" -m pip install -r "${REQUIREMENTS}"\n`
    );
    throw err;
  }
}

function main() {
  // ── CRLF warning — env files with Windows line endings silently break API keys
  for (const k of ["ARKHEIA_API_KEY", "ARKHEIA_PROXY_URL", "ARKHEIA_HOSTED_URL"]) {
    const v = process.env[k];
    if (v && /[\r\n]/.test(v)) {
      process.stderr.write(
        `[arkheia] WARNING: ${k} contains whitespace/newline characters.\n` +
        `[arkheia] Your env file may have Windows (CRLF) line endings. Run 'dos2unix' on it.\n`
      );
      process.env[k] = v.trim(); // auto-fix for this run
    }
  }

  const python = findPython();
  if (!python) {
    process.stderr.write(
      "[arkheia] Error: Python 3.10–3.13 is required but not found.\n\n" +
      "  macOS (Homebrew):\n" +
      "    brew install python@3.12\n\n" +
      "  NOTE: Homebrew's current default 'brew install python' installs 3.14,\n" +
      "  which has a broken pyexpat link on macOS as of April 2026.\n" +
      "  Use python@3.12 until Homebrew ships a fix.\n\n" +
      "  After installing, verify with:\n" +
      "    python3.12 -c \"import pyexpat, ensurepip\"\n\n" +
      "  Other platforms: https://python.org\n"
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
  const serverDir = PYTHON_DIR;
  const child = spawn(
    venvPython,
    ["-m", "mcp_server.server"],
    {
      cwd: serverDir,
      stdio: ["pipe", "pipe", "inherit"], // stdin/stdout piped, stderr inherited
      env: {
        ...process.env,
        PYTHONPATH: serverDir,
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
