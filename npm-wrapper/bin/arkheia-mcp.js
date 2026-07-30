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
 *   2. Verifies the bundled Python server tree against its pack-time manifest
 *   3. Ensures mcp_server dependencies are installed (pip install)
 *   4. Spawns `python -m mcp_server.server` with stdio transport
 *   5. Forwards stdin/stdout/stderr (MCP uses stdio)
 *
 * Environment variables:
 *   ARKHEIA_API_KEY     — API key for hosted detection (required)
 *   ARKHEIA_PROXY_URL   — Local proxy URL (optional, for enterprise)
 *   ARKHEIA_HOSTED_URL  — Hosted API URL (default: https://arkheia-proxy-production.up.railway.app)
 */

const { spawn, execFileSync } = require("child_process");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const os = require("os");

const PACKAGE_ROOT = path.resolve(__dirname, "..");
const USER_HOME = process.env.HOME || process.env.USERPROFILE || os.homedir();
if (!USER_HOME) {
  fail("could not determine a user home directory for Arkheia runtime state");
}
const ARKHEIA_HOME = path.join(USER_HOME, ".arkheia");
const BUNDLED_PYTHON_DIR = path.join(__dirname, "..", "python");
const VENV_DIR = path.join(ARKHEIA_HOME, "venv");
const VENV_MARKER = path.join(VENV_DIR, ".arkheia-venv.json");
const ENTRY_MODULE = "mcp_server.server";
const SERVER_RELATIVE = "mcp_server/server.py";
const REQUIREMENTS_RELATIVE = "requirements.txt";
const PROVENANCE_RELATIVE = ".arkheia-bundle-provenance.json";
const PROVENANCE_PATH = path.join(BUNDLED_PYTHON_DIR, PROVENANCE_RELATIVE);
const REQUIREMENTS = path.join(BUNDLED_PYTHON_DIR, REQUIREMENTS_RELATIVE);
const PROVENANCE_SCHEMA = "arkheia.npm.bundle-provenance.v1";
const VENV_SCHEMA = "arkheia.npm.venv.v1";
const RUNTIME_REQUIREMENTS = new Map([
  ["annotated-types", "0.8.0"],
  ["anyio", "4.14.2"],
  ["attrs", "26.1.0"],
  ["certifi", "2026.7.22"],
  ["cffi", "2.1.0"],
  ["click", "8.4.2"],
  ["cryptography", "49.0.0"],
  ["exceptiongroup", "1.3.1"],
  ["h11", "0.16.0"],
  ["httpcore", "1.0.9"],
  ["httpx", "0.27.1"],
  ["httpx-sse", "0.4.3"],
  ["idna", "3.18"],
  ["jsonschema", "4.26.0"],
  ["jsonschema-specifications", "2025.9.1"],
  ["mcp", "1.28.1"],
  ["pycparser", "3.0"],
  ["pydantic", "2.11.0"],
  ["pydantic-core", "2.33.0"],
  ["pydantic-settings", "2.14.2"],
  ["pyjwt", "2.13.0"],
  ["python-dotenv", "1.2.2"],
  ["python-multipart", "0.0.32"],
  ["pyyaml", "6.0.3"],
  ["referencing", "0.37.0"],
  ["rpds-py", "2026.6.3"],
  ["sniffio", "1.3.1"],
  ["sse-starlette", "3.4.6"],
  ["starlette", "1.3.1"],
  ["typing-extensions", "4.16.0"],
  ["typing-inspection", "0.4.2"],
  ["uvicorn", "0.52.0"],
]);
const BOOTSTRAP_ENV_ALLOWLIST = [
  "PATH",
  "HOME",
  "USERPROFILE",
  "SystemRoot",
  "WINDIR",
  "TMPDIR",
  "TEMP",
  "TMP",
  "APPDATA",
  "LOCALAPPDATA",
  "ARKHEIA_TEST_LOG",
];
const SERVER_ENV_ALLOWLIST = [
  ...BOOTSTRAP_ENV_ALLOWLIST,
  "ARKHEIA_API_KEY",
  "ARKHEIA_PROXY_URL",
  "ARKHEIA_HOSTED_URL",
  "MEMORY_DB_PATH",
  "XAI_API_KEY",
  "GOOGLE_API_KEY",
  "TOGETHER_API_KEY",
  "OLLAMA_BASE_URL",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "NO_PROXY",
  "SSL_CERT_FILE",
  "REQUESTS_CA_BUNDLE",
];

function fail(message) {
  process.stderr.write(`[arkheia] Error: ${message}\n`);
  process.exit(1);
}

function inside(child, parent) {
  return child === parent || child.startsWith(parent + path.sep);
}

function toPosix(relativePath) {
  return relativePath.split(path.sep).join("/");
}

function resolveBundlePath(relativePath, label) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    fail(`${label} is not a non-empty relative path`);
  }
  if (path.isAbsolute(relativePath) || /^[A-Za-z]:/.test(relativePath)) {
    fail(`${label} is absolute: ${relativePath}`);
  }
  const normalised = path.normalize(relativePath);
  if (normalised.split(/[\\/]/).includes("..")) {
    fail(`${label} escapes the bundled Python tree: ${relativePath}`);
  }
  const resolved = path.resolve(BUNDLED_PYTHON_DIR, normalised);
  if (!inside(resolved, BUNDLED_PYTHON_DIR)) {
    fail(`${label} resolves outside the bundled Python tree: ${relativePath}`);
  }
  return resolved;
}

function sha256File(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function currentUid() {
  if (process.platform === "win32" || typeof process.getuid !== "function") {
    return null;
  }
  return process.getuid();
}

function ownedByCurrentUser(stat) {
  const uid = currentUid();
  return uid === null || stat.uid === uid;
}

function hasGroupOrOtherBits(stat) {
  return process.platform !== "win32" && (stat.mode & 0o077) !== 0;
}

function ensurePrivateRuntimeHome() {
  if (!fs.existsSync(ARKHEIA_HOME)) {
    fs.mkdirSync(ARKHEIA_HOME, { recursive: true, mode: 0o700 });
    return true;
  }

  const stat = fs.lstatSync(ARKHEIA_HOME);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(`${ARKHEIA_HOME} is not a private runtime directory`);
  }
  if (!ownedByCurrentUser(stat)) {
    fail(`${ARKHEIA_HOME} is not owned by the current user`);
  }
  if (hasGroupOrOtherBits(stat)) {
    fs.chmodSync(ARKHEIA_HOME, 0o700);
    return false;
  }
  return true;
}

function privateRegularFile(filePath) {
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const stat = fs.lstatSync(filePath);
  return (
    stat.isFile() &&
    !stat.isSymbolicLink() &&
    ownedByCurrentUser(stat) &&
    !hasGroupOrOtherBits(stat)
  );
}

function writePrivateFile(filePath, contents) {
  fs.writeFileSync(filePath, contents, { encoding: "utf-8", mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, 0o600);
  }
}

function readJson(filePath, label) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch (err) {
    fail(`could not read ${label} at ${filePath}: ${err.message}`);
  }
}

function executableNames(command) {
  if (process.platform !== "win32") {
    return [command];
  }
  const extensions = (process.env.PATHEXT || ".EXE;.CMD;.BAT")
    .split(";")
    .filter(Boolean);
  const hasExtension = /\.[A-Za-z0-9]+$/.test(command);
  if (hasExtension) {
    return [command];
  }
  return [command, ...extensions.map((ext) => `${command}${ext.toLowerCase()}`)];
}

function findExecutableOnPath(command) {
  const pathValue = process.env.PATH || "";
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) continue;
    const resolvedDir = path.resolve(dir);
    for (const name of executableNames(command)) {
      const candidate = path.join(resolvedDir, name);
      try {
        const stat = fs.statSync(candidate);
        if (stat.isFile()) {
          return fs.realpathSync(candidate);
        }
      } catch {
        // Try the next PATH entry.
      }
    }
  }
  return null;
}

function bootstrapEnv(extra = {}) {
  const env = {};
  for (const name of BOOTSTRAP_ENV_ALLOWLIST) {
    if (process.env[name]) {
      env[name] = process.env[name];
    }
  }
  return { ...env, ...extra };
}

function serverEnv(extra = {}) {
  const env = {};
  for (const name of SERVER_ENV_ALLOWLIST) {
    if (process.env[name]) {
      env[name] = process.env[name];
    }
  }
  return { ...env, ...extra };
}

function collectBundleFiles(dir, relative = "") {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = relative ? path.join(relative, entry.name) : entry.name;
    const relPosix = toPosix(rel);
    if (relPosix === PROVENANCE_RELATIVE) continue;

    const absolute = path.resolve(dir, entry.name);
    if (!inside(absolute, BUNDLED_PYTHON_DIR)) {
      fail(`bundled path resolves outside the bundled Python tree: ${relPosix}`);
    }
    if (entry.isSymbolicLink()) {
      fail(`bundle provenance refuses symbolic links in the bundled Python tree: ${relPosix}`);
    }
    if (entry.isDirectory()) {
      files.push(...collectBundleFiles(absolute, rel));
    } else if (entry.isFile()) {
      files.push(relPosix);
    }
  }
  return files.sort();
}

function normaliseRequirementName(name) {
  return name.toLowerCase().replace(/_/g, "-");
}

function validateRequirementsPolicy() {
  const lines = fs.readFileSync(REQUIREMENTS, "utf-8").split(/\r?\n/);
  const seen = new Set();
  let pendingRequirement = null;
  let pendingHashes = 0;

  const finishRequirement = () => {
    if (pendingRequirement && pendingHashes === 0) {
      fail(`${REQUIREMENTS_RELATIVE} entry ${pendingRequirement} has no --hash pins`);
    }
    pendingRequirement = null;
    pendingHashes = 0;
  };

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    if (trimmed.startsWith("--hash=")) {
      if (!pendingRequirement) {
        fail(`${REQUIREMENTS_RELATIVE} contains a hash with no requirement`);
      }
      pendingHashes += 1;
      continue;
    }
    if (trimmed.startsWith("-")) {
      fail(`${REQUIREMENTS_RELATIVE} contains unsupported pip option: ${trimmed}`);
    }

    finishRequirement();
    const requirement = trimmed.endsWith("\\") ? trimmed.slice(0, -1).trim() : trimmed;
    const match = requirement.match(
      /^([A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?==([^\s;]+)(?:\s*;\s*[^#]+)?$/
    );
    if (!match) {
      fail(`${REQUIREMENTS_RELATIVE} entries must be exact hash-pinned packages: ${trimmed}`);
    }
    const name = normaliseRequirementName(match[1]);
    const version = match[2];
    const expectedVersion = RUNTIME_REQUIREMENTS.get(name);
    if (expectedVersion !== version) {
      fail(
        `${REQUIREMENTS_RELATIVE} contains unapproved package/version ` +
          `${name}==${version}`
      );
    }
    if (seen.has(name)) {
      fail(`${REQUIREMENTS_RELATIVE} contains duplicate package ${name}`);
    }
    seen.add(name);
    pendingRequirement = `${name}==${version}`;
  }
  finishRequirement();

  for (const [name] of RUNTIME_REQUIREMENTS) {
    if (!seen.has(name)) {
      fail(`${REQUIREMENTS_RELATIVE} is missing approved package ${name}`);
    }
  }
}

function verifyBundle() {
  if (!fs.existsSync(BUNDLED_PYTHON_DIR) || !fs.statSync(BUNDLED_PYTHON_DIR).isDirectory()) {
    fail(
      `bundled Python server tree is absent at ${BUNDLED_PYTHON_DIR}. ` +
        "This npm package is incomplete; refusing to fetch code at runtime."
    );
  }

  const serverPath = resolveBundlePath(SERVER_RELATIVE, "server module path");
  if (!fs.existsSync(serverPath) || !fs.statSync(serverPath).isFile()) {
    fail(
      `bundled Python server code is missing at ${serverPath}. ` +
        "This npm package is incomplete; refusing to fetch code at runtime."
    );
  }

  if (!fs.existsSync(REQUIREMENTS) || !fs.statSync(REQUIREMENTS).isFile()) {
    fail(
      `bundled dependency manifest is missing at ${REQUIREMENTS}. ` +
        "Dependencies may only be installed from the package-owned requirements file."
    );
  }

  if (!fs.existsSync(PROVENANCE_PATH) || !fs.statSync(PROVENANCE_PATH).isFile()) {
    fail(
      `bundle provenance manifest is missing at ${PROVENANCE_PATH}. ` +
        "The package content cannot be verified, so startup is blocked."
    );
  }

  const provenance = readJson(PROVENANCE_PATH, "bundle provenance manifest");
  const packageManifest = readJson(path.join(PACKAGE_ROOT, "package.json"), "package manifest");
  const packageInfo = provenance.package || {};

  if (provenance.schema !== PROVENANCE_SCHEMA) {
    fail(`unsupported bundle provenance schema: ${JSON.stringify(provenance.schema)}`);
  }
  if (packageInfo.name !== packageManifest.name || packageInfo.version !== packageManifest.version) {
    fail(
      "bundle provenance package identity does not match package.json " +
        `(${packageInfo.name}@${packageInfo.version} vs ` +
        `${packageManifest.name}@${packageManifest.version})`
    );
  }
  if (provenance.entry_module !== ENTRY_MODULE) {
    fail(
      `bundle provenance names entry module ${JSON.stringify(provenance.entry_module)}, ` +
        `but the launcher runs ${ENTRY_MODULE}`
    );
  }
  if (provenance.bundle_root !== path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)) {
    fail(
      `bundle provenance root ${JSON.stringify(provenance.bundle_root)} does not ` +
        `match ${path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)}`
    );
  }
  if (!Array.isArray(provenance.files) || provenance.files.length === 0) {
    fail("bundle provenance manifest contains no file hashes");
  }

  const manifestFiles = new Map();
  for (const entry of provenance.files) {
    if (!entry || typeof entry.path !== "string" || typeof entry.sha256 !== "string") {
      fail(`invalid bundle provenance file entry: ${JSON.stringify(entry)}`);
    }
    if (!/^[a-f0-9]{64}$/.test(entry.sha256)) {
      fail(`invalid sha256 for ${entry.path}: ${entry.sha256}`);
    }
    if (manifestFiles.has(entry.path)) {
      fail(`duplicate bundle provenance entry for ${entry.path}`);
    }
    const filePath = resolveBundlePath(entry.path, "bundle provenance path");
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      fail(`bundle provenance path is missing from disk: ${entry.path}`);
    }
    const actual = sha256File(filePath);
    if (actual !== entry.sha256) {
      fail(`bundle provenance hash mismatch for ${entry.path}`);
    }
    manifestFiles.set(entry.path, entry.sha256);
  }

  for (const required of [SERVER_RELATIVE, REQUIREMENTS_RELATIVE]) {
    if (!manifestFiles.has(required)) {
      fail(`bundle provenance does not pin required file ${required}`);
    }
  }
  validateRequirementsPolicy();

  const actualFiles = collectBundleFiles(BUNDLED_PYTHON_DIR);
  const declaredFiles = [...manifestFiles.keys()].sort();
  const extra = actualFiles.filter((p) => !manifestFiles.has(p));
  const missing = declaredFiles.filter((p) => !actualFiles.includes(p));
  if (extra.length || missing.length) {
    fail(
      "bundle provenance file set does not match the bundled Python tree. " +
        `Extra: ${JSON.stringify(extra)}; missing: ${JSON.stringify(missing)}`
    );
  }

  return {
    packageName: packageManifest.name,
    packageVersion: packageManifest.version,
    requirementsSha256: manifestFiles.get(REQUIREMENTS_RELATIVE),
  };
}

function findPython() {
  const candidates = ["python3", "python"];
  for (const cmd of candidates) {
    const resolved = findExecutableOnPath(cmd);
    if (!resolved) continue;
    try {
      const version = execFileSync(resolved, ["--version"], {
        encoding: "utf-8",
        timeout: 5000,
        stdio: ["ignore", "pipe", "pipe"],
        env: bootstrapEnv(),
      }).trim();
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (match) {
        const major = parseInt(match[1], 10);
        const minor = parseInt(match[2], 10);
        if (major > 3 || (major === 3 && minor >= 10)) {
          return resolved;
        }
      }
    } catch {
      // Try next candidate
    }
  }
  return null;
}

function venvMarkerMatches(bundle) {
  if (!privateRegularFile(VENV_MARKER)) {
    return false;
  }
  try {
    const data = JSON.parse(fs.readFileSync(VENV_MARKER, "utf-8"));
    return (
      data &&
      data.schema === VENV_SCHEMA &&
      data.package_name === bundle.packageName &&
      data.package_version === bundle.packageVersion &&
      data.requirements_sha256 === bundle.requirementsSha256
    );
  } catch {
    return false;
  }
}

function writeVenvMarker(bundle) {
  writePrivateFile(
    VENV_MARKER,
    JSON.stringify(
      {
        schema: VENV_SCHEMA,
        package_name: bundle.packageName,
        package_version: bundle.packageVersion,
        requirements_sha256: bundle.requirementsSha256,
        created_at: new Date().toISOString(),
      },
      null,
      2
    ) + "\n"
  );
}

function venvCanBeReused(bundle, runtimeHomeTrusted, venvPython) {
  if (!runtimeHomeTrusted || !venvMarkerMatches(bundle)) {
    return false;
  }
  try {
    const venvStat = fs.lstatSync(VENV_DIR);
    const pythonStat = fs.lstatSync(venvPython);
    if (!venvStat.isDirectory() || venvStat.isSymbolicLink()) {
      return false;
    }
    if (!pythonStat.isFile() || pythonStat.isSymbolicLink()) {
      return false;
    }
    const realVenv = fs.realpathSync(VENV_DIR);
    const realPython = fs.realpathSync(venvPython);
    return inside(realPython, realVenv);
  } catch {
    return false;
  }
}

function ensureVenv(python, bundle, runtimeHomeTrusted) {
  const venvPython =
    process.platform === "win32"
      ? path.join(VENV_DIR, "Scripts", "python.exe")
      : path.join(VENV_DIR, "bin", "python");

  if (venvCanBeReused(bundle, runtimeHomeTrusted, venvPython)) {
    return fs.realpathSync(venvPython);
  }

  if (fs.existsSync(VENV_DIR)) {
    process.stderr.write("[arkheia] Recreating virtual environment from verified package bytes...\n");
    fs.rmSync(VENV_DIR, { recursive: true, force: true });
  }

  process.stderr.write("[arkheia] Creating virtual environment...\n");
  execFileSync(python, ["-m", "venv", VENV_DIR], {
    stdio: "inherit",
    timeout: 120000,
    env: bootstrapEnv(),
  });
  if (!fs.existsSync(venvPython)) {
    fail(`virtual environment did not create expected interpreter at ${venvPython}`);
  }
  writeVenvMarker(bundle);
  return fs.realpathSync(venvPython);
}

function depsMarkerMatches(marker, bundle) {
  if (!privateRegularFile(marker)) {
    return false;
  }
  try {
    const data = JSON.parse(fs.readFileSync(marker, "utf-8"));
    return (
      data &&
      data.schema === "arkheia.npm.deps.v1" &&
      data.package_name === bundle.packageName &&
      data.package_version === bundle.packageVersion &&
      data.requirements_sha256 === bundle.requirementsSha256
    );
  } catch {
    return false;
  }
}

function installDeps(venvPython, bundle) {
  const marker = path.join(VENV_DIR, ".arkheia-deps-installed.json");
  if (depsMarkerMatches(marker, bundle)) {
    return; // Already installed for this verified requirements file
  }

  process.stderr.write("[arkheia] Installing dependencies from verified bundle requirements...\n");
  execFileSync(
    venvPython,
    [
      "-m",
      "pip",
      "install",
      "--quiet",
      "--disable-pip-version-check",
      "--no-cache-dir",
      "--require-hashes",
      "-r",
      REQUIREMENTS,
    ],
    {
      stdio: "inherit",
      timeout: 120000,
      env: bootstrapEnv({
        PIP_DISABLE_PIP_VERSION_CHECK: "1",
        PIP_NO_INPUT: "1",
        PIP_REQUIRE_VIRTUALENV: "1",
      }),
    }
  );

  writePrivateFile(
    marker,
    JSON.stringify(
      {
        schema: "arkheia.npm.deps.v1",
        package_name: bundle.packageName,
        package_version: bundle.packageVersion,
        requirements_sha256: bundle.requirementsSha256,
        installed_at: new Date().toISOString(),
      },
      null,
      2
    ) + "\n"
  );
}

function main() {
  const bundle = verifyBundle();
  const python = findPython();
  if (!python) {
    process.stderr.write(
      "[arkheia] Error: Python 3.10+ is required but not found.\n" +
        "Install Python from https://python.org and try again.\n"
    );
    process.exit(1);
  }
  const runtimeHomeTrusted = ensurePrivateRuntimeHome();

  // ── Load config from ~/.arkheia/config.json ──────────────────
  const configPath = path.join(ARKHEIA_HOME, "config.json");
  let arkheiaConfig = {};
  try {
    if (fs.existsSync(configPath)) {
      if (!runtimeHomeTrusted || !privateRegularFile(configPath)) {
        process.stderr.write(`[arkheia] Warning: Ignoring non-private config at ${configPath}\n`);
      } else {
        arkheiaConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        process.stderr.write(`[arkheia] Loaded config from ${configPath}\n`);
      }
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
        "Then set: export ARKHEIA_API_KEY=<arkheia-api-key>\n\n"
    );
  }

  let venvPython;
  try {
    venvPython = ensureVenv(python, bundle, runtimeHomeTrusted);
    installDeps(venvPython, bundle);
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
      cwd: BUNDLED_PYTHON_DIR,
      stdio: ["pipe", "pipe", "inherit"], // stdin/stdout piped, stderr inherited
      env: serverEnv({
        PYTHONPATH: BUNDLED_PYTHON_DIR,
        PYTHONDONTWRITEBYTECODE: "1",
      }),
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
