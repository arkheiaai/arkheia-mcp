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
 *   ARKHEIA_ALLOW_UNSAFE_HOSTED_URL — Set to 1 only for trusted public custom hosted URLs
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
const VENV_MARKER_RELATIVE = ".arkheia-venv.json";
const DEPS_MARKER_RELATIVE = ".arkheia-deps-installed.json";
const VENV_MARKER = path.join(VENV_DIR, VENV_MARKER_RELATIVE);
const ENTRY_MODULE = "mcp_server.server";
const SERVER_RELATIVE = "mcp_server/server.py";
const REQUIREMENTS_RELATIVE = "requirements.txt";
const PROVENANCE_RELATIVE = ".arkheia-bundle-provenance.json";
const PROVENANCE_PATH = path.join(BUNDLED_PYTHON_DIR, PROVENANCE_RELATIVE);
const TRUST_ROOT_RELATIVE = "bin/bundle-provenance-root.json";
const TRUST_ROOT_PATH = path.join(PACKAGE_ROOT, TRUST_ROOT_RELATIVE);
const REQUIREMENTS = path.join(BUNDLED_PYTHON_DIR, REQUIREMENTS_RELATIVE);
const PROVENANCE_SCHEMA = "arkheia.npm.bundle-provenance.v1";
const TRUST_ROOT_SCHEMA = "arkheia.npm.bundle-trust-root.v1";
const VENV_SCHEMA = "arkheia.npm.venv.v1";
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

function resolveFileUnder(root, relativePath, label) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    fail(`${label} is not a non-empty relative path`);
  }
  if (relativePath.includes("\0")) {
    fail(`${label} contains a NUL byte`);
  }
  if (path.isAbsolute(relativePath) || /^[A-Za-z]:/.test(relativePath)) {
    fail(`${label} is absolute: ${relativePath}`);
  }
  const normalised = path.normalize(relativePath);
  if (normalised.split(/[\\/]/).includes("..")) {
    fail(`${label} escapes its root: ${relativePath}`);
  }
  const resolved = path.resolve(root, normalised);
  if (!inside(resolved, root)) {
    fail(`${label} resolves outside ${root}: ${relativePath}`);
  }
  requireRegularFileNoSymlink(resolved, label);
  return resolved;
}

function sha256FileUnder(root, relativePath, label = "file to hash") {
  if (typeof relativePath !== "string" || relativePath.includes("\0")) {
    fail(`${label} is not a safe relative path`);
  }
  if (path.isAbsolute(relativePath) || /^[A-Za-z]:/.test(relativePath)) {
    fail(`${label} is absolute: ${relativePath}`);
  }
  if (path.normalize(relativePath).split(/[\\/]/).includes("..")) {
    fail(`${label} escapes its root: ${relativePath}`);
  }
  const resolved = resolveFileUnder(root, relativePath, label);
  return crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex");
}

function readJsonUnder(root, relativePath, label) {
  if (typeof relativePath !== "string" || relativePath.includes("\0")) {
    fail(`${label} is not a safe relative path`);
  }
  if (path.isAbsolute(relativePath) || /^[A-Za-z]:/.test(relativePath)) {
    fail(`${label} is absolute: ${relativePath}`);
  }
  if (path.normalize(relativePath).split(/[\\/]/).includes("..")) {
    fail(`${label} escapes its root: ${relativePath}`);
  }
  const resolved = resolveFileUnder(root, relativePath, label);
  try {
    return JSON.parse(fs.readFileSync(resolved, "utf-8"));
  } catch (err) {
    fail(`could not read ${label} at ${resolved}: ${err.message}`);
  }
}

function requireRegularFileNoSymlink(filePath, label) {
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (err) {
    fail(`${label} is missing at ${filePath}: ${err.message}`);
  }
  if (stat.isSymbolicLink()) {
    fail(`${label} is a symlink at ${filePath}`);
  }
  if (!stat.isFile()) {
    fail(`${label} is not a regular file at ${filePath}`);
  }
  return stat;
}

function requireDirectoryNoSymlink(dirPath, label) {
  let stat;
  try {
    stat = fs.lstatSync(dirPath);
  } catch (err) {
    fail(`${label} is missing at ${dirPath}: ${err.message}`);
  }
  if (stat.isSymbolicLink()) {
    fail(`${label} is a symlink at ${dirPath}`);
  }
  if (!stat.isDirectory()) {
    fail(`${label} is not a directory at ${dirPath}`);
  }
  return stat;
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
  requireDirectoryNoSymlink(
    dir,
    relative ? `bundled directory ${toPosix(relative)}` : "bundled Python tree"
  );

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
      fail(`bundled Python tree contains unsupported symlink: ${relPosix}`);
    }
    if (entry.isDirectory()) {
      files.push(...collectBundleFiles(absolute, rel));
    } else if (entry.isFile()) {
      files.push(relPosix);
    } else {
      fail(`bundled Python tree contains unsupported filesystem entry: ${relPosix}`);
    }
  }
  return files.sort();
}

function verifyBundle() {
  if (!fs.existsSync(BUNDLED_PYTHON_DIR)) {
    fail(
      `bundled Python server tree is absent at ${BUNDLED_PYTHON_DIR}. ` +
        "This npm package is incomplete; refusing to fetch code at runtime."
    );
  }
  requireDirectoryNoSymlink(BUNDLED_PYTHON_DIR, "bundled Python server tree");

  const serverPath = resolveBundlePath(SERVER_RELATIVE, "server module path");
  if (!fs.existsSync(serverPath)) {
    fail(
      `bundled Python server code is missing at ${serverPath}. ` +
        "This npm package is incomplete; refusing to fetch code at runtime."
    );
  }
  requireRegularFileNoSymlink(serverPath, "bundled Python server code");

  if (!fs.existsSync(REQUIREMENTS)) {
    fail(
      `bundled dependency manifest is missing at ${REQUIREMENTS}. ` +
        "Dependencies may only be installed from the package-owned requirements file."
    );
  }
  requireRegularFileNoSymlink(REQUIREMENTS, "bundled dependency manifest");

  if (!fs.existsSync(PROVENANCE_PATH)) {
    fail(
      `bundle provenance manifest is missing at ${PROVENANCE_PATH}. ` +
        "The package content cannot be verified, so startup is blocked."
    );
  }
  requireRegularFileNoSymlink(PROVENANCE_PATH, "bundle provenance manifest");
  if (!fs.existsSync(TRUST_ROOT_PATH)) {
    fail(
      `bundle provenance trust root is missing at ${TRUST_ROOT_PATH}. ` +
        "The package content cannot be anchored outside the bundled Python tree."
    );
  }
  requireRegularFileNoSymlink(TRUST_ROOT_PATH, "bundle provenance trust root");

  const provenance = readJsonUnder(
    BUNDLED_PYTHON_DIR,
    PROVENANCE_RELATIVE,
    "bundle provenance manifest"
  );
  const trustRoot = readJsonUnder(
    PACKAGE_ROOT,
    TRUST_ROOT_RELATIVE,
    "bundle provenance trust root"
  );
  const packageManifest = readJsonUnder(PACKAGE_ROOT, "package.json", "package manifest");
  const packageInfo = provenance.package || {};
  const trustPackageInfo = trustRoot.package || {};

  if (provenance.schema !== PROVENANCE_SCHEMA) {
    fail(`unsupported bundle provenance schema: ${JSON.stringify(provenance.schema)}`);
  }
  if (trustRoot.schema !== TRUST_ROOT_SCHEMA) {
    fail(`unsupported bundle provenance trust root schema: ${JSON.stringify(trustRoot.schema)}`);
  }
  if (packageInfo.name !== packageManifest.name || packageInfo.version !== packageManifest.version) {
    fail(
      "bundle provenance package identity does not match package.json " +
        `(${packageInfo.name}@${packageInfo.version} vs ` +
        `${packageManifest.name}@${packageManifest.version})`
    );
  }
  if (
    trustPackageInfo.name !== packageManifest.name ||
    trustPackageInfo.version !== packageManifest.version
  ) {
    fail(
      "bundle provenance trust root package identity does not match package.json " +
        `(${trustPackageInfo.name}@${trustPackageInfo.version} vs ` +
        `${packageManifest.name}@${packageManifest.version})`
    );
  }
  if (provenance.entry_module !== ENTRY_MODULE) {
    fail(
      `bundle provenance names entry module ${JSON.stringify(provenance.entry_module)}, ` +
        `but the launcher runs ${ENTRY_MODULE}`
    );
  }
  if (trustRoot.entry_module !== ENTRY_MODULE) {
    fail(
      `bundle provenance trust root names entry module ` +
        `${JSON.stringify(trustRoot.entry_module)}, but the launcher runs ${ENTRY_MODULE}`
    );
  }
  if (provenance.bundle_root !== path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)) {
    fail(
      `bundle provenance root ${JSON.stringify(provenance.bundle_root)} does not ` +
        `match ${path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)}`
    );
  }
  if (trustRoot.bundle_root !== path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)) {
    fail(
      `bundle provenance trust root names bundle root ` +
        `${JSON.stringify(trustRoot.bundle_root)}, but the launcher uses ` +
        `${path.relative(PACKAGE_ROOT, BUNDLED_PYTHON_DIR)}`
    );
  }
  const expectedProvenancePath = `${provenance.bundle_root}/${PROVENANCE_RELATIVE}`;
  if (trustRoot.provenance_path !== expectedProvenancePath) {
    fail(
      `bundle provenance trust root points at ${JSON.stringify(trustRoot.provenance_path)}, ` +
        `but the launcher verifies ${expectedProvenancePath}`
    );
  }
  if (typeof trustRoot.provenance_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(trustRoot.provenance_sha256)) {
    fail(`invalid bundle provenance trust root sha256: ${JSON.stringify(trustRoot.provenance_sha256)}`);
  }
  const provenanceSha256 = sha256FileUnder(
    BUNDLED_PYTHON_DIR,
    PROVENANCE_RELATIVE,
    "bundle provenance manifest"
  );
  if (trustRoot.provenance_sha256 !== provenanceSha256) {
    fail(
      "bundle provenance trust root mismatch: the bundled Python manifest has " +
        `${provenanceSha256}, expected ${trustRoot.provenance_sha256}`
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
    if (!fs.existsSync(filePath)) {
      fail(`bundle provenance path is missing from disk: ${entry.path}`);
    }
    requireRegularFileNoSymlink(filePath, `bundle provenance path ${entry.path}`);
    const actual = sha256FileUnder(
      BUNDLED_PYTHON_DIR,
      entry.path,
      `bundle provenance path ${entry.path}`
    );
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
  if (!fs.existsSync(VENV_MARKER)) {
    return false;
  }
  if (!regularFileNoSymlink(VENV_MARKER)) {
    return false;
  }
  try {
    const data = readJsonUnder(VENV_DIR, VENV_MARKER_RELATIVE, "virtual environment marker");
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
  writeMarkerJson(VENV_MARKER_RELATIVE, "virtual environment marker", {
    schema: VENV_SCHEMA,
    package_name: bundle.packageName,
    package_version: bundle.packageVersion,
    requirements_sha256: bundle.requirementsSha256,
    created_at: new Date().toISOString(),
  });
}

function regularFileNoSymlink(filePath) {
  try {
    const stat = fs.lstatSync(filePath);
    return stat.isFile() && !stat.isSymbolicLink();
  } catch {
    return false;
  }
}

function resolveVenvFile(relativePath, label) {
  const resolved = resolveFileUnder(VENV_DIR, relativePath, label);
  return resolved;
}

function writeMarkerJson(relativePath, label, data) {
  if (typeof relativePath !== "string" || relativePath.length === 0) {
    fail(`${label} is not a non-empty relative marker path`);
  }
  if (relativePath.includes("\0")) {
    fail(`${label} contains a NUL byte`);
  }
  if (path.isAbsolute(relativePath) || /^[A-Za-z]:/.test(relativePath)) {
    fail(`${label} is not a safe relative marker path: ${relativePath}`);
  }
  if (path.normalize(relativePath).split(/[\\/]/).includes("..")) {
    fail(`${label} escapes the virtual environment: ${relativePath}`);
  }
  const resolved = path.resolve(VENV_DIR, path.normalize(relativePath));
  if (!inside(resolved, VENV_DIR)) {
    fail(`${label} resolves outside the virtual environment at ${relativePath}`);
  }
  if (fs.existsSync(resolved) && !regularFileNoSymlink(resolved)) {
    fail(`${label} is not a regular file at ${resolved}`);
  }
  fs.writeFileSync(resolved, JSON.stringify(data, null, 2) + "\n", {
    encoding: "utf-8",
    mode: 0o600,
  });
}

function usableMarkedVenv(venvPython) {
  try {
    const venvStat = fs.lstatSync(VENV_DIR);
    if (!venvStat.isDirectory() || venvStat.isSymbolicLink()) {
      return false;
    }
    const venvRoot = fs.realpathSync(VENV_DIR);
    const pythonReal = fs.realpathSync(venvPython);
    return (
      inside(pythonReal, venvRoot) &&
      regularFileNoSymlink(venvPython) &&
      regularFileNoSymlink(path.join(VENV_DIR, "pyvenv.cfg"))
    );
  } catch {
    return false;
  }
}

function ensureVenv(python, bundle) {
  const venvPython =
    process.platform === "win32"
      ? path.join(VENV_DIR, "Scripts", "python.exe")
      : path.join(VENV_DIR, "bin", "python");

  if (venvMarkerMatches(bundle) && usableMarkedVenv(venvPython)) {
    return fs.realpathSync(venvPython);
  }

  if (fs.existsSync(VENV_DIR)) {
    process.stderr.write("[arkheia] Recreating untrusted or stale virtual environment...\n");
    fs.rmSync(VENV_DIR, { recursive: true, force: true });
  }

  if (!fs.existsSync(ARKHEIA_HOME)) {
    fs.mkdirSync(ARKHEIA_HOME, { recursive: true, mode: 0o700 });
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

function depsMarkerMatches(bundle) {
  const marker = path.join(VENV_DIR, DEPS_MARKER_RELATIVE);
  if (!fs.existsSync(marker)) {
    return false;
  }
  if (!regularFileNoSymlink(marker)) {
    return false;
  }
  try {
    const data = readJsonUnder(VENV_DIR, DEPS_MARKER_RELATIVE, "dependency install marker");
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
  const marker = path.join(VENV_DIR, DEPS_MARKER_RELATIVE);
  if (depsMarkerMatches(bundle)) {
    return; // Already installed for this verified requirements file
  }
  if (fs.existsSync(marker) && !regularFileNoSymlink(marker)) {
    fail(`dependency install marker is not a regular file at ${marker}`);
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

  writeMarkerJson(DEPS_MARKER_RELATIVE, "dependency install marker", {
    schema: "arkheia.npm.deps.v1",
    package_name: bundle.packageName,
    package_version: bundle.packageVersion,
    requirements_sha256: bundle.requirementsSha256,
    installed_at: new Date().toISOString(),
  });
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
    venvPython = ensureVenv(python, bundle);
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
