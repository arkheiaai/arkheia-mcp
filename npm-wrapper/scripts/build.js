#!/usr/bin/env node
/**
 * Build script — copies Python MCP server source into npm package.
 * Run before `npm publish`.
 *
 * Usage: node scripts/build.js
 *
 * WHY THIS COPIES MORE THAN `mcp_server/`
 * ---------------------------------------
 * `mcp_server.receipts` drives the estate's audit rail (`proxy.audit.writer`: JSONL,
 * secrets redaction, tamper-evident hash chain) rather than growing a second one, so
 * `mcp_server.tools.memory` — and therefore `mcp_server.server` — imports from the
 * `proxy` package. The bundle used to contain `mcp_server/` and nothing else, so that
 * import would raise ModuleNotFoundError on `npx @arkheia/mcp-server` while every test
 * on a developer's checkout passed, because a checkout has the whole repo on the path.
 * The registry image hit exactly this, and this is the same fix.
 *
 * Both added paths are stdlib-only, so this pulls in no new dependency.
 *
 * PACKAGE_SOURCES is the single declared list, and `tests/test_mcp_packaging_floor.py`
 * DERIVES the required set from the actual first-party imports of `mcp_server` and fails
 * if this list does not cover it. A future cross-package import that is not added here
 * fails there rather than at a customer's first run.
 */

const fs = require("fs");
const path = require("path");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const DEST_ROOT = path.resolve(__dirname, "..", "python");

// Repo-relative paths copied into the bundle, preserving their layout so package
// imports (`mcp_server.*`, `proxy.audit.*`) resolve unchanged. Directories are copied
// recursively; `.py` files only, no tests, no __pycache__.
const PACKAGE_SOURCES = [
  "mcp_server",
  "proxy/__init__.py",
  "proxy/audit",
];

function copyDir(src, dest) {
  if (!fs.existsSync(dest)) {
    fs.mkdirSync(dest, { recursive: true });
  }
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.name === "__pycache__" || entry.name === "tests") continue;
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else if (entry.name.endsWith(".py")) {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
}

for (const rel of PACKAGE_SOURCES) {
  const src = path.join(REPO_ROOT, rel);
  const dest = path.join(DEST_ROOT, rel);
  if (!fs.existsSync(src)) {
    console.error(`Build FAILED: declared source ${rel} does not exist at ${src}`);
    process.exit(1);
  }
  console.log(`Copying ${src} -> ${dest}`);
  if (fs.statSync(src).isDirectory()) {
    copyDir(src, dest);
  } else {
    copyFile(src, dest);
  }
}

console.log("Build complete. Run `npm publish` from npm-wrapper/.");
