#!/usr/bin/env node
/**
 * Build script — copies Python MCP server source into npm package.
 *
 * WIRED TO THE PACKAGE LIFECYCLE — do not rely on anyone running this by hand.
 * `package.json` declares `"prepack": "node scripts/build.js"`, so npm runs it
 * immediately before it assembles a tarball, on BOTH `npm pack` and `npm publish`
 * (and on install-from-git). It used to say only "Run before `npm publish`" and
 * nothing invoked it, so every published tarball shipped
 * `python/mcp_server/__init__.py` and no server: `npx @arkheia/mcp-server` died in
 * ModuleNotFoundError on a customer's first run while every test passed, because a
 * git checkout has the whole repo on sys.path.
 *
 * `prepack` rather than `prepublishOnly` deliberately: `prepublishOnly` does not
 * run on `npm pack`, so no check could observe whether it works without actually
 * publishing. `tests/test_packed_artifact_floor.py` runs the real pack and asserts
 * the tarball's contents, which only works if the hook fires at pack time.
 *
 * Manual use (still supported, e.g. to inspect the bundle):
 *   node scripts/build.js
 */

const fs = require("fs");
const path = require("path");

const SRC = path.resolve(__dirname, "..", "..", "mcp_server");
const DEST = path.resolve(__dirname, "..", "python", "mcp_server");

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

console.log(`Copying ${SRC} -> ${DEST}`);
copyDir(SRC, DEST);
console.log("Build complete. Run `npm publish` from npm-wrapper/.");
