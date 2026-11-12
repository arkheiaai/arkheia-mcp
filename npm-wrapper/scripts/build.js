#!/usr/bin/env node
/**
 * Build script — copies Python MCP server source into npm package.
 * Run before `npm publish`.
 *
 * Usage: node scripts/build.js
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
