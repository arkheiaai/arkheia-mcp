#!/usr/bin/env node
/**
 * Post-install script for @arkheia/mcp-server.
 *
 * It changes NOTHING on the user's machine: no file in the home directory, no agent instruction file, no saved key.
 * It reads no API key and prints no part of one. It only prints how to finish setup.
 *
 * The detection protocol for Claude Code or Codex is opt-in: copy CLAUDE_MD_TEMPLATE.md (shipped in this package)
 * into your own agent instructions file.
 */
"use strict";

const path = require("path");
const fs = require("fs");

const version = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")).version;
  } catch {
    return "unknown";
  }
})();

console.log(`
  [arkheia] @arkheia/mcp-server v${version} installed. Nothing on your machine was changed.

  To finish setup:
    1. Get a free API key at https://arkheia.ai/mcp/account and set ARKHEIA_API_KEY in your environment
       (or in your MCP client's configuration for this server).
    2. Optional: add the detection protocol to your agent's instructions yourself, by copying
       ${path.join(__dirname, "..", "CLAUDE_MD_TEMPLATE.md")}
`);
