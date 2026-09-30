#!/usr/bin/env node
/**
 * Installs the Arkheia detection protocol into AI CLI instruction files
 * and registers the MCP server with each detected CLI.
 *
 * Usage:
 *   npx @arkheia/mcp-server --setup
 *   node scripts/setup-claude.js
 *
 * What it does:
 *   1. Detects which AI CLIs are installed (claude, codex, gemini, grok)
 *   2. Appends detection protocol to instruction files that need it:
 *      - Claude Code: ~/.claude/CLAUDE.md
 *      - Codex: ~/.codex/CODEX.md
 *      - Gemini: not needed (reads protocol from tool descriptions)
 *      - Grok: not needed (no instruction file mechanism)
 *   3. Registers the MCP server with each detected CLI
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const { execSync } = require("child_process");

const MARKER = "# Arkheia Integration — Detection Protocol";

const PROTOCOL = `
# Arkheia Integration — Detection Protocol

When Arkheia MCP tools are available in this session, follow this protocol.

## Fabrication Detection

Call \`arkheia_verify\` on EVERY model response before surfacing it to the user. Do not skip responses that appear obviously correct.

## Risk Escalation

- **HIGH risk**: Warn the user that the response may be fabricated. Include the \`detection_id\`. Still show the response — never hide or suppress it. Ask the user if they want to verify with a different model.
- **MEDIUM risk**: Show the response with a brief confidence note.
- **LOW risk**: Show normally.
- **UNKNOWN risk**: Flag for human review. Include the \`detection_id\`.

## Cross-Model Verification

When HIGH or UNKNOWN risk is detected, offer to verify using: \`run_grok\`, \`run_gemini\`, \`run_ollama\`, \`run_together\`.

## Audit Trail

Use \`arkheia_audit_log\` when the user asks about detection history or for compliance evidence.

## Persistent Knowledge Graph

Use \`memory_store\` to persist facts, \`memory_retrieve\` to recall them, \`memory_relate\` to track relationships between entities.

## Key Rules

1. Never hide a response from the user regardless of risk level
2. Always include the \`detection_id\` when reporting HIGH or UNKNOWN risk
3. Call \`arkheia_verify\` proactively — do not wait for the user to ask
4. Audit logging happens automatically through \`arkheia_verify\`
`;

function cmdExists(cmd) {
  try {
    execSync(process.platform === "win32" ? `where ${cmd}` : `which ${cmd}`, { stdio: "pipe" });
    return true;
  } catch { return false; }
}

function installProtocol(filePath, cliName) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  if (fs.existsSync(filePath)) {
    const existing = fs.readFileSync(filePath, "utf8");
    if (existing.includes(MARKER)) {
      console.log(`  [${cliName}] Detection protocol already installed in ${filePath}`);
      return;
    }
    fs.appendFileSync(filePath, "\n" + PROTOCOL);
    console.log(`  [${cliName}] Detection protocol appended to ${filePath}`);
  } else {
    fs.writeFileSync(filePath, PROTOCOL.trim() + "\n");
    console.log(`  [${cliName}] Detection protocol written to ${filePath}`);
  }
}

function registerMcp(cli, args) {
  try {
    execSync(args, { stdio: "inherit", timeout: 15000 });
    console.log(`  [${cli}] MCP server registered`);
  } catch {
    console.log(`  [${cli}] Auto-registration failed — run manually:`);
    console.log(`    ${args}`);
  }
}

function main() {
  const apiKey = process.env.ARKHEIA_API_KEY || "";
  const home = os.homedir();
  const detected = [];

  console.log("\n[arkheia] Setting up detection protocol for installed AI CLIs...\n");

  // ── Claude Code ──────────────────────────────────────────────
  if (cmdExists("claude")) {
    detected.push("claude");
    console.log("[claude] Detected");
    installProtocol(path.join(home, ".claude", "CLAUDE.md"), "claude");
    if (apiKey) {
      registerMcp("claude", `claude mcp add arkheia -s user -e ARKHEIA_API_KEY="${apiKey}" -- mcp-server`);
    } else {
      console.log('  [claude] Set ARKHEIA_API_KEY then run: claude mcp add arkheia -s user -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY" -- mcp-server');
    }
  }

  // ── Codex ────────────────────────────────────────────────────
  if (cmdExists("codex")) {
    detected.push("codex");
    console.log("[codex] Detected");
    installProtocol(path.join(home, ".codex", "CODEX.md"), "codex");
    if (apiKey) {
      registerMcp("codex", `codex mcp add arkheia --env ARKHEIA_API_KEY="${apiKey}" -- mcp-server`);
    } else {
      console.log('  [codex] Set ARKHEIA_API_KEY then run: codex mcp add arkheia --env ARKHEIA_API_KEY="$ARKHEIA_API_KEY" -- mcp-server');
    }
  }

  // ── Gemini ───────────────────────────────────────────────────
  // Gemini reads the detection protocol directly from tool descriptions.
  // No instruction file needed — just register the MCP server.
  if (cmdExists("gemini")) {
    detected.push("gemini");
    console.log("[gemini] Detected (no instruction file needed — reads protocol from tool descriptions)");
    if (apiKey) {
      registerMcp("gemini", `gemini mcp add -s user -e ARKHEIA_API_KEY="${apiKey}" arkheia mcp-server`);
    } else {
      console.log('  [gemini] Set ARKHEIA_API_KEY then run: gemini mcp add -s user -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY" arkheia mcp-server');
    }
  }

  // ── Grok ─────────────────────────────────────────────────────
  // No instruction file mechanism. Register MCP server only.
  if (cmdExists("grok")) {
    detected.push("grok");
    console.log("[grok] Detected (no instruction file mechanism)");
    if (apiKey) {
      registerMcp("grok", `grok mcp add arkheia -t stdio -c mcp-server -e ARKHEIA_API_KEY="${apiKey}"`);
    } else {
      console.log('  [grok] Set ARKHEIA_API_KEY then run: grok mcp add arkheia -t stdio -c mcp-server -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY"');
    }
  }

  if (detected.length === 0) {
    console.log("No AI CLIs detected on PATH (claude, codex, gemini, grok).");
    console.log("Install one and re-run: npx @arkheia/mcp-server --setup");
  } else {
    console.log(`\n[arkheia] Setup complete for: ${detected.join(", ")}`);
    console.log("[arkheia] Restart each CLI to activate Arkheia detection.\n");
  }
}

main();
