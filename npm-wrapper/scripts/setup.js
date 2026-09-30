#!/usr/bin/env node
/**
 * Post-install script for @arkheia/mcp-server.
 *
 * 1. Checks for API key (saves env → config if found)
 * 2. Installs/updates Arkheia detection protocol in ~/.claude/CLAUDE.md
 *    - Versioned managed block with BEGIN/END markers
 *    - Idempotent, non-destructive, backs up before write
 *    - Opt-out: ARKHEIA_SKIP_CLAUDE_MD=1
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

// Resolve home dir — handle sudo
const HOME = (process.env.SUDO_USER
  ? path.join("/home", process.env.SUDO_USER)
  : process.env.HOME || process.env.USERPROFILE || "/tmp");

const ARKHEIA_DIR = path.join(HOME, ".arkheia");
const CONFIG_FILE = path.join(ARKHEIA_DIR, "config.json");
const CLAUDE_DIR = path.join(HOME, ".claude");
const CLAUDE_MD = path.join(CLAUDE_DIR, "CLAUDE.md");

// Read version from package.json
const PKG_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8")).version;
  } catch { return "unknown"; }
})();

// Read template from shipped file
const TEMPLATE = (() => {
  try {
    return fs.readFileSync(path.join(__dirname, "..", "CLAUDE_MD_TEMPLATE.md"), "utf8").trim();
  } catch { return ""; }
})();

const BEGIN_MARKER = `<!-- BEGIN ARKHEIA PROTOCOL v${PKG_VERSION} -->`;
const BEGIN_REGEX = /<!-- BEGIN ARKHEIA PROTOCOL v(.+?) -->/;
const BLOCK_REGEX = /<!-- BEGIN ARKHEIA PROTOCOL v.+? -->[\s\S]*?<!-- END ARKHEIA PROTOCOL -->/;
const END_MARKER = "<!-- END ARKHEIA PROTOCOL -->";

// ── API key provisioning ───────────────────────────────────────

function checkApiKey() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const config = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
      if (config.api_key && config.api_key.length > 0) return config.api_key;
    }
  } catch {}
  if (process.env.ARKHEIA_API_KEY) {
    saveConfig(process.env.ARKHEIA_API_KEY);
    return process.env.ARKHEIA_API_KEY;
  }
  return null;
}

function saveConfig(apiKey) {
  try {
    if (!fs.existsSync(ARKHEIA_DIR)) fs.mkdirSync(ARKHEIA_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
      api_key: apiKey,
      proxy_url: "https://arkheia-proxy-production.up.railway.app",
      provisioned_at: new Date().toISOString(),
    }, null, 2), "utf-8");
  } catch (err) {
    console.error(`  [arkheia] Warning: Could not save config: ${err.message}`);
  }
}

// ── CLAUDE.md managed block install ────────────────────────────

function installClaudeMd() {
  // Opt-out
  if (process.env.ARKHEIA_SKIP_CLAUDE_MD === "1") {
    console.log("  [arkheia] CLAUDE.md install skipped (ARKHEIA_SKIP_CLAUDE_MD=1)");
    return;
  }

  if (!TEMPLATE) {
    console.log("  [arkheia] Warning: CLAUDE_MD_TEMPLATE.md not found in package");
    return;
  }

  const newBlock = `${BEGIN_MARKER}\n${TEMPLATE}\n${END_MARKER}`;

  // Ensure ~/.claude exists
  try {
    if (!fs.existsSync(CLAUDE_DIR)) {
      fs.mkdirSync(CLAUDE_DIR, { recursive: true, mode: 0o700 });
    }
  } catch (err) {
    console.error(`  [arkheia] Could not create ${CLAUDE_DIR}: ${err.message}`);
    return;
  }

  // Symlink check — don't follow symlinks (chezmoi, yadm)
  try {
    if (fs.existsSync(CLAUDE_MD) && fs.lstatSync(CLAUDE_MD).isSymbolicLink()) {
      console.log(`  [arkheia] ${CLAUDE_MD} is a symlink — skipping to avoid corrupting dotfile manager.`);
      console.log(`  [arkheia] Install the Arkheia block manually. Template at: ${path.join(__dirname, "..", "CLAUDE_MD_TEMPLATE.md")}`);
      return;
    }
  } catch {}

  // Case 1: No CLAUDE.md exists — create fresh
  if (!fs.existsSync(CLAUDE_MD)) {
    try {
      fs.writeFileSync(CLAUDE_MD, newBlock + "\n", "utf-8");
      console.log(`  [arkheia] Installed detection protocol to ${CLAUDE_MD}`);
    } catch (err) {
      console.error(`  [arkheia] Could not write ${CLAUDE_MD}: ${err.message}`);
    }
    return;
  }

  // Case 2+: CLAUDE.md exists — read it
  let content;
  try {
    content = fs.readFileSync(CLAUDE_MD, "utf-8");
  } catch (err) {
    console.error(`  [arkheia] Could not read ${CLAUDE_MD}: ${err.message}`);
    return;
  }

  const match = content.match(BEGIN_REGEX);

  // Case 2: Exists but no Arkheia block — append
  if (!match) {
    // Check for multiple BEGIN markers (shouldn't happen)
    const allMatches = content.match(/<!-- BEGIN ARKHEIA PROTOCOL/g);
    if (allMatches && allMatches.length > 1) {
      console.log("  [arkheia] Multiple Arkheia blocks found — manual intervention needed. Skipping.");
      return;
    }

    backup(content);
    // Preserve line endings
    const eol = content.includes("\r\n") ? "\r\n" : "\n";
    const separator = content.endsWith(eol) ? eol : eol + eol;
    try {
      fs.appendFileSync(CLAUDE_MD, separator + newBlock + eol, "utf-8");
      console.log(`  [arkheia] Appended detection protocol to existing ${CLAUDE_MD} (backup at ${CLAUDE_MD}.arkheia.bak)`);
    } catch (err) {
      console.error(`  [arkheia] Could not append to ${CLAUDE_MD}: ${err.message}`);
    }
    return;
  }

  // Case 3: Block exists — check version
  const existingVersion = match[1];
  const existingBlock = content.match(BLOCK_REGEX);

  if (existingVersion === PKG_VERSION && existingBlock && existingBlock[0] === newBlock) {
    console.log(`  [arkheia] Detection protocol already up to date (v${PKG_VERSION})`);
    return;
  }

  // Case 4: Version mismatch or body drifted — replace in place
  backup(content);
  try {
    const updated = content.replace(BLOCK_REGEX, newBlock);
    fs.writeFileSync(CLAUDE_MD, updated, "utf-8");
    console.log(`  [arkheia] Updated detection protocol ${existingVersion} → ${PKG_VERSION} (backup at ${CLAUDE_MD}.arkheia.bak)`);
  } catch (err) {
    console.error(`  [arkheia] Could not update ${CLAUDE_MD}: ${err.message}`);
  }
}

function backup(content) {
  try {
    fs.writeFileSync(CLAUDE_MD + ".arkheia.bak", content, "utf-8");
  } catch {}
}

// ── Also install to Codex if present ───────────────────────────

function installCodexMd() {
  if (process.env.ARKHEIA_SKIP_CLAUDE_MD === "1") return;
  if (!TEMPLATE) return;

  const codexDir = path.join(HOME, ".codex");
  const codexMd = path.join(codexDir, "CODEX.md");
  const newBlock = `${BEGIN_MARKER}\n${TEMPLATE}\n${END_MARKER}`;

  // Only install if codex CLI exists
  try {
    execSync(process.platform === "win32" ? "where codex" : "which codex", { stdio: "pipe" });
  } catch { return; }

  try {
    if (!fs.existsSync(codexDir)) fs.mkdirSync(codexDir, { recursive: true, mode: 0o700 });

    if (!fs.existsSync(codexMd)) {
      fs.writeFileSync(codexMd, newBlock + "\n", "utf-8");
      console.log(`  [arkheia] Installed detection protocol to ${codexMd}`);
      return;
    }

    const content = fs.readFileSync(codexMd, "utf-8");
    if (content.includes(BEGIN_MARKER)) {
      console.log(`  [arkheia] Codex protocol already up to date (v${PKG_VERSION})`);
      return;
    }

    if (content.match(BEGIN_REGEX)) {
      // Upgrade
      fs.writeFileSync(codexMd + ".arkheia.bak", content, "utf-8");
      const updated = content.replace(BLOCK_REGEX, newBlock);
      fs.writeFileSync(codexMd, updated, "utf-8");
      console.log(`  [arkheia] Updated Codex detection protocol → ${PKG_VERSION}`);
    } else {
      // Append
      fs.writeFileSync(codexMd + ".arkheia.bak", content, "utf-8");
      const eol = content.includes("\r\n") ? "\r\n" : "\n";
      fs.appendFileSync(codexMd, eol + eol + newBlock + eol, "utf-8");
      console.log(`  [arkheia] Appended detection protocol to ${codexMd}`);
    }
  } catch {}
}

// ── Main ───────────────────────────────────────────────────────

// API key check
const existingKey = checkApiKey();
if (existingKey) {
  const masked = existingKey.substring(0, 8) + "..." + existingKey.substring(existingKey.length - 4);
  console.log(`\n  [arkheia] API key: ${masked}`);
} else {
  console.log(`\n  [arkheia] No API key. Get one free at https://arkheia.ai/mcp/account`);
}

// Install detection protocol
installClaudeMd();
installCodexMd();

console.log(`  [arkheia] @arkheia/mcp-server v${PKG_VERSION} ready\n`);
