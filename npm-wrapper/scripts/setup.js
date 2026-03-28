#!/usr/bin/env node
/**
 * Post-install script — verifies Python is available and prints setup instructions.
 * Does NOT auto-install Python dependencies (that happens on first run).
 */

const { execSync } = require("child_process");

function checkPython() {
  const candidates = ["python3", "python"];
  for (const cmd of candidates) {
    try {
      const version = execSync(`${cmd} --version 2>&1`, {
        encoding: "utf-8",
        timeout: 5000,
      }).trim();
      const match = version.match(/Python (\d+)\.(\d+)/);
      if (match && parseInt(match[1]) >= 3 && parseInt(match[2]) >= 10) {
        return { cmd, version };
      }
    } catch {
      // Try next
    }
  }
  return null;
}

const python = checkPython();

if (!python) {
  console.log(`
  ============================================================
  Arkheia MCP Server requires Python 3.10+

  Install Python from: https://python.org
  Then run: npx @arkheia/mcp-server
  ============================================================
  `);
} else {
  console.log(`
  ============================================================
  Arkheia MCP Server installed successfully.
  Python: ${python.version}

  To configure for Claude Desktop, add to your MCP config:

  {
    "mcpServers": {
      "arkheia": {
        "command": "npx",
        "args": ["@arkheia/mcp-server"],
        "env": {
          "ARKHEIA_API_KEY": "your_api_key_here"
        }
      }
    }
  }

  Get a free API key at: https://arkheia.ai/mcp
  ============================================================
  `);
}
