# Arkheia MCP Server — Setup Guide

This file is the single source of truth for installing and configuring the Arkheia MCP Server.
If you are an AI agent helping a user install Arkheia, follow these steps exactly.

## Prerequisites

- **Python 3.10+** — check: `python3 --version` (or `python --version` on Windows)
- **Git** — check: `git --version`

## Step 1: Get an API Key

Option A — Automatic (recommended):
```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/provision \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```
This returns `{"api_key": "ak_live_..."}`. Save this key.

Option B — Manual:
Visit https://arkheia.ai and sign up. Your key will be emailed.

## Step 2: Configure Claude Desktop

Edit your Claude Desktop config file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |

First, clone the repo (one time only):
```bash
git clone https://github.com/arkheiaai/arkheia-mcp.git ~/.arkheia-mcp
cd ~/.arkheia-mcp
pip install -r requirements.txt
```

On Windows, use `%USERPROFILE%\.arkheia-mcp` instead of `~/.arkheia-mcp`.

Then add this to the config file (create it if it doesn't exist):

```json
{
  "mcpServers": {
    "arkheia": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "~/.arkheia-mcp",
      "env": {
        "PYTHONPATH": "~/.arkheia-mcp",
        "ARKHEIA_API_KEY": "ak_live_YOUR_KEY_HERE"
      }
    }
  }
}
```

On Windows, replace `~/.arkheia-mcp` with the full path, e.g. `C:/Users/YourName/.arkheia-mcp`.

Replace `ak_live_YOUR_KEY_HERE` with your actual API key from Step 1.

## Step 2 (alt): Configure Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "arkheia": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "~/.arkheia-mcp",
      "env": {
        "PYTHONPATH": "~/.arkheia-mcp",
        "ARKHEIA_API_KEY": "ak_live_YOUR_KEY_HERE"
      }
    }
  }
}
```

## Step 3: Restart Claude

Close and reopen Claude Desktop (or restart Claude Code). The Arkheia tools will appear automatically.

## Step 4: Verify

Ask Claude: "Use arkheia_verify to check this response for fabrication: 'The Eiffel Tower is located in Berlin, Germany.'"

You should see a detection result with `risk_level: HIGH` and a confidence score.

## Available Tools

| Tool | What it does |
|------|-------------|
| `arkheia_verify` | Score any (prompt, response, model) triple for fabrication risk. Returns LOW/MEDIUM/HIGH with confidence. |
| `arkheia_audit_log` | Retrieve your detection history. |
| `run_grok` | Call xAI Grok and screen the response (requires `XAI_API_KEY`). |
| `run_gemini` | Call Google Gemini and screen the response (requires `GOOGLE_API_KEY`). |
| `run_together` | Call Together AI models and screen the response (requires `TOGETHER_API_KEY`). |
| `run_ollama` | Call a local Ollama model and screen the response (requires Ollama running). |
| `memory_store` | Store entities in a persistent knowledge graph. |
| `memory_retrieve` | Search the knowledge graph. |
| `memory_relate` | Create relationships between entities. |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ARKHEIA_API_KEY` | Yes | — | Your API key (`ak_live_...`). Get one free at Step 1. |
| `ARKHEIA_PROXY_URL` | No | `http://localhost:8098` | Enterprise proxy URL (if running on-prem). |
| `ARKHEIA_HOSTED_URL` | No | Railway production URL | Hosted detection API. |
| `XAI_API_KEY` | No | — | Required for `run_grok` tool. |
| `GOOGLE_API_KEY` | No | — | Required for `run_gemini` tool. |
| `TOGETHER_API_KEY` | No | — | Required for `run_together` tool. |

## Free Tier

1,500 detections/month. No credit card required. Upgrade at https://arkheia.ai.

## Troubleshooting

**"Python 3.10+ is required but not found"**
Install Python from https://python.org. On Windows, check "Add to PATH" during install.

**Tools don't appear in Claude**
1. Check the config file path is correct for your OS
2. Ensure valid JSON (no trailing commas)
3. Restart Claude completely (quit + reopen, not just close window)

**"Missing API key" or UNKNOWN results**
Set `ARKHEIA_API_KEY` in the env block of your config. Verify your key works:
```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/detect \
  -H "X-Arkheia-Key: <YOUR_KEY_HERE>" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","response":"test"}'
```

**Quota exceeded (429)**
Free tier is 1,500/month. Check usage or upgrade at https://arkheia.ai.

## Support

- GitHub Issues: https://github.com/arkheiaai/arkheia-mcp/issues
- Email: support@arkheia.ai
- Website: https://arkheia.ai
