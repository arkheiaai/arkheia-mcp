# Arkheia MCP Server — Fabrication Detection for LLMs

Detect fabrication (hallucination) in any LLM output.
Free tier included (1,500 detections/month).

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/arkheiaai/arkheia-mcp.git ~/.arkheia-mcp
cd ~/.arkheia-mcp
pip install -r requirements.txt
```

### 2. Get an API key (free)

```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/provision \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

### 3. Add to Claude Desktop

Edit your config file:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

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

On Windows, replace `~/.arkheia-mcp` with the full path (e.g. `C:/Users/YourName/.arkheia-mcp`).

### 4. Restart Claude

The `arkheia_verify` and `arkheia_audit_log` tools will appear automatically.

## Tools

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score any model output for fabrication risk (LOW/MEDIUM/HIGH) |
| `arkheia_audit_log` | Review detection history |
| `run_grok` | Call xAI Grok + screen for fabrication |
| `run_gemini` | Call Google Gemini + screen for fabrication |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |
| `run_ollama` | Call local Ollama model + screen |
| `memory_store` / `memory_retrieve` / `memory_relate` | Persistent knowledge graph |

## Pricing

- **Free:** 1,500 detections/month (no credit card)
- **Single Contributor:** $99/month (unlimited)
- **Professional:** $499/month (20 concurrent)
- **Team:** $1,999/month (50 concurrent)

## Requirements

- Python 3.10+
- Git

## Full Setup Guide

See [AGENTS.md](https://github.com/arkheiaai/arkheia-mcp/blob/master/AGENTS.md) for detailed instructions, troubleshooting, and environment variables.

## Links

- Website: https://arkheia.ai
- GitHub: https://github.com/arkheiaai/arkheia-mcp
- Support: support@arkheia.ai
