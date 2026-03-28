# Arkheia MCP Server — Fabrication Detection for LLMs

Detect fabrication (hallucination) in any LLM output.
One command to install. Free tier included.

## Install

```bash
npx @arkheia/mcp-server
```

## Configure for Claude Desktop

Add to your Claude Desktop MCP config (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "arkheia": {
      "command": "npx",
      "args": ["@arkheia/mcp-server"],
      "env": {
        "ARKHEIA_API_KEY": "ak_live_..."
      }
    }
  }
}
```

## What It Does

Screens model outputs for fabrication using behavioural signal analysis.
Returns a risk assessment (LOW/MEDIUM/HIGH) with confidence score and
detection features for audit trail.

## Tools

### arkheia_verify
Check any model output for fabrication risk.

### arkheia_audit_log
Review detection history for your session.

## Pricing

- Free: 1,500 detections/month
- Single Contributor: $99/month (unlimited)
- Professional: $499/month (20 concurrent)
- Team: $1,999/month (50 concurrent)

## Requirements

- Node.js 18+
- Python 3.10+ (auto-detected)

## Links

- Website: https://arkheia.ai
- Dashboard: https://hermes.arkheia.ai
- API Docs: https://arkheia.ai/docs
- Support: support@arkheia.ai
