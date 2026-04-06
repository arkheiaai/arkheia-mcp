# Arkheia MCP Server — Fabrication Detection for AI Agents

Know when your AI is making things up.

Arkheia screens model responses for fabrication using behavioural fingerprinting. Works with Claude, GPT, Gemini, Grok, Llama, Mistral, and 30+ other models. One tool call. Real-time risk scoring.

Free tier: 1,500 detections/month. No credit card.

## Quick Start

```bash
npx @arkheia/mcp-server
```

Get a free API key:

```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/provision \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

Add to your agent config (Claude Code, Claude Desktop, Cursor, or any MCP-compatible tool):

```json
{
  "mcpServers": {
    "arkheia": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "~/.arkheia/mcp",
      "env": {
        "PYTHONPATH": "~/.arkheia/mcp",
        "ARKHEIA_API_KEY": "ak_live_your_key_here"
      }
    }
  }
}
```

Restart your agent. Then ask it:

> "Use arkheia_verify to check this response: The Kafka 4.1 ConsumerLease API introduces a lease-based partition ownership model."

It should flag this as **HIGH** risk — because the Kafka 4.1 ConsumerLease API doesn't exist.

## What You Get

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score any model response for fabrication risk (LOW/MEDIUM/HIGH) |
| `arkheia_audit_log` | Review your detection history |
| `run_grok` | Call Grok + screen for fabrication |
| `run_gemini` | Call Gemini + screen for fabrication |
| `run_ollama` | Call local Ollama model + screen |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |

## 35+ Model Profiles

GPT-4o, GPT-5.4, Claude Opus/Sonnet/Haiku, Gemini 2.5/3.0, Grok 4, Llama, Mixtral, CodeLlama, Falcon, Phi4, Kimi K2.5, and more. If your model isn't listed, [let us know](mailto:dmurfet@arkheia.ai).

## Pricing

| Plan | Price | Detections |
|------|-------|------------|
| Free | $0 | 1,500/month |
| Single Contributor | $99/month | Unlimited |
| Professional | $499/month | Unlimited |
| Team | $1,999/month | Unlimited |

## Full Documentation

See the [GitHub repo](https://github.com/arkheiaai/arkheia-mcp) for:
- Complete setup guide for all agents
- CLAUDE.md template for automatic detection across projects
- Multi-agent quorum pattern
- Test prompts and examples

## Feedback

- **GitHub Issues:** https://github.com/arkheiaai/arkheia-mcp/issues
- **Email:** dmurfet@arkheia.ai

Every message is read by the founder.

## Links

- Website: https://arkheia.ai
- GitHub: https://github.com/arkheiaai/arkheia-mcp
