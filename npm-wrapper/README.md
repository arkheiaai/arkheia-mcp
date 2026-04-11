# Arkheia MCP Server — Fabrication Detection for AI Agents

Know when your AI is making things up.

Arkheia screens model responses for fabrication using behavioural fingerprinting. Works with Claude, GPT, Gemini, Grok, Llama, Mistral, and 30+ other models. One tool call. Real-time risk scoring.

Free tier: 1,500 detections/month. No credit card.

## Prerequisites

```
Requires:
  - Node 18+
  - Python 3.10–3.13 with working pyexpat

macOS note: Homebrew's current `brew install python` installs 3.14,
which has a broken pyexpat link. Use `brew install python@3.12` until
Homebrew ships a fix. Verify with:
  python3.12 -c "import pyexpat, ensurepip"
```

## Install

```bash
npm install -g @arkheia/mcp-server
```

Get a free API key at [arkheia.ai/mcp/account](https://arkheia.ai/mcp/account), or via the CLI:

```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/provision \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

Set your key:

```bash
export ARKHEIA_API_KEY="ak_live_..."
```

## Register with your CLI

Each AI CLI has a slightly different `mcp add` command. Use the one that matches your tool. All assume you've installed globally with `npm install -g`.

### Claude Code

```bash
claude mcp add arkheia -s user \
  -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY" \
  -- mcp-server
```

Config lands in: `~/.claude.json` under `mcpServers.arkheia`

### Codex

```bash
codex mcp add arkheia \
  --env ARKHEIA_API_KEY="$ARKHEIA_API_KEY" \
  -- mcp-server
```

Config lands in: `~/.codex/config.toml` under `[mcp_servers.arkheia.env]`

Note: `codex login --api-key` is deprecated. Use `printenv OPENAI_API_KEY | codex login --with-api-key` instead.

### Gemini

```bash
gemini mcp add -s user \
  -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY" \
  arkheia mcp-server
```

Config lands in: `~/.gemini/settings.json` under `mcpServers.arkheia`

**Gotcha:** `gemini mcp list` only shows project-scope servers. If you registered with `-s user`, verify by reading `~/.gemini/settings.json` directly.

**Gotcha:** Don't use `npx -y @arkheia/mcp-server` with Gemini — the `-y` flag gets eaten by Gemini's yargs parser as `--yolo`. Use the globally-installed `mcp-server` binary directly.

### Grok

```bash
grok mcp add arkheia \
  -t stdio \
  -c mcp-server \
  -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY"
```

Config lands in: `~/.grok/settings.json` under `mcpServers.arkheia` (note: env is nested under `transport`, unlike other CLIs)

## Verify it works

```bash
# Claude Code — live connection test
claude mcp list

# Codex — shows 'enabled' (not a live check)
codex mcp list

# Grok — best: spawns the server and lists all 9 tools
grok mcp test arkheia

# Gemini — no built-in test; start a session and try the tool
```

**Important:** MCP registrations are not hot-reloaded. Restart your CLI session after running `mcp add`.

## What You Get

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score any model response for fabrication risk (LOW/MEDIUM/HIGH) |
| `arkheia_audit_log` | Review your detection history |
| `run_grok` | Call Grok + screen for fabrication |
| `run_gemini` | Call Gemini + screen for fabrication |
| `run_ollama` | Call local Ollama model + screen |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |
| `memory_store` | Persistent knowledge graph — upsert entity |
| `memory_retrieve` | Knowledge graph lookup |
| `memory_relate` | Create relationship between entities |

## 35+ Model Profiles

GPT-4o, GPT-5.4, Claude Opus/Sonnet/Haiku, Gemini 2.5/3.0, Grok 4, Llama, Mixtral, CodeLlama, Falcon, Phi4, Kimi K2.5, and more. If your model isn't listed, [let us know](mailto:dmurfet@arkheia.ai).

## Pricing

| Plan | Price | Detections |
|------|-------|------------|
| Free | $0 | 1,500/month |
| Single Contributor | $99/month | Unlimited |
| Professional | $499/month | Unlimited |
| Team | $1,999/month | Unlimited |

Manage your account at [arkheia.ai/mcp/account](https://arkheia.ai/mcp/account).

## Where API keys are stored

| CLI | Config file | Key location |
|-----|-------------|-------------|
| Claude Code | `~/.claude.json` | `mcpServers.arkheia.env.ARKHEIA_API_KEY` |
| Codex | `~/.codex/config.toml` | `[mcp_servers.arkheia.env]` section |
| Gemini | `~/.gemini/settings.json` | `mcpServers.arkheia.env.ARKHEIA_API_KEY` |
| Grok | `~/.grok/settings.json` | `mcpServers.arkheia.transport.env.ARKHEIA_API_KEY` |

## Troubleshooting

**"Python 3.10+ is required but not found"** — Install Python 3.12: `brew install python@3.12` (macOS) or download from [python.org](https://python.org).

**"No module named pip"** — Your Python installation has broken pip (common with Python 3.14 on macOS). Delete `~/.arkheia/venv` and switch to Python 3.12: `brew install python@3.12`.

**Server registered but tools not showing** — Restart your CLI session. MCP registrations are not hot-reloaded.

**API key rejected** — Check for trailing whitespace or `\r` characters. If your env file was created on Windows, run `dos2unix` on it. The server will warn about this on startup.

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
- MCP Account: https://arkheia.ai/mcp/account
- GitHub: https://github.com/arkheiaai/arkheia-mcp
