# Arkheia MCP Server — Fabrication Detection for AI Agents

Know when your AI is making things up.

Arkheia screens model responses for fabrication using behavioural fingerprinting. Works with Claude, GPT, Gemini, Grok, Llama, Mistral, and 30+ other models. One tool call. Real-time risk scoring.

Free tier: 1,500 detections/month. No credit card.

## Prerequisites

```
Requires:
  - Node 20+
```

The npm package is a Node program and needs no Python.

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

New keys need email confirmation: we email a link to the address you gave. The key works once you open the link and press Confirm; a request that is not confirmed within 24 hours is deleted, and you can ask again. Until you confirm, the key is refused.

Then set your key:

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

# Grok — best: spawns the server and lists all 12 tools
grok mcp test arkheia

# Gemini — no built-in test; start a session and try the tool
```

**Important:** MCP registrations are not hot-reloaded. Restart your CLI session after running `mcp add`.

## What You Get

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score any model response for fabrication risk (LOW/MEDIUM/HIGH) |
| `arkheia_audit_log` | Review your detection history |
| `arkheia_feedback` | Send short feedback to Arkheia |
| `arkheia_report` | Say whether a checked response was really wrong or fine |
| `arkheia_reports` | List or delete your own reports |
| `run_grok` | Call Grok + screen for fabrication |
| `run_gemini` | Call Gemini + screen for fabrication |
| `run_ollama` | Call local Ollama model + screen |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |
| `memory_store` | Persistent knowledge graph — upsert entity |
| `memory_retrieve` | Knowledge graph lookup |
| `memory_relate` | Create relationship between entities |

## Sending feedback

Two tools let you (or your agent) tell us how Arkheia is doing. Both use your `ARKHEIA_API_KEY`.

Free-text feedback, for example "tell Arkheia the verdict on that answer was a false alarm":

```json
{"tool": "arkheia_feedback", "arguments": {"message": "The check flagged a correct answer.", "kind": "false_alarm"}}
```

`kind` is optional: `bug`, `false_alarm`, `missed_problem`, `feature_request`, `praise` or `other`. `email` is optional, used only to reply to you, and sent only if you supply it. `message` is 5 to 2,000 characters.

Whether a checked response was really wrong or fine. Pass the `detection_id` from the `arkheia_verify` result. Only a result with `reportable: true` (checked by the hosted service) can be reported; a result checked by a local proxy says `reportable: false` and cannot be linked to a hosted record, so use `arkheia_feedback` with kind `false_alarm` or `missed_problem` and describe it in your own words:

```json
{"tool": "arkheia_report", "arguments": {"detection_id": "<detection_id from arkheia_verify>", "outcome": "wrong", "evidence": "checked src/x.py: no such function", "category": "invented_api"}}
```

`outcome` is `wrong` or `fine` and describes the model's response, not Arkheia's score. `evidence` is optional, one line, at most 500 characters. `category` is optional: `invented_api`, `invented_file_or_path`, `wrong_fact_or_number`, `invented_source`, `wrong_code_behaviour`, `misread_context` or `other`. `reporter_kind` is `agent` (default) or `human`. `arkheia_reports` with `action: "list"` shows your own reports, and `action: "delete"` with a `report_id` removes one so you can report again.

**What is sent:** only the fields you pass to the tool (plus a random submission id for feedback, so a repeated submission can be recognised), with your API key in a request header. **What is not sent:** no conversation, prompt, response, file, environment details or API key in the text. Text that looks like a common API key or token format is refused rather than sent; this is a safety net, not a guarantee that every kind of secret is caught, so do not paste credentials.

**What you get back:** one of three results.

- `recorded: true` with an id: the service answered with its documented success status (201) and a valid id.
- `recorded: false`: the service refused it, or the request never left your machine. The error says why.
- `recorded: "unknown"`: the request may have reached the service (a timeout, a dropped connection, a server error, or a reply that is not the documented acknowledgement), so it may have been stored. The tool does not retry on its own after that. For `arkheia_feedback` the result includes a `submission_id` and the names of the arguments you supplied; to try again, call the tool with EVERY original argument (`message`, and `kind` and `email` if you gave them) unchanged and that same `submission_id`. A changed field under an existing `submission_id` is refused as a conflict. Whether a repeat is de-duplicated depends on the service, so a repeat may still be stored twice. For `arkheia_report`, check `arkheia_reports` with `action: "list"` before sending again; if a report already exists for that detection, a new one is refused.

The tool retries by itself only when the request provably never left your machine (for example connection refused), and only once. Error text from the service is never shown in the result.

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

**Server registered but tools not showing** — Restart your CLI session. MCP registrations are not hot-reloaded.

**API key rejected** — Check for trailing whitespace or `\r` characters. If your env file was created on Windows, run `dos2unix` on it. The server will warn about this on startup.

## The separate Python server

The repository also contains a separate Python MCP server with nine tools (no feedback tools). It is not part of the npm package. If you use it, you need Python 3.10 to 3.13. If it fails to start with an error about `pyexpat` or `ensurepip`, your Python build is incomplete: install a different Python 3.10 to 3.13 build (for example a Python 3.12 from your package manager or python.org) and check it with `python3 -c "import pyexpat, ensurepip"` before trying again.

**"Python 3.10+ is required but not found"** — Install Python 3.10 to 3.13 from your package manager or [python.org](https://python.org).

**"No module named pip"** — Your Python installation has no working pip. Delete `~/.arkheia/venv` and recreate it with a complete Python 3.10 to 3.13 build.

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
