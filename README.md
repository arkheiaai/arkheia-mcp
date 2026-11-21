# Arkheia MCP Server — Fabrication Detection for AI Agents

Know when your AI is making things up.

Arkheia screens model responses for fabrication using behavioural fingerprinting. Works with Claude, GPT, Gemini, Grok, Llama, Mistral, and 30+ other models. One tool call. Real-time risk scoring.

Free tier: 1,500 detections/month. No credit card.

## Install

Install the npm package. It is the full server: detection, the provider wrappers, memory, and the feedback tools (`arkheia_feedback`, `arkheia_report`, `arkheia_reports`).

```bash
npm install -g @arkheia/mcp-server
```

You'll need:
- Node.js 20+ (the npm package needs no Python)
- An API key (free — see below)

## Get an API Key

```bash
curl -X POST https://arkheia-proxy-production.up.railway.app/v1/provision \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com"}'
```

Save the key. You won't see it again.

New keys need email confirmation: we email a link to the address you gave. The key works once you open the link and press Confirm; a request that is not confirmed within 24 hours is deleted, and you can ask again.

## Add to Your Agent

Register the npm package with your agent. For Claude Code:

```bash
claude mcp add arkheia -s user \
  -e ARKHEIA_API_KEY="ak_live_your_key_here" \
  -- mcp-server
```

Commands for Codex, Gemini, Grok and where each stores its configuration are in [`npm-wrapper/README.md`](npm-wrapper/README.md#register-with-your-cli). Any MCP-compatible agent (Cursor, Windsurf, Cline, your own orchestrator) can run the same `mcp-server` command with `ARKHEIA_API_KEY` in its environment. Restart your agent after adding the configuration.

### The Python server in this repository

This repository also contains a Python MCP server (`python -m mcp_server.server`, run from a clone with `PYTHONPATH` set to the clone). It has nine tools and does **not** include `arkheia_feedback`, `arkheia_report` or `arkheia_reports`. To send feedback or reports, use the npm package above.

## Your First Detection

Once installed, ask your agent:

> "Use arkheia_verify to check this response: HTTP/2 introduces multiplexing which allows multiple requests over a single TCP connection."

You should see a **LOW** risk result — that's a truthful response.

Now try a fabricated one:

> "Use arkheia_verify to check this response: The Kafka 4.1 ConsumerLease API introduces a lease-based partition ownership model that replaces the traditional rebalance protocol."

You should see a **HIGH** risk result — the Kafka 4.1 ConsumerLease API doesn't exist. Arkheia caught it.

### Test Prompts to Try

These exercise different detection scenarios. Run them through your agent to see how it handles each:

**Truthful (should score LOW):**
- "Use arkheia_verify on: Docker caches each Dockerfile layer. Unchanged layers are reused. This is why COPY order matters."
- "Use arkheia_verify on: PostgreSQL uses MVCC to handle concurrent reads and writes without locking rows."
- "Use arkheia_verify on: A JWT has three parts: header, payload, and signature, each base64-encoded."

**Fabricated (should score HIGH):**
- "Use arkheia_verify on: The GraphQL Federation 3.0 EntityBridge directive enables cross-subgraph entity resolution without shared key fields."
- "Use arkheia_verify on: Docker BuildKit 3.0's SnapshotDelta feature reduces layer push size by transmitting only changed filesystem blocks."
- "Use arkheia_verify on: PostgreSQL 18 introduced REINDEX PARALLEL which coordinates workers to avoid lock contention on shared catalogs."

### Ask Your Agent What It Thinks

Try this — it's genuinely interesting:

> "You now have access to arkheia_verify for fabrication detection. How would you use this to improve the quality of your own outputs? Try verifying one of your own responses."

Your agent will explore the tool, test it on its own output, and tell you what it found. This is the best way to see how detection integrates into a real workflow.

## Add Detection to All Your Projects

Copy this into your project's `CLAUDE.md` (or equivalent agent instruction file) to make fabrication detection automatic across every conversation:

```markdown
# Fabrication Detection

This project uses Arkheia for runtime fabrication detection.
The arkheia_verify MCP tool is available in every conversation.

## Verification Protocol

Before presenting any substantive response to the user:
1. Call arkheia_verify with the model name, prompt, and response
2. Check the risk field in the result

### Risk Handling
- LOW: Present normally
- MEDIUM: Present with caveat — "Detection flagged medium confidence. Key claims should be verified."
- HIGH: Do not present as-is. Investigate the specific claims. If unverifiable, regenerate or escalate.

### Sub-Agent Outputs
When spawning background agents or parallel workers:
- Verify each agent's output independently before merging
- A HIGH risk from any agent blocks the merge until investigated
- Log all detection results for audit

### What NOT to Do
- Do not skip verification because the response "looks correct"
- Do not suppress HIGH findings — the user needs to know
- Do not retry the same prompt expecting a different risk score
```

A ready-to-use template file is available at [CLAUDE_MD_TEMPLATE.md](CLAUDE_MD_TEMPLATE.md).

## Multi-Agent Quorum Pattern

If you use multiple AI agents (Claude + Codex, Gemini + Grok, etc.), detection becomes your quality gate:

```
1. Draft agent generates a response
2. arkheia_verify screens the response → risk score
3. If LOW: accept
4. If MEDIUM: second agent reviews the specific claims
5. If HIGH: regenerate with a different model, or flag for human review
```

This catches fabrication that individual agents miss. The draft agent is confident. The detection layer is objective. The review agent has context. Together they produce higher quality output than any single agent.

## What the Risk Levels Mean

| Risk | What it means | What to do |
|------|--------------|------------|
| **LOW** | Response fingerprint is consistent with grounded content | Use normally |
| **MEDIUM** | Some statistical signals triggered — the model may have interpolated or substituted | Review key claims. Check references, API names, version numbers. |
| **HIGH** | Strong evidence of fabrication — multiple detection signals agree | Don't trust this output. Verify everything. Consider regenerating. |
| **UNKNOWN** | No detection profile for this model yet | [Let us know](mailto:dmurfet@arkheia.ai) — we'll add it |

## Model Coverage

35+ models with detection profiles:

- **OpenAI:** GPT-4o, GPT-5.4, GPT-5-Codex family
- **Anthropic:** Claude Opus 4.6, Sonnet 4.6, Haiku 4.5
- **Google:** Gemini 2.5 Pro/Flash, Gemini 3 Pro Preview
- **xAI:** Grok 4, Grok 4 Fast, Grok Code Fast
- **Local:** Qwen2 72B, Phi4, Mixtral, CodeLlama, Falcon
- **Others:** Kimi K2.5, Ouro

If your model isn't listed, [let us know](mailto:dmurfet@arkheia.ai) and we'll characterise it. We add new models regularly.

## Direct API Access

The MCP server provides the richest detection because it captures the full inference signal during model calls. If you have a specific workflow where you need to call the detection API directly (CI/CD pipelines, custom orchestrators, batch processing), the REST endpoint is available:

```
POST https://arkheia-proxy-production.up.railway.app/v1/detect
```

Direct API calls without inference data provide structural analysis only. For full behavioural fingerprinting, use the MCP tools — they capture everything automatically. If you're building a custom integration and want full detection quality, [get in touch](mailto:dmurfet@arkheia.ai) and we'll help you set it up.

## MCP Tools

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score a model response for fabrication risk |
| `arkheia_audit_log` | Review your detection history |
| `run_grok` | Call Grok + screen for fabrication |
| `run_gemini` | Call Gemini + screen for fabrication |
| `run_ollama` | Call local Ollama model + screen |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |

## Pricing

| Plan | Price | Detections | Concurrent |
|------|-------|------------|------------|
| Free | $0 | 1,500/month | 5 |
| Single Contributor | $99/month | Unlimited | 5 |
| Professional | $499/month | Unlimited | 20 |
| Team | $1,999/month | Unlimited | 50 |

No credit card for free tier. Upgrade when you're ready.

## Feedback

We built this because we needed it. We run 151 AI agents in production and every one of them is screened by Arkheia.

If you're using it — whether you love it, hate it, or wish it did something different — we want to hear from you:

- **GitHub Issues:** https://github.com/arkheiaai/arkheia-mcp/issues — bugs, feature requests, questions
- **Email:** dmurfet@arkheia.ai — anything at all
- **From your agent:** with the npm package installed, ask it to use `arkheia_feedback` to send short feedback, or `arkheia_report` to say whether a checked response was really wrong or fine. Each returns an id from the service on success and says plainly when it could not confirm that the message was stored. See [Sending feedback](npm-wrapper/README.md#sending-feedback).

Every message is read. Every piece of feedback shapes what we build next.

## Requirements

- Python 3.10+
- Node.js 20+
- Git

## Links

- Website: https://arkheia.ai
- GitHub: https://github.com/arkheiaai/arkheia-mcp
- Support: dmurfet@arkheia.ai
