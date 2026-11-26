# Arkheia MCP Server — Fabrication Detection for AI Agents

Screens model responses for signs of fabrication.

Coverage and accuracy vary by model and are improving. Every result says whether it could be assessed: a result we could not assess comes back `NOT_ASSESSED` with a reason, and is never shown as a clean LOW.

Free: 50,000 checks a month during the launch period. No credit card.

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

This repository also contains a Python MCP server (`python -m mcp_server.server`, run from a clone with `PYTHONPATH` set to the clone). It has nine tools and does **not** include `arkheia_feedback`, `arkheia_report` or `arkheia_reports`. It also does not yet report `NOT_ASSESSED`: a result it could not assess can still read as LOW. Use the npm package above.

## Your First Detection

Once installed, ask your agent:

> "Use arkheia_verify to check this response: HTTP/2 introduces multiplexing which allows multiple requests over a single TCP connection."

Check the result's `assessed` field. If it is `true`, the band (LOW, MEDIUM or HIGH) is a scored result. If the result is `NOT_ASSESSED`, the response could not be scored for this model; that is not a clean result.

Now try a fabricated one:

> "Use arkheia_verify to check this response: The Kafka 4.1 ConsumerLease API introduces a lease-based partition ownership model that replaces the traditional rebalance protocol."

The Kafka 4.1 ConsumerLease API doesn't exist. Whether a given check flags it depends on the model; results are not guaranteed for any single example.

### Test Prompts to Try

These exercise different detection scenarios. Run them through your agent to see how it handles each. They are examples, not guaranteed outcomes:

**Truthful statements:**
- "Use arkheia_verify on: Docker caches each Dockerfile layer. Unchanged layers are reused. This is why COPY order matters."
- "Use arkheia_verify on: PostgreSQL uses MVCC to handle concurrent reads and writes without locking rows."
- "Use arkheia_verify on: A JWT has three parts: header, payload, and signature, each base64-encoded."

**Fabricated statements:**
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
2. Check the `risk_level` field in the result

### Risk Handling
- LOW: Present normally
- MEDIUM: Present with caveat — "Arkheia raised a warning. Key claims should be verified."
- HIGH: Do not present as-is. Investigate the specific claims. If unverifiable, regenerate or escalate.

### Sub-Agent Outputs
When spawning background agents or parallel workers:
- Verify each agent's output independently before merging
- A HIGH risk from any agent blocks the merge until investigated
- Log all detection results for audit

### What NOT to Do
- Do not skip verification because the response "looks correct"
- Do not suppress HIGH findings — the user needs to know
- Do not retry the same prompt hoping for a different result
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
| **LOW** | No warning | Use normally |
| **MEDIUM** | Arkheia raised a warning | Check the key claims. Check references, API names, version numbers. |
| **HIGH** | Arkheia raised a strong warning | Verify before relying on it. Consider regenerating. |
| **NOT_ASSESSED** | Detection could not score this response (`not_assessed_reason` says why). Not a clean result. | Verify by other means. A `candidate_alert` of MEDIUM or HIGH means check the specific claims now. |

## Supported models

Coverage varies by model. If a result says `NOT_ASSESSED`, verify it yourself; it is never a clean LOW.

- **OpenAI:** GPT-4o, GPT-5.4, GPT-5-Codex family
- **Anthropic:** Claude Opus 4.6, Sonnet 4.6, Haiku 4.5
- **Google:** Gemini 2.5 Pro/Flash, Gemini 3 Pro Preview
- **xAI:** Grok 4, Grok 4 Fast, Grok Code Fast
- **Local:** Qwen2 72B, Phi4, Mixtral, CodeLlama, Falcon
- **Others:** Kimi K2.5, Ouro

If your model isn't listed, [open an issue](https://github.com/arkheiaai/arkheia-mcp/issues) and ask us about your model. We add new models regularly.

## Direct API Access

If you have a workflow where you need to call the detection API directly (CI/CD pipelines, custom orchestrators, batch processing), the REST endpoint is available:

```
POST https://arkheia-proxy-production.up.railway.app/v1/detect
```

The MCP tools send the same thing as a direct call: the prompt, the response and the model name, with your key in a header. Each response carries `assessed`, and `not_assessed_reason` when it could not be scored. If you're building a custom integration, [get in touch](mailto:dmurfet@arkheia.ai).

## MCP Tools

| Tool | Description |
|------|-------------|
| `arkheia_verify` | Score a model response for fabrication risk |
| `arkheia_audit_log` | Review your detection history |
| `run_grok` | Call Grok + screen for fabrication |
| `run_gemini` | Call Gemini + screen for fabrication |
| `run_ollama` | Call local Ollama model + screen |
| `run_together` | Call Together AI (Kimi, DeepSeek) + screen |

## Price

Free during the launch period: 50,000 checks a month, no credit card. Paid plans will be announced before the free period ends.

## Feedback

We built this because we needed it. We run 151 AI agents in production and every one of them is screened by Arkheia.

If you're using it — whether you love it, hate it, or wish it did something different — we want to hear from you:

- **GitHub Issues:** https://github.com/arkheiaai/arkheia-mcp/issues — bugs, feature requests, questions
- **Email:** dmurfet@arkheia.ai — anything at all
- **From your agent:** with the npm package installed, ask it to use `arkheia_feedback` to send short feedback, or `arkheia_report` to say whether a checked response was really wrong or fine. Each returns an id from the service on success and says plainly when it could not confirm that the message was stored. See [Sending feedback](npm-wrapper/README.md#sending-feedback).

Every message is read. Every piece of feedback shapes what we build next.

## Requirements

- Node.js 20+. The npm package needs no Python.
- Only for the separate Python server in this repository (nine tools, no feedback tools): Python 3.10+ and Git.

## Links

- Website: https://arkheia.ai
- GitHub: https://github.com/arkheiaai/arkheia-mcp
- Support: dmurfet@arkheia.ai
