# MCP Server Build — Session Context Pattern

## The Problem

When you build an MCP Trust Server and register it in Claude Code or Cursor, the
orchestrating agent (Claude) loses all context about your server every time the IDE
restarts. It doesn't know:

- What services are running and on which ports
- Which tools are available and what they do
- What work is in progress or pending
- Where the audit log, config files, and profiles live

This is not a bug in Claude — it is a fundamental property of stateless LLM sessions.
The solution is to externalise state into files that load automatically.

---

## The Pattern: Three-Layer Context

```
Layer 1: CLAUDE.md          — project-wide facts (codebases, deploy protocol)
Layer 2: MEMORY.md          — lightweight index, pointers to topic files
Layer 3: topic files        — deep context per component (e.g. arkheia-mcp.md)
```

Claude Code auto-loads `CLAUDE.md` (from your project root or `~/.claude/CLAUDE.md`)
and `MEMORY.md` (from `~/.claude/projects/<project>/memory/MEMORY.md`) at the start
of every session. Topic files are loaded on demand when MEMORY.md points to them.

### Layer 1 — CLAUDE.md
Put stable, project-wide facts here:
- Codebase locations (path → repo → deployment target)
- Environment file locations
- Deploy/promotion protocol
- Refactoring rules

Example entry for your MCP server:
```markdown
| **my-mcp-server** | `C:\my-mcp` | — | Local only — Enterprise Proxy (8098) + MCP stdio |
```

Keep this file small. It is the constitution, not the encyclopedia.

### Layer 2 — MEMORY.md
One or two lines per major component. Points to topic files:
```markdown
## my-mcp-server
Read `memory/my-mcp-server.md` at start of any MCP work — service state, tools, pending tasks.
```

**Hard limit**: MEMORY.md is truncated at 200 lines. Treat this as a strict budget.
Never put operational detail here — that belongs in topic files.

### Layer 3 — Topic files (e.g. `memory/my-mcp-server.md`)
Full operational context for one component. Include:
- Current service state (ports, PIDs, health check commands)
- Tool list with signatures and default models
- Key file paths
- Pending work (explicitly ordered by priority)
- Lessons learned / gotchas

---

## What To Put In Each Layer — Decision Table

| Information type | Layer |
|-----------------|-------|
| Codebase path + deploy target | CLAUDE.md |
| Env file locations | CLAUDE.md |
| "Read topic file X for component Y" | MEMORY.md |
| Which port a service runs on | topic file |
| What MCP tools are available | topic file |
| Pending work items | topic file |
| NSSM service names | topic file |
| Test commands | topic file |
| Session-specific in-progress notes | nowhere (ephemeral) |

---

## Startup Ritual For The Orchestrating Agent

Add this to your CLAUDE.md or as an instruction to your agent:

```
At the start of any session involving [component]:
1. Read memory/[component].md
2. Verify services are running (health check URLs listed there)
3. Confirm MCP tools are active before using them
```

Example health check commands to include in your topic file:
```bash
curl http://localhost:8098/admin/health   # Enterprise Proxy
curl http://localhost:8099/health         # local detection proxy
```

---

## Handling MCP Tool Availability After Restart

MCP tools registered in `settings.json` are not available until the IDE restarts.
After a restart, the agent should confirm tools are active before using them:

```
# In your session startup check
"What MCP tools do you have available?"
```

If `arkheia_verify`, `run_grok` etc. are not listed, the MCP server failed to start.
Check:
1. `PYTHONPATH` is set correctly in `settings.json` env block
2. The server script path uses forward slashes
3. All required Python packages are installed in the target Python environment

---

## Service Persistence — NSSM Pattern

The Enterprise Proxy (and any long-running sidecar) should be a Windows service,
not a background process. Background processes die on shell exit, service restart,
or reboot.

```batch
# Minimal NSSM registration
nssm install MyService python -m uvicorn myapp.main:app --port 8098
nssm set MyService AppDirectory C:\my-mcp
nssm set MyService AppEnvironmentExtra PYTHONPATH=C:\my-mcp
nssm set MyService Start SERVICE_AUTO_START
nssm set MyService AppRestartDelay 5000
nssm start MyService
```

Include the install script (`install_service.bat`) in your repo so any agent or
operator can re-register the service after a machine rebuild.

---

## Audit Log Continuity

The hash-chained JSONL audit log (`audit.jsonl`) is the one piece of state that
must survive restarts. The writer recovers chain state on startup by reading the
last record:

```python
# writer.py startup
self._last_hash, self._seq = _load_chain_state(self.log_path)
```

Add the audit log path to your topic file. After any restart, verify the chain
continues (seq increments, prev_hash matches previous this_hash):

```bash
python -c "
import json
lines = open('audit.jsonl').readlines()
if lines:
    last = json.loads(lines[-1])
    print('seq:', last['seq'], 'hash:', last['this_hash'][:16])
"
```

---

## Template: topic file for a new MCP server

```markdown
# my-mcp-server — Current State

## Services
- **MyProxy** (port 8098): NSSM service, auto-start
  health: `curl http://localhost:8098/health`

## MCP Tools
Registered in `~/.claude/settings.json`. Active after IDE restart.
| Tool | Signature | Purpose |
|------|-----------|---------|
| verify | (prompt, response, model) | Score response for fabrication |
| audit_log | (limit) | Retrieve recent events |

## Key Paths
- Entry point: `C:\my-mcp\mcp_server\server.py`
- Audit log: `C:\my-mcp\audit.jsonl`
- Install script: `C:\my-mcp\install_service.bat`
- Config: `C:\my-mcp\config.yaml`

## Tests
`PYTHONPATH=C:\my-mcp python -m pytest tests/ -v`
Last run [date]: N passed

## Pending Work
1. [highest priority item]
2. [next item]
```

---

## Summary

| Problem | Solution |
|---------|----------|
| Agent loses context on restart | MEMORY.md auto-loads every session |
| MEMORY.md fills up | Outsource detail to topic files, keep MEMORY.md as index |
| Stable project facts duplicated everywhere | Put once in CLAUDE.md |
| Service dies on reboot | NSSM service with auto-restart |
| Audit log breaks on restart | Hash-chain writer recovers state from last record |
| MCP tools not available after restart | Confirm in startup ritual; check PYTHONPATH |
