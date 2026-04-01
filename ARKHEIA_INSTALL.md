# Arkheia — Full Stack Installer Guide

**Audience:** Claude agent executing a fresh install on a new Windows machine
**OS target:** Windows 10 Pro for Workstations (Build 19045+)
**Last verified:** 2026-03-01

Read this entire document before executing. Stop and report any failure before proceeding to the next section. Ask the user to confirm keys and credentials — never guess them.

---

## 0. Hardware Requirements

| Resource | Minimum | Notes |
|----------|---------|-------|
| RAM | 32 GB | 64 GB recommended |
| GPU VRAM | 24 GB | For local model inference (Ollama / vLLM) |
| Storage | 500 GB SSD | Ollama models alone: ~200 GB |
| OS | Windows 10 Pro for Workstations 10.0.19045+ | |

---

## 1. Software Prerequisites

Install in this order. Verify each before proceeding.

### 1.1 Python 3.12
```powershell
winget install Python.Python.3.12
```
Verify: `python --version` → `Python 3.12.x`
Expected path: `C:\Users\<user>\AppData\Local\Programs\Python\Python312\`
**No venvs used** — all Arkheia services install into global Python 3.12.

### 1.2 Node.js v24+
```powershell
winget install OpenJS.NodeJS
```
Verify: `node --version` → `v24.x.x`, `npm --version` → `11.x.x`

### 1.3 Git
```powershell
winget install Git.Git
```
Configure: `git config --global user.name "David"` and `git config --global user.email "dmurfet@gmail.com"`

### 1.4 NSSM (Windows service manager)
```powershell
winget install NSSM.NSSM
```
After install, locate the binary — path will be:
`C:\Users\<user>\AppData\Local\Microsoft\WinGet\Packages\NSSM.NSSM_Microsoft.Winget.Source_8wekyb3d8bbwe\nssm-2.24-101-g897c7ad\win64\nssm.exe`
Set as variable `$NSSM` for use in Section 5.
**All NSSM commands require Administrator elevation.**

### 1.5 Ollama
```powershell
winget install Ollama.Ollama
# or download from https://ollama.ai/download
```
Verify: `ollama --version` → `0.15.4+`
Ollama starts automatically as a background Windows service on port 11434.

### 1.6 GitHub CLI
```powershell
winget install GitHub.cli
```
Auth: `gh auth login` → select GitHub.com → HTTPS → device flow → use account `arkheiaai`

### 1.7 Vercel CLI
```bash
npm install -g vercel
vercel login   # use arkheiaai Vercel account
```

### 1.8 Docker Desktop (for arkheia-mcp)
```powershell
winget install Docker.DockerDesktop
```
Verify: `docker --version`, `docker compose version`

---

## 2. Repository Clones

Clone all repos directly under `C:\`. Do not use subdirectories.

```bash
cd /c

git clone https://github.com/arkheiaai/arkheia-proxy.git
git clone https://github.com/arkheiaai/arkheia-mcp.git
git clone https://github.com/arkheiaai/arkheia-dashboard.git

# Website clones into a subdirectory by design:
mkdir arkheia-website-build
cd arkheia-website-build
git clone https://github.com/arkheiaai/arkheia-website.git arkheia-website
cd ..

# model-lab has no remote — restore from backup only
# Expected path if restored: C:\arkheia-model-lab\
```

### Branch setup
```bash
# arkheia-proxy: work on staging, merge to main for Railway deploy
cd /c/arkheia-proxy
git checkout main
git checkout -b staging

# arkheia-mcp: main branch only
cd /c/arkheia-mcp
git checkout main

# arkheia-dashboard: staging → main for Vercel deploy
cd /c/arkheia-dashboard
git checkout main
git checkout -b staging
```

---

## 3. Python Package Installation

All services use global Python 3.12. Install requirements for each:

```bash
pip install -r /c/arkheia-proxy/requirements.txt
pip install -r /c/arkheia-mcp/requirements.txt

# model-lab (only if restoring from backup):
pip install -r /c/arkheia-model-lab/requirements.txt
```

Key packages by service:

| Service | Key deps |
|---------|---------|
| arkheia-proxy | fastapi, uvicorn, asyncpg, redis, pyjwt, pyyaml, httpx |
| arkheia-mcp | mcp==1.26.0, fastapi, uvicorn, httpx, pyyaml |
| arkheia-model-lab | fastapi, uvicorn, sqlalchemy, aiosqlite, pandas, numpy, psutil |

---

## 4. Environment Variables

### 4.1 Windows User Env Vars (registry — survive reboots)

Open a normal (non-admin) PowerShell:

```powershell
# Route all CC / Claude API traffic through local detection proxy
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_BASE_URL", "http://localhost:8099", "User")

# Anthropic API key (keep in Windows env, NOT in .env files)
[System.Environment]::SetEnvironmentVariable("ANTHROPIC_API_KEY", "<key from master.env>", "User")
```

Verify:
```powershell
[System.Environment]::GetEnvironmentVariable("ANTHROPIC_BASE_URL", "User")
# → http://localhost:8099
```

### 4.2 Service .env Files

Populate from `C:\keys\master.env`. See Section 11 for the full key inventory.

**C:\arkheia-proxy\.env** — required keys:
```
ENVIRONMENT=development
DEBUG=true
DATABASE_URL=<from master.env>
REDIS_URL=<from master.env>
OPENAI_API_KEY=<from master.env>
GOOGLE_API_KEY=<from master.env>
ARKHEIA_API_KEY=<from master.env>
JWT_SECRET=<from master.env JWT_SECRET_PROXY>
STATUS_ADMIN_SECRET=<from master.env>
XAI_API_KEY=<from master.env>
ARKHEIA_VERCEL_TOKEN=<from master.env>
DASHBOARD_REPO_TOKEN=<from master.env>
ARKHEIA_RAILWAY_API_TOKEN_STAGING=<from master.env>
ARKHEIA_RAILWAY_API_TOKEN_PROD=<from master.env>
```

**C:\arkheia-model-lab\.env** — required keys:
```
GOOGLE_CLIENT_ID=<from master.env>
GOOGLE_CLIENT_SECRET=<from master.env>
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/callback
JWT_SECRET=<from master.env JWT_SECRET_MODELLAB>
EMAIL_WHITELIST=dmurfet@gmail.com
DATABASE_URL=sqlite:///data/arkheia.db
RESEND_API_KEY=<from master.env>
OPENAI_API_KEY=<from master.env>
XAI_API_KEY=<from master.env>
APP_HOST=0.0.0.0
APP_PORT=8000
```

---

## 5. NSSM Service Registration

**Requires Administrator.** Open Administrator cmd or PowerShell.

Set the NSSM path (update hash segment to match your WinGet install):
```cmd
set NSSM=C:\Users\<user>\AppData\Local\Microsoft\WinGet\Packages\NSSM.NSSM_Microsoft.Winget.Source_8wekyb3d8bbwe\nssm-2.24-101-g897c7ad\win64\nssm.exe
set PY=C:\Users\<user>\AppData\Local\Programs\Python\Python312\python.exe
```

### 5.1 ArkheiaLocalProxy — detection proxy on port 8099

```cmd
%NSSM% install ArkheiaLocalProxy "%PY%" "C:\arkheia-proxy\local_proxy.py"
%NSSM% set ArkheiaLocalProxy AppDirectory "C:\arkheia-proxy"
%NSSM% set ArkheiaLocalProxy AppEnvironmentExtra "PYTHONUNBUFFERED=1"
%NSSM% set ArkheiaLocalProxy Start SERVICE_AUTO_START
%NSSM% set ArkheiaLocalProxy AppRestartDelay 5000
%NSSM% set ArkheiaLocalProxy AppStdout "C:\arkheia-proxy\logs\service.log"
%NSSM% set ArkheiaLocalProxy AppStderr "C:\arkheia-proxy\logs\service_err.log"
%NSSM% start ArkheiaLocalProxy
```

### 5.2 ArkheiaModelLab — model lab API on port 8001

```cmd
%NSSM% install ArkheiaModelLab "%PY%" "-m uvicorn service_entry:app --host 0.0.0.0 --port 8001"
%NSSM% set ArkheiaModelLab AppDirectory "C:\arkheia-model-lab"
%NSSM% set ArkheiaModelLab AppEnvironmentExtra "PYTHONUNBUFFERED=1"
%NSSM% set ArkheiaModelLab Start SERVICE_AUTO_START
%NSSM% set ArkheiaModelLab AppRestartDelay 5000
%NSSM% start ArkheiaModelLab
```

Verify both services:
```cmd
sc query ArkheiaLocalProxy
sc query ArkheiaModelLab
```
Both should show `STATE: 4 RUNNING`.

---

## 6. arkheia-mcp (Docker)

```bash
cd /c/arkheia-mcp

# Inject API key from master.env
export ARKHEIA_API_KEY=<from master.env ARKHEIA_API_KEY>

# Start all three services:
#   proxy      → port 8099  (Enterprise Proxy / forward proxy)
#   registry   → port 8200  (Profile registry)
#   mcp_server → stdio      (MCP Trust Server for Claude Code / Cursor)
docker compose up -d

# Verify
docker compose ps
curl http://localhost:8099/admin/health
curl http://localhost:8200/health
```

Register the MCP server in Claude Code (see Section 8).

---

## 7. Ollama Models

Pull all production models. **~200 GB total.** Run in a terminal that can stay open.

```bash
ollama pull phi4:14b                      # 9.1 GB
ollama pull phi4-reasoning:14b            # 11  GB
ollama pull zoecohn4/Ouro:latest          # 4.7 GB
ollama pull llama3.1:70b                  # 42  GB
ollama pull deepseek-coder:33b-instruct   # 18  GB
ollama pull qwen2:72b-instruct            # 41  GB
ollama pull falcon:40b-instruct           # 23  GB
ollama pull codellama:34b-instruct        # 19  GB
ollama pull mixtral:8x7b                  # 26  GB
# kimi-k2.5:cloud — cloud-routed stub, no pull needed
```

Verify: `ollama list`

---

## 8. Claude Code Configuration

File: `C:\Users\<user>\.claude\settings.json`

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash|Task",
        "hooks": [
          {
            "type": "command",
            "command": "python C:/arkheia-proxy/check_signal.py"
          }
        ]
      }
    ]
  },
  "mcpServers": {
    "arkheia": {
      "command": "python",
      "args": ["C:/arkheia-mcp/server.py"],
      "env": {
        "ARKHEIA_PROXY_URL": "http://localhost:8099"
      }
    }
  }
}
```

Note: use **forward slashes** in all paths — Windows bash converts backslashes.

---

## 9. Port Allocation Reference

| Port | Service | Process |
|------|---------|---------|
| 8099 | ArkheiaLocalProxy / MCP Enterprise Proxy | NSSM / docker |
| 8001 | ArkheiaModelLab | NSSM uvicorn |
| 8200 | arkheia-mcp Registry | docker |
| 11434 | Ollama | Windows service (auto) |
| 3000 | arkheia-dashboard (dev) | next dev |

---

## 10. Verification Checklist

```bash
curl http://localhost:8099/health              # local proxy
curl http://localhost:8001/health              # model lab
curl http://localhost:8099/admin/health        # mcp enterprise proxy
ollama list                                    # ollama models present
cmd.exe /c "echo %ANTHROPIC_BASE_URL%"         # → http://localhost:8099
cmd.exe /c "sc query ArkheiaLocalProxy"        # → RUNNING
cmd.exe /c "sc query ArkheiaModelLab"          # → RUNNING
python C:/arkheia-proxy/check_signal.py        # → [Arkheia] LOW (any result = reachable)
```

---

## 11. Repository & Deployment Map

| Repo | Local Path | Remote | Auto-deploy |
|------|-----------|--------|-------------|
| arkheia-proxy | `C:\arkheia-proxy` | github.com/arkheiaai/arkheia-proxy | Push to `main` → Railway |
| arkheia-mcp | `C:\arkheia-mcp` | github.com/arkheiaai/arkheia-mcp | Docker (local) |
| arkheia-dashboard | `C:\arkheia-dashboard` | github.com/arkheiaai/arkheia-dashboard | Push to `main` → Vercel |
| arkheia-website | `C:\arkheia-website-build\arkheia-website` | github.com/arkheiaai/arkheia-website | Push to `main` → Vercel |
| arkheia-model-lab | `C:\arkheia-model-lab` | _(none — local only)_ | — |

Commit protocol:
- Work on `staging` branch; PR to `main` via `gh pr create --base main --head staging`
- Git author: `David <dmurfet@gmail.com>`
- Co-author every commit: `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`

---

## 12. Key Management

Master key file: `C:\keys\master.env` — single source of truth. Off git, encrypted storage only.

Keys NOT in master.env:
- `ANTHROPIC_API_KEY` — Windows user env var (HKCU\Environment)
- Vercel auth — `C:\Users\<user>\AppData\Roaming\com.vercel.cli\Data\auth.json`
- GitHub auth — Windows Credential Manager (managed by `gh auth login`)

---

## 13. Troubleshooting

### MCP Trust Server silently not connecting (Claude Code / Windows)

**Symptom:** After adding `mcpServers` to `~/.claude/settings.json`, the MCP tools
(`arkheia_verify`, `run_grok`, etc.) never appear in Claude Code — even after restart.
The CC debug log (`~/.claude/debug/<session-id>.txt`) shows the MCP startup block
completes (with a multi-second delay) but **zero log entries** for the server name.

**Root cause:** Windows fails to spawn executables whose path contains spaces
(e.g. `C:\Users\David Murfet\...`) when the path is passed directly as `command`
in the MCP server config. Claude Code silently drops the server without logging an error.

**Fix:** Use the short command name instead of the full path, provided the executable
is on PATH.

Change this in `~/.claude/settings.json`:
```json
"command": "C:/Users/David Murfet/AppData/Local/Programs/Python/Python312/python.exe"
```
To this:
```json
"command": "python"
```

Verify `python` resolves to the correct interpreter first:
```bash
where python   # should show the Python 3.12 path
```

After the fix, restart Claude Code. The server startup log should show the MCP
server by name within the startup block.

**Diagnosed 2026-03-01** via `~/.claude/debug/<session>.txt` grep for server name
returning zero hits despite healthy server (confirmed via manual stdio test).

Recovery if master.env lost: Railway dashboard (DB/Redis URLs) + API provider dashboards (OpenAI, Google, xAI, Resend) + GitHub → Settings → Personal access tokens.
