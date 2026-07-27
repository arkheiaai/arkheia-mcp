#!/usr/bin/env bash
# ============================================================================
# Arkheia MCP Server - One-Command Installer
#
# Usage:
#   curl -fsSL https://arkheia.ai/install-mcp | bash
#   curl -fsSL https://arkheia.ai/install-mcp | bash -s -- --api-key <arkheia-api-key>
#
# What it does:
#   1. Checks prerequisites (Node.js 18+, Python 3.10+)
#   2. Provisions a free-tier API key (or uses the one you provide)
#   3. Installs @arkheia/mcp-server via npx
#   4. Writes Claude Desktop / Claude Code MCP config
#
# API keys are not persisted unless you pass --persist-api-key or explicitly
# opt in at the interactive prompt.
# ============================================================================

set -euo pipefail

HOSTED_URL="${ARKHEIA_HOSTED_URL:-https://arkheia-proxy-production.up.railway.app}"
API_KEY="${ARKHEIA_API_KEY:-}"
EMAIL=""
DRY_RUN=0
PERSIST_API_KEY="${ARKHEIA_PERSIST_API_KEY:-}"
if [ "${ARKHEIA_PERSIST_API_KEY+x}" = "x" ]; then
    PERSIST_API_KEY_SET=1
else
    PERSIST_API_KEY_SET=0
fi

# ---------------------------------------------------------------------------
# Colours (disabled if not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
    BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

info()  { echo -e "${BLUE}[arkheia]${NC} $*"; }
ok()    { echo -e "${GREEN}[arkheia]${NC} $*"; }
warn()  { echo -e "${YELLOW}[arkheia]${NC} $*"; }
fail()  { echo -e "${RED}[arkheia]${NC} $*" >&2; exit 1; }

truthy() {
    case "${1:-}" in
        1|true|TRUE|True|yes|YES|Yes|y|Y|on|ON|On) return 0 ;;
        *) return 1 ;;
    esac
}

require_value() {
    local option="$1"
    local value="${2:-}"
    if [ -z "$value" ]; then
        fail "${option} requires a value."
    fi
}

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)
            require_value "$1" "${2:-}"
            API_KEY="$2"
            shift 2
            ;;
        --email)
            require_value "$1" "${2:-}"
            EMAIL="$2"
            shift 2
            ;;
        --persist-api-key)
            PERSIST_API_KEY=1
            PERSIST_API_KEY_SET=1
            shift
            ;;
        --no-persist-api-key)
            PERSIST_API_KEY=0
            PERSIST_API_KEY_SET=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --help|-h)
            echo "Usage: curl -fsSL https://arkheia.ai/install-mcp | bash"
            echo ""
            echo "Options (pass via: bash -s -- --option value):"
            echo "  --api-key KEY          Use an existing API key (skip provisioning)"
            echo "  --email EMAIL          Email for free-tier key provisioning"
            echo "  --persist-api-key      Save ARKHEIA_API_KEY to ~/.arkheia/config.json"
            echo "  --no-persist-api-key   Do not save ARKHEIA_API_KEY"
            echo "  --dry-run              Print planned actions without writing files or calling network services"
            exit 0
            ;;
        *) warn "Unknown option: $1"; shift ;;
    esac
done

if [ "$DRY_RUN" -eq 1 ]; then
    info "Dry run: no files, package installs, or network calls will be performed."
fi

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

# Node.js 18+
if ! command -v node &>/dev/null; then
    fail "Node.js is required but not found. Install from https://nodejs.org"
fi
NODE_VERSION_RAW=$(node -v)
NODE_MAJOR=${NODE_VERSION_RAW#v}
NODE_MAJOR=${NODE_MAJOR%%.*}
if ! [[ "$NODE_MAJOR" =~ ^[0-9]+$ ]]; then
    fail "Could not parse Node.js version: ${NODE_VERSION_RAW}"
fi
if [ "$NODE_MAJOR" -lt 18 ]; then
    fail "Node.js 18+ required (found ${NODE_VERSION_RAW}). Update from https://nodejs.org"
fi
ok "Node.js ${NODE_VERSION_RAW}"

# npx
if ! command -v npx &>/dev/null; then
    fail "npx is required but not found. It should come with Node.js."
fi

# Python 3.10+
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VERSION=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)
        PY_MAJOR=${PY_VERSION%%.*}
        PY_MINOR=${PY_VERSION#*.}
        if [[ "$PY_MAJOR" =~ ^[0-9]+$ ]] && [[ "$PY_MINOR" =~ ^[0-9]+$ ]]; then
            if [ "$PY_MAJOR" -gt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 10 ]; }; then
                PYTHON_CMD="$cmd"
                break
            fi
        fi
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3.10+ is required but not found. Install from https://python.org"
fi
ok "Python $($PYTHON_CMD --version 2>&1)"

write_arkheia_api_key_config() {
    local config_file="$1"
    local api_key="$2"
    local hosted_url="$3"

    if [ "$DRY_RUN" -eq 1 ]; then
        info "Dry run: would save API key to ${config_file} with private file modes."
        return 0
    fi

    "$PYTHON_CMD" - "$config_file" "$hosted_url" 3<<<"$api_key" <<'PY'
import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

config_path = Path(sys.argv[1]).expanduser()
hosted_url = sys.argv[2]
with os.fdopen(3, "r", encoding="utf-8") as secret_fh:
    api_key = secret_fh.read().rstrip("\n")

dir_mode = 0o700
file_mode = 0o600

config_path.parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
os.chmod(config_path.parent, dir_mode)

existing = {}
if config_path.exists():
    try:
        existing = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"refusing to overwrite invalid JSON in {config_path}: {exc}") from exc

next_config = dict(existing)
next_config["api_key"] = api_key
next_config["proxy_url"] = next_config.get("proxy_url") or hosted_url
if existing.get("api_key") != api_key or not next_config.get("provisioned_at"):
    next_config["provisioned_at"] = datetime.now(timezone.utc).isoformat()

serialized = json.dumps(next_config, indent=2) + "\n"
current = config_path.read_text(encoding="utf-8") if config_path.exists() else None
if current == serialized:
    os.chmod(config_path, file_mode)
    print("unchanged")
    raise SystemExit(0)

tmp_path = config_path.with_name(f".{config_path.name}.{os.getpid()}.tmp")
previous = config_path.read_bytes() if config_path.exists() else None

try:
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(serialized)
    os.chmod(tmp_path, file_mode)
    os.replace(tmp_path, config_path)
    os.chmod(config_path, file_mode)

    # Test-only exact-path failure injection for rollback coverage.
    fail_after = os.environ.get("ARKHEIA_INSTALL_TEST_FAIL_AFTER_WRITE")
    if fail_after and os.path.abspath(fail_after) == os.path.abspath(str(config_path)):
        raise RuntimeError("simulated write failure after replace")
except Exception:
    try:
        if tmp_path.exists():
            tmp_path.unlink()
    except OSError:
        pass
    try:
        if previous is None:
            if config_path.exists():
                config_path.unlink()
        else:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, file_mode)
            with os.fdopen(fd, "wb") as fh:
                fh.write(previous)
            os.chmod(tmp_path, file_mode)
            os.replace(tmp_path, config_path)
            os.chmod(config_path, file_mode)
    except OSError:
        pass
    raise

print("updated")
PY
}

verify_arkheia_api_key() {
    local api_key="$1"
    local hosted_url="$2"

    "$PYTHON_CMD" - "$hosted_url" 3<<<"$api_key" <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

hosted_url = sys.argv[1].rstrip("/")
with os.fdopen(3, "r", encoding="utf-8") as secret_fh:
    api_key = secret_fh.read().rstrip("\n")

payload = json.dumps({"model": "test", "response": "Hello world test."}).encode("utf-8")
request = urllib.request.Request(
    f"{hosted_url}/v1/detect",
    data=payload,
    headers={
        "Content-Type": "application/json",
        "X-Arkheia-Key": api_key,
    },
    method="POST",
)

try:
    with urllib.request.urlopen(request, timeout=20) as response:
        print(response.status)
except urllib.error.HTTPError as exc:
    print(exc.code)
except Exception:
    print("000")
PY
}

write_mcp_client_config() {
    local config_file="$1"
    local entry_file="$2"
    local label="$3"

    if [ "$DRY_RUN" -eq 1 ]; then
        info "Dry run: would configure ${label} MCP at ${config_file}."
        return 0
    fi

    "$PYTHON_CMD" - "$config_file" "$entry_file" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

config_path = Path(sys.argv[1]).expanduser()
entry_path = Path(sys.argv[2]).expanduser()
config_path.parent.mkdir(parents=True, exist_ok=True)

with entry_path.open("r", encoding="utf-8") as fh:
    entry = json.load(fh)

def contains_embedded_arkheia_key(value):
    if isinstance(value, dict):
        env = value.get("env")
        if isinstance(env, dict) and "ARKHEIA_API_KEY" in env:
            return True
        return any(contains_embedded_arkheia_key(v) for v in value.values())
    if isinstance(value, list):
        return any(contains_embedded_arkheia_key(v) for v in value)
    return False

if config_path.exists():
    with config_path.open("r", encoding="utf-8") as fh:
        config = json.load(fh)
else:
    config = {}

servers = config.setdefault("mcpServers", {})
existing = servers.get("arkheia")

if existing == entry:
    print("unchanged")
    raise SystemExit(0)
if existing is not None and not contains_embedded_arkheia_key(existing):
    print("custom")
    raise SystemExit(0)

servers["arkheia"] = entry
serialized = json.dumps(config, indent=2) + "\n"
mode = 0o600
if config_path.exists():
    mode = stat.S_IMODE(config_path.stat().st_mode) or mode

tmp_path = config_path.with_name(f".{config_path.name}.{os.getpid()}.tmp")
previous = config_path.read_bytes() if config_path.exists() else None

try:
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(serialized)
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, config_path)
    os.chmod(config_path, mode)

    # Test-only exact-path failure injection for rollback coverage.
    fail_after = os.environ.get("ARKHEIA_INSTALL_TEST_FAIL_AFTER_WRITE")
    if fail_after and os.path.abspath(fail_after) == os.path.abspath(str(config_path)):
        raise RuntimeError("simulated write failure after replace")
except Exception:
    try:
        if tmp_path.exists():
            tmp_path.unlink()
    except OSError:
        pass
    try:
        if previous is None:
            if config_path.exists():
                config_path.unlink()
        else:
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "wb") as fh:
                fh.write(previous)
            os.chmod(tmp_path, mode)
            os.replace(tmp_path, config_path)
            os.chmod(config_path, mode)
    except OSError:
        pass
    raise

print("updated")
PY
}

# ---------------------------------------------------------------------------
# API Key provisioning
# ---------------------------------------------------------------------------
if [ -z "$API_KEY" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        info "Dry run: would provision a free-tier API key if no key is provided."
    else
        info "No API key provided; provisioning a free-tier key..."

        # Get email if not provided
        if [ -z "$EMAIL" ]; then
            if [ -t 0 ]; then
                printf "${BOLD}Enter your email address:${NC} "
                read -r EMAIL
            else
                fail "Email required for provisioning. Use: bash -s -- --email you@example.com"
            fi
        fi

        if [ -z "$EMAIL" ]; then
            fail "Email cannot be empty."
        fi

        # Validate email format before sending (prevent injection in JSON payload)
        if ! [[ "$EMAIL" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then
            fail "Invalid email format: ${EMAIL}"
        fi

        # Call the provisioning endpoint; email is validated above, payload built safely.
        PROVISION_PAYLOAD=$(printf '{"email": "%s"}' "$EMAIL")
        PROVISION_RESPONSE=$(curl -sS -w "\n%{http_code}" \
            -X POST "${HOSTED_URL}/v1/provision" \
            -H "Content-Type: application/json" \
            -d "$PROVISION_PAYLOAD" 2>&1) || fail "Failed to reach ${HOSTED_URL}"

        HTTP_CODE=$(echo "$PROVISION_RESPONSE" | tail -1)
        BODY=$(echo "$PROVISION_RESPONSE" | sed '$d')

        case "$HTTP_CODE" in
            201)
                API_KEY=$("$PYTHON_CMD" -c 'import json, sys; print(json.load(sys.stdin).get("api_key", ""))' <<<"$BODY")
                if [ -z "$API_KEY" ]; then
                    fail "Provisioning succeeded but could not parse API key from response."
                fi
                ok "Free-tier API key provisioned."
                warn "The full API key is not printed. Persist it with --persist-api-key or manage keys at https://hermes.arkheia.ai."
                ;;
            409)
                fail "This email already has a free-tier key. Log in at https://hermes.arkheia.ai to manage your keys, or pass --api-key."
                ;;
            429)
                fail "Rate limit exceeded. Try again later or pass --api-key."
                ;;
            *)
                fail "Provisioning failed (HTTP $HTTP_CODE)."
                ;;
        esac
    fi
fi

if [ -n "$API_KEY" ] && [ "$PERSIST_API_KEY_SET" -eq 0 ] && [ -t 0 ] && [ "$DRY_RUN" -eq 0 ]; then
    printf "%bStore API key in ~/.arkheia/config.json with mode 0600? [y/N] %b" "$BOLD" "$NC"
    read -r PERSIST_REPLY
    case "$PERSIST_REPLY" in
        y|Y|yes|YES|Yes)
            PERSIST_API_KEY=1
            PERSIST_API_KEY_SET=1
            ;;
        *)
            PERSIST_API_KEY=0
            PERSIST_API_KEY_SET=1
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Verify the key works
# ---------------------------------------------------------------------------
if [ -n "$API_KEY" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
        info "Dry run: would verify API key."
    else
        info "Verifying API key..."
        VERIFY_CODE=$(verify_arkheia_api_key "$API_KEY" "$HOSTED_URL" 2>/dev/null || printf "000")

        case "$VERIFY_CODE" in
            200) ok "API key verified." ;;
            401) fail "API key is invalid. Check your key and try again." ;;
            *)   warn "Could not verify key (HTTP $VERIFY_CODE); continuing anyway." ;;
        esac
    fi
else
    warn "No API key available; hosted detection will require ARKHEIA_API_KEY at runtime."
fi

# ---------------------------------------------------------------------------
# Persist API key only after explicit opt-in
# ---------------------------------------------------------------------------
ARKHEIA_CONFIG_DIR="${HOME}/.arkheia"
ARKHEIA_CONFIG_FILE="${ARKHEIA_CONFIG_DIR}/config.json"

if [ -n "$API_KEY" ]; then
    if truthy "$PERSIST_API_KEY"; then
        if [ "$DRY_RUN" -eq 1 ]; then
            write_arkheia_api_key_config "$ARKHEIA_CONFIG_FILE" "$API_KEY" "$HOSTED_URL"
        elif WRITE_RESULT=$(write_arkheia_api_key_config "$ARKHEIA_CONFIG_FILE" "$API_KEY" "$HOSTED_URL"); then
            if [ "$WRITE_RESULT" = "unchanged" ]; then
                ok "API key config already current at ${ARKHEIA_CONFIG_FILE}"
            else
                ok "Saved API key to ${ARKHEIA_CONFIG_FILE}"
            fi
        else
            warn "Could not save API key config; continuing without persisting the key."
        fi
    else
        warn "API key was not persisted. Rerun with --persist-api-key to save it to ${ARKHEIA_CONFIG_FILE}."
    fi
fi

# ---------------------------------------------------------------------------
# Install the npm package (this also sets up the Python venv on first run)
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    info "Dry run: would install @arkheia/mcp-server via npx."
else
    info "Installing @arkheia/mcp-server..."
    npx @arkheia/mcp-server --version 2>/dev/null || true
    ok "Package installed."
fi

# ---------------------------------------------------------------------------
# Write Claude Desktop config
# ---------------------------------------------------------------------------
info "Configuring Claude Desktop MCP..."

# Detect config location
if [ "$(uname)" = "Darwin" ]; then
    CONFIG_DIR="${HOME}/Library/Application Support/Claude"
elif [ "$(uname -o 2>/dev/null)" = "Msys" ] || [ "$(uname -o 2>/dev/null)" = "Cygwin" ] || [ -n "${APPDATA:-}" ]; then
    CONFIG_DIR="${APPDATA}/Claude"
else
    CONFIG_DIR="${HOME}/.config/claude"
fi

CONFIG_FILE="${CONFIG_DIR}/claude_desktop_config.json"

# Build the MCP server entry as a temp file. The raw API key is deliberately not
# embedded in Claude config; the Node wrapper loads ~/.arkheia/config.json when
# the user explicitly persisted a key.
if [ "$DRY_RUN" -eq 0 ]; then
    ARKHEIA_CONFIG_TMP=$(mktemp)
    trap 'rm -f "$ARKHEIA_CONFIG_TMP"' EXIT
    "$PYTHON_CMD" -c "
import json, sys
config = {
    'command': 'npx',
    'args': ['@arkheia/mcp-server'],
}
json.dump(config, sys.stdout, indent=2)
" > "$ARKHEIA_CONFIG_TMP"
else
    ARKHEIA_CONFIG_TMP=""
fi

if [ "$DRY_RUN" -eq 1 ]; then
    info "Dry run: would write ${CONFIG_FILE}."
else
    if WRITE_RESULT=$(write_mcp_client_config "$CONFIG_FILE" "$ARKHEIA_CONFIG_TMP" "Claude Desktop"); then
        case "$WRITE_RESULT" in
            unchanged) warn "Arkheia is already configured in ${CONFIG_FILE}." ;;
            custom)    warn "Arkheia is already in ${CONFIG_FILE}; not overwriting custom entry." ;;
            *)         ok "Configured ${CONFIG_FILE}" ;;
        esac
    else
        warn "Could not configure ${CONFIG_FILE}; add the MCP server manually."
    fi
fi

# ---------------------------------------------------------------------------
# Also write Claude Code config (~/.claude/settings.json) if it already exists.
# ---------------------------------------------------------------------------
CLAUDE_CODE_DIR="${HOME}/.claude"
CLAUDE_CODE_CONFIG="${CLAUDE_CODE_DIR}/settings.json"

if [ -d "$CLAUDE_CODE_DIR" ]; then
    if [ -f "$CLAUDE_CODE_CONFIG" ]; then
        if [ "$DRY_RUN" -eq 1 ]; then
            info "Dry run: would configure Claude Code MCP at ${CLAUDE_CODE_CONFIG}."
        elif WRITE_RESULT=$(write_mcp_client_config "$CLAUDE_CODE_CONFIG" "$ARKHEIA_CONFIG_TMP" "Claude Code"); then
            case "$WRITE_RESULT" in
                unchanged) warn "Arkheia is already configured in Claude Code settings." ;;
                custom)    warn "Arkheia is already in Claude Code settings; not overwriting custom entry." ;;
                *)         ok "Configured Claude Code settings." ;;
            esac
        else
            warn "Could not configure Claude Code settings; add the MCP server manually."
        fi
    else
        info "Claude Code directory exists but settings.json is absent; leaving it unchanged."
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}Arkheia MCP Server installed successfully!${NC}"
echo ""
echo "  What's next:"
echo "  1. Restart Claude Desktop (or Claude Code)"
echo "  2. The arkheia_verify tool is now available in your conversations"
echo "  3. If you did not persist a key, start Claude with ARKHEIA_API_KEY set"
echo "  4. Dashboard: https://hermes.arkheia.ai"
echo "  5. Docs: https://arkheia.ai/docs"
echo ""
echo "  ~/.claude/CLAUDE.md was not modified by this installer."
echo -e "  ${YELLOW}Free tier: 1,500 detections/month${NC}"
echo -e "  ${YELLOW}Upgrade at https://arkheia.ai/pricing${NC}"
echo ""
