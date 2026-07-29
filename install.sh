#!/usr/bin/env bash
# ============================================================================
# Arkheia MCP Server — One-Command Installer
#
# Usage:
#   curl -fsSL https://arkheia.ai/install-mcp | bash
#   curl -fsSL https://arkheia.ai/install-mcp | bash -s -- --api-key ak_live_...
#
# What it does:
#   1. Checks prerequisites (Node.js 18+, Python 3.10+)
#   2. Provisions a free-tier API key (or uses the one you provide)
#   3. Installs @arkheia/mcp-server via npx
#   4. Writes Claude Desktop / Claude Code MCP config
#
# No data leaves your machine except the API key provisioning call.
# ============================================================================

set -euo pipefail

HOSTED_URL="${ARKHEIA_HOSTED_URL:-https://arkheia-proxy-production.up.railway.app}"
API_KEY="${ARKHEIA_API_KEY:-}"
EMAIL=""
VALIDATE_HOSTED_URL_ONLY=0

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

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)  API_KEY="$2"; shift 2 ;;
        --email)    EMAIL="$2"; shift 2 ;;
        --validate-hosted-url-only) VALIDATE_HOSTED_URL_ONLY=1; shift ;;
        --help|-h)
            echo "Usage: curl -fsSL https://arkheia.ai/install-mcp | bash"
            echo ""
            echo "Options (pass via: bash -s -- --option value):"
            echo "  --api-key KEY   Use an existing API key (skip provisioning)"
            echo "  --email EMAIL   Email for free-tier key provisioning"
            exit 0
            ;;
        *) warn "Unknown option: $1"; shift ;;
    esac
done

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

if [ "$VALIDATE_HOSTED_URL_ONLY" -eq 0 ]; then
    # Node.js 18+
    if ! command -v node &>/dev/null; then
        fail "Node.js is required but not found. Install from https://nodejs.org"
    fi
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        fail "Node.js 18+ required (found v$(node -v)). Update from https://nodejs.org"
    fi
    ok "Node.js $(node -v)"

    # npx
    if ! command -v npx &>/dev/null; then
        fail "npx is required but not found. It should come with Node.js."
    fi
fi

# Python 3.10+
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VERSION=$("$cmd" --version 2>&1 | sed -E 's/.* ([0-9]+)\.([0-9]+).*/\1.\2/' | head -1)
        PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
        PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3.10+ is required but not found. Install from https://python.org"
fi
ok "Python $($PYTHON_CMD --version 2>&1)"

authorize_hosted_url() {
    "$PYTHON_CMD" - "$HOSTED_URL" "${ARKHEIA_ALLOW_UNSAFE_HOSTED_URL:-}" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit, urlunsplit

DEFAULT = "https://arkheia-proxy-production.up.railway.app"
TRUE_VALUES = {"1", "true", "yes", "on"}


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


def default_port(scheme):
    return 80 if scheme == "http" else 443


def self_hosted(host):
    if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private or addr.is_link_local


raw = (sys.argv[1] or DEFAULT).strip() or DEFAULT
allow_unsafe = sys.argv[2].strip().lower() in TRUE_VALUES
parsed = urlsplit(raw)
scheme = parsed.scheme.lower()
host = (parsed.hostname or "").lower()

if scheme not in {"http", "https"} or not host:
    fail("hosted URL must be an absolute http(s) URL")
if parsed.username or parsed.password:
    fail("hosted URL must not contain userinfo")
if parsed.query or parsed.fragment:
    fail("hosted URL must not contain query or fragment")
try:
    port = parsed.port
except ValueError:
    fail("hosted URL contains an invalid port")

netloc = host
if port is not None and port != default_port(scheme):
    netloc = f"{netloc}:{port}"
path = parsed.path.rstrip("/")
base_url = urlunsplit((scheme, netloc, path, "", ""))
origin = urlunsplit((scheme, netloc, "", "", ""))
is_self_hosted = self_hosted(host)

if not allow_unsafe and origin != DEFAULT and not is_self_hosted:
    fail(
        "hosted URL is not the approved Arkheia production authority; "
        "set ARKHEIA_ALLOW_UNSAFE_HOSTED_URL=1 only for trusted custom endpoints"
    )
if not allow_unsafe and scheme != "https" and not is_self_hosted:
    fail("hosted URL must use HTTPS")

print(base_url)
PY
}

AUTHORIZED_HOSTED_URL=$(authorize_hosted_url) || fail "Refusing ARKHEIA_HOSTED_URL=${HOSTED_URL}"
if [ "$VALIDATE_HOSTED_URL_ONLY" -eq 1 ]; then
    echo "$AUTHORIZED_HOSTED_URL"
    exit 0
fi

# ---------------------------------------------------------------------------
# API Key provisioning
# ---------------------------------------------------------------------------
if [ -z "$API_KEY" ]; then
    info "No API key provided — provisioning a free-tier key..."

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
    if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$ ]]; then
        fail "Invalid email format: ${EMAIL}"
    fi

    # Call the provisioning endpoint — email is validated above, payload built safely
    PROVISION_PAYLOAD=$(printf '{"email": "%s"}' "$EMAIL")
    PROVISION_RESPONSE=$(curl -sS -w "\n%{http_code}" \
        -X POST "${AUTHORIZED_HOSTED_URL}/v1/provision" \
        -H "Content-Type: application/json" \
        -d "$PROVISION_PAYLOAD" 2>&1) || fail "Failed to reach ${AUTHORIZED_HOSTED_URL}"

    HTTP_CODE=$(echo "$PROVISION_RESPONSE" | tail -1)
    BODY=$(echo "$PROVISION_RESPONSE" | sed '$d')

    case "$HTTP_CODE" in
        201)
            API_KEY=$(printf '%s' "$BODY" | "$PYTHON_CMD" -c 'import json, sys; print(json.load(sys.stdin).get("api_key", ""))' 2>/dev/null || true)
            if [ -z "$API_KEY" ]; then
                fail "Provisioning succeeded but could not parse API key from response."
            fi
            ok "Free-tier API key provisioned successfully."
            echo ""
            echo -e "  ${BOLD}Your API key: ${API_KEY}${NC}"
            echo -e "  ${YELLOW}Save this key — it will not be shown again.${NC}"
            echo ""
            ;;
        409)
            fail "This email already has a free-tier key. Log in at https://hermes.arkheia.ai to manage your keys, or pass --api-key."
            ;;
        429)
            fail "Rate limit exceeded. Try again later or pass --api-key."
            ;;
        *)
            fail "Provisioning failed (HTTP $HTTP_CODE): $BODY"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# Verify the key works
# ---------------------------------------------------------------------------
info "Verifying API key..."
VERIFY_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    -X POST "${AUTHORIZED_HOSTED_URL}/v1/detect" \
    -H "Content-Type: application/json" \
    -H "X-Arkheia-Key: ${API_KEY}" \
    -d '{"model": "test", "response": "Hello world test."}' 2>&1) || true

case "$VERIFY_CODE" in
    200) ok "API key verified." ;;
    401) fail "API key is invalid. Check your key and try again." ;;
    *)   warn "Could not verify key (HTTP $VERIFY_CODE) — continuing anyway." ;;
esac

# ---------------------------------------------------------------------------
# Install the npm package (this also sets up the Python venv)
# ---------------------------------------------------------------------------
info "Installing @arkheia/mcp-server..."
npx @arkheia/mcp-server --version 2>/dev/null || true
ok "Package installed."

# ---------------------------------------------------------------------------
# Write Claude Desktop config
# ---------------------------------------------------------------------------
info "Configuring Claude Desktop MCP..."

# Detect config location
if [ "$(uname)" = "Darwin" ]; then
    CONFIG_DIR="$HOME/Library/Application Support/Claude"
elif [ "$(uname -o 2>/dev/null)" = "Msys" ] || [ "$(uname -o 2>/dev/null)" = "Cygwin" ] || [ -n "${APPDATA:-}" ]; then
    CONFIG_DIR="${APPDATA}/Claude"
else
    CONFIG_DIR="${HOME}/.config/claude"
fi

CONFIG_FILE="${CONFIG_DIR}/claude_desktop_config.json"

# Create config dir if needed
mkdir -p "$CONFIG_DIR"

# Build the MCP server entry as a temp file (avoids shell interpolation injection)
ARKHEIA_CONFIG_TMP=$(mktemp)
trap 'rm -f "$ARKHEIA_CONFIG_TMP"' EXIT
"$PYTHON_CMD" -c "
import json, sys
config = {
    'command': 'npx',
    'args': ['@arkheia/mcp-server'],
    'env': {'ARKHEIA_API_KEY': sys.argv[1]}
}
json.dump(config, sys.stdout, indent=2)
" "$API_KEY" > "$ARKHEIA_CONFIG_TMP"

if [ -f "$CONFIG_FILE" ]; then
    # Config exists — check if arkheia is already configured
    if grep -q '"arkheia"' "$CONFIG_FILE" 2>/dev/null; then
        warn "Arkheia is already in ${CONFIG_FILE} — not overwriting."
        warn "Update ARKHEIA_API_KEY manually if needed."
    else
        # Merge into existing config using Python — reads from temp file, no interpolation
        "$PYTHON_CMD" -c "
import json, sys
config_path, entry_path = sys.argv[1], sys.argv[2]
with open(config_path, 'r') as f:
    config = json.load(f)
with open(entry_path, 'r') as f:
    entry = json.load(f)
config.setdefault('mcpServers', {})
config['mcpServers']['arkheia'] = entry
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
print('Merged arkheia into existing config.')
" "$CONFIG_FILE" "$ARKHEIA_CONFIG_TMP" || warn "Could not merge config — add manually."
    fi
else
    # Create new config wrapping the entry
    "$PYTHON_CMD" -c "
import json, sys
with open(sys.argv[1], 'r') as f:
    entry = json.load(f)
config = {'mcpServers': {'arkheia': entry}}
with open(sys.argv[2], 'w') as f:
    json.dump(config, f, indent=2)
" "$ARKHEIA_CONFIG_TMP" "$CONFIG_FILE"
    ok "Created ${CONFIG_FILE}"
fi

# ---------------------------------------------------------------------------
# Also write Claude Code config (~/.claude/settings.json)
# ---------------------------------------------------------------------------
CLAUDE_CODE_DIR="${HOME}/.claude"
CLAUDE_CODE_CONFIG="${CLAUDE_CODE_DIR}/settings.json"

if [ -d "$CLAUDE_CODE_DIR" ]; then
    if [ -f "$CLAUDE_CODE_CONFIG" ]; then
        if grep -q '"arkheia"' "$CLAUDE_CODE_CONFIG" 2>/dev/null; then
            warn "Arkheia is already in Claude Code settings — not overwriting."
        else
            "$PYTHON_CMD" -c "
import json, sys
config_path, entry_path = sys.argv[1], sys.argv[2]
with open(config_path, 'r') as f:
    config = json.load(f)
with open(entry_path, 'r') as f:
    entry = json.load(f)
config.setdefault('mcpServers', {})
config['mcpServers']['arkheia'] = entry
with open(config_path, 'w') as f:
    json.dump(config, f, indent=2)
print('Merged arkheia into Claude Code settings.')
" "$CLAUDE_CODE_CONFIG" "$ARKHEIA_CONFIG_TMP" || warn "Could not merge Claude Code config — add manually."
        fi
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
echo "  3. Dashboard: https://hermes.arkheia.ai"
echo "  4. Docs: https://arkheia.ai/docs"
echo ""
echo -e "  ${YELLOW}Free tier: 1,500 detections/month${NC}"
echo -e "  ${YELLOW}Upgrade at https://arkheia.ai/pricing${NC}"
echo ""
