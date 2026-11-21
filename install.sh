#!/usr/bin/env bash
# ============================================================================
# Arkheia MCP Server — One-Command Installer
#
# Usage:
#   curl -fsSL https://arkheia.ai/install-mcp | bash
#   curl -fsSL https://arkheia.ai/install-mcp | bash -s -- --api-key ak_live_...
#
# What it does:
#   1. Checks prerequisites (Node.js 20+, npm; Python 3.10+ is used only by this script to read
#      JSON and edit config files, the server itself is Node and needs no Python)
#   2. Provisions a free-tier API key (or uses the one you provide). A new key works only after
#      you confirm your email address.
#   3. Installs @arkheia/mcp-server globally with npm and checks that the `mcp-server` command exists
#   4. Registers it with Claude Code using `claude mcp add` (if the `claude` command is present);
#      otherwise prints the exact command to run and says registration was NOT done
#   5. If Claude Desktop is installed, also writes its MCP config
#
# Exit status: 0 = installed and registered; 1 = a step failed; 3 = the key is not confirmed yet;
#              10 = installed, but NOT registered (no `claude` command; run the printed command).
# A success message is printed only when the install and the registration both succeeded.
#
# No data leaves your machine except the API key provisioning and check calls.
# ============================================================================

set -euo pipefail

HOSTED_URL="${ARKHEIA_HOSTED_URL:-https://arkheia-proxy-production.up.railway.app}"
API_KEY="${ARKHEIA_API_KEY:-}"
EMAIL=""

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
# Prerequisites (portable: no GNU-only grep or mktemp options)
# ---------------------------------------------------------------------------
info "Checking prerequisites..."

# Node.js 20+
if ! command -v node >/dev/null 2>&1; then
    fail "Node.js is required but not found. Install from https://nodejs.org"
fi
NODE_VERSION=$(node -v | sed 's/^v//' | cut -d. -f1)
case "$NODE_VERSION" in
    ''|*[!0-9]*) fail "Could not read the Node.js version. Install Node.js 20+ from https://nodejs.org" ;;
esac
if [ "$NODE_VERSION" -lt 20 ]; then
    fail "Node.js 20+ required (found $(node -v)). Update from https://nodejs.org"
fi
ok "Node.js $(node -v)"

# npm
if ! command -v npm >/dev/null 2>&1; then
    fail "npm is required but not found. It should come with Node.js."
fi

# Python 3.10+ (used only by this script, to read JSON and edit config files)
PYTHON_CMD=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1; then
        if "$cmd" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)' >/dev/null 2>&1; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done
if [ -z "$PYTHON_CMD" ]; then
    fail "Python 3.10+ is required by this installer (to read and edit JSON) but was not found. Install from https://python.org"
fi
ok "Python $("$PYTHON_CMD" --version 2>&1)"

# The address printed in messages: scheme, host and port only (never a username, password, path or query).
display_origin() {
    "$PYTHON_CMD" -c '
import sys
from urllib.parse import urlsplit
try:
    u = urlsplit(sys.argv[1])
    host = u.netloc.rsplit("@", 1)[-1]
    print(u.scheme + "://" + host if u.scheme in ("http", "https") and host else "an address that is not valid")
except Exception:
    print("an address that is not valid")
' "$1" 2>/dev/null || echo "the configured address"
}

# Reads one string field from a JSON document on stdin; prints nothing if it is absent or not JSON.
json_field() {
    "$PYTHON_CMD" -c '
import json, sys
try:
    v = json.load(sys.stdin).get(sys.argv[1], "")
    print(v if isinstance(v, str) else "")
except Exception:
    print("")
' "$1"
}

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
    EMAIL_RE='^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if ! [[ "$EMAIL" =~ $EMAIL_RE ]]; then
        fail "Invalid email format: ${EMAIL}"
    fi

    # Call the provisioning endpoint — email is validated above, payload built safely
    PROVISION_PAYLOAD=$(printf '{"email": "%s"}' "$EMAIL")
    PROVISION_RESPONSE=$(curl -sS -w "\n%{http_code}" \
        -X POST "${HOSTED_URL}/v1/provision" \
        -H "Content-Type: application/json" \
        -d "$PROVISION_PAYLOAD" 2>/dev/null) || fail "Failed to reach $(display_origin "$HOSTED_URL")"

    HTTP_CODE=$(echo "$PROVISION_RESPONSE" | tail -1)
    BODY=$(echo "$PROVISION_RESPONSE" | sed '$d')

    case "$HTTP_CODE" in
        201)
            API_KEY=$(printf '%s' "$BODY" | json_field api_key)
            if [ -z "$API_KEY" ]; then
                fail "Provisioning succeeded but could not read the API key from the response."
            fi
            ok "Free-tier API key requested."
            echo ""
            echo -e "  ${BOLD}Your API key: ${API_KEY}${NC}"
            echo -e "  ${YELLOW}Save this key — it will not be shown again.${NC}"
            echo -e "  ${YELLOW}It works only after you confirm your email: open the link we emailed you and press Confirm.${NC}"
            echo ""
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

# ---------------------------------------------------------------------------
# Verify the key works
# ---------------------------------------------------------------------------
info "Verifying API key..."
VERIFY_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
    -X POST "${HOSTED_URL}/v1/detect" \
    -H "Content-Type: application/json" \
    -H "X-Arkheia-Key: ${API_KEY}" \
    -d '{"model": "test", "response": "Hello world test."}' 2>/dev/null) || VERIFY_CODE="unreachable"

case "$VERIFY_CODE" in
    200) ok "API key verified." ;;
    401) fail "API key is invalid. Check your key and try again." ;;
    403)
        echo -e "${RED}[arkheia]${NC} This key is not confirmed yet (HTTP 403)." >&2
        echo "  A new key works only after you confirm your email address:" >&2
        echo "    1. Open the email we sent you and click the link." >&2
        echo "    2. Press Confirm on the page that opens." >&2
        echo "    3. Run this installer again with:  --api-key <your key>" >&2
        echo "  A request that is not confirmed within 24 hours is deleted; you can then ask for a new key." >&2
        echo "  Nothing was installed or registered." >&2
        exit 3
        ;;
    *)   warn "Could not verify the key (${VERIFY_CODE}) — continuing, but detection will not work until the key is accepted." ;;
esac

# ---------------------------------------------------------------------------
# Install the npm package, and check that it really installed
# ---------------------------------------------------------------------------
info "Installing @arkheia/mcp-server with npm..."
if ! npm install -g @arkheia/mcp-server; then
    fail "npm could not install @arkheia/mcp-server (see the npm output above). Nothing was registered. If this is a permissions error, fix your npm prefix (https://docs.npmjs.com/resolving-eacces-permissions-errors-when-installing-packages-globally) and run the installer again."
fi
if ! command -v mcp-server >/dev/null 2>&1; then
    fail "npm reported success but the 'mcp-server' command is not on your PATH. Add npm's global bin directory ($(npm prefix -g 2>/dev/null || echo 'see: npm prefix -g')/bin) to PATH and run the installer again. Nothing was registered."
fi
ok "Package installed ('mcp-server' is on your PATH)."

# ---------------------------------------------------------------------------
# Register with Claude Code (the documented command), when the claude CLI is present
# ---------------------------------------------------------------------------
REGISTER_CMD='claude mcp add arkheia -s user -e ARKHEIA_API_KEY="$ARKHEIA_API_KEY" -- mcp-server'
REGISTERED=0
if command -v claude >/dev/null 2>&1; then
    info "Registering with Claude Code..."
    if claude mcp add arkheia -s user -e "ARKHEIA_API_KEY=${API_KEY}" -- mcp-server; then
        REGISTERED=1
        ok "Registered with Claude Code."
    else
        REG_STATUS=$?
        echo -e "${RED}[arkheia]${NC} 'claude mcp add' failed (exit status ${REG_STATUS}); Arkheia is NOT registered with Claude Code." >&2
        echo "  If arkheia is already registered, remove it with:  claude mcp remove arkheia -s user   and run the installer again." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
# Claude Desktop (only if it is installed): extra, never counted as the registration above
# ---------------------------------------------------------------------------
if [ "$(uname)" = "Darwin" ]; then
    CONFIG_DIR="$HOME/Library/Application Support/Claude"
elif [ -n "${APPDATA:-}" ]; then
    CONFIG_DIR="${APPDATA}/Claude"
else
    CONFIG_DIR="${HOME}/.config/Claude"
fi
CONFIG_FILE="${CONFIG_DIR}/claude_desktop_config.json"
DESKTOP_NOTE=""
if [ -d "$CONFIG_DIR" ]; then
    ARKHEIA_CONFIG_TMP=$(mktemp "${TMPDIR:-/tmp}/arkheia-config.XXXXXX")
    trap 'rm -f "$ARKHEIA_CONFIG_TMP"' EXIT
    # The key goes through the environment, never the command line.
    if ARKHEIA_KEY_FOR_CONFIG="$API_KEY" "$PYTHON_CMD" -c '
import json, os, sys
path = sys.argv[1]
try:
    with open(path) as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}
servers = config.setdefault("mcpServers", {})
if "arkheia" in servers:
    print("exists")
    raise SystemExit(0)
servers["arkheia"] = {"command": "npx", "args": ["@arkheia/mcp-server"], "env": {"ARKHEIA_API_KEY": os.environ["ARKHEIA_KEY_FOR_CONFIG"]}}
with open(path, "w") as f:
    json.dump(config, f, indent=2)
print("written")
' "$CONFIG_FILE" > "$ARKHEIA_CONFIG_TMP"; then
        if grep -q exists "$ARKHEIA_CONFIG_TMP"; then
            DESKTOP_NOTE="Claude Desktop already lists arkheia; its config was not changed."
        else
            DESKTOP_NOTE="Claude Desktop config updated: ${CONFIG_FILE}"
        fi
    else
        DESKTOP_NOTE="Claude Desktop config could not be updated; add the server there by hand."
        warn "$DESKTOP_NOTE"
    fi
fi

# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
echo ""
if [ "$REGISTERED" -ne 1 ]; then
    echo -e "${YELLOW}${BOLD}Arkheia is installed but NOT registered with Claude Code.${NC}" >&2
    echo "  The 'claude' command was not found. Registration was NOT done." >&2
    echo "  Run this yourself, with your key in ARKHEIA_API_KEY:" >&2
    echo "      export ARKHEIA_API_KEY=<your key>" >&2
    echo "      ${REGISTER_CMD}" >&2
    [ -n "$DESKTOP_NOTE" ] && echo "  ${DESKTOP_NOTE}" >&2
    echo "  Commands for other agents: https://github.com/arkheiaai/arkheia-mcp/blob/main/npm-wrapper/README.md#register-with-your-cli" >&2
    exit 10
fi

echo -e "${GREEN}${BOLD}Arkheia MCP Server installed and registered.${NC}"
echo ""
[ -n "$DESKTOP_NOTE" ] && echo "  ${DESKTOP_NOTE}"
echo "  What's next:"
echo "  1. Restart Claude Code (or Claude Desktop)"
echo "  2. The arkheia_verify tool is now available in your conversations"
echo "  3. Dashboard: https://hermes.arkheia.ai"
echo "  4. Docs: https://arkheia.ai/docs"
echo ""
echo -e "  ${YELLOW}Free tier: 1,500 detections/month${NC}"
echo -e "  ${YELLOW}Upgrade at https://arkheia.ai/pricing${NC}"
echo ""
