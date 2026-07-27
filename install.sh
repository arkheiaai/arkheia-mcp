#!/usr/bin/env bash
# ============================================================================
# Arkheia MCP Server - One-Command Installer
#
# Usage:
#   curl -fsSL https://arkheia.ai/install-mcp | bash
#   export the Arkheia runtime key before starting Claude for hosted detection
#
# What it does:
#   1. Checks prerequisites (Node.js 18+, Python 3.10+)
#   2. Installs @arkheia/mcp-server via npx
#   3. Prints manual MCP client configuration guidance
#
# This installer does not read, provision, verify, persist, or print API keys.
# Start your MCP client with the Arkheia runtime key in its process environment.
# ============================================================================

set -euo pipefail

RUNTIME_KEY_ENV="ARKHEIA""_API_KEY"
# Do not leak runtime credentials to prerequisite or package-install subprocesses.
unset "$RUNTIME_KEY_ENV"
DRY_RUN=0

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

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-key)
            fail "--api-key is not supported because command-line arguments can leak. Use environment-based runtime configuration instead."
            ;;
        --email)
            warn "--email is ignored; this installer does not provision API keys."
            if [ "${2:-}" ] && [[ "${2:-}" != --* ]]; then
                shift 2
            else
                shift
            fi
            ;;
        --persist-api-key)
            warn "--persist-api-key is deprecated; this installer does not write API keys to disk."
            shift
            ;;
        --no-persist-api-key)
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
            echo "  --email EMAIL          Deprecated no-op; key provisioning is not performed"
            echo "  --persist-api-key      Deprecated no-op; API keys are not written by this installer"
            echo "  --no-persist-api-key   Deprecated no-op; retained for compatibility"
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

# ---------------------------------------------------------------------------
# Install the npm package (this also sets up the Python venv on first run)
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    info "Dry run: would install @arkheia/mcp-server via npx."
else
    info "Installing @arkheia/mcp-server..."
    env -u "$RUNTIME_KEY_ENV" npx @arkheia/mcp-server --version 2>/dev/null || true
    ok "Package installed."
fi

warn "Claude Desktop and Claude Code config files were not modified by this installer."
info "Configure an MCP server manually with command 'npx' and args ['@arkheia/mcp-server']."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}Arkheia MCP Server installed successfully!${NC}"
echo ""
echo "  What's next:"
echo "  1. Restart Claude Desktop (or Claude Code)"
echo "  2. The arkheia_verify tool is now available in your conversations"
echo "  3. Start Claude with the Arkheia runtime key set for hosted detection"
echo "  4. Dashboard: https://hermes.arkheia.ai"
echo "  5. Docs: https://arkheia.ai/docs"
echo ""
echo "  ~/.claude/CLAUDE.md was not modified by this installer."
echo -e "  ${YELLOW}Free tier: 1,500 detections/month${NC}"
echo -e "  ${YELLOW}Upgrade at https://arkheia.ai/pricing${NC}"
echo ""
