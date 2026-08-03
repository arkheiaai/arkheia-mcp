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
HOSTED_URL="${ARKHEIA_HOSTED_URL:-https://arkheia-proxy-production.up.railway.app}"
VALIDATE_HOSTED_URL_ONLY=0
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
        --validate-hosted-url-only) VALIDATE_HOSTED_URL_ONLY=1; shift ;;
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

if [ "$VALIDATE_HOSTED_URL_ONLY" -eq 0 ]; then
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

authorize_hosted_url() {
    "$PYTHON_CMD" - "$HOSTED_URL" "${ARKHEIA_ALLOW_UNSAFE_HOSTED_URL:-}" <<'PY'
import ipaddress
import socket
import sys
from urllib.parse import urlsplit, urlunsplit

DEFAULT = "https://arkheia-proxy-production.up.railway.app"
TRUE_VALUES = {"1", "true", "yes", "on"}
SELF_HOSTED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(2)


def default_port(scheme):
    return 80 if scheme == "http" else 443


def resolve_host_addresses(host):
    if host == "localhost" or host.endswith(".localhost"):
        return (ipaddress.ip_address("127.0.0.1"),)
    try:
        return (ipaddress.ip_address(host),)
    except ValueError:
        pass

    addresses = set()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()

    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        if not sockaddr:
            continue
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return tuple(addresses)


def normalize_mapped(addr):
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def loopback(host):
    addresses = resolve_host_addresses(host)
    return bool(addresses) and all(normalize_mapped(addr).is_loopback for addr in addresses)


def self_hosted(host):
    addresses = resolve_host_addresses(host)
    return bool(addresses) and all(
        any(normalize_mapped(addr) in network for network in SELF_HOSTED_NETWORKS)
        for addr in addresses
    )


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
needs_self_hosted_check = not allow_unsafe and origin != DEFAULT
is_self_hosted = self_hosted(host) if needs_self_hosted_check else False
needs_loopback_check = not allow_unsafe and scheme != "https"
is_loopback = loopback(host) if needs_loopback_check else False

if not allow_unsafe and origin != DEFAULT and not is_self_hosted:
    fail(
        "hosted URL is not the approved Arkheia production authority; "
        "set ARKHEIA_ALLOW_UNSAFE_HOSTED_URL=1 only for trusted custom endpoints"
    )
if not allow_unsafe and scheme != "https" and not is_loopback:
    fail("hosted URL must use HTTPS unless it is loopback-local")

print(base_url)
PY
}

AUTHORIZED_HOSTED_URL=$(authorize_hosted_url) || fail "Refusing ARKHEIA_HOSTED_URL=${HOSTED_URL}"
if [ "$VALIDATE_HOSTED_URL_ONLY" -eq 1 ]; then
    echo "$AUTHORIZED_HOSTED_URL"
    exit 0
fi

hosted_curl() {
    curl --noproxy '*' "$@"
}

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
