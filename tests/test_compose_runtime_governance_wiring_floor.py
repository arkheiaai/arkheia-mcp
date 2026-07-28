"""
Floor candidate: mcp.compose_runtime_governance_wiring.

The compose stack is a runtime contract, not documentation: the proxy port,
healthcheck URL, MCP proxy URL, registry URL, and writable profile directory all
have to agree at once. A mismatch leaves the stack "up" only on paper.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"


def _service_block(name: str) -> str:
    text = COMPOSE.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"(?ms)^  {re.escape(name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_]+:\n|^volumes:\n|\Z)"
    )
    match = pattern.search(text)
    assert match, f"docker-compose.yaml has no {name!r} service"
    return match.group("body")


def _env(block: str, key: str) -> str:
    match = re.search(rf"^\s+- {re.escape(key)}=([^\n#]+)", block, re.M)
    assert match, f"environment variable {key!r} missing from service block"
    return match.group(1).strip()


def _healthcheck_url(block: str) -> str:
    healthcheck = re.search(r"(?ms)^\s+healthcheck:\n(?P<body>.*?)(?=^\s{4}[A-Za-z_]+:|^  [A-Za-z0-9_]+:|\Z)", block)
    assert healthcheck, f"service block has no healthcheck section: {block!r}"
    match = re.search(r"https?://[^'\" )]+", healthcheck.group("body"))
    assert match, f"healthcheck does not contain an http URL: {healthcheck.group('body')!r}"
    return match.group(0)


def _dockerfile_healthcheck_url(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"HEALTHCHECK\b.*?CMD\s+(.*)", text, re.S)
    assert match, f"{path} has no HEALTHCHECK CMD"
    url = re.search(r"https?://[^'\" )]+", match.group(1))
    assert url, f"{path} HEALTHCHECK CMD has no http URL"
    return url.group(0)


def _dockerfile_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) >= 2 and parts[0] == "ENV":
            if len(parts) == 2 and "=" in parts[1]:
                key, value = parts[1].split("=", 1)
            elif len(parts) == 3:
                key, value = parts[1], parts[2]
            else:
                continue
            env[key] = value
    return env


def _volume_targets(block: str) -> dict[str, tuple[str, set[str]]]:
    targets: dict[str, tuple[str, set[str]]] = {}
    for entry in re.findall(r"^\s+- ([^\n]+)", block, re.M):
        entry = entry.split("#", 1)[0].strip()
        if ":" not in entry or "=" in entry:
            continue
        source, target, *rest = entry.split(":")
        if target.startswith("/"):
            targets[target] = (source, set(rest))
    return targets


def test_proxy_compose_healthcheck_uses_unauthenticated_reachable_runtime_route():
    proxy = _service_block("proxy")
    proxy_port = _env(proxy, "ARKHEIA_PROXY_PORT")
    health_url = urlparse(_healthcheck_url(proxy))

    assert health_url.hostname == "localhost"
    assert health_url.port == int(proxy_port)
    assert health_url.path == "/admin/runtime-health"

    admin_source = (ROOT / "proxy" / "endpoints" / "admin.py").read_text(encoding="utf-8")
    assert '@router.get("/runtime-health")' in admin_source
    assert "async def runtime_health()" in admin_source

    protected = re.search(
        r'@router\.get\("/health"\)\s*\nasync def health\([^)]*Depends\(require_auth\)',
        admin_source,
        re.S,
    )
    assert protected, "operator /admin/health must stay auth-gated"


def test_mcp_proxy_port_agreement_is_consistent_across_compose_and_images():
    proxy = _service_block("proxy")
    mcp = _service_block("mcp_server")
    proxy_port = int(_env(proxy, "ARKHEIA_PROXY_PORT"))

    mcp_proxy = urlparse(_env(mcp, "ARKHEIA_PROXY_URL"))
    assert mcp_proxy.hostname == "proxy"
    assert mcp_proxy.port == proxy_port

    proxy_dockerfile = ROOT / "proxy" / "Dockerfile"
    proxy_image_env = _dockerfile_env(proxy_dockerfile)
    assert proxy_image_env["ARKHEIA_PROXY_PORT"] == str(proxy_port)
    assert f"EXPOSE {proxy_port}" in proxy_dockerfile.read_text(encoding="utf-8")
    assert urlparse(_dockerfile_healthcheck_url(proxy_dockerfile)).port == proxy_port

    mcp_image_env = _dockerfile_env(ROOT / "mcp_server" / "Dockerfile")
    assert urlparse(mcp_image_env["ARKHEIA_PROXY_URL"]).port == proxy_port

    server_source = (ROOT / "mcp_server" / "server.py").read_text(encoding="utf-8")
    assert f"http://localhost:{proxy_port}" in server_source


def test_registry_and_profile_paths_are_reachable_and_writable_from_compose():
    proxy = _service_block("proxy")
    registry = _service_block("registry")

    registry_url = urlparse(_env(proxy, "ARKHEIA_REGISTRY_URL"))
    advertised_base = urlparse(_env(registry, "ARKHEIA_REGISTRY_BASE_URL"))
    assert registry_url.scheme == "http"
    assert registry_url.hostname == "registry"
    assert registry_url.port == 8200
    assert advertised_base.geturl() == registry_url.geturl()
    assert registry_url.hostname not in {"localhost", "127.0.0.1", "::1"}

    profile_dir = _env(proxy, "ARKHEIA_PROFILES_DIR")
    assert profile_dir == "/etc/arkheia/profiles"

    targets = _volume_targets(proxy)
    assert profile_dir in targets, (
        "the profile write directory must be a mounted volume, not the read-only "
        "./profiles bind mount"
    )
    source, flags = targets[profile_dir]
    assert source == "profile_data"
    assert "ro" not in flags and "true" not in flags

    proxy_image_env = _dockerfile_env(ROOT / "proxy" / "Dockerfile")
    assert proxy_image_env["ARKHEIA_PROFILES_DIR"] == profile_dir


def test_registry_url_environment_variable_reaches_proxy_settings():
    source = (ROOT / "proxy" / "config.py").read_text(encoding="utf-8")
    registry_settings = re.search(r"class _RegistrySettings:.*?class _AuditSettings:", source, re.S)
    assert registry_settings, "proxy.config has no _RegistrySettings block"
    assert (
        'os.environ.get(\n        "ARKHEIA_REGISTRY_URL",' in registry_settings.group(0)
    ), "ARKHEIA_REGISTRY_URL must feed proxy.settings.registry.url"
