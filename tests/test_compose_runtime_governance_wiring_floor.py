"""
Floor candidate: mcp.compose_runtime_governance_wiring.

The compose stack is a runtime contract, not documentation: the proxy port,
healthcheck URL, MCP proxy URL, registry URL, and writable profile directory all
have to agree at once. A mismatch leaves the stack "up" only on paper.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"
ADMIN = ROOT / "proxy" / "endpoints" / "admin.py"
EXPECTED_COMPOSE_SERVICES = {"proxy", "registry", "mcp_server"}
EXPECTED_ADMIN_ROUTES = {
    ("GET", "/admin/health"),
    ("GET", "/admin/runtime-health"),
    ("POST", "/admin/registry/pull"),
    ("POST", "/admin/profiles/{model_id}/rollback"),
    ("GET", "/admin/profiles"),
    ("GET", "/admin/ui"),
}
PATH_PARAM = re.compile(r"\{([^}:]+)(?::[^}]+)?\}")


class _AdminRoute(NamedTuple):
    method: str
    path: str
    function: str
    depends_require_auth: bool


def _service_blocks() -> dict[str, str]:
    text = COMPOSE.read_text(encoding="utf-8")
    services = re.search(r"(?ms)^services:\n(?P<body>.*?)(?=^volumes:\n|\Z)", text)
    assert services, "docker-compose.yaml has no services block"
    return {
        match.group("name"): match.group("body")
        for match in re.finditer(
            r"(?ms)^  (?P<name>[A-Za-z0-9_-]+):\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|^volumes:\n|\Z)",
            services.group("body"),
        )
    }


def _service_block(name: str) -> str:
    blocks = _service_blocks()
    assert name in blocks, f"docker-compose.yaml has no {name!r} service"
    return blocks[name]


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _canonical_route_path(path: str) -> str:
    """Compare route identity without pinning FastAPI path-converter spelling."""
    return PATH_PARAM.sub(r"{\1}", path)


def _admin_prefix(tree: ast.Module) -> str:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "router"
            for target in node.targets
        ):
            continue
        if not isinstance(node.value, ast.Call) or _name(node.value.func) != "APIRouter":
            continue
        for kw in node.value.keywords:
            if (
                kw.arg == "prefix"
                and isinstance(kw.value, ast.Constant)
                and isinstance(kw.value.value, str)
            ):
                return kw.value.value
    raise AssertionError("proxy.endpoints.admin has no APIRouter(prefix=...) declaration")


def _depends_require_auth(node: ast.AST) -> bool:
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or _name(call.func).split(".")[-1] != "Depends":
            continue
        if call.args and _name(call.args[0]) == "require_auth":
            return True
        for kw in call.keywords:
            if kw.arg == "dependency" and _name(kw.value) == "require_auth":
                return True
    return False


def _router_depends_require_auth(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "router"
            for target in node.targets
        ):
            continue
        if isinstance(node.value, ast.Call) and _name(node.value.func) == "APIRouter":
            return _depends_require_auth(node.value)
    raise AssertionError("proxy.endpoints.admin has no APIRouter(...) declaration")


def _admin_routes() -> list[_AdminRoute]:
    source = ADMIN.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(ADMIN))
    prefix = _admin_prefix(tree)
    router_requires_auth = _router_depends_require_auth(tree)
    routes: list[_AdminRoute] = []
    for node in tree.body:
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            if not _name(decorator.func).startswith("router."):
                continue
            method = _name(decorator.func).split(".")[-1].upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                continue
            if not decorator.args:
                continue
            route_path = decorator.args[0]
            if not isinstance(route_path, ast.Constant) or not isinstance(route_path.value, str):
                continue
            routes.append(
                _AdminRoute(
                    method=method,
                    path=f"{prefix}{route_path.value}",
                    function=node.name,
                    depends_require_auth=router_requires_auth or _depends_require_auth(node),
                )
            )
    return routes


def test_compose_service_population_is_discovered_and_non_vacuous():
    services = _service_blocks()
    assert services, "discovered ZERO compose services; this floor is vacuous"
    missing = sorted(EXPECTED_COMPOSE_SERVICES - set(services))
    assert missing == [], f"compose services missing from current runtime floor: {missing}"
    empty = sorted(
        name for name in EXPECTED_COMPOSE_SERVICES
        if name in services and not services[name].strip()
    )
    assert empty == [], f"compose service blocks parsed as empty: {empty}"


def test_admin_route_population_is_discovered_and_runtime_health_stays_public():
    routes = _admin_routes()
    assert routes, "discovered ZERO admin routes; this floor is vacuous"
    discovered = {
        (route.method, _canonical_route_path(route.path))
        for route in routes
    }
    missing = sorted(EXPECTED_ADMIN_ROUTES - discovered)
    assert missing == [], f"admin route population shrank or route parser drifted: {missing}"
    assert len(routes) >= len(EXPECTED_ADMIN_ROUTES), (
        "admin route population is smaller than the known governance baseline"
    )

    by_route = {
        (route.method, _canonical_route_path(route.path)): route
        for route in routes
    }
    runtime = by_route[("GET", "/admin/runtime-health")]
    assert runtime.function == "runtime_health"
    assert runtime.depends_require_auth is False, (
        "/admin/runtime-health is the unauthenticated container liveness route; "
        "adding Depends(require_auth) makes Docker/compose healthchecks fail closed"
    )

    health = by_route[("GET", "/admin/health")]
    assert health.depends_require_auth is True, "operator /admin/health must stay auth-gated"


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
