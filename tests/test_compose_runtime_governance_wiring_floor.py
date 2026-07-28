"""
Floor candidate: mcp.compose_runtime_governance_wiring.

The compose stack is a runtime contract, not documentation: the proxy port,
healthcheck URL, MCP proxy URL, registry URL, and writable profile directory all
have to agree at once. A mismatch leaves the stack "up" only on paper.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.endpoints.admin import router as admin_router

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yaml"


def _compose() -> dict:
    data = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert data and data.get("services"), "docker-compose.yaml defined no services"
    return data


def _service(name: str) -> dict:
    services = _compose()["services"]
    assert name in services, f"docker-compose.yaml has no {name!r} service"
    return services[name]


def _env(service: dict) -> dict[str, str]:
    raw = service.get("environment", {})
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    env: dict[str, str] = {}
    for item in raw:
        key, sep, value = str(item).partition("=")
        assert sep, f"environment item is not KEY=value: {item!r}"
        env[key] = value
    return env


def _healthcheck_url(service: dict) -> str:
    test = service.get("healthcheck", {}).get("test", [])
    text = " ".join(str(part) for part in test)
    match = re.search(r"https?://[^'\" )]+", text)
    assert match, f"healthcheck does not contain an http URL: {test!r}"
    return match.group(0)


def _dockerfile_healthcheck_url(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"HEALTHCHECK\b.*?CMD\s+(.*)", text, re.S)
    assert match, f"{path} has no HEALTHCHECK CMD"
    return _healthcheck_url({"healthcheck": {"test": [match.group(1)]}})


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


def _volume_targets(service: dict) -> dict[str, tuple[str, set[str]]]:
    targets: dict[str, tuple[str, set[str]]] = {}
    for entry in service.get("volumes", []):
        if isinstance(entry, str):
            source, target, *rest = entry.split(":")
            targets[target] = (source, set(rest))
        else:
            targets[str(entry["target"])] = (
                str(entry.get("source", "")),
                {str(entry.get("read_only", False)).lower()},
            )
    return targets


def test_proxy_compose_healthcheck_uses_unauthenticated_reachable_runtime_route():
    proxy = _service("proxy")
    proxy_env = _env(proxy)
    health_url = urlparse(_healthcheck_url(proxy))

    assert health_url.hostname == "localhost"
    assert health_url.port == int(proxy_env["ARKHEIA_PROXY_PORT"])
    assert health_url.path == "/admin/runtime-health"

    app = FastAPI()
    app.include_router(admin_router)
    client = TestClient(app)

    runtime = client.get(health_url.path)
    assert runtime.status_code == 200, runtime.text
    assert runtime.json() == {"status": "ok"}

    protected = client.get("/admin/health")
    assert protected.status_code == 401, (
        "Docker healthchecks need an unauthenticated endpoint, but the operator "
        "health endpoint must stay protected."
    )


def test_mcp_proxy_port_agreement_is_consistent_across_compose_and_images():
    proxy_env = _env(_service("proxy"))
    mcp_env = _env(_service("mcp_server"))
    proxy_port = int(proxy_env["ARKHEIA_PROXY_PORT"])

    mcp_proxy = urlparse(mcp_env["ARKHEIA_PROXY_URL"])
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
    proxy_env = _env(_service("proxy"))
    registry_env = _env(_service("registry"))

    registry_url = urlparse(proxy_env["ARKHEIA_REGISTRY_URL"])
    advertised_base = urlparse(registry_env["ARKHEIA_REGISTRY_BASE_URL"])
    assert registry_url.scheme == "http"
    assert registry_url.hostname == "registry"
    assert registry_url.port == 8200
    assert advertised_base.geturl() == registry_url.geturl()
    assert registry_url.hostname not in {"localhost", "127.0.0.1", "::1"}

    profile_dir = proxy_env["ARKHEIA_PROFILES_DIR"]
    assert profile_dir == "/etc/arkheia/profiles"

    targets = _volume_targets(_service("proxy"))
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
    env = os.environ.copy()
    env["ARKHEIA_REGISTRY_URL"] = "http://registry:8200"
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from proxy.config import settings; print(settings.registry.url)",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=True,
    )
    assert result.stdout.strip().splitlines()[-1] == "http://registry:8200"
