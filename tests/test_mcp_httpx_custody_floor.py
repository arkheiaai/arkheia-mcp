"""
FLOOR TIER -- MCP outbound HTTP custody.

These checks are static and dependency-light: they discover every MCP-owned
``httpx.AsyncClient`` constructor that can carry provider, proxy, or Arkheia API
credentials and require the client to opt out of environment proxy settings.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _first_party_sources() -> list[Path]:
    return sorted(
        path
        for root in (REPO_ROOT / "mcp_server", REPO_ROOT / "proxy")
        for path in root.rglob("*.py")
        if "tests" not in path.relative_to(REPO_ROOT).parts
    )


def _httpx_bindings(tree: ast.AST) -> tuple[set[str], set[str]]:
    module_aliases = {"httpx"}
    async_client_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "httpx":
                    module_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "httpx":
            for alias in node.names:
                if alias.name == "AsyncClient":
                    async_client_names.add(alias.asname or alias.name)
    return module_aliases, async_client_names


def _is_httpx_async_client(
    call: ast.Call,
    module_aliases: set[str],
    async_client_names: set[str],
) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        return (
            func.attr == "AsyncClient"
            and isinstance(func.value, ast.Name)
            and func.value.id in module_aliases
        )
    return isinstance(func, ast.Name) and func.id in async_client_names


def _async_clients_without_trust_env_false(source: str) -> list[int]:
    tree = ast.parse(source)
    module_aliases, async_client_names = _httpx_bindings(tree)
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_httpx_async_client(
            node, module_aliases, async_client_names
        ):
            continue
        explicit_false = any(
            kw.arg == "trust_env"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.keywords
        )
        if not explicit_false:
            bad.append(node.lineno)
    return bad


def _ambient_client_imports(source: str) -> list[str]:
    tree = ast.parse(source)
    bad = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "requests" or alias.name == "urllib.request":
                    bad.append(f"{alias.name} at line {node.lineno}")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "requests":
                bad.append(f"from requests at line {node.lineno}")
            if node.module == "urllib.request" and any(
                alias.name == "urlopen" for alias in node.names
            ):
                bad.append(f"urllib.request.urlopen at line {node.lineno}")
    return bad


def test_all_mcp_outbound_httpx_clients_disable_environment_proxy_custody():
    discovered = 0
    violations = []
    source_files = _first_party_sources()
    assert source_files, "no mcp_server source files discovered"
    for path in source_files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, str(path))
        clients = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _is_httpx_async_client(node, *_httpx_bindings(tree))
        ]
        discovered += len(clients)
        for line in _async_clients_without_trust_env_false(source):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{line}")

    assert discovered >= 14, (
        f"discovered only {discovered} MCP/proxy outbound clients; the census likely "
        "missed a target module or directory."
    )
    assert violations == [], (
        "MCP outbound httpx clients must pass trust_env=False so HTTP_PROXY and "
        "HTTPS_PROXY cannot capture provider/proxy credentials by default:\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_no_unowned_requests_or_urlopen_clients_enter_custody_surface():
    violations = []
    for path in _first_party_sources():
        for marker in _ambient_client_imports(path.read_text(encoding="utf-8")):
            violations.append(f"{path.relative_to(REPO_ROOT)}: {marker}")

    assert violations == [], (
        "MCP/proxy credentialed egress must not introduce ambient-proxy-capable "
        "requests or urllib.request.urlopen clients outside the owned custody helper:\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_negative_self_test_prefix_client_is_flagged():
    pre_fix = "async with httpx.AsyncClient(timeout=10.0) as client:\n    pass\n"
    assert _async_clients_without_trust_env_false(pre_fix) == [1]


def test_negative_self_test_httpx_aliases_are_flagged():
    assert _async_clients_without_trust_env_false(
        "import httpx as hx\nasync with hx.AsyncClient(timeout=10.0) as client:\n    pass\n"
    ) == [2]
    assert _async_clients_without_trust_env_false(
        "from httpx import AsyncClient\nasync with AsyncClient(timeout=10.0) as client:\n    pass\n"
    ) == [2]


def test_negative_self_test_ambient_requests_and_urlopen_are_flagged():
    bad = "\n".join([
        "import requests",
        "import urllib.request as ureq",
        "from urllib.request import urlopen",
    ])
    assert _ambient_client_imports(bad) == [
        "requests at line 1",
        "urllib.request at line 2",
        "urllib.request.urlopen at line 3",
    ]


def test_control_client_with_trust_env_false_is_not_flagged():
    good = (
        "async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:\n"
        "    pass\n"
    )
    assert _async_clients_without_trust_env_false(good) == []
