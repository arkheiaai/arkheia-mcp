"""
FLOOR TIER -- MCP outbound HTTP custody.

These checks are static and dependency-light: they discover every MCP/proxy
egress site that can carry provider, proxy, or Arkheia API credentials and
require those sites to use the shared no-ambient-proxy client factories.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EGRESS_FACTORY_NAMES = {"egress_async_client", "hosted_key_egress_client"}


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


def _egress_factory_bindings(tree: ast.AST) -> set[str]:
    names = set(EGRESS_FACTORY_NAMES)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module not in {"arkheia_common.egress", "arkheia_common.hosted_authority"}:
            continue
        for alias in node.names:
            if alias.name in EGRESS_FACTORY_NAMES:
                names.add(alias.asname or alias.name)
    return names


def _is_egress_factory_call(call: ast.Call, factory_names: set[str]) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in factory_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr in EGRESS_FACTORY_NAMES
    )


def _egress_factory_call_lines(source: str) -> list[int]:
    tree = ast.parse(source)
    factory_names = _egress_factory_bindings(tree)
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _is_egress_factory_call(node, factory_names)
    ]


def test_all_mcp_outbound_http_uses_shared_no_proxy_custody_factories():
    factory_sites = []
    violations = []
    source_files = _first_party_sources()
    assert source_files, "no mcp_server source files discovered"
    for path in source_files:
        source = path.read_text(encoding="utf-8")
        for line in _egress_factory_call_lines(source):
            factory_sites.append(f"{path.relative_to(REPO_ROOT)}:{line}")
        for line in _async_clients_without_trust_env_false(source):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{line}")

    assert len(factory_sites) >= 12, (
        f"discovered only {len(factory_sites)} shared egress factory sites; "
        "the census likely missed a target module or directory."
    )
    assert violations == [], (
        "MCP/proxy outbound HTTP must use arkheia_common egress factories so "
        "HTTP_PROXY and HTTPS_PROXY cannot capture provider/proxy credentials "
        "by default; raw clients found at:\n"
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


def test_control_shared_factory_sites_are_counted():
    source = "\n".join([
        "from arkheia_common.egress import egress_async_client as owned_client",
        "from arkheia_common.hosted_authority import hosted_key_egress_client",
        "async def send():",
        "    async with owned_client(timeout=1.0):",
        "        pass",
        "    async with hosted_key_egress_client(timeout=1.0):",
        "        pass",
    ])
    assert _egress_factory_call_lines(source) == [4, 6]
