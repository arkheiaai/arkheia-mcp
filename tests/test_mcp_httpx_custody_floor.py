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
        for path in (REPO_ROOT / "mcp_server").rglob("*.py")
        if "tests" not in path.relative_to(REPO_ROOT).parts
    )


def _is_httpx_async_client(call: ast.Call) -> bool:
    func = call.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "AsyncClient"
        and isinstance(func.value, ast.Name)
        and func.value.id == "httpx"
    )


def _async_clients_without_trust_env_false(source: str) -> list[int]:
    tree = ast.parse(source)
    bad = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _is_httpx_async_client(node):
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
            if isinstance(node, ast.Call) and _is_httpx_async_client(node)
        ]
        discovered += len(clients)
        for line in _async_clients_without_trust_env_false(source):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{line}")

    assert discovered >= 7, (
        f"discovered only {discovered} MCP outbound clients; the census likely "
        "missed a target module."
    )
    assert violations == [], (
        "MCP outbound httpx clients must pass trust_env=False so HTTP_PROXY and "
        "HTTPS_PROXY cannot capture provider/proxy credentials by default:\n"
        + "\n".join(f"  {v}" for v in violations)
    )


def test_negative_self_test_prefix_client_is_flagged():
    pre_fix = "async with httpx.AsyncClient(timeout=10.0) as client:\n    pass\n"
    assert _async_clients_without_trust_env_false(pre_fix) == [1]


def test_control_client_with_trust_env_false_is_not_flagged():
    good = (
        "async with httpx.AsyncClient(timeout=10.0, trust_env=False) as client:\n"
        "    pass\n"
    )
    assert _async_clients_without_trust_env_false(good) == []
