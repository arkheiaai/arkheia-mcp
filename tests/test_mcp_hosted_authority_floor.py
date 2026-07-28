"""
FLOOR TIER -- hosted Arkheia key egress authority.

The defect this floor pins is narrow: two hosted MCP/proxy paths send
``X-Arkheia-Key`` to ``ARKHEIA_HOSTED_URL`` without first proving that URL is an
approved Arkheia authority. This file is stdlib + pytest only and reasons over
source text, so it runs in the bare floor-invariants job.
"""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "arkheia_common" / "hosted_authority.py"

EGRESS_SITES = {
    ROOT / "mcp_server" / "proxy_client.py": "_verify_hosted",
    ROOT / "proxy" / "crypto" / "profile_crypto.py": "_fetch_from_hosted",
}


def _tree(path: Path) -> ast.Module:
    assert path.exists(), f"{path.relative_to(ROOT)} is missing; floor observes nothing"
    return ast.parse(path.read_text(encoding="utf-8"), str(path))


def _function(tree: ast.Module, name: str) -> ast.AsyncFunctionDef | ast.FunctionDef:
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name}() not found; egress site moved without updating floor")


def _calls_authorizer(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "authorize_hosted_base_url"
    )


def _imports_authorizer_from_policy(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.module != "arkheia_common.hosted_authority":
            continue
        if any(alias.name == "authorize_hosted_base_url" for alias in node.names):
            return True
    return False


def test_policy_defaults_to_https_production_arkheia_authority_with_explicit_opt_in():
    tree = _tree(POLICY)
    constants = {
        target.id: node.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
        if isinstance(node.value, ast.Constant)
    }

    assert constants.get("DEFAULT_HOSTED_API_URL") == (
        "https://arkheia-proxy-production.up.railway.app"
    )
    assert constants.get("ALLOW_UNSAFE_HOSTED_URL_ENV") == (
        "ARKHEIA_ALLOW_UNSAFE_HOSTED_URL"
    )

    source = POLICY.read_text(encoding="utf-8")
    assert "scheme not in {\"http\", \"https\"}" in source
    assert "origin != DEFAULT_HOSTED_API_URL" in source
    assert "scheme != \"https\"" in source
    assert "allow_unsafe_hosted_url_from_env()" in source


def test_every_key_bearing_hosted_egress_site_uses_the_shared_authorizer_first():
    violations = []
    observed = []

    for path, fn_name in EGRESS_SITES.items():
        tree = _tree(path)
        assert _imports_authorizer_from_policy(tree), (
            f"{path.relative_to(ROOT)} does not import the shared hosted authority "
            "chokepoint"
        )
        fn = _function(tree, fn_name)
        authorizer_lines = [
            n.lineno for n in ast.walk(fn)
            if _calls_authorizer(n)
        ]
        key_header_lines = [
            n.lineno for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and n.value == "X-Arkheia-Key"
        ]
        observed.append(f"{path.relative_to(ROOT)}::{fn_name}")

        if not authorizer_lines:
            violations.append(f"{path.relative_to(ROOT)}::{fn_name} never calls authorizer")
            continue
        if not key_header_lines:
            violations.append(f"{path.relative_to(ROOT)}::{fn_name} no key header found")
            continue
        if min(authorizer_lines) >= min(key_header_lines):
            violations.append(
                f"{path.relative_to(ROOT)}::{fn_name} builds X-Arkheia-Key "
                f"at line {min(key_header_lines)} before authorizing at "
                f"line {min(authorizer_lines)}"
            )

    assert observed == [
        "mcp_server/proxy_client.py::_verify_hosted",
        "proxy/crypto/profile_crypto.py::_fetch_from_hosted",
    ], f"floor observed wrong egress set: {observed}"
    assert not violations, "\n".join(violations)
