"""
FLOOR TIER -- hosted Arkheia key egress authority.

Any production function that sends ``X-Arkheia-Key`` to a hosted Arkheia URL must first pass that
URL through ``arkheia_common.hosted_authority.authorize_hosted_base_url`` and must derive the POST
URL from the returned decision's ``base_url``. The site population is discovered from production
Python files, not hard-coded.
"""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "arkheia_common" / "hosted_authority.py"
KEY_HEADER = "X-Arkheia-Key"
AUTHORIZE = "authorize_hosted_base_url"

PRODUCTION_ROOTS = ("mcp_server", "proxy")
KNOWN_KEY_BEARING_SITES = {
    "mcp_server/proxy_client.py::_verify_hosted",
    "proxy/crypto/profile_crypto.py::_fetch_from_hosted",
}


def _tree(path: Path) -> ast.Module:
    assert path.exists(), f"{path.relative_to(ROOT)} is missing; floor observes nothing"
    return ast.parse(path.read_text(encoding="utf-8"), str(path))


def _functions(tree: ast.AST) -> dict[str, ast.AST]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef))
    }


def _call_name(node: ast.Call) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _production_py_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for root in PRODUCTION_ROOTS:
        for path in (ROOT / root).rglob("*.py"):
            rel = path.relative_to(ROOT).as_posix()
            if "/tests/" in f"/{rel}/" or rel.startswith("proxy/tests/"):
                continue
            files.append(path)
    return tuple(sorted(files))


def _key_bearing_functions(source: str) -> dict[str, ast.AST]:
    funcs = _functions(ast.parse(source))
    return {
        name: fn
        for name, fn in funcs.items()
        if any(
            isinstance(node, ast.Constant) and node.value == KEY_HEADER
            for node in ast.walk(fn)
        )
    }


def _authorizer_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    """Return (bare-name aliases, module aliases) for the shared hosted authorizer."""
    bare: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "arkheia_common.hosted_authority":
            for alias in node.names:
                if alias.name == AUTHORIZE:
                    bare.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "arkheia_common.hosted_authority":
                    modules.add(alias.asname or alias.name)
    return bare, modules


def _is_authorizer_call(node: ast.AST, bare: set[str], modules: set[str]) -> bool:
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in bare
    if isinstance(func, ast.Attribute) and func.attr == AUTHORIZE:
        value = func.value
        return isinstance(value, ast.Name) and value.id in modules
    return False


def _authorizer_decision_names(fn: ast.AST, bare: set[str], modules: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        if not _is_authorizer_call(node.value, bare, modules):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _expr_uses_authorized_base_url(expr: ast.AST, decision_names: set[str]) -> bool:
    for node in ast.walk(expr):
        if not isinstance(node, ast.Attribute) or node.attr != "base_url":
            continue
        value = node.value
        if isinstance(value, ast.Name) and value.id in decision_names:
            return True
    return False


def _derived_url_names(fn: ast.AST, decision_names: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        if not _expr_uses_authorized_base_url(node.value, decision_names):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _post_calls(fn: ast.AST) -> list[ast.Call]:
    return [
        node for node in ast.walk(fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "post"
    ]


def _post_uses_authorized_base_url(
    call: ast.Call,
    decision_names: set[str],
    derived_names: set[str],
) -> bool:
    if not call.args:
        return False
    url = call.args[0]
    if isinstance(url, ast.Name) and url.id in derived_names:
        return True
    return _expr_uses_authorized_base_url(url, decision_names)


def _key_header_lines(fn: ast.AST) -> list[int]:
    return [
        node.lineno for node in ast.walk(fn)
        if isinstance(node, ast.Constant) and node.value == KEY_HEADER
    ]


def _authorizer_call_lines(fn: ast.AST, bare: set[str], modules: set[str]) -> list[int]:
    return [
        node.lineno for node in ast.walk(fn)
        if _is_authorizer_call(node, bare, modules)
    ]


def _hosted_key_egress_violations(
    modules: dict[str, str],
) -> tuple[list[str], list[str]]:
    observed: list[str] = []
    violations: list[str] = []

    for rel, source in modules.items():
        tree = ast.parse(source)
        bare, module_aliases = _authorizer_aliases(tree)
        for name, fn in _key_bearing_functions(source).items():
            site = f"{rel}::{name}"
            observed.append(site)
            key_lines = _key_header_lines(fn)
            auth_lines = _authorizer_call_lines(fn, bare, module_aliases)
            decision_names = _authorizer_decision_names(fn, bare, module_aliases)
            derived_names = _derived_url_names(fn, decision_names)
            posts = _post_calls(fn)

            if not bare and not module_aliases:
                violations.append(f"{site} does not import the shared hosted-authority chokepoint")
            if not auth_lines:
                violations.append(f"{site} never calls {AUTHORIZE}()")
            elif key_lines and min(auth_lines) >= min(key_lines):
                violations.append(
                    f"{site} builds {KEY_HEADER} at line {min(key_lines)} before "
                    f"authorizing at line {min(auth_lines)}"
                )
            if not decision_names:
                violations.append(f"{site} does not store the authorizer decision")
            if not posts:
                violations.append(f"{site} has a key header but no POST call")
            for post in posts:
                if not _post_uses_authorized_base_url(post, decision_names, derived_names):
                    violations.append(
                        f"{site} POST at line {post.lineno} is not derived from "
                        "authorize_hosted_base_url(...).base_url"
                    )

    return sorted(observed), violations


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


def test_every_discovered_key_bearing_hosted_egress_site_uses_the_shared_authorizer():
    modules = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in _production_py_files()
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert KNOWN_KEY_BEARING_SITES <= set(observed), (
        f"hosted key egress census missed baseline sites "
        f"{sorted(KNOWN_KEY_BEARING_SITES - set(observed))}; observed={observed}"
    )
    assert not violations, "\n".join(violations)


def test_scanner_catches_a_new_key_bearing_site_without_authorizer_negative_self_test():
    modules = {
        "mcp_server/new_site.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        )
    }
    observed, violations = _hosted_key_egress_violations(modules)
    assert observed == ["mcp_server/new_site.py::_score"]
    assert any("never calls authorize_hosted_base_url" in v for v in violations), violations
    assert any("not derived from authorize_hosted_base_url" in v for v in violations), violations


def test_scanner_catches_authorizer_result_being_ignored_negative_self_test():
    modules = {
        "mcp_server/new_site.py": (
            "from arkheia_common.hosted_authority import authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(self.hosted_url)\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        )
    }
    observed, violations = _hosted_key_egress_violations(modules)
    assert observed == ["mcp_server/new_site.py::_score"]
    assert any("not derived from authorize_hosted_base_url" in v for v in violations), violations

    safe = {
        "mcp_server/new_site.py": (
            "from arkheia_common.hosted_authority import authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(self.hosted_url)\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{authorized.base_url}/v1/score', headers=headers)\n"
        )
    }
    assert _hosted_key_egress_violations(safe) == (
        ["mcp_server/new_site.py::_score"],
        [],
    )

