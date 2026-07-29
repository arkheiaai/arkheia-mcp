"""
FLOOR TIER -- hosted Arkheia key egress authority.

Any production site that sends ``X-Arkheia-Key`` to a hosted Arkheia URL must
first pass that URL through ``arkheia_common.hosted_authority.
authorize_hosted_base_url`` and must derive the outbound URL from the returned
decision's ``base_url``. The site population is discovered from production
Python files, including new files and new package roots.
"""
from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "arkheia_common" / "hosted_authority.py"
KEY_HEADER = "X-Arkheia-Key"
AUTHORIZE = "authorize_hosted_base_url"

EXCLUDED_DIRS = frozenset({
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
})
KNOWN_KEY_BEARING_SITES = {
    "mcp_server/proxy_client.py::ProxyClient._verify_hosted",
    "proxy/crypto/profile_crypto.py::DynamicKeyLoader._fetch_from_hosted",
}


def _tree(path: Path) -> ast.Module:
    assert path.exists(), f"{path.relative_to(ROOT)} is missing; floor observes nothing"
    return ast.parse(path.read_text(encoding="utf-8"), str(path))


def _prod_python_files(root: Path = ROOT) -> tuple[Path, ...]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if "tests" in rel.parts or path.name.startswith("test_") or path.name == "conftest.py":
            continue
        files.append(path)
    return tuple(sorted(files))


def _function_scopes(tree: ast.Module) -> dict[str, ast.AST]:
    scopes: dict[str, ast.AST] = {}

    def visit(body: list[ast.stmt], prefix: tuple[str, ...] = ()) -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, prefix + (node.name,))
            elif isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
                name = ".".join(prefix + (node.name,))
                scopes[name] = node
                visit(node.body, prefix + (node.name,))

    visit(tree.body)
    return scopes


def _module_scope(tree: ast.Module) -> ast.Module:
    body = [
        node for node in tree.body
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef, ast.ClassDef))
    ]
    return ast.Module(body=body, type_ignores=[])


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _call_name(node: ast.Call) -> str | None:
    return _dotted_name(node.func)


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        out: set[str] = set()
        for elt in target.elts:
            out |= _assigned_names(elt)
        return out
    return set()


def _key_header_aliases(tree: ast.AST) -> set[str]:
    aliases: set[str] = set()
    for node in ast.walk(tree):
        value = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if isinstance(value, ast.Constant) and value.value == KEY_HEADER:
            for target in targets:
                aliases |= _assigned_names(target)
    return aliases


def _expr_uses_key_header(expr: ast.AST, aliases: set[str]) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Constant) and node.value == KEY_HEADER:
            return True
        if isinstance(node, ast.Name) and node.id in aliases:
            return True
    return False


def _key_header_var_names(scope: ast.AST, aliases: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(scope):
        value = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if value is not None and _expr_uses_key_header(value, aliases):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _header_kw_uses_key(call: ast.Call, header_vars: set[str], aliases: set[str]) -> bool:
    for kw in call.keywords:
        if kw.arg != "headers":
            continue
        if isinstance(kw.value, ast.Name) and kw.value.id in header_vars:
            return True
        if _expr_uses_key_header(kw.value, aliases):
            return True
    return False


def _http_egress_calls(scope: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name:
            continue
        if name.endswith(".post") or name == "post":
            calls.append(node)
            continue
        if name.endswith(".request") or name == "request":
            calls.append(node)
    return calls


def _url_expr(call: ast.Call) -> ast.AST | None:
    name = _call_name(call) or ""
    if name.endswith(".request") or name == "request":
        if len(call.args) >= 2:
            return call.args[1]
        for kw in call.keywords:
            if kw.arg == "url":
                return kw.value
        return None
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _scope_is_key_bearing(scope: ast.AST, aliases: set[str]) -> bool:
    calls = _http_egress_calls(scope)
    header_vars = _key_header_var_names(scope, aliases)
    if any(_header_kw_uses_key(call, header_vars, aliases) for call in calls):
        return True
    return bool(calls) and _expr_uses_key_header(scope, aliases)


def _authorizer_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
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
    name = _call_name(node)
    if name in bare:
        return True
    return any(name == f"{module}.{AUTHORIZE}" for module in modules)


def _authorizer_decision_names(scope: ast.AST, bare: set[str], modules: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(scope):
        value = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if value is not None and _is_authorizer_call(value, bare, modules):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _expr_uses_authorized_base_url(expr: ast.AST, decision_names: set[str]) -> bool:
    for node in ast.walk(expr):
        if not isinstance(node, ast.Attribute) or node.attr != "base_url":
            continue
        if isinstance(node.value, ast.Name) and node.value.id in decision_names:
            return True
    return False


def _derived_url_names(scope: ast.AST, decision_names: set[str]) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(scope):
        value = None
        targets: list[ast.AST] = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = list(node.targets)
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if value is not None and _expr_uses_authorized_base_url(value, decision_names):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _post_uses_authorized_base_url(
    call: ast.Call,
    decision_names: set[str],
    derived_names: set[str],
) -> bool:
    url = _url_expr(call)
    if url is None:
        return False
    if isinstance(url, ast.Name) and url.id in derived_names:
        return True
    return _expr_uses_authorized_base_url(url, decision_names)


def _key_header_lines(scope: ast.AST, aliases: set[str]) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(scope):
        if isinstance(node, ast.Constant) and node.value == KEY_HEADER:
            lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in aliases:
            lines.append(node.lineno)
    return lines


def _authorizer_call_lines(scope: ast.AST, bare: set[str], modules: set[str]) -> list[int]:
    return [
        node.lineno for node in ast.walk(scope)
        if _is_authorizer_call(node, bare, modules)
    ]


def _module_sites(rel: str, source: str) -> dict[str, ast.AST]:
    tree = ast.parse(source)
    scopes = {
        f"{rel}::{name}": scope
        for name, scope in _function_scopes(tree).items()
    }
    module = _module_scope(tree)
    if module.body:
        scopes[f"{rel}::<module>"] = module
    return scopes


def _hosted_key_egress_violations(
    modules: dict[str, str],
) -> tuple[list[str], list[str]]:
    observed: list[str] = []
    violations: list[str] = []

    for rel, source in modules.items():
        tree = ast.parse(source)
        bare, module_aliases = _authorizer_aliases(tree)
        aliases = _key_header_aliases(tree)
        for site, scope in _module_sites(rel, source).items():
            if not _scope_is_key_bearing(scope, aliases):
                continue
            observed.append(site)

            key_lines = _key_header_lines(scope, aliases)
            auth_lines = _authorizer_call_lines(scope, bare, module_aliases)
            decision_names = _authorizer_decision_names(scope, bare, module_aliases)
            derived_names = _derived_url_names(scope, decision_names)
            posts = _http_egress_calls(scope)

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
                violations.append(f"{site} has a key header but no outbound HTTP call")
            for post in posts:
                if not _post_uses_authorized_base_url(post, decision_names, derived_names):
                    violations.append(
                        f"{site} outbound call at line {post.lineno} is not derived from "
                        "authorize_hosted_base_url(...).base_url"
                    )

    return sorted(observed), violations


def test_policy_defaults_to_https_production_and_local_self_hosted_with_explicit_opt_in():
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
    assert "origin != DEFAULT_HOSTED_API_URL and not self_hosted" in source
    assert "scheme != \"https\" and not self_hosted" in source
    assert "allow_unsafe_hosted_url_from_env()" in source
    assert "_is_self_hosted_host(host)" in source


def test_every_discovered_key_bearing_hosted_egress_site_uses_the_shared_authorizer():
    modules = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in _prod_python_files()
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert KNOWN_KEY_BEARING_SITES <= set(observed), (
        f"hosted key egress census missed baseline sites "
        f"{sorted(KNOWN_KEY_BEARING_SITES - set(observed))}; observed={observed}"
    )
    assert not violations, "\n".join(violations)


def test_scanner_catches_new_files_and_new_shapes_negative_self_test():
    modules = {
        "registry_server/new_site.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "mcp_server/new_constant_site.py": (
            "KEY_HEADER = 'X-Arkheia-Key'\n"
            "async def _score(self, client):\n"
            "    headers = {KEY_HEADER: self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "proxy/new_request_site.py": (
            "async def _score(self, client):\n"
            "    return await client.request('POST', self.hosted_url + '/v1/score', "
            "headers={'X-Arkheia-Key': self.api_key})\n"
        ),
        "arkheia_common/new_class_site.py": (
            "class NewClient:\n"
            "    async def send(self, client):\n"
            "        headers = {'X-Arkheia-Key': self.api_key}\n"
            "        return await client.post(self.hosted_url, headers=headers)\n"
        ),
        "top_level_site.py": (
            "headers = {'X-Arkheia-Key': API_KEY}\n"
            "client.post(HOSTED_URL, headers=headers)\n"
        ),
        "scripts/new_site.py": (
            "async def _score(self, client):\n"
            "    target = f'{self.hosted_url}/v1/score'\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(target, headers=headers)\n"
        ),
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert observed == [
        "arkheia_common/new_class_site.py::NewClient.send",
        "mcp_server/new_constant_site.py::_score",
        "proxy/new_request_site.py::_score",
        "registry_server/new_site.py::_score",
        "scripts/new_site.py::_score",
        "top_level_site.py::<module>",
    ]
    assert len(violations) >= len(observed)
    assert any("registry_server/new_site.py::_score never calls" in v for v in violations)
    assert any("mcp_server/new_constant_site.py::_score never calls" in v for v in violations)
    assert any("proxy/new_request_site.py::_score outbound call" in v for v in violations)
    assert any("arkheia_common/new_class_site.py::NewClient.send never calls" in v for v in violations)
    assert any("top_level_site.py::<module> never calls" in v for v in violations)
    assert any("scripts/new_site.py::_score outbound call" in v for v in violations)


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
            "import arkheia_common.hosted_authority as hosted_authority\n"
            "async def _score(self, client):\n"
            "    authorized = hosted_authority.authorize_hosted_base_url(self.hosted_url)\n"
            "    target = f'{authorized.base_url}/v1/score'\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.request('POST', target, headers=headers)\n"
        )
    }
    assert _hosted_key_egress_violations(safe) == (
        ["mcp_server/new_site.py::_score"],
        [],
    )
