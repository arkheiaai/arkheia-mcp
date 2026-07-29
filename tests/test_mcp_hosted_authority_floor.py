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
CLIENT_HELPER = "hosted_key_egress_client"
MIN_PROD_PYTHON_FILES = 50

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
KNOWN_KEY_BEARING_SHELL_SITES = {
    "install.sh",
}
HTTP_EGRESS_METHODS = frozenset({
    "delete",
    "get",
    "patch",
    "post",
    "put",
    "request",
    "send",
    "stream",
    "urlopen",
})


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


def _string_literal(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                return None
            parts.append(value.value)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_literal(node.left)
        right = _string_literal(node.right)
        if left is not None and right is not None:
            return left + right
    return None


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
        literal = _string_literal(value) if value is not None else None
        if isinstance(literal, str) and literal.lower() == KEY_HEADER.lower():
            for target in targets:
                aliases |= _assigned_names(target)
    return aliases


def _expr_uses_key_header(expr: ast.AST, aliases: set[str]) -> bool:
    for node in ast.walk(expr):
        literal = _string_literal(node)
        if isinstance(literal, str) and literal.lower() == KEY_HEADER.lower():
            return True
        if isinstance(node, ast.Name) and node.id in aliases:
            return True
    return False


def _expr_uses_secret_key(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        if isinstance(node, ast.Name) and node.id in {"API_KEY", "ARKHEIA_API_KEY"}:
            return True
        dotted = _dotted_name(node)
        if dotted and dotted.lower().endswith("api_key"):
            return True
    return False


def _expr_uses_configured_hosted_url(expr: ast.AST) -> bool:
    for node in ast.walk(expr):
        dotted = _dotted_name(node)
        if not dotted:
            continue
        lowered = dotted.lower()
        if lowered.endswith("hosted_url") or lowered == "hosted_url":
            return True
        if lowered.endswith("hosted_api_url") or lowered == "hosted_api_url":
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


def _headers_expr_uses_key(expr: ast.AST, header_vars: set[str], aliases: set[str]) -> bool:
    if isinstance(expr, ast.Name) and expr.id in header_vars:
        return True
    if _expr_uses_key_header(expr, aliases):
        return True
    if isinstance(expr, ast.Dict):
        for key, value in zip(expr.keys, expr.values):
            literal = _string_literal(key) if key is not None else None
            lowered = literal.lower() if isinstance(literal, str) else ""
            if lowered == KEY_HEADER.lower():
                return True
    return False


def _headers_expr_uses_authorization_key(
    expr: ast.AST,
    auth_header_vars: set[str] | None = None,
) -> bool:
    if isinstance(expr, ast.Name) and auth_header_vars and expr.id in auth_header_vars:
        return True
    if isinstance(expr, ast.Dict):
        for key, value in zip(expr.keys, expr.values):
            literal = _string_literal(key) if key is not None else None
            if isinstance(literal, str) and literal.lower() == "authorization":
                return _expr_uses_secret_key(value)
    return False


def _url_is_hosted_key_surface(url: ast.AST | None) -> bool:
    if url is None:
        return False
    return (
        _expr_uses_configured_hosted_url(url)
        or _expr_uses_secret_key(url)
    )


def _auth_header_var_names(scope: ast.AST) -> set[str]:
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
        if value is not None and _headers_expr_uses_authorization_key(value):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _request_var_names(
    scope: ast.AST,
    header_vars: set[str],
    auth_header_vars: set[str],
    aliases: set[str],
) -> set[str]:
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
        if isinstance(value, ast.Call) and _request_call_carries_key(
            value,
            header_vars,
            auth_header_vars,
            aliases,
        ):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _request_call_carries_key(
    call: ast.Call,
    header_vars: set[str],
    auth_header_vars: set[str],
    aliases: set[str],
) -> bool:
    url = _request_call_url(call)
    for kw in call.keywords:
        if kw.arg == "headers" and _headers_expr_uses_key(kw.value, header_vars, aliases):
            return True
        if kw.arg == "headers" and _headers_expr_uses_authorization_key(
            kw.value,
            auth_header_vars,
        ):
            return _url_is_hosted_key_surface(url)
    return url is not None and _expr_uses_secret_key(url)


def _call_carries_key(
    call: ast.Call,
    header_vars: set[str],
    auth_header_vars: set[str],
    request_vars: set[str],
    aliases: set[str],
) -> bool:
    url = _url_expr(call)
    for arg in call.args:
        if isinstance(arg, ast.Name) and arg.id in request_vars:
            return True
    for kw in call.keywords:
        if kw.arg == "headers" and _headers_expr_uses_key(kw.value, header_vars, aliases):
            return True
        if kw.arg == "headers" and _headers_expr_uses_authorization_key(
            kw.value,
            auth_header_vars,
        ):
            return _url_is_hosted_key_surface(url)
        if (
            kw.arg in {"params", "data", "json"}
            and _expr_uses_secret_key(kw.value)
            and _url_is_hosted_key_surface(url)
        ):
            return True
    for arg in call.args:
        if isinstance(arg, ast.Call):
            for kw in arg.keywords:
                if kw.arg == "headers" and _headers_expr_uses_key(
                    kw.value,
                    header_vars,
                    aliases,
                ):
                    return True
    return url is not None and _expr_uses_secret_key(url)


def _http_egress_calls(scope: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name or not _is_http_egress_name(name):
            continue
        calls.append(node)
    return calls


def _is_http_egress_name(name: str) -> bool:
    method = name.rsplit(".", 1)[-1]
    if method not in HTTP_EGRESS_METHODS:
        return False
    if method == "urlopen":
        return "urllib" in name or name == "urlopen"
    return True


def _url_expr(call: ast.Call) -> ast.AST | None:
    name = _call_name(call) or ""
    method = name.rsplit(".", 1)[-1]
    if method == "send" and call.args and isinstance(call.args[0], ast.Call):
        return _request_call_url(call.args[0])
    if method == "urlopen" and call.args:
        if isinstance(call.args[0], ast.Call):
            return _request_call_url(call.args[0])
        return call.args[0]
    if method in {"request", "stream"}:
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


def _request_call_url(call: ast.Call) -> ast.AST | None:
    name = _call_name(call) or ""
    if not (name.endswith(".Request") or name == "Request"):
        return None
    if len(call.args) >= 2:
        return call.args[1]
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg in {"url", "full_url"}:
            return kw.value
    return None


def _scope_is_key_bearing(scope: ast.AST, aliases: set[str]) -> bool:
    calls = _http_egress_calls(scope)
    header_vars = _key_header_var_names(scope, aliases)
    auth_header_vars = _auth_header_var_names(scope)
    request_vars = _request_var_names(scope, header_vars, auth_header_vars, aliases)
    if any(
        _call_carries_key(call, header_vars, auth_header_vars, request_vars, aliases)
        for call in calls
    ):
        return True
    return False


def _hosted_authority_symbol_aliases(tree: ast.AST, symbol: str) -> tuple[set[str], set[str]]:
    bare: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "arkheia_common.hosted_authority":
            for alias in node.names:
                if alias.name == symbol:
                    bare.add(alias.asname or alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "arkheia_common.hosted_authority":
                    modules.add(alias.asname or alias.name)
    return bare, modules


def _authorizer_aliases(tree: ast.AST) -> tuple[set[str], set[str]]:
    return _hosted_authority_symbol_aliases(tree, AUTHORIZE)


def _is_hosted_authority_symbol_call(
    node: ast.AST,
    bare: set[str],
    modules: set[str],
    symbol: str,
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _call_name(node)
    if name in bare:
        return True
    return any(name == f"{module}.{symbol}" for module in modules)


def _is_authorizer_call(node: ast.AST, bare: set[str], modules: set[str]) -> bool:
    return _is_hosted_authority_symbol_call(node, bare, modules, AUTHORIZE)


def _authorizer_allows_unsafe(node: ast.Call) -> bool:
    for kw in node.keywords:
        if kw.arg == "allow_unsafe" and isinstance(kw.value, ast.Constant):
            return kw.value.value is True
    return False


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
        if (
            value is not None
            and _is_authorizer_call(value, bare, modules)
            and not _authorizer_allows_unsafe(value)
        ):
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
        if (
            value is not None
            and _expr_uses_authorized_base_url(value, decision_names)
            and not _expr_uses_configured_hosted_url(value)
        ):
            for target in targets:
                names |= _assigned_names(target)
    return names


def _rebound_derived_url_names(scope: ast.AST, decision_names: set[str]) -> set[str]:
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
        if value is None:
            continue
        assigned = set()
        for target in targets:
            assigned |= _assigned_names(target)
        if not assigned:
            continue
        if not _expr_uses_authorized_base_url(value, decision_names):
            names |= assigned
        elif _expr_uses_configured_hosted_url(value):
            names |= assigned
    return names


def _post_uses_authorized_base_url(
    call: ast.Call,
    decision_names: set[str],
    derived_names: set[str],
    rebound_names: set[str],
) -> bool:
    url = _url_expr(call)
    if url is None:
        return False
    if isinstance(url, ast.Name) and url.id in derived_names and url.id not in rebound_names:
        return True
    return _expr_uses_authorized_base_url(url, decision_names)


def _key_header_lines(scope: ast.AST, aliases: set[str]) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(scope):
        literal = _string_literal(node)
        if isinstance(literal, str) and literal.lower() == KEY_HEADER.lower():
            lines.append(node.lineno)
        elif isinstance(node, ast.Name) and node.id in aliases:
            lines.append(node.lineno)
    return lines


def _authorizer_call_lines(scope: ast.AST, bare: set[str], modules: set[str]) -> list[int]:
    return [
        node.lineno for node in ast.walk(scope)
        if _is_authorizer_call(node, bare, modules)
    ]


def _helper_call_lines(
    scope: ast.AST,
    bare: set[str],
    modules: set[str],
    symbol: str,
) -> list[int]:
    return [
        node.lineno for node in ast.walk(scope)
        if _is_hosted_authority_symbol_call(node, bare, modules, symbol)
    ]


def _raw_async_client_lines(scope: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(scope):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in {"AsyncClient", "httpx.AsyncClient"} or (
            name and name.endswith(".AsyncClient")
        ):
            lines.append(node.lineno)
    return lines


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
        client_bare, client_module_aliases = _hosted_authority_symbol_aliases(
            tree,
            CLIENT_HELPER,
        )
        aliases = _key_header_aliases(tree)
        for site, scope in _module_sites(rel, source).items():
            if not _scope_is_key_bearing(scope, aliases):
                continue
            observed.append(site)

            header_vars = _key_header_var_names(scope, aliases)
            auth_header_vars = _auth_header_var_names(scope)
            request_vars = _request_var_names(scope, header_vars, auth_header_vars, aliases)
            key_lines = _key_header_lines(scope, aliases)
            auth_lines = _authorizer_call_lines(scope, bare, module_aliases)
            client_lines = _helper_call_lines(
                scope,
                client_bare,
                client_module_aliases,
                CLIENT_HELPER,
            )
            decision_names = _authorizer_decision_names(scope, bare, module_aliases)
            derived_names = _derived_url_names(scope, decision_names)
            rebound_names = _rebound_derived_url_names(scope, decision_names)
            posts = [
                call for call in _http_egress_calls(scope)
                if _call_carries_key(
                    call,
                    header_vars,
                    auth_header_vars,
                    request_vars,
                    aliases,
                )
            ]

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
            if not client_lines:
                violations.append(
                    f"{site} does not use {CLIENT_HELPER}() for no-proxy hosted key egress"
                )
            for line in _raw_async_client_lines(scope):
                violations.append(
                    f"{site} constructs raw httpx.AsyncClient at line {line} "
                    f"instead of {CLIENT_HELPER}()"
                )
            for node in ast.walk(scope):
                if isinstance(node, ast.Call) and _is_authorizer_call(node, bare, module_aliases):
                    if _authorizer_allows_unsafe(node):
                        violations.append(
                            f"{site} calls {AUTHORIZE}(..., allow_unsafe=True)"
                        )
            if not posts:
                violations.append(f"{site} has a key header but no outbound HTTP call")
            for post in posts:
                if not _post_uses_authorized_base_url(
                    post,
                    decision_names,
                    derived_names,
                    rebound_names,
                ):
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
    assert "scheme != \"https\" and not loopback" in source
    assert "allow_unsafe_hosted_url_from_env()" in source
    assert "_is_self_hosted_host(host)" in source
    assert "socket.getaddrinfo" in source
    assert "_SELF_HOSTED_NETWORKS" in source
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"):
        assert cidr in source
    assert "addr.is_private" not in source
    assert "trust_env=False" in source
    assert f"def {CLIENT_HELPER}" in source
    assert "host.endswith(\".local\")" not in source


def test_every_discovered_key_bearing_hosted_egress_site_uses_the_shared_authorizer():
    prod_files = _prod_python_files()
    assert len(prod_files) >= MIN_PROD_PYTHON_FILES
    modules = {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in prod_files
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert KNOWN_KEY_BEARING_SITES <= set(observed), (
        f"hosted key egress census missed baseline sites "
        f"{sorted(KNOWN_KEY_BEARING_SITES - set(observed))}; observed={observed}"
    )
    assert not violations, "\n".join(violations)


def test_shell_key_bearing_hosted_egress_uses_authorized_hosted_url():
    observed = set()
    violations = []
    for rel in KNOWN_KEY_BEARING_SHELL_SITES:
        source = (ROOT / rel).read_text(encoding="utf-8")
        if KEY_HEADER in source:
            observed.add(rel)
            if "AUTHORIZED_HOSTED_URL=$(authorize_hosted_url)" not in source:
                violations.append(f"{rel} never authorizes HOSTED_URL")
            if "hosted_curl() {" not in source or "curl --noproxy '*'" not in source:
                violations.append(f"{rel} does not centralize hosted curl through --noproxy")
            if "socket.getaddrinfo" not in source:
                violations.append(f"{rel} does not resolve self-hosted hostnames structurally")
            if "SELF_HOSTED_NETWORKS" not in source or "addr.is_private" in source:
                violations.append(f"{rel} drifted from explicit self-hosted network policy")
            if '"${HOSTED_URL}/v1/detect"' in source:
                violations.append(f"{rel} posts detect to raw HOSTED_URL")
            if '"${HOSTED_URL}/v1/provision"' in source:
                violations.append(f"{rel} posts provision to raw HOSTED_URL")
            if "VERIFY_CODE=$(curl" in source:
                violations.append(f"{rel} verifies API keys with raw curl")
            if '"${AUTHORIZED_HOSTED_URL}/v1/detect"' not in source:
                violations.append(f"{rel} detect verification is not authorized")
    assert KNOWN_KEY_BEARING_SHELL_SITES <= observed
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
        "scripts/renamed_receiver.py": (
            "async def _score(self, wire):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await wire.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert observed == [
        "arkheia_common/new_class_site.py::NewClient.send",
        "mcp_server/new_constant_site.py::_score",
        "proxy/new_request_site.py::_score",
        "registry_server/new_site.py::_score",
        "scripts/new_site.py::_score",
        "scripts/renamed_receiver.py::_score",
        "top_level_site.py::<module>",
    ]
    assert len(violations) >= len(observed)
    assert any("registry_server/new_site.py::_score never calls" in v for v in violations)
    assert any("mcp_server/new_constant_site.py::_score never calls" in v for v in violations)
    assert any("proxy/new_request_site.py::_score outbound call" in v for v in violations)
    assert any("arkheia_common/new_class_site.py::NewClient.send never calls" in v for v in violations)
    assert any("top_level_site.py::<module> never calls" in v for v in violations)
    assert any("scripts/new_site.py::_score outbound call" in v for v in violations)
    assert any("scripts/renamed_receiver.py::_score never calls" in v for v in violations)


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
            "async def _score(self):\n"
            "    authorized = hosted_authority.authorize_hosted_base_url(self.hosted_url)\n"
            "    target = f'{authorized.base_url}/v1/score'\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    async with hosted_authority.hosted_key_egress_client(timeout=10) as client:\n"
            "        return await client.request('POST', target, headers=headers)\n"
        )
    }
    assert _hosted_key_egress_violations(safe) == (
        ["mcp_server/new_site.py::_score"],
        [],
    )


def test_scanner_catches_round4_hosted_key_egress_bypass_shapes():
    modules = {
        "r4/lower_header.py": (
            "async def _score(self, client):\n"
            "    headers = {'x-arkheia-key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/concat_header.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia' + '-Key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/get_method.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.get(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/patch_method.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.patch(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/renamed_receiver.py": (
            "async def _score(self, gateway):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await gateway.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/send_request.py": (
            "import httpx\n"
            "async def _score(self, client):\n"
            "    req = httpx.Request('POST', f'{self.hosted_url}/v1/score', "
            "headers={'X-Arkheia-Key': self.api_key})\n"
            "    return await client.send(req)\n"
        ),
        "r4/stream_request.py": (
            "async def _score(self, client):\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return client.stream('POST', f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/urllib_request.py": (
            "import urllib.request\n"
            "def _score(self):\n"
            "    req = urllib.request.Request(f'{self.hosted_url}/v1/score', "
            "headers={'X-Arkheia-Key': self.api_key})\n"
            "    return urllib.request.urlopen(req)\n"
        ),
        "r4/query_key.py": (
            "async def _score(self, client):\n"
            "    return await client.post(f'{self.hosted_url}/v1/score?api_key={self.api_key}')\n"
        ),
        "r4/auth_header.py": (
            "async def _score(self, client):\n"
            "    headers = {'Authorization': f'Bearer {self.api_key}'}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
        "r4/unsafe_authorizer.py": (
            "from arkheia_common.hosted_authority import authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(self.hosted_url, allow_unsafe=True)\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{authorized.base_url}/v1/score', headers=headers)\n"
        ),
        "r4/replaced_authorized_url.py": (
            "from arkheia_common.hosted_authority import authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(self.hosted_url)\n"
            "    target = f'{authorized.base_url}/v1/score'\n"
            "    url = target.replace(authorized.base_url, self.hosted_url)\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(url, headers=headers)\n"
        ),
        "r4/rebound_authorized_url.py": (
            "from arkheia_common.hosted_authority import authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(self.hosted_url)\n"
            "    base = authorized.base_url\n"
            "    base = self.hosted_url\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(base, headers=headers)\n"
        ),
        "r4/default_authorized_wrong_url.py": (
            "from arkheia_common.hosted_authority import DEFAULT_HOSTED_API_URL, authorize_hosted_base_url\n"
            "async def _score(self, client):\n"
            "    authorized = authorize_hosted_base_url(DEFAULT_HOSTED_API_URL)\n"
            "    headers = {'X-Arkheia-Key': self.api_key}\n"
            "    return await client.post(f'{self.hosted_url}/v1/score', headers=headers)\n"
        ),
    }
    observed, violations = _hosted_key_egress_violations(modules)

    assert observed == [
        "r4/auth_header.py::_score",
        "r4/concat_header.py::_score",
        "r4/default_authorized_wrong_url.py::_score",
        "r4/get_method.py::_score",
        "r4/lower_header.py::_score",
        "r4/patch_method.py::_score",
        "r4/query_key.py::_score",
        "r4/rebound_authorized_url.py::_score",
        "r4/renamed_receiver.py::_score",
        "r4/replaced_authorized_url.py::_score",
        "r4/send_request.py::_score",
        "r4/stream_request.py::_score",
        "r4/unsafe_authorizer.py::_score",
        "r4/urllib_request.py::_score",
    ]
    for site in observed:
        assert any(site in violation for violation in violations), (site, violations)
    assert any("allow_unsafe=True" in violation for violation in violations), violations
