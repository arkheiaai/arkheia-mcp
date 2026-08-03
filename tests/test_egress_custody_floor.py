"""
FLOOR TIER -- credentialed outbound HTTP custody.

Production calls that carry provider, Arkheia, OAuth, forwarded Authorization,
or HMAC credentials must use the shared egress factories. Those factories force
``trust_env=False`` so ambient HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/SSL_CERT_FILE
settings cannot capture credentials from the process environment.

The population is discovered from repo-root production Python, then compared to
a node-id manifest. This is deliberately not a collected-test count: a union that
adds unrelated floors should not fail on arithmetic, and a shrink of this custody
population should name the missing site.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EGRESS_HELPER = ROOT / "arkheia_common" / "egress.py"

EXCLUDED_DIRS = {
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
}

# Reconciled when master merged in: the four hosted-key sites that used to call
# the factory directly (examples/integration_test.py::verify_response,
# examples/verify_response.py::main,
# mcp_server/proxy_client.py::ProxyClient._verify_hosted and
# proxy/crypto/profile_crypto.py::DynamicKeyLoader._fetch_from_hosted) now reach
# it one hop away, through
# arkheia_common.hosted_authority.hosted_key_egress_client, which is itself a
# thin `return egress_async_client(timeout=timeout)`. So the FACTORY CALL SITE
# moved into that helper, which is listed below; the four callers did not stop
# being custodied. They are pinned harder than this census pins them, by
# tests/test_mcp_hosted_authority_floor.py, which auto-discovers every
# X-Arkheia-Key-bearing production site (examples/ included -- it is not in that
# floor's EXCLUDED_DIRS) and fails unless the site uses hosted_key_egress_client()
# AND routes its URL through authorize_hosted_base_url(). The bypass invariant in
# this file -- `report.raw_credentialed_sites == []` below -- is unchanged and
# still proves no credentialed call reaches httpx without the no-env-proxy factory.
EGRESS_SITE_MANIFEST = frozenset({
    "arkheia_common/hosted_authority.py::hosted_key_egress_client",
    "mcp_server/proxy_client.py::ProxyClient._verify_local",
    "mcp_server/proxy_client.py::ProxyClient.get_audit_log",
    "mcp_server/tools/providers.py::call_gemini",
    "mcp_server/tools/providers.py::call_grok",
    "mcp_server/tools/providers.py::call_ollama",
    "mcp_server/tools/providers.py::call_together",
    "proxy/auth.py::exchange_google_code",
    "proxy/detection_adapter.py::push_event",
    "proxy/endpoints/passthrough.py::_forward",
    "proxy/middleware/interception.py::AIInterceptionMiddleware._obtain",
    "proxy/registry/client.py::RegistryClient._download_and_apply",
    "proxy/registry/client.py::RegistryClient.pull",
})

HTTPX_SHORTCUTS = {"delete", "get", "patch", "post", "put", "request", "stream"}
CLIENT_METHODS = HTTPX_SHORTCUTS | {"send"}
EGRESS_HELPERS = {"egress_async_client", "egress_client"}
FACTORY_HELPER = "_without_environment_proxy"

CREDENTIAL_HEADER_KEYS = {
    "authorization",
    "proxy-authorization",
    "x-arkheia-key",
    "x-arkheia-key-id",
    "x-arkheia-signature",
    "x-arkheia-timestamp",
    "x-goog-api-key",
}
CREDENTIAL_DICT_KEYS = CREDENTIAL_HEADER_KEYS | {
    "access_token",
    "api_key",
    "client_secret",
    "key",
    "token",
}
CREDENTIAL_NAME_PARTS = (
    "access_token",
    "api_key",
    "client_secret",
    "credential",
    "hmac_secret",
    "jwt",
    "secret",
    "signature",
    "token",
)


@dataclass
class Bindings:
    httpx_modules: set[str] = field(default_factory=set)
    aiohttp_modules: set[str] = field(default_factory=set)
    async_clients: set[str] = field(default_factory=set)
    sync_clients: set[str] = field(default_factory=set)
    shortcuts: set[str] = field(default_factory=set)
    aiohttp_sessions: set[str] = field(default_factory=set)


@dataclass
class ScanReport:
    helper_sites: set[str] = field(default_factory=set)
    raw_credentialed_sites: list[str] = field(default_factory=list)


def _prod_python_files(root: Path = ROOT) -> tuple[Path, ...]:
    files: list[Path] = []
    for path in root.rglob("*.py"):
        rel = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in rel.parts):
            continue
        if "tests" in rel.parts or path.name.startswith("test_") or path.name == "conftest.py":
            continue
        files.append(path)

    required = {
        EGRESS_HELPER,
        ROOT / "mcp_server" / "proxy_client.py",
        ROOT / "mcp_server" / "tools" / "providers.py",
        ROOT / "proxy" / "registry" / "client.py",
        ROOT / "examples" / "verify_response.py",
    }
    missing = sorted(p.relative_to(root).as_posix() for p in required - set(files))
    assert not missing, (
        "repo-root egress custody census missed required production files: "
        + ", ".join(missing)
    )
    assert len(files) >= 50, (
        f"repo-root egress custody census scanned only {len(files)} production "
        "Python files; this is a hard-empty/soft-empty signature, not a clean repo"
    )
    return tuple(sorted(files))


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dotted(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                parts.append("{}")
            else:
                return None
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string(node.left)
        right = _string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _target_names(target: ast.AST | None) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        out: set[str] = set()
        for elt in target.elts:
            out |= _target_names(elt)
        return out
    return set()


def _assigned_names(node: ast.Assign | ast.AnnAssign) -> set[str]:
    if isinstance(node, ast.Assign):
        out: set[str] = set()
        for target in node.targets:
            out |= _target_names(target)
        return out
    return _target_names(node.target)


def _call_name(call: ast.Call) -> str | None:
    return _dotted(call.func)


def _binding_kind(expr: ast.AST, bindings: Bindings) -> str | None:
    dotted = _dotted(expr)
    if dotted:
        parts = dotted.split(".")
        if len(parts) == 2 and parts[0] in bindings.httpx_modules:
            if parts[1] == "AsyncClient":
                return "httpx_async_client"
            if parts[1] == "Client":
                return "httpx_client"
            if parts[1] in HTTPX_SHORTCUTS:
                return "httpx_shortcut"
        if len(parts) == 2 and parts[0] in bindings.aiohttp_modules and parts[1] == "ClientSession":
            return "aiohttp_session"
        if dotted in bindings.async_clients:
            return "httpx_async_client"
        if dotted in bindings.sync_clients:
            return "httpx_client"
        if dotted in bindings.shortcuts:
            return "httpx_shortcut"
        if dotted in bindings.aiohttp_sessions:
            return "aiohttp_session"

    if (
        isinstance(expr, ast.Call)
        and _dotted(expr.func) == "getattr"
        and len(expr.args) >= 2
    ):
        base = _dotted(expr.args[0])
        attr = _string(expr.args[1])
        if base in bindings.httpx_modules:
            if attr == "AsyncClient":
                return "httpx_async_client"
            if attr == "Client":
                return "httpx_client"
            if attr in HTTPX_SHORTCUTS:
                return "httpx_shortcut"
        if base in bindings.aiohttp_modules and attr == "ClientSession":
            return "aiohttp_session"
    return None


def _http_bindings(tree: ast.AST) -> Bindings:
    bindings = Bindings()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name
                if alias.name == "httpx":
                    bindings.httpx_modules.add(local)
                elif alias.name == "aiohttp":
                    bindings.aiohttp_modules.add(local)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                local = alias.asname or alias.name
                if node.module == "httpx":
                    if alias.name == "AsyncClient":
                        bindings.async_clients.add(local)
                    elif alias.name == "Client":
                        bindings.sync_clients.add(local)
                    elif alias.name in HTTPX_SHORTCUTS:
                        bindings.shortcuts.add(local)
                elif node.module == "aiohttp" and alias.name == "ClientSession":
                    bindings.aiohttp_sessions.add(local)

    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            kind = _binding_kind(node.value, bindings)
            if kind is None:
                continue
            before = (
                len(bindings.async_clients),
                len(bindings.sync_clients),
                len(bindings.shortcuts),
                len(bindings.aiohttp_sessions),
            )
            names = _assigned_names(node)
            if kind == "httpx_async_client":
                bindings.async_clients.update(names)
            elif kind == "httpx_client":
                bindings.sync_clients.update(names)
            elif kind == "httpx_shortcut":
                bindings.shortcuts.update(names)
            elif kind == "aiohttp_session":
                bindings.aiohttp_sessions.update(names)
            after = (
                len(bindings.async_clients),
                len(bindings.sync_clients),
                len(bindings.shortcuts),
                len(bindings.aiohttp_sessions),
            )
            changed = changed or before != after
    return bindings


def _is_httpx_async_client(call: ast.Call, bindings: Bindings) -> bool:
    return _binding_kind(call.func, bindings) == "httpx_async_client"


def _is_httpx_client(call: ast.Call, bindings: Bindings) -> bool:
    return _binding_kind(call.func, bindings) == "httpx_client"


def _is_aiohttp_session(call: ast.Call, bindings: Bindings) -> bool:
    return _binding_kind(call.func, bindings) == "aiohttp_session"


def _is_httpx_shortcut(call: ast.Call, bindings: Bindings) -> bool:
    return _binding_kind(call.func, bindings) == "httpx_shortcut"


def _trust_env_false(call: ast.Call) -> bool:
    return any(
        kw.arg == "trust_env"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is False
        for kw in call.keywords
    )


def _expr_has_credential(expr: ast.AST, credential_names: set[str]) -> bool:
    if isinstance(expr, ast.Name) and expr.id in credential_names:
        return True
    if isinstance(expr, ast.Dict):
        for key, value in zip(expr.keys, expr.values):
            literal = _string(key)
            lowered = literal.lower() if literal else ""
            if lowered in CREDENTIAL_HEADER_KEYS:
                return True
            if lowered in CREDENTIAL_DICT_KEYS and _expr_has_credential(value, credential_names):
                return True

    for node in ast.walk(expr):
        if isinstance(node, ast.Name):
            lowered = node.id.lower()
            if node.id in credential_names or any(part in lowered for part in CREDENTIAL_NAME_PARTS):
                return True
        elif isinstance(node, ast.Attribute):
            lowered = node.attr.lower()
            if any(part in lowered for part in CREDENTIAL_NAME_PARTS):
                return True
        literal = _string(node)
        if literal:
            lowered = literal.lower()
            if any(key in lowered for key in CREDENTIAL_HEADER_KEYS):
                return True
            if "bearer " in lowered or "client_secret" in lowered:
                return True
    return False


def _credential_names(scope: ast.AST) -> set[str]:
    names = {
        node.id
        for node in ast.walk(scope)
        if isinstance(node, ast.Name)
        and any(part in node.id.lower() for part in CREDENTIAL_NAME_PARTS)
    }

    changed = True
    while changed:
        changed = False
        for node in ast.walk(scope):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            call = node.value if isinstance(node.value, ast.Call) else None
            call_name = _call_name(call) if call else None
            credential_value = (
                _expr_has_credential(node.value, names)
                or call_name in {"_sign_headers", "build_auth_headers"}
            )
            if credential_value:
                before = len(names)
                names.update(_assigned_names(node))
                changed = changed or len(names) != before
    return names


def _call_has_credentials(call: ast.Call, credential_names: set[str]) -> bool:
    for kw in call.keywords:
        if kw.arg in {"auth", "content", "data", "headers", "json", "params"}:
            if _expr_has_credential(kw.value, credential_names):
                return True
    return any(_expr_has_credential(arg, credential_names) for arg in call.args[2:])


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


def _client_vars(scope: ast.AST, bindings: Bindings) -> tuple[set[str], set[str]]:
    unsafe_httpx: set[str] = set()
    aiohttp_sessions: set[str] = set()
    for node in ast.walk(scope):
        value: ast.AST | None = None
        targets: set[str] = set()
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = _assigned_names(node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                value = item.context_expr
                targets = _target_names(item.optional_vars)
                if isinstance(value, ast.Call):
                    if (
                        (_is_httpx_async_client(value, bindings) or _is_httpx_client(value, bindings))
                        and not _trust_env_false(value)
                    ):
                        unsafe_httpx.update(targets)
                    elif _is_aiohttp_session(value, bindings):
                        aiohttp_sessions.update(targets)
                value = None
        if not isinstance(value, ast.Call):
            continue
        if (
            (_is_httpx_async_client(value, bindings) or _is_httpx_client(value, bindings))
            and not _trust_env_false(value)
        ):
            unsafe_httpx.update(targets)
        elif _is_aiohttp_session(value, bindings):
            aiohttp_sessions.update(targets)
    return unsafe_httpx, aiohttp_sessions


def _is_client_method_call(call: ast.Call, names: set[str]) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr not in CLIENT_METHODS:
        return False
    return isinstance(call.func.value, ast.Name) and call.func.value.id in names


def _scan_source(path: Path, source: str) -> ScanReport:
    tree = ast.parse(source, filename=str(path))
    bindings = _http_bindings(tree)
    report = ScanReport()
    rel = path.relative_to(ROOT).as_posix() if path.is_absolute() else path.as_posix()

    for scope_name, scope in _function_scopes(tree).items():
        node_id = f"{rel}::{scope_name}"
        credential_names = _credential_names(scope)
        unsafe_httpx, aiohttp_sessions = _client_vars(scope, bindings)

        for call in ast.walk(scope):
            if not isinstance(call, ast.Call):
                continue
            callee = _call_name(call) or ""
            bare_callee = callee.rsplit(".", 1)[-1]
            if bare_callee in EGRESS_HELPERS and path != EGRESS_HELPER:
                report.helper_sites.add(node_id)

            if _is_httpx_shortcut(call, bindings) and _call_has_credentials(call, credential_names):
                report.raw_credentialed_sites.append(
                    f"{node_id}: raw httpx shortcut {callee} carries credentials"
                )
            elif (
                (_is_httpx_async_client(call, bindings) or _is_httpx_client(call, bindings))
                and not _trust_env_false(call)
                and _call_has_credentials(call, credential_names)
            ):
                report.raw_credentialed_sites.append(
                    f"{node_id}: raw httpx client constructor carries credentials"
                )
            elif _is_aiohttp_session(call, bindings) and _call_has_credentials(call, credential_names):
                report.raw_credentialed_sites.append(
                    f"{node_id}: aiohttp ClientSession constructor carries credentials"
                )
            elif _is_client_method_call(call, unsafe_httpx) and _call_has_credentials(call, credential_names):
                report.raw_credentialed_sites.append(
                    f"{node_id}: raw httpx client method {callee} carries credentials"
                )
            elif _is_client_method_call(call, aiohttp_sessions) and _call_has_credentials(call, credential_names):
                report.raw_credentialed_sites.append(
                    f"{node_id}: aiohttp ClientSession method {callee} carries credentials"
                )
    return report


def _merge_reports(reports: list[ScanReport]) -> ScanReport:
    merged = ScanReport()
    for report in reports:
        merged.helper_sites.update(report.helper_sites)
        merged.raw_credentialed_sites.extend(report.raw_credentialed_sites)
    return merged


def _helper_contract_issues(source: str) -> list[str]:
    tree = ast.parse(source)
    funcs = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    issues: list[str] = []
    if FACTORY_HELPER not in funcs:
        issues.append(f"{FACTORY_HELPER} is missing")
        return issues

    factory = funcs[FACTORY_HELPER]
    sets_trust_env_false = False
    for node in ast.walk(factory):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if (
                isinstance(target, ast.Subscript)
                and _string(target.slice) == "trust_env"
                and isinstance(node.value, ast.Constant)
                and node.value.value is False
            ):
                sets_trust_env_false = True
    if not sets_trust_env_false:
        issues.append(f"{FACTORY_HELPER} does not assign trust_env=False")

    for helper, constructor in (
        ("egress_async_client", "httpx.AsyncClient"),
        ("egress_client", "httpx.Client"),
    ):
        fn = funcs.get(helper)
        if fn is None:
            issues.append(f"{helper} is missing")
            continue
        constructor_calls = [
            node for node in ast.walk(fn)
            if isinstance(node, ast.Call) and _call_name(node) == constructor
        ]
        if not constructor_calls:
            issues.append(f"{helper} does not call {constructor}")
            continue
        guarded = False
        for call in constructor_calls:
            for kw in call.keywords:
                if (
                    kw.arg is None
                    and isinstance(kw.value, ast.Call)
                    and _call_name(kw.value) == FACTORY_HELPER
                ):
                    guarded = True
        if not guarded:
            issues.append(f"{helper} reaches {constructor} without {FACTORY_HELPER}")
    return issues


def test_repo_root_credentialed_egress_population_uses_the_shared_factory() -> None:
    report = _merge_reports([
        _scan_source(path, path.read_text(encoding="utf-8"))
        for path in _prod_python_files()
    ])
    missing = sorted(EGRESS_SITE_MANIFEST - report.helper_sites)
    extra = sorted(report.helper_sites - EGRESS_SITE_MANIFEST)

    assert not missing and not extra, (
        "credentialed egress factory population changed.\n"
        f"  missing from repo-root census: {missing}\n"
        f"  new/unreviewed factory sites: {extra}\n"
        "Update the node-id manifest only with the code change that adds/removes "
        "the credentialed egress site."
    )
    assert report.raw_credentialed_sites == [], (
        "credentialed outbound calls bypass the shared no-env-proxy factory:\n  "
        + "\n  ".join(report.raw_credentialed_sites)
    )


def test_egress_factory_guard_is_alive_in_source() -> None:
    issues = _helper_contract_issues(EGRESS_HELPER.read_text(encoding="utf-8"))
    assert issues == [], (
        "arkheia_common.egress no longer proves ambient proxy custody:\n  "
        + "\n  ".join(issues)
    )


def test_negative_self_test_dead_factory_guard_is_flagged() -> None:
    dead = """
import httpx
def _without_environment_proxy(kwargs):
    return dict(kwargs)
def egress_async_client(**kwargs):
    return httpx.AsyncClient(**kwargs)
def egress_client(**kwargs):
    return httpx.Client(**kwargs)
"""
    issues = _helper_contract_issues(dead)
    assert f"{FACTORY_HELPER} does not assign trust_env=False" in issues
    assert "egress_async_client reaches httpx.AsyncClient without _without_environment_proxy" in issues
    assert "egress_client reaches httpx.Client without _without_environment_proxy" in issues


def test_negative_self_test_raw_credentialed_http_clients_are_flagged() -> None:
    plants = {
        "async-client": """
import httpx
async def leak(api_key):
    async with httpx.AsyncClient() as client:
        await client.post("https://example.invalid", headers={"Authorization": f"Bearer {api_key}"})
""",
        "sync-client": """
import httpx
def leak(api_key):
    with httpx.Client() as client:
        client.post("https://example.invalid", headers={"X-Arkheia-Key": api_key})
""",
        "post-shortcut": """
import httpx
def leak(api_key):
    httpx.post("https://example.invalid", headers={"Authorization": f"Bearer {api_key}"})
""",
        "request-shortcut": """
import httpx
def leak(api_key):
    httpx.request("POST", "https://example.invalid", headers={"X-Arkheia-Key": api_key})
""",
        "stream-shortcut": """
import httpx
def leak(api_key):
    with httpx.stream("POST", "https://example.invalid", headers={"Authorization": f"Bearer {api_key}"}):
        pass
""",
        "from-import-alias": """
from httpx import AsyncClient as AC
async def leak(api_key):
    async with AC() as client:
        await client.post("https://example.invalid", headers={"Authorization": f"Bearer {api_key}"})
""",
        "indirect-constructor": """
import httpx
Factory = httpx.AsyncClient
async def leak(api_key):
    async with Factory() as client:
        await client.post("https://example.invalid", headers={"Authorization": f"Bearer {api_key}"})
""",
        "aiohttp-session": """
import aiohttp
async def leak(api_key):
    async with aiohttp.ClientSession() as session:
        await session.post("https://example.invalid", headers={"Authorization": f"Bearer {api_key}"})
""",
    }
    for name, source in plants.items():
        report = _scan_source(Path(f"{name}.py"), source)
        assert report.raw_credentialed_sites, (
            f"{name} plant was not flagged; the floor no longer catches this egress form"
        )


def test_control_noncredentialed_httpx_shortcut_is_not_flagged() -> None:
    source = """
import httpx
def healthcheck(url):
    return httpx.get(url, timeout=2.0)
"""
    report = _scan_source(Path("healthcheck.py"), source)
    assert report.raw_credentialed_sites == []
