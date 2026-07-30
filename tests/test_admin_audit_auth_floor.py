"""AST floor for protected proxy admin/audit routes.

The unit test in ``proxy/tests`` drives today's router objects. This floor is
the mutation guard: it scans every production endpoint module under
``proxy/endpoints`` with stdlib AST only, so a new ``/audit/export`` or
``/admin/*`` route in a new file cannot bypass auth while the floor tier stays
green.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENDPOINT_DIR = ROOT / "proxy" / "endpoints"

PROTECTED_PREFIXES = ("/admin", "/audit")
EXPECTED_PROTECTED_ROUTES = frozenset({
    "GET /admin/health",
    "POST /admin/registry/pull",
    "POST /admin/profiles/{model_id}/rollback",
    "GET /admin/profiles",
    "GET /admin/ui",
    "GET /audit/log",
})
PUBLIC_COOKIE_ROUTES = frozenset({"GET /admin/ui"})


@dataclass(frozen=True)
class RouteSite:
    label: str
    file: str
    function: str
    lineno: int
    container_auth: bool
    decorator_auth: bool
    function_auth: bool
    cookie_guard: bool

    @property
    def is_protected(self) -> bool:
        if self.label in PUBLIC_COOKIE_ROUTES:
            return self.cookie_guard
        return self.container_auth or self.decorator_auth or self.function_auth


def _read_endpoint_sources() -> dict[str, str]:
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(ENDPOINT_DIR.rglob("*.py"))
        if path.name != "__init__.py"
    }


def _call_name(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _string_value(node: ast.AST | None, constants: dict[str, str]) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return constants.get(node.id)
    return None


def _module_string_constants(tree: ast.AST) -> dict[str, str]:
    constants: dict[str, str] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.Assign):
            continue
        value = _string_value(node.value, constants={})
        if value is None:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = value
    return constants


def _imported_names(tree: ast.AST, *, module: str, names: set[str]) -> set[str]:
    out = set(names)
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module != module:
            continue
        for alias in node.names:
            if alias.name in names:
                out.add(alias.asname or alias.name)
    return out


def _auth_names(tree: ast.AST) -> tuple[set[str], set[str], set[str], set[str]]:
    depends = _imported_names(tree, module="fastapi", names={"Depends"})
    require_auth = _imported_names(tree, module="proxy.auth", names={"require_auth"})
    verify_jwt = _imported_names(tree, module="proxy.auth", names={"verify_jwt"})
    redirects = _imported_names(
        tree, module="fastapi.responses", names={"RedirectResponse"}
    )
    return depends, require_auth, verify_jwt, redirects


def _is_require_auth_name(node: ast.AST | None, require_auth_names: set[str]) -> bool:
    return _call_name(node) in require_auth_names


def _is_depends_require_auth(
    node: ast.AST | None,
    *,
    depends_names: set[str],
    require_auth_names: set[str],
) -> bool:
    if not isinstance(node, ast.Call) or _call_name(node.func) not in depends_names:
        return False
    if node.args and _is_require_auth_name(node.args[0], require_auth_names):
        return True
    for kw in node.keywords:
        if kw.arg == "dependency" and _is_require_auth_name(kw.value, require_auth_names):
            return True
    return False


def _dependencies_include_require_auth(
    node: ast.AST | None,
    *,
    depends_names: set[str],
    require_auth_names: set[str],
) -> bool:
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(
            _is_depends_require_auth(
                elt, depends_names=depends_names, require_auth_names=require_auth_names
            )
            for elt in node.elts
        )
    return _is_depends_require_auth(
        node, depends_names=depends_names, require_auth_names=require_auth_names
    )


def _function_has_auth_dependency(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    depends_names: set[str],
    require_auth_names: set[str],
) -> bool:
    defaults = list(fn.args.defaults) + [
        d for d in fn.args.kw_defaults if d is not None
    ]
    return any(
        _is_depends_require_auth(
            default,
            depends_names=depends_names,
            require_auth_names=require_auth_names,
        )
        for default in defaults
    )


def _function_has_cookie_guard(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    verify_jwt_names: set[str],
    redirect_names: set[str],
) -> bool:
    calls = [node for node in ast.walk(fn) if isinstance(node, ast.Call)]
    calls_verify_jwt = any(_call_name(call.func) in verify_jwt_names for call in calls)
    redirects_to_login = False
    for call in calls:
        if _call_name(call.func) not in redirect_names:
            continue
        values = list(call.args) + [kw.value for kw in call.keywords]
        if any(_string_value(value, {}) == "/auth/google" for value in values):
            redirects_to_login = True
    return calls_verify_jwt and redirects_to_login


def _route_container_constructors(tree: ast.AST) -> set[str]:
    return _imported_names(tree, module="fastapi", names={"APIRouter", "FastAPI"})


def _route_containers(
    tree: ast.AST,
    *,
    constants: dict[str, str],
    depends_names: set[str],
    require_auth_names: set[str],
) -> dict[str, tuple[str, bool]]:
    constructors = _route_container_constructors(tree)
    containers: dict[str, tuple[str, bool]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        if _call_name(node.value.func) not in constructors:
            continue
        prefix = ""
        auth = False
        for kw in node.value.keywords:
            if kw.arg == "prefix":
                prefix = _string_value(kw.value, constants) or ""
            if kw.arg == "dependencies":
                auth = _dependencies_include_require_auth(
                    kw.value,
                    depends_names=depends_names,
                    require_auth_names=require_auth_names,
                )
        for target in node.targets:
            if isinstance(target, ast.Name):
                containers[target.id] = (prefix, auth)
    return containers


def _route_path(call: ast.Call, constants: dict[str, str]) -> str | None:
    if call.args:
        value = _string_value(call.args[0], constants)
        if value is not None:
            return value
    for kw in call.keywords:
        if kw.arg in {"path", "url_path"}:
            return _string_value(kw.value, constants)
    return None


def _route_methods(call: ast.Call, default: str) -> list[str]:
    for kw in call.keywords:
        if kw.arg != "methods":
            continue
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return [kw.value.value]
        if isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
            return [
                elt.value
                for elt in kw.value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ] or ["ANY"]
    return [default]


def _join_path(prefix: str, route_path: str) -> str:
    if not prefix:
        return route_path
    if not route_path:
        return prefix
    if prefix.endswith("/") and route_path.startswith("/"):
        return prefix[:-1] + route_path
    if not prefix.endswith("/") and not route_path.startswith("/"):
        return prefix + "/" + route_path
    return prefix + route_path


def _route_sites_for_source(rel: str, source: str) -> list[RouteSite]:
    tree = ast.parse(source)
    constants = _module_string_constants(tree)
    depends_names, require_auth_names, verify_jwt_names, redirect_names = _auth_names(tree)
    containers = _route_containers(
        tree,
        constants=constants,
        depends_names=depends_names,
        require_auth_names=require_auth_names,
    )
    sites: list[RouteSite] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        function_auth = _function_has_auth_dependency(
            fn, depends_names=depends_names, require_auth_names=require_auth_names
        )
        cookie_guard = _function_has_cookie_guard(
            fn, verify_jwt_names=verify_jwt_names, redirect_names=redirect_names
        )
        for dec in fn.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            callee = dec.func
            if not (
                isinstance(callee, ast.Attribute)
                and isinstance(callee.value, ast.Name)
                and callee.value.id in containers
                and callee.attr in {"get", "post", "put", "patch", "delete", "api_route"}
            ):
                continue
            route_path = _route_path(dec, constants)
            if route_path is None:
                continue
            prefix, container_auth = containers[callee.value.id]
            full_path = _join_path(prefix, route_path)
            decorator_auth = any(
                kw.arg == "dependencies"
                and _dependencies_include_require_auth(
                    kw.value,
                    depends_names=depends_names,
                    require_auth_names=require_auth_names,
                )
                for kw in dec.keywords
            )
            methods = _route_methods(
                dec, "ANY" if callee.attr == "api_route" else callee.attr.upper()
            )
            for method in methods:
                sites.append(
                    RouteSite(
                        label=f"{method.upper()} {full_path}",
                        file=rel,
                        function=fn.name,
                        lineno=dec.lineno,
                        container_auth=container_auth,
                        decorator_auth=decorator_auth,
                        function_auth=function_auth,
                        cookie_guard=cookie_guard,
                    )
                )
    return sites


def _protected_route_sites(sources: dict[str, str]) -> list[RouteSite]:
    sites: list[RouteSite] = []
    for rel, source in sources.items():
        for site in _route_sites_for_source(rel, source):
            path = site.label.split(" ", 1)[1]
            if path.startswith(PROTECTED_PREFIXES):
                sites.append(site)
    return sites


def _unprotected_protected_routes(sources: dict[str, str]) -> list[str]:
    return [
        f"{site.file}:{site.lineno} {site.label} -> {site.function}"
        for site in _protected_route_sites(sources)
        if not site.is_protected
    ]


def test_all_admin_and_audit_routes_are_auth_guarded() -> None:
    sites = _protected_route_sites(_read_endpoint_sources())
    labels = frozenset(site.label for site in sites)

    assert EXPECTED_PROTECTED_ROUTES <= labels, (
        "admin/audit route discovery lost expected production routes: "
        f"missing={sorted(EXPECTED_PROTECTED_ROUTES - labels)} found={sorted(labels)}"
    )
    assert _unprotected_protected_routes(_read_endpoint_sources()) == []


def test_floor_catches_new_audit_export_route_in_new_file() -> None:
    sources = {
        "proxy/endpoints/audit_export.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter()\n"
            "@router.get('/audit/export')\n"
            "async def export():\n"
            "    return {'ok': True}\n"
        )
    }

    assert _unprotected_protected_routes(sources) == [
        "proxy/endpoints/audit_export.py:3 GET /audit/export -> export"
    ]


def test_floor_catches_prefixed_audit_route_in_new_file() -> None:
    sources = {
        "proxy/endpoints/audit_export.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter(prefix='/audit')\n"
            "@router.post('/export')\n"
            "async def export():\n"
            "    return {'ok': True}\n"
        )
    }

    assert _unprotected_protected_routes(sources) == [
        "proxy/endpoints/audit_export.py:3 POST /audit/export -> export"
    ]


def test_floor_accepts_dependency_auth_on_route_or_router() -> None:
    sources = {
        "proxy/endpoints/audit_export.py": (
            "from fastapi import APIRouter, Depends\n"
            "from proxy.auth import require_auth\n"
            "audit = APIRouter(prefix='/audit')\n"
            "@audit.get('/export')\n"
            "async def route_dep(_: str = Depends(require_auth)):\n"
            "    return {'ok': True}\n"
            "admin = APIRouter(prefix='/admin', dependencies=[Depends(require_auth)])\n"
            "@admin.post('/jobs')\n"
            "async def router_dep():\n"
            "    return {'ok': True}\n"
        )
    }

    assert _unprotected_protected_routes(sources) == []


def test_floor_catches_admin_ui_without_cookie_jwt_redirect_guard() -> None:
    sources = {
        "proxy/endpoints/admin.py": (
            "from fastapi import APIRouter\n"
            "router = APIRouter(prefix='/admin')\n"
            "@router.get('/ui')\n"
            "async def admin_ui(request):\n"
            "    return '<html>open dashboard</html>'\n"
        )
    }

    assert _unprotected_protected_routes(sources) == [
        "proxy/endpoints/admin.py:3 GET /admin/ui -> admin_ui"
    ]
