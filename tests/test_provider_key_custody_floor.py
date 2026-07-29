"""
FLOOR INVARIANT -- provider API keys must stay behind one custody boundary.

This is stdlib-only on purpose: the floor runs by parsing source, not by
starting the MCP server or opening a socket.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVIDERS = ROOT / "mcp_server" / "tools" / "providers.py"
SERVER = ROOT / "mcp_server" / "server.py"
CUSTODY = ROOT / "mcp_server" / "provider_key_custody.py"

SECRET_ENV_NAMES = {"XAI_API_KEY", "GOOGLE_API_KEY", "TOGETHER_API_KEY"}
CLOUD_PROVIDER_CALLS = {
    "run_grok": "call_grok",
    "run_gemini": "call_gemini",
    "run_together": "call_together",
}
PROVIDER_FUNCTIONS = {"call_grok", "call_gemini", "call_together", "call_ollama"}


def _production_py_files() -> list[Path]:
    files = [
        path
        for path in (ROOT / "mcp_server").rglob("*.py")
        if "tests" not in path.parts and path.name != "__init__.py"
    ]
    assert len(files) >= 5, (
        f"provider custody floor scanned only {len(files)} production files: "
        f"{[str(p.relative_to(ROOT)) for p in files]}"
    )
    return sorted(files)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _functions(tree: ast.Module) -> dict[str, ast.AsyncFunctionDef | ast.FunctionDef]:
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


def _call_lines(fn: ast.AST, name: str) -> list[int]:
    return [
        node.lineno
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and _call_name(node) == name
    ]


def _literal_arg(node: ast.Call, index: int) -> str | None:
    if len(node.args) <= index:
        return None
    arg = node.args[index]
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    return None


def _literal_slice(node: ast.Subscript) -> str | None:
    sl = node.slice
    if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
        return sl.value
    return None


class _SecretEnvReadScanner(ast.NodeVisitor):
    """Find direct provider-secret environment reads, including common aliases."""

    def __init__(self) -> None:
        self.os_aliases: set[str] = set()
        self.environ_aliases: set[str] = set()
        self.getenv_aliases: set[str] = set()
        self.reads: list[tuple[int, str]] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "os":
                self.os_aliases.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "os":
            for alias in node.names:
                name = alias.asname or alias.name
                if alias.name == "getenv":
                    self.getenv_aliases.add(name)
                elif alias.name == "environ":
                    self.environ_aliases.add(name)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._record_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        env_name = None
        if self._is_getenv_func(node.func):
            env_name = _literal_arg(node, 0)
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and self._is_environ_expr(node.func.value)
        ):
            env_name = _literal_arg(node, 0)
        if env_name in SECRET_ENV_NAMES:
            self.reads.append((node.lineno, env_name))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        env_name = _literal_slice(node)
        if env_name in SECRET_ENV_NAMES and self._is_environ_expr(node.value):
            self.reads.append((node.lineno, env_name))
        self.generic_visit(node)

    def _record_aliases(self, targets: list[ast.expr], value: ast.expr) -> None:
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not names:
            return
        if self._is_environ_expr(value):
            self.environ_aliases.update(names)
        elif self._is_getenv_func(value):
            self.getenv_aliases.update(names)
        elif (
            isinstance(value, ast.Attribute)
            and value.attr == "get"
            and self._is_environ_expr(value.value)
        ):
            self.getenv_aliases.update(names)

    def _is_getenv_func(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.getenv_aliases
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "getenv"
            and self._is_os_expr(node.value)
        )

    def _is_environ_expr(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.environ_aliases
        return (
            isinstance(node, ast.Attribute)
            and node.attr == "environ"
            and self._is_os_expr(node.value)
        )

    def _is_os_expr(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id in self.os_aliases


def _secret_env_reads(source: str) -> list[tuple[int, str]]:
    scanner = _SecretEnvReadScanner()
    scanner.visit(ast.parse(source))
    return scanner.reads


def test_secret_env_scanner_catches_common_bypass_forms() -> None:
    snippets = {
        "os.environ.get": "import os\nx = os.environ.get('XAI_API_KEY')\n",
        "os.getenv": "import os\nx = os.getenv('GOOGLE_API_KEY')\n",
        "os.environ subscript": "import os\nx = os.environ['TOGETHER_API_KEY']\n",
        "import os as alias": "import os as _os\nx = _os.environ.get('XAI_API_KEY')\n",
        "from os import getenv as alias": (
            "from os import getenv as get\nx = get('GOOGLE_API_KEY')\n"
        ),
        "from os import environ as alias": (
            "from os import environ as env\nx = env.get('TOGETHER_API_KEY')\n"
        ),
        "env assignment": "import os\nenv = os.environ\nx = env.get('XAI_API_KEY')\n",
        "getter assignment": (
            "import os\nget = os.environ.get\nx = get('GOOGLE_API_KEY')\n"
        ),
    }
    missed = {name: _secret_env_reads(src) for name, src in snippets.items()}
    assert all(reads for reads in missed.values()), missed


def test_provider_secret_env_reads_are_confined_to_custody_module() -> None:
    seen_in_custody: set[str] = set()
    offenders: list[str] = []

    for path in _production_py_files():
        source = path.read_text(encoding="utf-8")
        reads = _secret_env_reads(source)
        rel = path.relative_to(ROOT)
        if path == CUSTODY:
            seen_in_custody.update(env_name for _, env_name in reads)
            continue
        offenders.extend(f"{rel}:{line}:{env_name}" for line, env_name in reads)

    assert seen_in_custody == SECRET_ENV_NAMES, (
        "the custody module must be the single observed reader for every "
        f"provider secret env var; saw {sorted(seen_in_custody)}"
    )
    assert offenders == [], (
        "provider API keys must be read only by mcp_server/provider_key_custody.py; "
        f"direct reads found at {offenders}"
    )


def test_provider_http_post_is_chokepointed() -> None:
    tree = _parse(PROVIDERS)
    funcs = _functions(tree)
    post_call_owners: list[str] = []

    for fn_name, fn in funcs.items():
        for node in ast.walk(fn):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "post"
            ):
                post_call_owners.append(fn_name)

    assert post_call_owners == ["_provider_post"], (
        "raw client.post calls in provider wrappers bypass the provider egress "
        f"chokepoint: {post_call_owners}"
    )

    missing = sorted(
        name for name in PROVIDER_FUNCTIONS
        if not _call_lines(funcs[name], "_provider_post")
    )
    assert missing == [], (
        f"provider wrapper(s) no longer use _provider_post: {missing}"
    )


def test_provider_http_chokepoint_enforces_cloud_network_egress() -> None:
    fn = _functions(_parse(PROVIDERS))["_provider_post"]
    require_lines = _call_lines(fn, "require_network_egress")
    post_lines = [
        node.lineno
        for node in ast.walk(fn)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "post"
        )
    ]
    assert require_lines, "_provider_post no longer enforces cloud network egress"
    assert post_lines, "_provider_post no longer owns the raw client.post call"
    assert min(require_lines) < min(post_lines), (
        "_provider_post must enforce network_egress before the HTTP call; "
        f"got require={require_lines}, post={post_lines}"
    )


def test_provider_exception_paths_do_not_surface_raw_exception_text() -> None:
    tree = _parse(PROVIDERS)
    offenders: list[str] = []

    for handler in (n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)):
        target = handler.name
        if not target:
            continue
        for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "str"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id == target
            ):
                offenders.append(f"str({target}) at line {node.lineno}")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"debug", "info", "warning", "error", "exception"}
                and any(isinstance(arg, ast.Name) and arg.id == target for arg in node.args)
            ):
                offenders.append(f"logger.{node.func.attr}({target}) at line {node.lineno}")
            if isinstance(node, ast.JoinedStr):
                for value in node.values:
                    if (
                        isinstance(value, ast.FormattedValue)
                        and isinstance(value.value, ast.Name)
                        and value.value.id == target
                    ):
                        offenders.append(f"f-string {target} at line {node.lineno}")

    assert offenders == [], (
        "provider exceptions may carry URLs, params, or headers containing API "
        f"keys; raw exception text reached an output/log path: {offenders}"
    )


def test_cloud_provider_tools_enforce_network_egress_before_calling_provider() -> None:
    funcs = _functions(_parse(SERVER))
    missing = sorted(set(CLOUD_PROVIDER_CALLS) - set(funcs))
    assert missing == [], f"cloud tool wrappers not found: {missing}"

    for tool_name, provider_call in CLOUD_PROVIDER_CALLS.items():
        fn = funcs[tool_name]
        check_lines = [
            node.lineno
            for node in ast.walk(fn)
            if (
                isinstance(node, ast.Call)
                and _call_name(node) == "check"
                and _literal_arg(node, 0) == tool_name
            )
        ]
        egress_lines = _call_lines(fn, "require_network_egress")
        provider_lines = _call_lines(fn, provider_call)

        assert check_lines, f"{tool_name} no longer calls check({tool_name!r})"
        assert egress_lines, f"{tool_name} does not enforce network_egress"
        assert provider_lines, f"{tool_name} no longer calls {provider_call}"
        assert min(check_lines) < min(egress_lines) < min(provider_lines), (
            f"{tool_name} must check policy, enforce network_egress, then call "
            f"{provider_call}; got check={check_lines}, "
            f"egress={egress_lines}, provider={provider_lines}"
        )

    ollama = funcs["run_ollama"]
    assert _call_lines(ollama, "check"), "run_ollama still needs the registry gate"
    assert not _call_lines(ollama, "require_network_egress"), (
        "run_ollama is a local transport and should not require cloud egress"
    )
