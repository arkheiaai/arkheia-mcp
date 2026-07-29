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
PROVIDER_ENDPOINT_MARKERS = {
    "api.x.ai",
    "generativelanguage.googleapis.com",
    "api.together.xyz",
}
PROVIDER_EGRESS_CALL_NAMES = PROVIDER_FUNCTIONS | {
    "provider_api_key",
    "_provider_post",
}
RAW_HTTP_CALL_NAMES = {"post", "request", "stream"}


def _production_py_files() -> list[Path]:
    files = [
        path
        for path in ROOT.rglob("*.py")
        if "tests" not in path.relative_to(ROOT).parts
        and ".git" not in path.parts
        and "__pycache__" not in path.parts
    ]
    expected = {
        CUSTODY,
        PROVIDERS,
        ROOT / "mcp_server" / "tools" / "__init__.py",
        ROOT / "proxy" / "__init__.py",
    }
    missing = sorted(str(path.relative_to(ROOT)) for path in expected - set(files))
    assert missing == [], f"provider custody floor missed production files: {missing}"
    assert len(files) >= 50, (
        f"provider custody floor scanned only {len(files)} production files: "
        f"{[str(p.relative_to(ROOT)) for p in files]}"
    )
    return sorted(files)


def _mcp_production_py_files() -> list[Path]:
    files = [
        path
        for path in (ROOT / "mcp_server").rglob("*.py")
        if "tests" not in path.relative_to(ROOT).parts
        and "__pycache__" not in path.parts
    ]
    expected = {PROVIDERS, SERVER, CUSTODY}
    missing = sorted(str(path.relative_to(ROOT)) for path in expected - set(files))
    assert missing == [], f"provider egress floor missed production files: {missing}"
    assert len(files) >= 8, (
        f"provider egress floor scanned only {len(files)} MCP production files: "
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


def _string_value(node: ast.AST, constants: dict[str, str] | None = None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if constants and isinstance(node, ast.Name):
        return constants.get(node.id)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _string_value(node.left, constants)
        right = _string_value(node.right, constants)
        if left is not None and right is not None:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                part = _string_value(value.value, constants)
                if part is None:
                    return None
                parts.append(part)
            else:
                return None
        return "".join(parts)
    return None


def _literal_arg(node: ast.Call, index: int, constants: dict[str, str] | None = None) -> str | None:
    if len(node.args) <= index:
        return None
    return _string_value(node.args[index], constants)


def _literal_slice(node: ast.Subscript, constants: dict[str, str] | None = None) -> str | None:
    return _string_value(node.slice, constants)


class _SecretEnvReadScanner(ast.NodeVisitor):
    """Find direct provider-secret environment reads, including common aliases."""

    def __init__(self) -> None:
        self.os_aliases: set[str] = set()
        self.environ_aliases: set[str] = set()
        self.getenv_aliases: set[str] = set()
        self.string_constants: dict[str, str] = {}
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
        self._record_string_constants(node.targets, node.value)
        self._record_aliases(node.targets, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._record_string_constants([node.target], node.value)
            self._record_aliases([node.target], node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        env_name = None
        if self._is_getenv_func(node.func):
            env_name = _literal_arg(node, 0, self.string_constants)
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr not in {"clear", "copy", "items", "keys", "values"}
            and self._is_environ_expr(node.func.value)
        ):
            env_name = _literal_arg(node, 0, self.string_constants)
        if env_name in SECRET_ENV_NAMES:
            self.reads.append((node.lineno, env_name))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        env_name = _literal_slice(node, self.string_constants)
        if env_name in SECRET_ENV_NAMES and self._is_environ_expr(node.value):
            self.reads.append((node.lineno, env_name))
        self.generic_visit(node)

    def _record_string_constants(self, targets: list[ast.expr], value: ast.expr) -> None:
        literal = _string_value(value, self.string_constants)
        if literal is None:
            return
        for target in targets:
            if isinstance(target, ast.Name):
                self.string_constants[target.id] = literal

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


class _ProviderEgressReport:
    def __init__(self) -> None:
        self.provider_calls: list[tuple[int, str, str]] = []
        self.endpoint_literals: list[tuple[int, str, str]] = []
        self.raw_http_calls: list[tuple[str, int, str]] = []

    @property
    def is_provider_egress(self) -> bool:
        return bool(self.provider_calls or self.endpoint_literals)


class _ProviderEgressScanner(ast.NodeVisitor):
    def __init__(self) -> None:
        self.report = _ProviderEgressReport()
        self._function_stack: list[str] = ["<module>"]

    @property
    def _function_name(self) -> str:
        return self._function_stack[-1]

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        call_name = _call_name(node)
        if call_name in PROVIDER_EGRESS_CALL_NAMES:
            self.report.provider_calls.append((node.lineno, call_name, self._function_name))
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in RAW_HTTP_CALL_NAMES
        ):
            self.report.raw_http_calls.append(
                (self._function_name, node.lineno, node.func.attr)
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            for marker in PROVIDER_ENDPOINT_MARKERS:
                if marker in node.value:
                    self.report.endpoint_literals.append(
                        (node.lineno, marker, self._function_name)
                    )


def _provider_egress_report_from_source(source: str) -> _ProviderEgressReport:
    scanner = _ProviderEgressScanner()
    scanner.visit(ast.parse(source))
    return scanner.report


def _provider_egress_report(path: Path) -> _ProviderEgressReport:
    return _provider_egress_report_from_source(path.read_text(encoding="utf-8"))


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
        "environ setdefault": (
            "import os\nx = os.environ.setdefault('XAI_API_KEY', '')\n"
        ),
        "environ pop": "import os\nx = os.environ.pop('GOOGLE_API_KEY', '')\n",
        "constant name": (
            "import os\n_SECRET = 'TOGETHER_API_KEY'\nx = os.environ.get(_SECRET)\n"
        ),
        "constant concatenation": (
            "import os\n_SECRET = 'XAI_API' + '_KEY'\nx = os.getenv(_SECRET)\n"
        ),
        "constant f-string": (
            "import os\n_PART = 'GOOGLE'\n_SECRET = f'{_PART}_API_KEY'\nx = os.environ[_SECRET]\n"
        ),
    }
    missed = {name: _secret_env_reads(src) for name, src in snippets.items()}
    assert all(reads for reads in missed.values()), missed


def test_provider_egress_scanner_catches_new_raw_http_file() -> None:
    source = """
import httpx
from mcp_server.provider_key_custody import provider_api_key

async def run_shadow_provider(prompt):
    api_key = provider_api_key("xai")
    async with httpx.AsyncClient() as client:
        return await client.post(
            "https://api.x.ai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"messages": [{"role": "user", "content": prompt}]},
        )
"""
    report = _provider_egress_report_from_source(source)

    assert report.is_provider_egress
    assert report.provider_calls == [(6, "provider_api_key", "run_shadow_provider")]
    assert report.endpoint_literals == [(9, "api.x.ai", "run_shadow_provider")]
    assert report.raw_http_calls == [("run_shadow_provider", 8, "post")]


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
    reports = {
        path: report
        for path in _mcp_production_py_files()
        if (report := _provider_egress_report(path)).is_provider_egress
    }
    missing_expected = sorted(
        str(path.relative_to(ROOT))
        for path in {PROVIDERS, SERVER} - set(reports)
    )
    assert missing_expected == [], (
        "provider egress discovery missed expected production sites: "
        f"{missing_expected}; discovered "
        f"{[str(path.relative_to(ROOT)) for path in reports]}"
    )
    assert len(reports) >= 2, (
        "provider egress discovery measured too little work: "
        f"{[str(path.relative_to(ROOT)) for path in reports]}"
    )

    offenders: list[str] = []
    raw_http_sites: list[str] = []
    for path, report in reports.items():
        rel = path.relative_to(ROOT)
        for fn_name, line, method in report.raw_http_calls:
            site = f"{rel}:{fn_name}:{line}:{method}"
            raw_http_sites.append(site)
            if not (path == PROVIDERS and fn_name == "_provider_post" and method == "post"):
                offenders.append(site)

    assert offenders == [], (
        "raw provider HTTP calls outside the single provider egress chokepoint: "
        f"{offenders}; discovered provider-egress files were "
        f"{[str(path.relative_to(ROOT)) for path in reports]}"
    )
    assert len(raw_http_sites) == 1, (
        "provider egress must have exactly one raw HTTP write site, owned by "
        f"_provider_post; got {raw_http_sites}"
    )

    funcs = _functions(_parse(PROVIDERS))
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


def test_ollama_base_url_is_loopback_validated_before_post() -> None:
    funcs = _functions(_parse(PROVIDERS))
    call_ollama = funcs["call_ollama"]
    validator_lines = _call_lines(call_ollama, "_local_ollama_base_url")
    post_lines = _call_lines(call_ollama, "_provider_post")
    client_calls = [
        node
        for node in ast.walk(call_ollama)
        if isinstance(node, ast.Call) and _call_name(node) == "AsyncClient"
    ]

    assert validator_lines, "call_ollama no longer validates OLLAMA_BASE_URL"
    assert post_lines, "call_ollama no longer calls the provider post chokepoint"
    assert min(validator_lines) < min(post_lines), (
        "call_ollama must validate the base URL before opening the HTTP path; "
        f"got validator={validator_lines}, post={post_lines}"
    )
    assert len(client_calls) == 1, (
        "call_ollama must open exactly one local HTTP client; got "
        f"{len(client_calls)}"
    )
    trust_env_keywords = [
        kw.value
        for kw in client_calls[0].keywords
        if kw.arg == "trust_env"
    ]
    assert (
        len(trust_env_keywords) == 1
        and isinstance(trust_env_keywords[0], ast.Constant)
        and trust_env_keywords[0].value is False
    ), "call_ollama must disable proxy/env transport inheritance with trust_env=False"


def test_ollama_loopback_validator_resolves_hostname_addresses() -> None:
    funcs = _functions(_parse(PROVIDERS))
    resolver = funcs.get("_resolved_host_addresses")
    validator = funcs.get("_is_loopback_host")

    assert resolver is not None, "loopback validation no longer has a resolver helper"
    assert validator is not None, "loopback validation helper is missing"
    assert _call_lines(resolver, "getaddrinfo"), (
        "hostname loopback validation must resolve DNS/hosts-file addresses"
    )
    assert _call_lines(resolver, "ip_address"), (
        "hostname loopback validation must classify resolved IP addresses"
    )
    assert _call_lines(validator, "_resolved_host_addresses"), (
        "_is_loopback_host must validate the resolved address population"
    )
    assert _call_lines(validator, "all"), (
        "_is_loopback_host must require every resolved address to be loopback"
    )

    literal_accepts: list[int] = []
    for node in ast.walk(validator):
        if not isinstance(node, ast.Compare):
            continue
        values = [_string_value(node.left)]
        values.extend(_string_value(comparator) for comparator in node.comparators)
        if "localhost" in values:
            literal_accepts.append(node.lineno)
    assert literal_accepts == [], (
        "localhost must not be accepted by string comparison; it must resolve to "
        f"loopback addresses first: {literal_accepts}"
    )


def test_floor_self_test_catches_setdefault_constant_and_off_root_secret_reads() -> None:
    snippets = {
        "setdefault": "import os\nx = os.environ.setdefault('XAI_API_KEY', '')\n",
        "__init__": "import os as _os\nx = _os.environ.get('GOOGLE_API_KEY')\n",
        "constant": "import os\n_N='TOGETHER_API_KEY'\nx = os.getenv(_N)\n",
    }
    missed = {name: _secret_env_reads(src) for name, src in snippets.items()}
    assert all(reads for reads in missed.values()), missed
