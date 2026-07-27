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

SECRET_ENV_NAMES = {"XAI_API_KEY", "GOOGLE_API_KEY", "TOGETHER_API_KEY"}
CLOUD_PROVIDER_CALLS = {
    "run_grok": "call_grok",
    "run_gemini": "call_gemini",
    "run_together": "call_together",
}
PROVIDER_FUNCTIONS = {"call_grok", "call_gemini", "call_together", "call_ollama"}


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


def test_provider_secret_env_reads_are_chokepointed() -> None:
    tree = _parse(PROVIDERS)
    funcs = _functions(tree)
    seen: set[str] = set()
    offenders: list[str] = []

    for fn_name, fn in funcs.items():
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "get":
                continue
            if not (
                isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "environ"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "os"
            ):
                continue
            env_name = _literal_arg(node, 0)
            if env_name in SECRET_ENV_NAMES:
                seen.add(env_name)
                if fn_name != "_provider_api_key":
                    offenders.append(f"{fn_name}:{node.lineno}:{env_name}")

    assert seen == SECRET_ENV_NAMES, (
        f"the floor did not observe every provider secret env read: {sorted(seen)}"
    )
    assert offenders == [], (
        "provider API keys must be read only by _provider_api_key; direct reads "
        f"found at {offenders}"
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
