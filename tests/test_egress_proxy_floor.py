from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROD_ROOTS = ("arkheia_common", "mcp_server", "proxy")


def _prod_python_files() -> list[Path]:
    files: list[Path] = []
    for root in PROD_ROOTS:
        for path in (ROOT / root).rglob("*.py"):
            rel_parts = path.relative_to(ROOT).parts
            if "tests" in rel_parts or "__pycache__" in rel_parts:
                continue
            files.append(path)
    return sorted(files)


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _raw_async_client_calls(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"AsyncClient", "httpx.AsyncClient"} or (
            name and name.endswith(".AsyncClient")
        ):
            lines.append(node.lineno)
    return lines


def test_raw_async_clients_are_confined_to_the_shared_egress_factory():
    calls = {
        path.relative_to(ROOT).as_posix(): _raw_async_client_calls(path)
        for path in _prod_python_files()
    }
    calls = {rel: lines for rel, lines in calls.items() if lines}

    assert calls, "raw AsyncClient census found nothing; the floor is not observing code"
    assert set(calls) == {"arkheia_common/egress.py"}
    assert len(calls["arkheia_common/egress.py"]) == 1


def test_raw_async_client_census_negative_control_flags_old_call_site():
    tree = ast.parse(
        "import httpx\n"
        "async def send():\n"
        "    async with httpx.AsyncClient(timeout=30.0) as client:\n"
        "        return await client.get('https://registry.example.test')\n"
    )
    calls = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node.func) == "httpx.AsyncClient":
            calls.append(node.lineno)
    assert calls == [3]
