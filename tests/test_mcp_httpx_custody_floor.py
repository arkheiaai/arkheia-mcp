"""
FLOOR TIER -- MCP outbound HTTP custody.

Production code may construct ``httpx.AsyncClient`` only in the shared egress
factory. The floor scans from the repo root so adding, deleting, or moving a
package root cannot silently move credentialed egress out of custody.
"""
from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EGRESS_FACTORY = "arkheia_common/egress.py"
KNOWN_EGRESS_SURFACE_FILES = frozenset({
    EGRESS_FACTORY,
    "arkheia_common/hosted_authority.py",
    "mcp_server/proxy_client.py",
    "mcp_server/tools/providers.py",
    "proxy/crypto/profile_crypto.py",
    "proxy/detection_adapter.py",
    "proxy/endpoints/passthrough.py",
    "proxy/middleware/interception.py",
    "proxy/registry/client.py",
})
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


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _raw_async_client_calls_from_tree(tree: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node.func)
        if name in {"AsyncClient", "httpx.AsyncClient"} or (
            name and name.endswith(".AsyncClient")
        ):
            lines.append(node.lineno)
    return lines


def _raw_async_client_calls(path: Path) -> list[int]:
    return _raw_async_client_calls_from_tree(
        ast.parse(path.read_text(encoding="utf-8"), str(path))
    )


class _FakeHttpx(types.ModuleType):
    class AsyncClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs


def _load_egress_with_fake_httpx():
    module_path = ROOT / EGRESS_FACTORY
    spec = importlib.util.spec_from_file_location("_floor_egress_factory", module_path)
    assert spec and spec.loader, "could not load egress factory module"
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get("httpx")
    sys.modules["httpx"] = _FakeHttpx("httpx")
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop("httpx", None)
        else:
            sys.modules["httpx"] = previous
    return module


def test_prod_census_is_repo_rooted_and_covers_known_egress_surfaces():
    rels = {path.relative_to(ROOT).as_posix() for path in _prod_python_files()}

    missing = sorted(KNOWN_EGRESS_SURFACE_FILES - rels)
    assert not missing, (
        "egress custody census missed known runtime files; root-wide discovery is "
        "broken or an owned egress surface moved without updating this floor:\n  "
        + "\n  ".join(missing)
    )


def test_raw_async_clients_are_confined_to_the_shared_egress_factory():
    calls = {
        path.relative_to(ROOT).as_posix(): _raw_async_client_calls(path)
        for path in _prod_python_files()
    }
    calls = {rel: lines for rel, lines in calls.items() if lines}

    assert calls, "raw AsyncClient census found nothing; the floor is not observing code"
    assert set(calls) == {EGRESS_FACTORY}, (
        "raw httpx.AsyncClient construction must stay inside the shared egress "
        "factory so credentialed provider/proxy calls cannot opt back into "
        "ambient HTTP(S)_PROXY custody:\n  "
        + "\n  ".join(f"{rel}: {lines}" for rel, lines in sorted(calls.items()))
    )
    assert len(calls[EGRESS_FACTORY]) == 1


def test_shared_egress_factory_forces_trust_env_false_and_rejects_true():
    egress = _load_egress_with_fake_httpx()

    client = egress.egress_async_client(timeout=12.5)
    assert client.kwargs["trust_env"] is False
    assert client.kwargs["timeout"] == 12.5

    with pytest.raises(ValueError, match="trust_env"):
        egress.egress_async_client(timeout=12.5, trust_env=True)


def test_raw_async_client_census_negative_controls_cover_common_bypass_shapes():
    modules = {
        "direct.py": "import httpx\nhttpx.AsyncClient()\n",
        "aliased_module.py": "import httpx as hx\nhx.AsyncClient(timeout=1)\n",
        "bare_import.py": "from httpx import AsyncClient\nAsyncClient(timeout=1)\n",
        "nested.py": (
            "import httpx\n"
            "def factory():\n"
            "    return httpx.AsyncClient(timeout=1, trust_env=False)\n"
        ),
        "async_with.py": (
            "import httpx\n"
            "async def send():\n"
            "    async with httpx.AsyncClient(timeout=1) as client:\n"
            "        return client\n"
        ),
        "module_chain.py": (
            "import vendor.httpx as owned\n"
            "client = owned.AsyncClient(timeout=1)\n"
        ),
    }

    observed = {
        rel: _raw_async_client_calls_from_tree(ast.parse(source, rel))
        for rel, source in modules.items()
    }

    assert observed == {
        "direct.py": [2],
        "aliased_module.py": [2],
        "bare_import.py": [2],
        "nested.py": [3],
        "async_with.py": [3],
        "module_chain.py": [2],
    }
