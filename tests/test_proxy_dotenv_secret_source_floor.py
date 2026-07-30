"""
FLOOR INVARIANT - production modules do not make `.env` a secret source.

This is a source-text floor: stdlib only, no project imports, no sockets, no app
startup. It guards the production entrypoint class that let `proxy/main.py` load
the nearest cwd `.env` before `proxy.config` imported, with `override=True`.

Two properties are enforced:

* production modules may not call `load_dotenv` at all; OS environment remains
  the production secret authority.
* production modules may not use `find_dotenv(usecwd=True)`, which turns an
  arbitrary process cwd into configuration authority.

If a future local-development dotenv opt-in is needed, it must be explicit and
reviewed in the same change as this floor. Until then, the production tree has
no dotenv loader call site.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

PRODUCTION_DIRS = ("proxy", "mcp_server", "registry_server")
PRODUCTION_FILES = ("server.py",)
TEST_DIR_NAMES = {"tests", "__pycache__"}

DOTENV_LOADERS = frozenset({"load_dotenv"})
DOTENV_FINDERS = frozenset({"find_dotenv"})


def _production_python_files() -> list[Path]:
    out: list[Path] = []
    for dirname in PRODUCTION_DIRS:
        base = ROOT / dirname
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            rel_parts = set(path.relative_to(ROOT).parts)
            if TEST_DIR_NAMES & rel_parts or path.name.startswith("test_"):
                continue
            out.append(path)

    for name in PRODUCTION_FILES:
        path = ROOT / name
        if path.is_file():
            out.append(path)

    return sorted(out)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _dotenv_function_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module != "dotenv":
            continue
        for alias in node.names:
            if alias.name in DOTENV_LOADERS | DOTENV_FINDERS:
                aliases[alias.asname or alias.name] = alias.name
    return aliases


def _call_name(node: ast.Call, aliases: dict[str, str]) -> str | None:
    func = node.func
    if isinstance(func, ast.Name):
        if func.id in aliases:
            return aliases[func.id]
        if func.id in DOTENV_LOADERS | DOTENV_FINDERS:
            return func.id
    if isinstance(func, ast.Attribute) and func.attr in DOTENV_LOADERS | DOTENV_FINDERS:
        return func.attr
    return None


def _literal_false(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _kw(call: ast.Call, name: str) -> ast.AST | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _dotenv_findings(tree: ast.Module, label: str) -> list[str]:
    aliases = _dotenv_function_aliases(tree)
    findings: list[str] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node, aliases)
        if name == "load_dotenv":
            override = _kw(node, "override")
            if override is not None and not _literal_false(override):
                findings.append(
                    f"{label}:{node.lineno}: load_dotenv override is not literal False"
                )
            elif len(node.args) >= 4 and not _literal_false(node.args[3]):
                findings.append(
                    f"{label}:{node.lineno}: load_dotenv positional override is not literal False"
                )
            findings.append(
                f"{label}:{node.lineno}: production module calls load_dotenv"
            )
        elif name == "find_dotenv":
            usecwd = _kw(node, "usecwd")
            if usecwd is not None and not _literal_false(usecwd):
                findings.append(
                    f"{label}:{node.lineno}: find_dotenv usecwd is not literal False"
                )
            elif len(node.args) >= 3 and not _literal_false(node.args[2]):
                findings.append(
                    f"{label}:{node.lineno}: find_dotenv positional usecwd is not literal False"
                )

    return findings


def test_floor_scans_the_production_entrypoints():
    files = _production_python_files()
    rels = {path.relative_to(ROOT).as_posix() for path in files}

    assert "proxy/main.py" in rels, (
        "proxy/main.py was not in the production scan; the floor lost the "
        "entrypoint that earned it"
    )
    assert "mcp_server/server.py" in rels, (
        "mcp_server/server.py was not in the production scan; the MCP entrypoint "
        "is part of this lane's runtime surface"
    )
    assert len(files) >= 30, (
        f"only {len(files)} production Python files were scanned. A floor that "
        "passes by examining a tiny or empty population is not evidence."
    )


def test_production_modules_do_not_load_dotenv_or_search_cwd_dotenv():
    findings: list[str] = []
    for path in _production_python_files():
        findings.extend(
            _dotenv_findings(_parse(path), path.relative_to(ROOT).as_posix())
        )

    assert not findings, (
        "production modules must not make `.env` a secret/config source:\n  "
        + "\n  ".join(findings)
    )


def test_negative_self_test_flags_override_and_cwd_dotenv_sources():
    synthetic = ast.parse(
        "from dotenv import load_dotenv as ld, find_dotenv\n"
        "ld(find_dotenv(usecwd=True), override=True)\n"
        "load_dotenv('x', None, False, True)\n"
    )
    findings = _dotenv_findings(synthetic, "synthetic.py")

    assert any("load_dotenv override" in item for item in findings), findings
    assert any("production module calls load_dotenv" in item for item in findings), findings
    assert any("find_dotenv usecwd" in item for item in findings), findings
    assert any("positional override" in item for item in findings), findings


def test_negative_self_test_allows_non_cwd_find_without_loader_call():
    synthetic = ast.parse(
        "from dotenv import find_dotenv\n"
        "path = find_dotenv(usecwd=False)\n"
        "other = find_dotenv('.env')\n"
    )

    assert _dotenv_findings(synthetic, "safe.py") == []
