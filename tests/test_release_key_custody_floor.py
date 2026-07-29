from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = ROOT / "scripts"
PROFILE_MASTER_KEY_ENV = "ARKHEIA_PROFILE_MASTER_KEY"

BASE64_LITERAL = re.compile(
    r"^(?=.{16,}$)(?:[A-Za-z0-9+/]{4})+"
    r"(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
RAW_RELEASE_KEY_EXAMPLE = re.compile(
    r"(?:(?:--(?:profile-)?key|--key-b64)(?:=|\s+)(?:<[^>\s]*base64[^>\s]*>|\$[A-Z_]+|[A-Za-z0-9+/]{16,}=*)"
    r"|ARKHEIA_PROFILE_MASTER_KEY=<[^>\s]*base64[^>\s]*>)"
)


def _script_files() -> list[Path]:
    return sorted(SCRIPTS_ROOT.rglob("*.py"))


def _custody_doc_files() -> list[Path]:
    suffixes = {".md", ".py", ".sh", ".yml", ".yaml", ".toml", ".json"}
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.suffix in suffixes
        and path.relative_to(ROOT).parts[0] != "tests"
        and ".git" not in path.parts
        and ".tmp_test_build_pipeline" not in path.parts
        and "__pycache__" not in path.parts
    )


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_argparse_suppress(node: ast.AST | None) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "argparse"
        and node.attr == "SUPPRESS"
    )


def _name_loads(node: ast.AST, names: set[str]) -> bool:
    return any(
        isinstance(child, ast.Name)
        and isinstance(child.ctx, ast.Load)
        and child.id in names
        for child in ast.walk(node)
    )


def _import_aliases(tree: ast.Module) -> tuple[set[str], set[str], set[str], set[str]]:
    base64_modules = {"base64"}
    b64decode_names: set[str] = set()
    os_modules = {"os"}
    getenv_names: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "base64":
                    base64_modules.add(alias.asname or alias.name)
                if alias.name == "os":
                    os_modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if node.module == "base64" and alias.name == "b64decode":
                    b64decode_names.add(alias.asname or alias.name)
                if node.module == "os" and alias.name == "getenv":
                    getenv_names.add(alias.asname or alias.name)

    return base64_modules, b64decode_names, os_modules, getenv_names


def _is_b64decode_call(node: ast.Call, aliases: tuple[set[str], set[str], set[str], set[str]]) -> bool:
    base64_modules, b64decode_names, _, _ = aliases
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Name)
        and func.value.id in base64_modules
        and func.attr == "b64decode"
    ) or (isinstance(func, ast.Name) and func.id in b64decode_names)


def _is_profile_key_env_call(node: ast.Call, aliases: tuple[set[str], set[str], set[str], set[str]]) -> bool:
    _, _, os_modules, getenv_names = aliases
    func = node.func
    first_arg = _literal_string(node.args[0]) if node.args else None

    if first_arg != PROFILE_MASTER_KEY_ENV:
        return False

    if isinstance(func, ast.Attribute) and func.attr == "getenv":
        return isinstance(func.value, ast.Name) and func.value.id in os_modules

    return (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "environ"
        and isinstance(func.value.value, ast.Name)
        and func.value.value.id in os_modules
    ) or (isinstance(func, ast.Name) and func.id in getenv_names)


def _is_profile_key_env_subscript(
    node: ast.Subscript,
    aliases: tuple[set[str], set[str], set[str], set[str]],
) -> bool:
    _, _, os_modules, _ = aliases
    return (
        isinstance(node.value, ast.Attribute)
        and node.value.attr == "environ"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id in os_modules
        and _literal_string(node.slice) == PROFILE_MASTER_KEY_ENV
    )


def _contains_release_key_source(
    node: ast.AST,
    aliases: tuple[set[str], set[str], set[str], set[str]],
) -> bool:
    return any(
        (
            isinstance(child, ast.Call)
            and (_is_b64decode_call(child, aliases) or _is_profile_key_env_call(child, aliases))
        )
        or (isinstance(child, ast.Subscript) and _is_profile_key_env_subscript(child, aliases))
        for child in ast.walk(node)
    )


def _normalise_option(label: str | None) -> str:
    if not label:
        return ""
    return label.lstrip("-").replace("-", "_").lower()


def _is_secret_value_argument(labels: list[str | None]) -> bool:
    for label in labels:
        normalised = _normalise_option(label)
        if not normalised or normalised.endswith(("_file", "_path", "_dir")):
            continue
        if normalised in {"k", "key", "key_b64", "profile_key", "master_key", "profile_master_key"}:
            return True
        if any(word in normalised for word in ("secret", "token", "credential")):
            return True
        if "key" in normalised and ("profile" in normalised or "master" in normalised or "b64" in normalised):
            return True
    return False


def _secret_cli_flag_violations(path: Path, tree: ast.Module) -> list[str]:
    violations: list[str] = []

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_argument":
            continue

        flags = [_literal_string(arg) for arg in call.args]
        keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        dest = _literal_string(keywords.get("dest"))

        if not _is_secret_value_argument([*flags, dest]):
            continue

        display = ", ".join(flag for flag in flags if flag) or dest or "<unknown>"
        if not dest or not dest.endswith("_cli"):
            violations.append(
                f"{path}:{call.lineno} secret-bearing CLI option {display} "
                "is not marked rejection-only with an *_cli dest"
            )
        if not _is_argparse_suppress(keywords.get("help")):
            violations.append(f"{path}:{call.lineno} secret-bearing CLI option {display} is visible in CLI help")
        if "required" in keywords:
            violations.append(f"{path}:{call.lineno} secret-bearing CLI option {display} may still be required")

    return violations


def _guard_for_cli_param(func: ast.FunctionDef, param: str) -> ast.If | None:
    for stmt in func.body:
        if not isinstance(stmt, ast.If):
            continue
        if not _name_loads(stmt.test, {param}):
            continue
        if any(isinstance(child, ast.Raise) for child in ast.walk(stmt)):
            return stmt
    return None


def _loads_outside_guard(func: ast.FunctionDef, param: str, guard: ast.If | None) -> list[int]:
    lines: list[int] = []

    class Visitor(ast.NodeVisitor):
        def visit(self, node: ast.AST) -> None:  # type: ignore[override]
            if guard is not None and node is guard:
                return
            super().visit(node)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Load) and node.id == param:
                lines.append(node.lineno)

    Visitor().visit(func)
    return lines


def _resolver_cli_violations(path: Path, func: ast.FunctionDef) -> list[str]:
    violations: list[str] = []
    cli_params = [arg.arg for arg in func.args.args if arg.arg.endswith("_cli")]
    for param in cli_params:
        guard = _guard_for_cli_param(func, param)
        if guard is None:
            violations.append(f"{path}:{func.lineno} {func.name} does not raise under {param}")
            continue

        leaked_reads = _loads_outside_guard(func, param, guard)
        if leaked_reads:
            violations.append(
                f"{path}:{func.lineno} {func.name} reads {param} outside its rejecting guard "
                f"at lines {leaked_reads}"
            )

    return violations


def _base64_literal_violations(path: Path, func: ast.FunctionDef) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(func):
        value = _literal_string(node)
        if value and BASE64_LITERAL.fullmatch(value.strip()):
            violations.append(
                f"{path}:{getattr(node, 'lineno', func.lineno)} {func.name} contains a "
                "base64-shaped release-key literal"
            )
    return violations


def _script_base64_literal_violations(path: Path, tree: ast.Module) -> list[str]:
    violations: list[str] = []
    for node in ast.walk(tree):
        value = _literal_string(node)
        if value and BASE64_LITERAL.fullmatch(value.strip()):
            violations.append(
                f"{path}:{getattr(node, 'lineno', 1)} contains a base64-shaped release-key literal"
            )
    return violations


def _enclosing_functions(tree: ast.Module) -> dict[ast.AST, ast.FunctionDef]:
    enclosing: dict[ast.AST, ast.FunctionDef] = {}

    def visit(node: ast.AST, current: ast.FunctionDef | None = None) -> None:
        if isinstance(node, ast.FunctionDef):
            current = node
        elif current is not None:
            enclosing[node] = current
        for child in ast.iter_child_nodes(node):
            visit(child, current)

    visit(tree)
    return enclosing


def _release_key_custody_violations(path: Path, tree: ast.Module) -> list[str]:
    aliases = _import_aliases(tree)
    violations = _secret_cli_flag_violations(path, tree)
    violations.extend(_script_base64_literal_violations(path, tree))
    enclosing = _enclosing_functions(tree)
    resolver_functions: set[ast.FunctionDef] = set()
    key_source_functions = 0

    for node in ast.walk(tree):
        is_key_source = (
            isinstance(node, ast.Call)
            and (_is_b64decode_call(node, aliases) or _is_profile_key_env_call(node, aliases))
        ) or (isinstance(node, ast.Subscript) and _is_profile_key_env_subscript(node, aliases))
        if not is_key_source:
            continue

        func = enclosing.get(node)
        if func is None:
            violations.append(f"{path}:{getattr(node, 'lineno', 1)} release-key source at module scope")
            continue
        if not (func.name.startswith("resolve_") and "key" in func.name):
            violations.append(
                f"{path}:{func.lineno} release-key decode/env read occurs outside a resolve_*key chokepoint"
            )
        else:
            resolver_functions.add(func)

    for func in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        if not _contains_release_key_source(func, aliases):
            continue

        key_source_functions += 1
        violations.extend(_resolver_cli_violations(path, func))

    if key_source_functions and not resolver_functions:
        violations.append(f"{path}: release-key source present but no resolve_*key chokepoint")

    return violations


def _violations_for_source(source: str, rel_path: str = "scripts/planted.py") -> list[str]:
    path = ROOT / rel_path
    return _release_key_custody_violations(path, ast.parse(source, filename=str(path)))


def test_profile_master_key_custody_scans_every_script():
    files = _script_files()
    assert ROOT / "scripts" / "build_release.py" in files
    assert ROOT / "scripts" / "encrypt_profiles.py" in files
    assert ROOT / "scripts" / "pilot_validate.py" in files

    violations: list[str] = []
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        violations.extend(_release_key_custody_violations(path, tree))

    assert violations == []


def test_floor_self_test_catches_new_script_accepting_argv_profile_key():
    violations = _violations_for_source(
        """
import argparse
import base64

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile-key")
    args = parser.parse_args(argv)
    return base64.b64decode(args.profile_key)
""",
        "scripts/pilot_validate.py",
    )

    assert any("secret-bearing CLI option --profile-key" in violation for violation in violations)
    assert any("outside a resolve_*key chokepoint" in violation for violation in violations)


def test_floor_self_test_catches_secret_cli_aliases():
    violations = _violations_for_source(
        """
import argparse

def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-b64")
    parser.add_argument("--profile-master-key")
    parser.add_argument("-k")
    return parser.parse_args(argv)
""",
        "scripts/build_release.py",
    )

    assert any("secret-bearing CLI option --key-b64" in violation for violation in violations)
    assert any("secret-bearing CLI option --profile-master-key" in violation for violation in violations)
    assert any("secret-bearing CLI option -k" in violation for violation in violations)


def test_floor_self_test_catches_release_key_literal_fallback():
    violations = _violations_for_source(
        """
import base64
import os

def resolve_profile_key(profile_key_cli=None, profile_key_file=None):
    if profile_key_cli:
        raise ValueError("no argv secrets")
    key_b64 = os.environ.get("ARKHEIA_PROFILE_MASTER_KEY") or "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    return base64.b64decode(key_b64)
""",
        "scripts/build_release.py",
    )

    assert any("base64-shaped release-key literal" in violation for violation in violations)


def test_floor_self_test_catches_module_scope_release_key_sources():
    violations = _violations_for_source(
        """
import base64
import os

DEFAULT_KEY = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
ENV_KEY = os.environ["ARKHEIA_PROFILE_MASTER_KEY"]
""",
        "scripts/build_release.py",
    )

    assert any("release-key source at module scope" in violation for violation in violations)
    assert any("base64-shaped release-key literal" in violation for violation in violations)


def test_floor_self_test_catches_resolver_accepting_hidden_cli_secret():
    violations = _violations_for_source(
        """
import argparse
import base64
import os

def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile-key", dest="profile_key_cli", help=argparse.SUPPRESS)
    return parser.parse_args(argv)

def resolve_profile_key(profile_key_cli=None):
    if profile_key_cli:
        key_b64 = profile_key_cli
    else:
        key_b64 = os.environ.get("ARKHEIA_PROFILE_MASTER_KEY")
    return base64.b64decode(key_b64)
""",
        "scripts/build_release.py",
    )

    assert any("does not raise under profile_key_cli" in violation for violation in violations)


def test_release_key_docs_do_not_recommend_raw_secret_cli_or_inline_env_values():
    violations: list[str] = []
    for path in _custody_doc_files():
        text = path.read_text(encoding="utf-8")
        if RAW_RELEASE_KEY_EXAMPLE.search(text):
            violations.append(str(path.relative_to(ROOT)))

    assert violations == []


def test_doc_floor_self_test_catches_raw_release_key_examples():
    bad = (
        "python scripts/build_release.py --profile-key <base64-master-key>\n"
        "python scripts/encrypt_profiles.py --key=$PROFILE_MASTER_KEY\n"
        "ARKHEIA_PROFILE_MASTER_KEY=<base64-master-key> python scripts/encrypt_profiles.py\n"
    )

    assert RAW_RELEASE_KEY_EXAMPLE.search(bad)
