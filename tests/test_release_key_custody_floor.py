from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECRET_CLI_FLAGS = {
    "scripts/build_release.py": "--profile-key",
    "scripts/encrypt_profiles.py": "--key",
}


def _literal_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _is_argparse_suppress(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "argparse"
        and node.attr == "SUPPRESS"
    )


def _secret_flag_violations(path: Path, flag: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    violations: list[str] = []
    seen = False

    for call in ast.walk(tree):
        if not isinstance(call, ast.Call):
            continue
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "add_argument":
            continue
        flags = {_literal_string(arg) for arg in call.args}
        if flag not in flags:
            continue

        seen = True
        keywords = {kw.arg: kw.value for kw in call.keywords if kw.arg}
        dest = _literal_string(keywords.get("dest", ast.Constant("")))
        if not dest or not dest.endswith("_cli"):
            violations.append(f"{path}:{call.lineno} {flag} is not marked as rejection-only dest")
        if not _is_argparse_suppress(keywords.get("help", ast.Constant(""))):
            violations.append(f"{path}:{call.lineno} {flag} is visible in CLI help")
        if "required" in keywords:
            violations.append(f"{path}:{call.lineno} {flag} may still be required")

    if not seen:
        violations.append(f"{path}: no explicit rejection-only parser entry for {flag}")
    return violations


def test_profile_master_key_cli_flags_are_rejection_only():
    violations: list[str] = []
    for rel, flag in SECRET_CLI_FLAGS.items():
        violations.extend(_secret_flag_violations(ROOT / rel, flag))
    assert violations == []


def test_release_key_docs_do_not_recommend_secret_values_on_argv():
    text = (ROOT / "scripts/encrypt_profiles.py").read_text(encoding="utf-8")
    assert "--key <base64" not in text
    assert "--key-file" in text
