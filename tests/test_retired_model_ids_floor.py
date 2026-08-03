"""
FLOOR TIER — no shipped code DEFAULTS to a retired provider model id.

Runs in the REQUIRED `floor-invariants` context (.github/workflows/floor-invariants.yml,
`pytest tests -o python_files="test_*_floor.py test_floor_*.py"`). Stdlib only — ast, re and
pathlib — so it has zero project dependencies, makes no network calls and carries zero
interpreter variance. It is a deterministic check, not an interpreted one.

WHY IT EXISTS. On 2026-07-26 `run_grok` had been failing with `provider_error: http_400` and
the working diagnosis was that its default id, `grok-4-fast-non-reasoning`, had been retired.
The actual cause turned out to be a rejected API key (see mcp_server/tests/test_provider_defaults.py),
but the investigation surfaced the real structural problem: a model id default is a piece of
operational configuration that silently expires, and NOTHING in the build noticed. The same
week, an ungated-server incident was traced to a stale instruction in an install doc.

A retired id in a default is worse than a retired id in prose: prose misleads a human who can
question it, a default is executed. So this pins the executed ones.

WHAT THIS DOES **NOT** COVER — stated so a pass here is not mistaken for a clean sweep:
  * PROSE. Retired ids in markdown, docstrings and comments are not flagged. Much of that
    prose legitimately DISCUSSES retired ids (this file does), and a regex over prose would
    either false-positive on the discussion or be too weak to catch anything. Docs were swept
    by hand in the same change; that sweep is not automated and will go stale.
  * detection PROFILES. profiles/grok-3-mini-fast.yaml and friends are deliberately retained:
    a profile characterises a model so that traffic claiming that id can still be scored, and
    deleting it would remove the ability to assess archived output. A profile for a retired
    model is an asset, not a defect.
  * TEST FIXTURES that use a retired id as an opaque string (e.g. proxy/tests/test_passthrough.py
    exercising model-id EXTRACTION). Those assert parsing, not reachability.
  * Whether the REPLACEMENT ids exist. That needs a working provider key and cannot be
    asserted offline — this file deliberately claims nothing about it.

MAINTAINING THE LIST: when a provider retires an id, add it to RETIRED_MODEL_IDS. The check
then fails for anything still defaulting to it, naming the file, line and function.
"""

from __future__ import annotations

import ast
import pathlib

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Provider model ids that are retired / no longer served.
#
# xAI retirement batch of 2026-05-15 (grok-3 family and the grok-4-fast pair). NOTE:
# `grok-code-fast-1` is deliberately NOT listed — it still resolves, but as an ALIAS onto a
# different underlying model than it originally named, so code depending on that name means
# something other than it used to. That is a semantic drift, not a retirement, and it is
# recorded in profiles/grok-code-fast-1.yaml rather than enforced here.
RETIRED_MODEL_IDS = frozenset({
    "grok-3",
    "grok-3-mini",
    "grok-3-mini-fast",
    "grok-4-fast-non-reasoning",
    "grok-4-fast-reasoning",
})

# Directories holding shipped code. Tests and profiles are excluded on purpose (see the
# module docstring); tools/ is a developer harness, not shipped behaviour.
SOURCE_DIRS = ("mcp_server", "proxy", "registry_server")

# Parameter names whose default is a model id.
MODEL_PARAM_NAMES = frozenset({"model", "model_id", "default_model"})


def _python_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for directory in SOURCE_DIRS:
        root = REPO_ROOT / directory
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            if "tests" in path.parts or "__pycache__" in path.parts:
                continue
            files.append(path)
    return files


def _defaults_of(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[tuple[str, ast.expr]]:
    """(param_name, default_node) for every parameter that HAS a default."""
    args = func.args
    positional = args.posonlyargs + args.args
    pairs: list[tuple[str, ast.expr]] = []

    # Trailing positional params are the ones carrying defaults.
    for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
        pairs.append((arg.arg, default))
    for arg, default in zip(args.kwonlyargs, args.kw_defaults):
        if default is not None:
            pairs.append((arg.arg, default))
    return pairs


def test_no_shipped_default_uses_a_retired_model_id():
    """
    THE INVARIANT. Every default value of a model-ish parameter, across all shipped source,
    checked against the retired set.
    """
    offenders: list[str] = []
    inspected = 0

    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for param_name, default in _defaults_of(node):
                if param_name not in MODEL_PARAM_NAMES:
                    continue
                if not isinstance(default, ast.Constant) or not isinstance(default.value, str):
                    continue
                inspected += 1
                if default.value in RETIRED_MODEL_IDS:
                    offenders.append(
                        f"{path.relative_to(REPO_ROOT)}:{default.lineno} "
                        f"{node.name}({param_name}={default.value!r})"
                    )

    # POSITIVE CONTROL, in the same test: if the walk inspected nothing, an empty `offenders`
    # would be meaningless. The repo really does define model defaults, so a zero here means
    # the AST scan is broken, not that the code is clean.
    assert inspected >= 4, (
        f"expected to inspect >=4 model-id defaults across {SOURCE_DIRS}, inspected {inspected}"
        " — the scan is not finding what it is supposed to check"
    )

    assert not offenders, "shipped code defaults to retired model id(s):\n  " + "\n  ".join(offenders)


def test_the_retired_id_registry_is_populated():
    """
    Guards the guard. An empty RETIRED_MODEL_IDS would make the check above vacuously pass
    forever, which is the failure mode of every allowlist-shaped test.
    """
    assert len(RETIRED_MODEL_IDS) >= 5
    assert "grok-4-fast-non-reasoning" in RETIRED_MODEL_IDS


def test_grok_code_fast_1_is_not_treated_as_retired():
    """
    Pins the deliberate exclusion so a later tidy-up does not quietly add it. It still
    resolves; what changed is WHAT IT POINTS AT. Listing it here would fail the build for a
    working id and hide the actual concern, which is semantic drift under a stable name.
    """
    assert "grok-code-fast-1" not in RETIRED_MODEL_IDS
