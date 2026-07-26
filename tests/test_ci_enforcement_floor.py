"""
FLOOR INVARIANTS — CI enforcement holes.

Floor tier contract: stdlib-only (``ast`` / ``pathlib`` / ``re`` / ``shlex``).
Imports no third-party package, opens no socket, starts no app. It reasons purely
over source text, so it runs under a bare ``pytest`` with zero project
dependencies and has zero interpreter variance.

------------------------------------------------------------------------------
Why these invariants exist (real defects, arkheia-mcp @ base 3037f0c)
------------------------------------------------------------------------------
Four defects found 2026-07-24/26, all of the same class: **a check that cannot
observe the thing it claims to check.** Each was prose in a report; each is now a
red build.

INV-1  ``security_scan.yml`` and ``smoke-test.yml`` triggered on
       ``push: [main, staging]`` / ``pull_request: [main]`` while this repo's
       default branch is ``master``. Neither branch exists, so those triggers
       could never fire. (They were NOT dead — ``schedule`` runs against the
       default branch and both passed weekly — but they could never GATE A
       COMMIT.) A workflow wired to a non-existent branch is a gate that is
       structurally incapable of gating.

INV-2  ``unit-tests.yml`` pip-installed ``cryptography respx pytest
       pytest-asyncio pytest-timeout`` and ``smoke-test.yml`` pip-installed
       ``pytest pytest-asyncio pytest-timeout`` on top of the declared
       manifests. ``pytest-timeout`` and ``respx`` were declared in NO
       requirements file, so CI green did not mean the DECLARED manifest could
       run the suite: from ``requirements.txt`` alone, the repo's own CI command
       fails with ``unrecognized arguments: --timeout=120``. A workflow that
       installs its way around a manifest gap hides the gap.

INV-3  ``tests/test_smoke_e2e.py`` was doubly orphaned — ``--ignore``d by
       ``unit-tests.yml`` AND owned by a workflow whose triggers could never
       fire (INV-1). No required status context could ever collect it. A test
       nothing can run is not a test; leaving it in the tree overclaims coverage.

INV-4  ``tests/test_smoke_e2e.py::TestHostedFallback`` carried
       ``xfail(strict=True)`` nested under ``skipif(not _api_key)``. A skip
       short-circuits xfail evaluation, so the strict tripwire could never fire
       (confirmed: smoke-test run 29727531417, 2026-07-20, reported SKIPPED).
       Per ~/.claude/DONE.md floor invariant 9(d), an outcome that produced no
       observation must not be counted as a success — and a silent skip inside a
       strict xfail is the most deceptive available combination, because it reads
       as a rigorous test.

------------------------------------------------------------------------------
Each invariant carries a POSITIVE CONTROL
------------------------------------------------------------------------------
Per DONE.md "Prove the check can fail" (v1.22) and "A check that passes by
finding nothing must prove it can find something" (v1.19): every detector below
is also run against a known-bad synthetic input and asserted to flag it. So a
green result means "the detector works AND found nothing", never "the detector
silently matched nothing". Every invariant additionally asserts the quantity of
work it did is non-zero and NAMES THE UNITS behind it (floor 9(a)).
"""
from __future__ import annotations

import ast
import re
import shlex
from pathlib import Path

# Repo root: this file is <root>/tests/test_ci_enforcement_floor.py
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# The default branch of arkheiaai/arkheia-mcp. A workflow whose push /
# pull_request trigger names anything else cannot gate a commit on this repo.
DEFAULT_BRANCH = "master"

# Branches other than the default that a trigger may legitimately name.
# Map: branch -> reason. Deliberately EMPTY: there is no `main`, no `staging` and
# no release branch in this repo. Adding an entry is a deliberate, reviewed act
# and must state why the branch exists.
ALLOWED_NON_DEFAULT_BRANCHES: dict[str, str] = {}

# Packages a workflow may `pip install` ad hoc without declaring them in any
# requirements file. Map: normalised name -> reason. These are CI-only scanners
# that no shipped code imports, so pinning them in a runtime manifest would be
# wrong. Anything a test or production module IMPORTS must be declared instead.
CI_ONLY_TOOLS: dict[str, str] = {
    "pip": "the installer itself (`pip install --upgrade pip`)",
    "bandit": "static analyser, security_scan.yml only; not imported by any module",
    "pip-audit": "CVE scanner, security_scan.yml only; not imported by any module",
}

# Directories whose test files must be collectable by some workflow that can
# trigger on the default branch.
TEST_DIRS = ("tests", "proxy/tests", "mcp_server/tests", "registry_server/tests")


# ---------------------------------------------------------------------------
# Workflow text helpers (stdlib only — no yaml in the floor tier)
# ---------------------------------------------------------------------------

def _workflow_files() -> list[Path]:
    if not WORKFLOW_DIR.is_dir():
        return []
    return sorted(
        p for p in WORKFLOW_DIR.iterdir()
        if p.suffix in (".yml", ".yaml") and p.is_file()
    )


def _join_continuations(text: str) -> str:
    """Collapse shell backslash-continuations so a command is one line."""
    return re.sub(r"\\\n\s*", " ", text)


def trigger_branches(text: str) -> list[str]:
    """
    Every branch named by a `branches:` key in the workflow's trigger block.

    Supports both the inline form (`branches: [master]`) and the block form
    (`branches:` / `  - master`). Only `branches:` under push/pull_request keys
    exists in this repo, and `branches-ignore` is deliberately NOT treated as a
    positive trigger.
    """
    found: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"\s*branches:\s*(.*)$", line)
        if not m:
            continue
        rest = m.group(1).strip()
        if rest.startswith("[") :
            inner = rest.strip("[]")
            found.extend(
                b.strip().strip("'\"") for b in inner.split(",") if b.strip()
            )
        elif not rest:
            # Block form: consume following `- name` items.
            for follow in lines[i + 1:]:
                fm = re.match(r"\s*-\s*(\S+)\s*$", follow)
                if not fm:
                    break
                found.append(fm.group(1).strip("'\""))
    return found


def adhoc_pip_packages(text: str) -> list[str]:
    """
    Package names installed by a `pip install` that is NOT `-r <file>`.

    Returns normalised (lowercase, `_`->`-`, extras/specifiers stripped) names.
    """
    pkgs: list[str] = []
    for line in _join_continuations(text).splitlines():
        stripped = line.strip()
        if "pip install" not in stripped:
            continue
        # Everything after `pip install` on the line, truncated at the first
        # shell control operator or redirection. Without this truncation,
        # `pip install -r requirements.txt --dry-run 2>/dev/null || true` in
        # security_scan.yml yields the "packages" '2', '||' and 'true' — a false
        # positive found while red-testing this very check.
        args = stripped.split("pip install", 1)[1]
        try:
            tokens = shlex.split(args)
        except ValueError:
            tokens = args.split()
        skip_next = False
        for tok in tokens:
            if _is_shell_break(tok):
                break
            if skip_next:
                skip_next = False
                continue
            if tok in ("-r", "--requirement", "-c", "--constraint"):
                skip_next = True
                continue
            if tok.startswith("-"):
                continue
            pkgs.append(_normalise_pkg(tok))
    return pkgs


_SHELL_BREAK = {"||", "&&", ";", "|", "&", ">", ">>", "<"}


def _is_shell_break(tok: str) -> bool:
    """True for a shell control operator or a redirection like `2>/dev/null`."""
    if tok in _SHELL_BREAK:
        return True
    return re.match(r"^\d?>{1,2}", tok) is not None


def _normalise_pkg(raw: str) -> str:
    name = re.split(r"[<>=!~;\[]", raw, maxsplit=1)[0]
    return name.strip().lower().replace("_", "-")


def declared_packages() -> set[str]:
    """Every package name declared in any requirements*.txt in the repo."""
    declared: set[str] = set()
    for rq in sorted(ROOT.rglob("requirements*.txt")):
        if any(part.startswith(".venv") or part == "node_modules" for part in rq.parts):
            continue
        for line in rq.read_text(encoding="utf-8").splitlines():
            line = line.split("#")[0].strip()
            if not line or line.startswith("-"):
                continue
            declared.add(_normalise_pkg(line))
    return declared


class PytestInvocation:
    """A `pytest ...` command extracted from a workflow, with its filters."""

    def __init__(self, tokens: list[str]) -> None:
        self.targets: list[str] = []
        self.ignores: list[str] = []
        self.python_files: list[str] = []
        skip_next = False
        for tok in tokens[1:]:  # tokens[0] == "pytest"
            if skip_next:
                # Value of a separated option, e.g. `-o python_files="..."`.
                if tok.startswith("python_files="):
                    self.python_files = tok.split("=", 1)[1].split()
                skip_next = False
                continue
            if tok in ("-o", "--override-ini", "-p", "-k", "-m"):
                skip_next = True
                continue
            if tok.startswith("--ignore="):
                self.ignores.append(tok.split("=", 1)[1])
                continue
            if tok.startswith("-o"):
                inline = tok[2:]
                if inline.startswith("python_files="):
                    self.python_files = inline.split("=", 1)[1].split()
                continue
            if tok.startswith("-"):
                continue
            self.targets.append(tok)

    def collects(self, rel_path: str) -> bool:
        """True if `rel_path` (repo-relative posix) would be collected."""
        if self.python_files:
            name = rel_path.rsplit("/", 1)[-1]
            if not any(_glob_match(name, pat) for pat in self.python_files):
                return False
        for ign in self.ignores:
            ign = ign.rstrip("/")
            if rel_path == ign or rel_path.startswith(ign + "/"):
                return False
        for tgt in self.targets:
            tgt = tgt.rstrip("/")
            if rel_path == tgt or rel_path.startswith(tgt + "/"):
                return True
        return False


def _glob_match(name: str, pattern: str) -> bool:
    """fnmatch-free glob for the `*`-only patterns pytest's python_files uses."""
    rx = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.match(rx, name) is not None


def pytest_invocations(text: str) -> list[PytestInvocation]:
    out: list[PytestInvocation] = []
    for line in _join_continuations(text).splitlines():
        stripped = line.strip()
        if not re.match(r"^pytest\b", stripped):
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        out.append(PytestInvocation(tokens))
    return out


# ---------------------------------------------------------------------------
# INV-1 — a workflow trigger must name a branch that exists
# ---------------------------------------------------------------------------

def test_workflow_triggers_name_an_existing_branch() -> None:
    workflows = _workflow_files()
    assert workflows, (
        "INV-1 examined ZERO workflow files — the detector found nothing to "
        f"check, which is not a pass. Expected .yml/.yaml under {WORKFLOW_DIR}."
    )

    branches_seen = 0
    failures: list[str] = []
    for wf in workflows:
        for branch in trigger_branches(wf.read_text(encoding="utf-8")):
            branches_seen += 1
            if branch == DEFAULT_BRANCH or branch in ALLOWED_NON_DEFAULT_BRANCHES:
                continue
            failures.append(
                f"{wf.relative_to(ROOT).as_posix()}: trigger names branch "
                f"{branch!r}, which is not the default branch "
                f"({DEFAULT_BRANCH!r}) and is not in "
                f"ALLOWED_NON_DEFAULT_BRANCHES. That trigger can never fire, so "
                f"the workflow can never gate a commit. Fix: use "
                f"[{DEFAULT_BRANCH}], or add {branch!r} to "
                f"ALLOWED_NON_DEFAULT_BRANCHES with a reason."
            )

    # Work-done, with units named (floor 9(a)).
    assert branches_seen, (
        f"INV-1 parsed {len(workflows)} workflow file(s) but extracted ZERO "
        "trigger branches. Either every workflow lost its push/pull_request "
        "branch filter, or trigger_branches() no longer understands the syntax. "
        "Not a pass — the check measured nothing."
    )
    assert not failures, (
        f"workflow trigger(s) naming a non-existent branch "
        f"({branches_seen} branch refs checked across {len(workflows)} "
        f"workflows):\n  - " + "\n  - ".join(failures)
    )


def test_inv1_positive_control() -> None:
    """The INV-1 detector must flag a wrong-branch trigger (proves it can fail)."""
    bad = "on:\n  push:\n    branches: [main, staging]\n  pull_request:\n    branches: [main]\n"
    found = trigger_branches(bad)
    assert found == ["main", "staging", "main"], found
    offenders = [b for b in found if b != DEFAULT_BRANCH and b not in ALLOWED_NON_DEFAULT_BRANCHES]
    assert offenders == ["main", "staging", "main"], (
        "INV-1 positive control FAILED: the detector did not flag the exact "
        "pre-fix trigger block of security_scan.yml / smoke-test.yml. A detector "
        f"that cannot see the original defect proves nothing. Got: {offenders}"
    )
    # And the block form must be understood too.
    assert trigger_branches("    branches:\n      - main\n      - staging\n") == [
        "main", "staging",
    ]


# ---------------------------------------------------------------------------
# INV-2 — a workflow may not install its way around a manifest gap
# ---------------------------------------------------------------------------

def test_workflows_do_not_install_undeclared_packages() -> None:
    workflows = _workflow_files()
    assert workflows, f"INV-2 examined ZERO workflow files under {WORKFLOW_DIR}."

    declared = declared_packages()
    assert declared, (
        "INV-2 found ZERO declared packages across every requirements*.txt in "
        "the repo. The detector measured nothing — not a pass."
    )

    installs_seen = 0
    failures: list[str] = []
    for wf in workflows:
        for pkg in adhoc_pip_packages(wf.read_text(encoding="utf-8")):
            installs_seen += 1
            if pkg in declared or pkg in CI_ONLY_TOOLS:
                continue
            failures.append(
                f"{wf.relative_to(ROOT).as_posix()}: ad-hoc `pip install {pkg}` "
                f"but {pkg!r} is declared in NO requirements*.txt. CI green then "
                f"does not prove the declared manifest can run. Fix: declare it "
                f"in the right requirements file, or add it to CI_ONLY_TOOLS "
                f"with a reason if no module imports it."
            )

    assert installs_seen, (
        f"INV-2 parsed {len(workflows)} workflow file(s) and {len(declared)} "
        "declared package(s) but extracted ZERO ad-hoc pip installs. If the "
        "workflows genuinely install only via `-r`, that is the desired state, "
        "but this assertion exists so the case is reviewed rather than silently "
        "passing: confirm adhoc_pip_packages() still parses `pip install` lines "
        "(its positive control covers this) and relax this assertion "
        "deliberately."
    )
    assert not failures, (
        f"workflow(s) installing undeclared package(s) ({installs_seen} ad-hoc "
        f"install(s) checked against {len(declared)} declared package(s)):\n  - "
        + "\n  - ".join(failures)
    )


def test_inv2_positive_control() -> None:
    """The INV-2 detector must flag the exact pre-fix install line."""
    bad = (
        "      - name: Install dependencies\n"
        "        run: |\n"
        "          pip install -r requirements.txt\n"
        "          pip install cryptography respx pytest pytest-asyncio pytest-timeout\n"
    )
    pkgs = adhoc_pip_packages(bad)
    assert pkgs == [
        "cryptography", "respx", "pytest", "pytest-asyncio", "pytest-timeout",
    ], (
        "INV-2 positive control FAILED: the detector did not extract the exact "
        f"pre-fix ad-hoc install list from unit-tests.yml. Got: {pkgs}"
    )
    # `-r requirements.txt` must NOT be reported as a package.
    assert "requirements.txt" not in pkgs
    # A package declared nowhere must be flagged against the real manifest set.
    assert "definitely-not-a-real-package" not in declared_packages()

    # NEGATIVE control — shell operators and redirections are not packages. This
    # is security_scan.yml's real line, which produced '2', '||' and 'true' on
    # the first red run of this check.
    assert adhoc_pip_packages(
        "          pip install -r requirements.txt --dry-run 2>/dev/null || true\n"
    ) == [], "INV-2 false positive: shell operators parsed as package names."
    assert adhoc_pip_packages("        run: pip install pip-audit\n") == ["pip-audit"]
    assert adhoc_pip_packages("        run: pip install bandit[toml]\n") == ["bandit"], (
        "INV-2 must strip extras so `bandit[toml]` matches the CI_ONLY_TOOLS key."
    )


# ---------------------------------------------------------------------------
# INV-3 — every test file must be collectable by a gating workflow
# ---------------------------------------------------------------------------

def _repo_test_files() -> list[str]:
    files: list[str] = []
    for d in TEST_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("test_*.py")):
            files.append(p.relative_to(ROOT).as_posix())
    return files


def test_every_test_file_is_collectable_by_a_gating_workflow() -> None:
    test_files = _repo_test_files()
    assert test_files, (
        "INV-3 found ZERO test files under "
        f"{TEST_DIRS} — the detector measured nothing, which is not a pass."
    )

    # Only workflows that can actually trigger on the default branch count. A
    # workflow wired to a non-existent branch cannot gate (that is INV-1), so it
    # cannot be what makes a test file 'covered'.
    gating: list[tuple[str, PytestInvocation]] = []
    for wf in _workflow_files():
        text = wf.read_text(encoding="utf-8")
        branches = trigger_branches(text)
        if DEFAULT_BRANCH not in branches:
            continue
        for inv in pytest_invocations(text):
            gating.append((wf.relative_to(ROOT).as_posix(), inv))

    assert gating, (
        "INV-3 found ZERO pytest invocations in any workflow that triggers on "
        f"{DEFAULT_BRANCH!r}. No test file can be gated at all — not a pass."
    )

    failures: list[str] = []
    for rel in test_files:
        if not any(inv.collects(rel) for _, inv in gating):
            failures.append(
                f"{rel} is collected by NO workflow that triggers on "
                f"{DEFAULT_BRANCH!r}. It cannot run in any gating context, so it "
                f"contributes nothing to coverage while making the suite look "
                f"larger. Fix: add it to a gating workflow's pytest targets, "
                f"remove the --ignore that excludes it, or delete the file."
            )

    assert not failures, (
        f"orphaned test file(s) ({len(test_files)} test file(s) checked against "
        f"{len(gating)} gating pytest invocation(s)):\n  - " + "\n  - ".join(failures)
    )


def test_inv3_positive_control() -> None:
    """The INV-3 collection model must flag an --ignore'd file (proves it can fail)."""
    pre_fix = PytestInvocation(shlex.split(
        "pytest proxy/tests mcp_server/tests registry_server/tests tests "
        "--ignore=tests/test_smoke_e2e.py -v --timeout=120"
    ))
    assert pre_fix.collects("tests/test_proxy_client.py") is True
    assert pre_fix.collects("tests/test_smoke_e2e.py") is False, (
        "INV-3 positive control FAILED: the collection model did not see that "
        "the pre-fix unit-tests.yml command excluded tests/test_smoke_e2e.py. A "
        "model blind to the original defect proves nothing."
    )

    # And the floor tier's python_files override must narrow collection, so
    # floor-invariants.yml is not miscredited with collecting every test file.
    floor = PytestInvocation(shlex.split(
        'pytest tests -o python_files="test_*_floor.py test_floor_*.py" '
        "-p no:cacheprovider -v"
    ))
    assert floor.collects("tests/test_audit_floor.py") is True
    assert floor.collects("tests/test_smoke_e2e.py") is False, (
        "INV-3 positive control FAILED: floor-invariants.yml restricts "
        "python_files, so it must NOT count as collecting non-floor test files."
    )


# ---------------------------------------------------------------------------
# INV-4 — a strict xfail must not be nested under a conditional skip
# ---------------------------------------------------------------------------

def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _is_strict_xfail(dec: ast.AST) -> bool:
    if not isinstance(dec, ast.Call):
        return False
    if not _dotted(dec.func).endswith("mark.xfail"):
        return False
    for kw in dec.keywords:
        if kw.arg == "strict":
            return isinstance(kw.value, ast.Constant) and kw.value.value is True
    return False


def _is_conditional_skip(dec: ast.AST) -> bool:
    """`skipif(<runtime condition>, ...)` — a literal True/False is not runtime."""
    if not isinstance(dec, ast.Call):
        return False
    if not _dotted(dec.func).endswith("mark.skipif"):
        return False
    cond = None
    if dec.args:
        cond = dec.args[0]
    else:
        for kw in dec.keywords:
            if kw.arg == "condition":
                cond = kw.value
    if cond is None:
        return False
    return not isinstance(cond, ast.Constant)


def strict_xfail_under_conditional_skip(source: str, label: str) -> tuple[list[str], dict]:
    """
    Find every strict xfail whose evaluation a conditional skip can prevent.

    Returns (findings, stats). Class-level marks are inherited by methods, which
    is exactly how the real defect was shaped: the `skipif` sat on the class and
    the `strict=True` xfail on the method.
    """
    stats = {"strict_xfail": 0, "conditional_skip": 0}
    findings: list[str] = []
    tree = ast.parse(source)

    def scan(node: ast.AST, inherited: list[ast.AST], owner: str) -> None:
        for child in getattr(node, "body", []):
            if isinstance(child, ast.ClassDef):
                marks = list(child.decorator_list)
                stats["conditional_skip"] += sum(
                    1 for d in marks if _is_conditional_skip(d)
                )
                stats["strict_xfail"] += sum(1 for d in marks if _is_strict_xfail(d))
                scan(child, inherited + marks, f"{owner}{child.name}::")
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                own = list(child.decorator_list)
                stats["conditional_skip"] += sum(
                    1 for d in own if _is_conditional_skip(d)
                )
                stats["strict_xfail"] += sum(1 for d in own if _is_strict_xfail(d))
                all_marks = inherited + own
                if any(_is_strict_xfail(d) for d in all_marks) and any(
                    _is_conditional_skip(d) for d in all_marks
                ):
                    findings.append(
                        f"{label}:{child.lineno} {owner}{child.name} carries "
                        f"xfail(strict=True) while a conditional skipif applies "
                        f"to it (on the function or its enclosing class). A skip "
                        f"short-circuits xfail evaluation, so the strict "
                        f"tripwire can NEVER fire: it advertises rigour it "
                        f"cannot deliver, and reads as a passing rigorous test. "
                        f"Fix: drop strict=True and report the not-observed "
                        f"state loudly, or remove the skip so the xfail can "
                        f"actually be evaluated."
                    )

    scan(tree, [], "")
    return findings, stats


def test_no_strict_xfail_under_a_conditional_skip() -> None:
    test_files = _repo_test_files()
    assert test_files, "INV-4 found ZERO test files — the detector measured nothing."

    findings: list[str] = []
    totals = {"strict_xfail": 0, "conditional_skip": 0}
    parsed = 0
    unparsed: list[str] = []
    for rel in test_files:
        path = ROOT / rel
        try:
            src = path.read_text(encoding="utf-8")
            found, stats = strict_xfail_under_conditional_skip(src, rel)
        except (SyntaxError, UnicodeDecodeError) as exc:
            # A file we could not read is NOT-OBSERVED, never a pass (floor 9(d)).
            unparsed.append(f"{rel}: {exc}")
            continue
        parsed += 1
        findings.extend(found)
        for k in totals:
            totals[k] += stats[k]

    assert not unparsed, (
        "INV-4 could not parse the following test file(s), so they were NOT "
        "examined. An unobserved file must not be counted as clean:\n  - "
        + "\n  - ".join(unparsed)
    )
    assert parsed == len(test_files), (
        f"INV-4 examined {parsed} of {len(test_files)} test files — "
        f"{len(test_files) - parsed} went unexamined and must be named, not "
        "summarised (floor 9(a))."
    )
    assert not findings, (
        f"strict xfail(s) that can never be evaluated ({parsed} file(s) parsed; "
        f"{totals['strict_xfail']} strict-xfail mark(s) and "
        f"{totals['conditional_skip']} conditional-skip mark(s) examined):\n  - "
        + "\n  - ".join(findings)
    )


def test_inv4_positive_control() -> None:
    """The INV-4 detector must flag the exact pre-fix shape (proves it can fail)."""
    bad = (
        "import pytest\n"
        "_api_key = None\n"
        "@pytest.mark.skipif(not _api_key, reason='no key')\n"
        "class TestHostedFallback:\n"
        "    @pytest.mark.xfail(reason='BLOCKED: 404', strict=True)\n"
        "    @pytest.mark.asyncio\n"
        "    async def test_verify_returns_real_detection(self):\n"
        "        assert True\n"
    )
    findings, stats = strict_xfail_under_conditional_skip(bad, "<control>")
    assert len(findings) == 1, (
        "INV-4 positive control FAILED: the detector did not flag the exact "
        "pre-fix shape of tests/test_smoke_e2e.py::TestHostedFallback (a "
        "class-level conditional skipif with a method-level strict xfail). A "
        f"detector blind to the original defect proves nothing. Got: {findings}"
    )
    assert stats == {"strict_xfail": 1, "conditional_skip": 1}, stats

    # NEGATIVE controls — the detector must not cry wolf.
    ok_non_strict = bad.replace("strict=True", "strict=False")
    assert strict_xfail_under_conditional_skip(ok_non_strict, "<c>")[0] == [], (
        "INV-4 false positive: a NON-strict xfail under a skip is honest — it "
        "claims nothing — and must not be flagged."
    )
    ok_no_skip = bad.replace(
        "@pytest.mark.skipif(not _api_key, reason='no key')\n", ""
    )
    assert strict_xfail_under_conditional_skip(ok_no_skip, "<c>")[0] == [], (
        "INV-4 false positive: a strict xfail with no skip above it CAN be "
        "evaluated and must not be flagged."
    )
    ok_literal = bad.replace("not _api_key", "False")
    assert strict_xfail_under_conditional_skip(ok_literal, "<c>")[0] == [], (
        "INV-4 false positive: `skipif(False, ...)` never skips, so the strict "
        "xfail is still evaluated."
    )
