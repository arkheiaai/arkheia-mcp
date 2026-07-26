"""
FLOOR INVARIANTS — CI enforcement holes.

Floor tier contract: stdlib-only (``ast`` / ``datetime`` / ``itertools`` / ``json``
/ ``pathlib`` / ``re`` / ``shlex``). Imports no third-party package, opens no
socket, starts no app. It reasons purely over source text, so it runs under a bare
``pytest`` with zero project dependencies and has zero interpreter variance.

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

       CODEX FINDING 1 (2026-07-26), fixed here: INV-3's first implementation
       credited ANY workflow that triggers on the default branch. That conflates
       "a gate that CAN run" with "a gate that IS required" — the exact
       distinction this file argued for in prose and then failed to encode.
       Probe: re-adding ``--ignore=tests/test_smoke_e2e.py`` to the REQUIRED
       ``unit-tests`` job still gave ``8 passed``, because the NON-required
       ``smoke-test.yml`` was miscredited with collecting the file. INV-3 now
       credits only jobs whose check name is a required status context on
       ``master`` per ``.github/required-status-checks.json``, and that fixture
       carries its own expiry (INV-5) so a stale claim reads as NOT-OBSERVED.

INV-5  The required-context fixture is a committed CLAIM about a mutable remote
       setting, so it can rot silently and certify things that are no longer
       true. Two independent staleness detectors: a date-based expiry
       (``observed_at`` + ``max_age_days``), and a tree cross-check that every
       required GitHub-Actions context is actually produced by a job in
       ``.github/workflows`` (a context no job produces is a phantom that blocks
       every PR forever; a job renamed out from under the fixture is a gate the
       fixture still claims).

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
import itertools
import json
import re
import shlex
from datetime import date, timedelta
from pathlib import Path

# Repo root: this file is <root>/tests/test_ci_enforcement_floor.py
ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

# Committed read-back of `gh api repos/<repo>/branches/master/protection`. The
# floor tier is offline and stdlib-only, so the required-context list cannot be
# fetched at test time; it is a fixture with an expiry instead (INV-5).
REQUIRED_CHECKS_FIXTURE = ROOT / ".github" / "required-status-checks.json"

# GitHub Actions' own GitHub App id. A required context with this app_id must be
# produced by a job in this repo's workflow tree; a context belonging to any other
# app (e.g. Aikido, 898896) is posted from outside the tree and cannot be checked
# against the workflow files.
GITHUB_ACTIONS_APP_ID = 15368

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


def workflow_texts() -> dict[str, str]:
    """Map repo-relative workflow path -> file text."""
    return {
        wf.relative_to(ROOT).as_posix(): wf.read_text(encoding="utf-8")
        for wf in _workflow_files()
    }


# ---------------------------------------------------------------------------
# Workflow JOB parsing — needed to tell a REQUIRED job from a job that merely
# runs. GitHub derives a check-run's context from the job's `name:` (falling back
# to the job key), appending `(matrix values)` for a matrix job.
# ---------------------------------------------------------------------------

def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


class WorkflowJob:
    """One entry under a workflow's `jobs:` mapping."""

    def __init__(self, key: str, text: str) -> None:
        self.key = key
        self.text = text
        self.name = self._job_name()
        self.matrix = _matrix_axes(text)

    def _job_name(self) -> str:
        lines = self.text.splitlines()
        body = [ln for ln in lines[1:] if ln.strip() and not ln.lstrip().startswith("#")]
        if not body:
            return self.key
        attr_indent = min(_indent(ln) for ln in body)
        for ln in body:
            if _indent(ln) != attr_indent:
                continue
            m = re.match(r"^\s*name:\s*(.+?)\s*$", ln)
            if m:
                return m.group(1).strip().strip("'\"")
        return self.key

    def check_contexts(self) -> list[str]:
        """
        Every check-run name this job can post.

        A non-matrix job posts exactly `name`. A matrix job posts
        `name (v1, v2, ...)` for each combination, in declaration order — which is
        how `CodeQL Analysis` becomes `CodeQL Analysis (python)`.
        """
        if not self.matrix:
            return [self.name]
        out = []
        for combo in itertools.product(*self.matrix):
            out.append(f"{self.name} ({', '.join(combo)})")
        return out


def _matrix_axes(job_text: str) -> list[list[str]]:
    """
    Values of each `strategy.matrix` axis, in declaration order.

    HANDLED: inline (`language: [python, javascript]`) and block
    (`language:` / `  - python`) list forms.
    NOT HANDLED (named, not silently ignored): `include:` / `exclude:`, matrix
    values produced by an expression (`${{ fromJSON(...) }}`), and mappings as
    axis values. `_matrix_unhandled()` reports those so INV-5 can treat the job
    as NOT-OBSERVED instead of quietly under-generating context names.
    """
    lines = job_text.splitlines()
    axes: list[list[str]] = []
    for i, line in enumerate(lines):
        if not re.match(r"^\s*matrix:\s*$", line):
            continue
        base = _indent(line)
        j = i + 1
        while j < len(lines):
            ln = lines[j]
            if not ln.strip():
                j += 1
                continue
            if _indent(ln) <= base:
                break
            key_indent = _indent(ln)
            inline = re.match(r"^\s*[A-Za-z0-9_.\-]+:\s*\[(.*)\]\s*$", ln)
            if inline:
                axes.append([
                    v.strip().strip("'\"") for v in inline.group(1).split(",") if v.strip()
                ])
                j += 1
                continue
            block = re.match(r"^\s*([A-Za-z0-9_.\-]+):\s*$", ln)
            if block and block.group(1) not in ("include", "exclude"):
                vals: list[str] = []
                k = j + 1
                while k < len(lines):
                    fm = re.match(r"^\s*-\s*(\S.*?)\s*$", lines[k])
                    if not fm or _indent(lines[k]) <= key_indent:
                        break
                    vals.append(fm.group(1).strip("'\""))
                    k += 1
                if vals:
                    axes.append(vals)
                j = k
                continue
            j += 1
        break
    return axes


def _matrix_unhandled(job_text: str) -> list[str]:
    """Matrix constructs this parser deliberately does not model."""
    found = []
    if re.search(r"^\s*(include|exclude):\s*$", job_text, re.M):
        found.append("matrix include:/exclude:")
    if re.search(r"matrix:\s*\$\{\{", job_text) or re.search(
        r"^\s*[A-Za-z0-9_.\-]+:\s*\$\{\{.*fromJSON", job_text, re.M
    ):
        found.append("matrix built from an expression (${{ ... }})")
    return found


def workflow_jobs(text: str) -> list[WorkflowJob]:
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^jobs:\s*(#.*)?$", line):
            start = i + 1
            break
    if start is None:
        return []
    body = lines[start:]
    for j, line in enumerate(body):
        if line.strip() and _indent(line) == 0:
            body = body[:j]
            break
    live = [ln for ln in body if ln.strip() and not ln.lstrip().startswith("#")]
    if not live:
        return []
    job_indent = min(_indent(ln) for ln in live)
    starts: list[tuple[int, str]] = []
    for j, line in enumerate(body):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if _indent(line) != job_indent:
            continue
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+):\s*(#.*)?$", line)
        if m:
            starts.append((j, m.group(1)))
    jobs: list[WorkflowJob] = []
    for idx, (j, key) in enumerate(starts):
        stop = starts[idx + 1][0] if idx + 1 < len(starts) else len(body)
        jobs.append(WorkflowJob(key, "\n".join(body[j:stop])))
    return jobs


# ---------------------------------------------------------------------------
# The REQUIRED-context fixture, and its expiry (INV-5)
# ---------------------------------------------------------------------------

_FIXTURE_KEYS = (
    "repo", "branch", "observed_at", "max_age_days", "refresh_command",
    "github_actions_app_id", "required_checks",
)


def validate_required_checks(data: object, today: date) -> list[str]:
    """
    Problems with the committed branch-protection fixture. Empty list == usable.

    Any non-empty result means the required-context list is NOT OBSERVED, and
    every invariant that depends on it must fail rather than pass.
    """
    problems: list[str] = []
    if not isinstance(data, dict):
        return [f"fixture is {type(data).__name__}, expected a JSON object"]
    for key in _FIXTURE_KEYS:
        if key not in data:
            problems.append(f"missing required key {key!r}")
    if problems:
        return problems

    if data["branch"] != DEFAULT_BRANCH:
        problems.append(
            f"fixture describes branch {data['branch']!r} but this repo's default "
            f"branch is {DEFAULT_BRANCH!r} — protection on another branch gates "
            f"nothing here"
        )
    try:
        observed = date.fromisoformat(str(data["observed_at"]))
    except ValueError as exc:
        problems.append(f"observed_at is not an ISO date: {exc}")
        return problems
    try:
        max_age = int(data["max_age_days"])
    except (TypeError, ValueError):
        problems.append(f"max_age_days is not an integer: {data['max_age_days']!r}")
        return problems
    if max_age <= 0:
        problems.append(f"max_age_days must be positive, got {max_age}")
    age = (today - observed).days
    if age < 0:
        problems.append(
            f"observed_at {observed.isoformat()} is in the FUTURE (today "
            f"{today.isoformat()}) — a fixture cannot record an observation that "
            f"has not happened"
        )
    elif age > max_age:
        problems.append(
            f"STALE: observed_at {observed.isoformat()} is {age} day(s) old, past "
            f"max_age_days={max_age}. Branch protection is a mutable remote "
            f"setting and this fixture is only a claim about it, so past its "
            f"expiry the required-context list is NOT OBSERVED and must not "
            f"certify anything. Fix: re-run `{data['refresh_command']}`, update "
            f"required_checks + observed_at, and say in the commit whether the "
            f"remote actually changed."
        )

    checks = data["required_checks"]
    if not isinstance(checks, list) or not checks:
        problems.append("required_checks must be a non-empty list")
        return problems
    for i, entry in enumerate(checks):
        if not isinstance(entry, dict) or "context" not in entry or "app_id" not in entry:
            problems.append(
                f"required_checks[{i}] must be an object with 'context' and "
                f"'app_id' keys, got {entry!r}"
            )
        elif not str(entry["context"]).strip():
            problems.append(f"required_checks[{i}] has an empty context")
    return problems


def load_required_checks() -> tuple[list[dict], list[str]]:
    """(required_checks entries, problems). Problems => NOT OBSERVED."""
    rel = REQUIRED_CHECKS_FIXTURE.relative_to(ROOT).as_posix()
    if not REQUIRED_CHECKS_FIXTURE.is_file():
        return [], [
            f"{rel} is MISSING. Without a read-back of branch protection there is "
            f"no way to tell a required context from a workflow that merely runs, "
            f"so no coverage claim can be made. Fix: create it from `gh api "
            f"repos/arkheiaai/arkheia-mcp/branches/{DEFAULT_BRANCH}/protection`."
        ]
    try:
        data = json.loads(REQUIRED_CHECKS_FIXTURE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return [], [f"{rel} could not be parsed: {exc}"]
    problems = [f"{rel}: {p}" for p in validate_required_checks(data, date.today())]
    if problems:
        return [], problems
    return list(data["required_checks"]), []


def required_contexts() -> tuple[set[str], list[str]]:
    checks, problems = load_required_checks()
    return {str(c["context"]) for c in checks}, problems


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
# INV-3 — every test file must be collectable by a REQUIRED status context
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


def credited_invocations(
    texts: dict[str, str], required: set[str]
) -> tuple[list[tuple[str, str, PytestInvocation]], list[str]]:
    """
    Every pytest invocation that a REQUIRED status context actually runs.

    Returns ``(credited, rejected)`` where credited entries are
    ``(workflow, required_context, invocation)`` and ``rejected`` explains, by
    name, each pytest-running job that was NOT credited and why. Two conditions
    must both hold for credit:

      1. the workflow has a push/pull_request trigger naming the default branch
         (a workflow wired to a branch that does not exist can never fire — INV-1);
      2. the job's check-run name is a REQUIRED status context on that branch.

    (2) is the Codex-finding-1 fix. A job that runs on master but is not a
    required context can go red without blocking anything, so it is not a gate
    and must not make a test file "covered".
    """
    credited: list[tuple[str, str, PytestInvocation]] = []
    rejected: list[str] = []
    for wf, text in sorted(texts.items()):
        on_default = DEFAULT_BRANCH in trigger_branches(text)
        for job in workflow_jobs(text):
            invs = pytest_invocations(job.text)
            if not invs:
                continue
            names = job.check_contexts()
            if not on_default:
                rejected.append(
                    f"{wf}:{job.key} (check name {names}) runs pytest but no "
                    f"push/pull_request trigger names {DEFAULT_BRANCH!r} — it can "
                    f"never fire on a commit, so it gates nothing (INV-1)."
                )
                continue
            matched = sorted(n for n in names if n in required)
            if not matched:
                rejected.append(
                    f"{wf}:{job.key} (check name {names}) runs pytest and DOES "
                    f"trigger on {DEFAULT_BRANCH!r}, but none of its check names "
                    f"is a REQUIRED status context. A gate that CAN run is not a "
                    f"gate that IS required: it may go red without blocking the "
                    f"merge, so it credits no coverage."
                )
                continue
            for inv in invs:
                credited.append((wf, matched[0], inv))
    return credited, rejected


def orphaned_test_files(
    test_files: list[str], credited: list[tuple[str, str, PytestInvocation]]
) -> list[str]:
    """Test files no credited (required-context) invocation would collect."""
    return [
        rel for rel in test_files
        if not any(inv.collects(rel) for _, _, inv in credited)
    ]


def test_every_test_file_is_collectable_by_a_required_context() -> None:
    test_files = _repo_test_files()
    assert test_files, (
        "INV-3 found ZERO test files under "
        f"{TEST_DIRS} — the detector measured nothing, which is not a pass."
    )

    required, problems = required_contexts()
    assert not problems, (
        "INV-3 NOT OBSERVED — the required-status-context fixture is unusable, so "
        "no statement about what gates this repo can be made. This is a FAILURE, "
        "not a pass:\n  - " + "\n  - ".join(problems)
    )

    credited, rejected = credited_invocations(workflow_texts(), required)
    assert credited, (
        "INV-3 found ZERO pytest invocations in any job whose check name is a "
        f"REQUIRED status context on {DEFAULT_BRANCH!r} (required: "
        f"{sorted(required)}). No test file is gated at all — not a pass. "
        f"Jobs that run pytest but were rejected:\n  - "
        + ("\n  - ".join(rejected) if rejected else "(none found)")
    )

    orphans = orphaned_test_files(test_files, credited)
    detail = [
        f"{rel} is collected by NO REQUIRED status context. It cannot block a "
        f"merge, so it contributes nothing to enforcement while making the suite "
        f"look larger. Fix: add it to a REQUIRED job's pytest targets, remove the "
        f"--ignore that excludes it, make its workflow a required context, or "
        f"delete the file."
        for rel in orphans
    ]
    assert not orphans, (
        f"test file(s) not collected by any REQUIRED context "
        f"({len(test_files)} test file(s) checked against {len(credited)} credited "
        f"invocation(s) from contexts "
        f"{sorted({ctx for _, ctx, _ in credited})}):\n  - "
        + "\n  - ".join(detail)
        + "\n\nNOT credited (ran pytest but is not a required gate):\n  - "
        + ("\n  - ".join(rejected) if rejected else "(none)")
    )


def test_inv3_credits_only_required_contexts_codex_probe() -> None:
    """
    Codex finding 1, frozen as a test.

    Probe: re-add ``--ignore=tests/test_smoke_e2e.py`` to the REQUIRED
    ``unit-tests`` job. The old INV-3 still passed (``8 passed``) because the
    NON-required ``smoke-test.yml`` was credited with collecting the file. Driven
    here on synthetic workflow text so the probe is permanent and needs no
    mutation of the real tree.
    """
    required = {"unit-tests", "floor-invariants"}
    unit_tpl = (
        "on:\n"
        "  push:\n"
        "    branches: [master]\n"
        "  pull_request:\n"
        "    branches: [master]\n"
        "jobs:\n"
        "  unit:\n"
        "    name: unit-tests\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Run suites\n"
        "        run: |\n"
        "          pytest proxy/tests tests {ignore}-v\n"
    )
    # Not a required context, but it DOES trigger on master and DOES collect the
    # file — this is the entry that made the probe pass.
    smoke = (
        "on:\n"
        "  push:\n"
        "    branches: [master]\n"
        "jobs:\n"
        "  smoke:\n"
        "    name: MCP server end-to-end smoke test\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Run smoke tests\n"
        "        run: |\n"
        "          pytest tests/test_smoke_e2e.py -v --timeout=60\n"
    )
    test_files = ["tests/test_proxy_client.py", "tests/test_smoke_e2e.py"]

    # --- PROBE (the defect): required job ignores the file; non-required job runs it.
    texts = {
        ".github/workflows/unit-tests.yml":
            unit_tpl.format(ignore="--ignore=tests/test_smoke_e2e.py "),
        ".github/workflows/smoke-test.yml": smoke,
    }
    credited, rejected = credited_invocations(texts, required)
    assert [(wf, ctx) for wf, ctx, _ in credited] == [
        (".github/workflows/unit-tests.yml", "unit-tests"),
    ], (
        "INV-3 must credit EXACTLY the required unit-tests job and nothing else; "
        f"got {[(wf, ctx) for wf, ctx, _ in credited]}"
    )
    assert len(rejected) == 1, rejected
    assert "smoke-test.yml:smoke" in rejected[0], rejected
    assert "none of its check names is a REQUIRED status context" in rejected[0], (
        rejected
    )
    assert orphaned_test_files(test_files, credited) == ["tests/test_smoke_e2e.py"], (
        "INV-3 FAILED Codex's probe: with --ignore restored to the REQUIRED "
        "unit-tests job, tests/test_smoke_e2e.py must be reported orphaned. "
        "Crediting the non-required smoke-test.yml is the exact conflation of "
        "'can run' with 'is required' that this invariant exists to reject."
    )

    # --- NEGATIVE CONTROL: drop the --ignore and the orphan must disappear, so the
    # assertion above is pinned to the defect and not to a permanently-red check.
    fixed = dict(texts)
    fixed[".github/workflows/unit-tests.yml"] = unit_tpl.format(ignore="")
    fixed_credited, _ = credited_invocations(fixed, required)
    assert orphaned_test_files(test_files, fixed_credited) == [], (
        "INV-3 false positive: with the file collected by the REQUIRED job it "
        "must not be reported orphaned."
    )

    # --- NEGATIVE CONTROL: a required job whose workflow cannot trigger on the
    # default branch is still not a gate (INV-1 interaction).
    wrong_branch = unit_tpl.format(ignore="").replace("[master]", "[main]")
    wb_credited, wb_rejected = credited_invocations(
        {".github/workflows/unit-tests.yml": wrong_branch}, required
    )
    assert wb_credited == [] and len(wb_rejected) == 1, (wb_credited, wb_rejected)
    assert "can never fire" in wb_rejected[0], wb_rejected


def test_workflow_job_parsing_matches_the_real_tree() -> None:
    """
    The job/context parser must reproduce the check names GitHub actually posts.

    Pinned to observed reality: PR #13 head 6fcd599 posted check-runs named
    exactly `floor-invariants`, `unit-tests`, `CodeQL Analysis (python)` and
    `CodeQL Analysis (javascript)`. If this parser cannot derive those names from
    the workflow files, INV-3's required/not-required distinction is worthless.
    """
    texts = workflow_texts()
    got: dict[str, list[str]] = {}
    for wf, text in sorted(texts.items()):
        for job in workflow_jobs(text):
            got[f"{wf}:{job.key}"] = job.check_contexts()

    assert got.get(".github/workflows/unit-tests.yml:unit") == ["unit-tests"], got
    assert got.get(".github/workflows/floor-invariants.yml:floor") == [
        "floor-invariants"
    ], got
    assert got.get(".github/workflows/codeql.yml:analyze") == [
        "CodeQL Analysis (python)", "CodeQL Analysis (javascript)",
    ], (
        "matrix expansion is how `CodeQL Analysis` becomes the two required "
        f"contexts; got {got.get('.github/workflows/codeql.yml:analyze')}"
    )
    assert got.get(".github/workflows/smoke-test.yml:smoke") == [
        "MCP server end-to-end smoke test"
    ], got
    assert got.get(".github/workflows/security_scan.yml:bandit") == [
        "Bandit static analysis"
    ], got
    # A job with no `name:` falls back to its key, as GitHub does.
    assert workflow_jobs("jobs:\n  build:\n    runs-on: x\n")[0].check_contexts() == [
        "build"
    ]
    # A step-level `- name:` must NOT be mistaken for the job name.
    assert workflow_jobs(
        "jobs:\n  j:\n    runs-on: x\n    steps:\n      - name: Checkout\n"
    )[0].name == "j"
    # Block-form matrix lists expand too.
    assert workflow_jobs(
        "jobs:\n  j:\n    name: N\n    strategy:\n      matrix:\n"
        "        v:\n          - a\n          - b\n"
    )[0].check_contexts() == ["N (a)", "N (b)"]


# ---------------------------------------------------------------------------
# INV-5 — the required-context fixture must not be able to rot silently
# ---------------------------------------------------------------------------

def test_required_context_fixture_is_fresh_and_wellformed() -> None:
    checks, problems = load_required_checks()
    assert not problems, (
        "the committed branch-protection read-back is unusable or expired, so "
        "INV-3 cannot certify anything (NOT OBSERVED, not a pass):\n  - "
        + "\n  - ".join(problems)
    )
    assert checks, "required_checks parsed empty — the detector measured nothing."
    # Work-done with units named: these are the contexts INV-3 will credit.
    assert len(checks) >= 2, (
        f"only {len(checks)} required context(s) recorded; the read-back of "
        f"2026-07-26 had 5. A shrunken list means protection was relaxed or the "
        f"fixture was truncated — review it deliberately."
    )


def test_inv5_freshness_positive_control() -> None:
    """The expiry detector must flag a stale / malformed / future fixture."""
    today = date(2026, 7, 26)
    good = {
        "repo": "arkheiaai/arkheia-mcp",
        "branch": DEFAULT_BRANCH,
        "observed_at": "2026-07-26",
        "max_age_days": 45,
        "refresh_command": "gh api ...",
        "github_actions_app_id": GITHUB_ACTIONS_APP_ID,
        "required_checks": [{"context": "unit-tests", "app_id": GITHUB_ACTIONS_APP_ID}],
    }
    assert validate_required_checks(good, today) == [], validate_required_checks(good, today)

    stale = {**good, "observed_at": (today - timedelta(days=46)).isoformat()}
    probs = validate_required_checks(stale, today)
    assert len(probs) == 1 and probs[0].startswith("STALE:"), probs
    assert "46 day(s) old" in probs[0] and "NOT OBSERVED" in probs[0], probs

    # Exactly at the boundary is still fresh — pins the comparison, not just "flags".
    assert validate_required_checks(
        {**good, "observed_at": (today - timedelta(days=45)).isoformat()}, today
    ) == []

    future = {**good, "observed_at": (today + timedelta(days=1)).isoformat()}
    fprobs = validate_required_checks(future, today)
    assert len(fprobs) == 1 and "in the FUTURE" in fprobs[0], fprobs

    wrong_branch = {**good, "branch": "main"}
    bprobs = validate_required_checks(wrong_branch, today)
    assert len(bprobs) == 1, bprobs
    assert "gates nothing here" in bprobs[0] and "'main'" in bprobs[0], bprobs

    for key in _FIXTURE_KEYS:
        missing = {k: v for k, v in good.items() if k != key}
        mprobs = validate_required_checks(missing, today)
        assert mprobs == [f"missing required key {key!r}"], (key, mprobs)

    empty = {**good, "required_checks": []}
    assert validate_required_checks(empty, today) == [
        "required_checks must be a non-empty list"
    ]
    shapeless = {**good, "required_checks": ["unit-tests"]}
    sprobs = validate_required_checks(shapeless, today)
    assert len(sprobs) == 1 and "must be an object" in sprobs[0], sprobs
    assert validate_required_checks("not a dict", today) == [
        "fixture is str, expected a JSON object"
    ]
    assert validate_required_checks({**good, "max_age_days": 0}, today) == [
        "max_age_days must be positive, got 0"
    ]
    dprobs = validate_required_checks({**good, "observed_at": "not-a-date"}, today)
    assert len(dprobs) == 1 and dprobs[0].startswith(
        "observed_at is not an ISO date:"
    ), dprobs


def test_every_required_actions_context_is_produced_by_a_job() -> None:
    """
    Tree cross-check on the fixture: a required GitHub-Actions context with no
    job to produce it is a PHANTOM (it can never go green, so it blocks every PR
    forever); a job renamed out from under the fixture leaves the fixture
    asserting a gate that no longer posts. Either way the fixture is stale in a
    way the date cannot detect.
    """
    checks, problems = load_required_checks()
    assert not problems, "INV-5 NOT OBSERVED:\n  - " + "\n  - ".join(problems)

    produced: dict[str, str] = {}
    unhandled: list[str] = []
    for wf, text in sorted(workflow_texts().items()):
        for job in workflow_jobs(text):
            for name in job.check_contexts():
                produced.setdefault(name, f"{wf}:{job.key}")
            for reason in _matrix_unhandled(job.text):
                unhandled.append(f"{wf}:{job.key} uses {reason}")

    assert not unhandled, (
        "INV-5 NOT OBSERVED — a job uses a matrix construct this stdlib parser "
        "does not model, so its posted check names cannot be derived and the "
        "fixture cannot be cross-checked against it. Extend _matrix_axes() or "
        "record the job's contexts explicitly:\n  - " + "\n  - ".join(unhandled)
    )
    assert produced, "no workflow jobs discovered — the cross-check measured nothing."

    actions_checks = [
        c for c in checks if int(c["app_id"]) == GITHUB_ACTIONS_APP_ID
    ]
    assert actions_checks, (
        f"no required context has app_id {GITHUB_ACTIONS_APP_ID} (GitHub Actions) "
        f"— nothing to cross-check, which is not a pass."
    )
    missing = [c["context"] for c in actions_checks if c["context"] not in produced]
    assert not missing, (
        f"required GitHub-Actions context(s) that NO workflow job produces "
        f"({len(actions_checks)} Actions context(s) checked against "
        f"{len(produced)} job check-name(s)): {missing}. Such a context can never "
        f"report, so every PR is blocked forever. Fix: restore the job (or its "
        f"`name:`), or remove the context from branch protection and refresh "
        f"{REQUIRED_CHECKS_FIXTURE.relative_to(ROOT).as_posix()}. "
        f"Job check names present: {sorted(produced)}"
    )
    # Positive control: a context no job produces MUST be reported missing.
    assert "no-such-context-xyz" not in produced


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
