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

       CODEX FINDING (2026-07-26): those two detectors prove the fixture is
       FRESH and COHERENT. They do NOT prove branch protection actually requires
       those contexts — that is fixture-trust, not proof. Offline the trust root
       is IRREDUCIBLE: the floor contract forbids network access, and reading
       protection needs an authenticated admin-scope API call.

       The decision taken was to declare the boundary rather than dress it up.
       In one sentence: **PROVEN — the fixture is fresh, well-formed and
       coherent with the workflow tree; ASSUMED — that it matches live branch
       protection on master.** ``TRUST_STATEMENT`` carries that wording into
       every message these invariants emit (floor entry 9(d): a property that
       was not observed must not be rendered as a success), the fixture must
       carry its own ``_trust_root`` declaration or it is NOT OBSERVED, and
       ``test_fixture_manipulation_is_undetectable_offline`` executes the gap so
       a green floor tier can never be read as proof of the remote setting.

       To make it LIVE (proposed, not implemented here): a scheduled privileged
       job holding a PAT with ``administration: read`` that re-runs
       ``refresh_command`` and fails on drift. The default ``GITHUB_TOKEN``
       cannot read branch protection, so it needs a secret this PR does not
       create. Cross-checking the check-runs POSTED on a PR is NOT a substitute:
       posted and required are different properties — a job can post while being
       non-required, which is the very confusion INV-3 was written to end.

INV-4  ``tests/test_smoke_e2e.py::TestHostedFallback`` carried
       ``xfail(strict=True)`` nested under ``skipif(not _api_key)``. A skip
       short-circuits xfail evaluation, so the strict tripwire could never fire
       (confirmed: smoke-test run 29727531417, 2026-07-20, reported SKIPPED).
       Per ~/.claude/DONE.md floor invariant 9(d), an outcome that produced no
       observation must not be counted as a success — and a silent skip inside a
       strict xfail is the most deceptive available combination, because it reads
       as a rigorous test.

INV-6  ``security_scan.yml`` is the repo's security gate candidate, but its
       dependency and secret scanners used ``continue-on-error: true``. If those
       contexts are made required, a high-CVSS ``pip-audit`` finding or verified
       TruffleHog secret can still post green. PR #61 fixed one dependency-audit
       step, but the CLASS was still open: a new gate-like security job could
       continue on error and remain unclassified; Bandit could discard scanner
       failure with ``|| true`` and pass via a grep-only summary; and none of the
       standalone security_scan.yml jobs was actually a required branch-protection
       context. Required security jobs must fail closed, and the floor must
       discover the workflow tree rather than trusting a literal list.

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
    "bandit": "static analyser for CI security gates; not imported by any module",
    "pip-audit": "CVE scanner for CI security gates; not imported by any module",
}

# Security scan jobs that queue policy treats as gates. They may be branch
# protection requirements today, candidates to become directly required, or an
# aggregate folded into an existing required context. Either way, their job
# definitions must be fail-closed before they can safely gate merges.
SECURITY_SCAN_GATE_JOBS: dict[str, tuple[str, ...]] = {
    ".github/workflows/codeql.yml:analyze": (
        "CodeQL Analysis (python)",
        "CodeQL Analysis (javascript)",
    ),
    ".github/workflows/security_scan.yml:bandit": ("Bandit static analysis",),
    ".github/workflows/security_scan.yml:dependency-audit": (
        "Dependency vulnerability audit",
    ),
    ".github/workflows/security_scan.yml:secrets-check": (
        "Check for committed secrets",
    ),
    ".github/workflows/unit-tests.yml:unit": ("unit-tests",),
}

# Jobs in SECURITY_SCAN_GATE_JOBS that are deliberately advisory-only. The key is
# "<workflow path>:<job key>"; the value must explain why a scanner failure should
# not block. Empty by design: all current security_scan.yml jobs are gates.
ADVISORY_ONLY_SECURITY_JOBS: dict[str, str] = {}

# Blocking scanner classes that must be represented by at least one existing
# required context. The direct security_scan.yml jobs are not required per
# .github/required-status-checks.json; unit-tests therefore aggregates Bandit,
# pip-audit, and TruffleHog under an existing required context.
REQUIRED_SECURITY_SCANNERS: dict[str, str] = {
    "bandit": "Bandit static analysis",
    "pip-audit": "dependency vulnerability audit",
    "trufflehog": "verified secret scan",
    "codeql": "CodeQL analysis",
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
        # -k / -m / --deselect DESELECT tests rather than skip them. This parser
        # does not model their effect on collection; it records them verbatim so
        # INV-4's unmodelled-path surface can report them by name instead of the
        # invariant silently over-claiming coverage.
        self.raw_filters: list[str] = []
        skip_next = False
        pending = ""
        for tok in tokens[1:]:  # tokens[0] == "pytest"
            if skip_next:
                # Value of a separated option, e.g. `-o python_files="..."`.
                if tok.startswith("python_files="):
                    self.python_files = tok.split("=", 1)[1].split()
                if pending in ("-k", "-m"):
                    self.raw_filters.extend([pending, tok])
                skip_next = False
                pending = ""
                continue
            if tok in ("-o", "--override-ini", "-p", "-k", "-m"):
                skip_next = True
                pending = tok
                continue
            if tok.startswith("--ignore="):
                self.ignores.append(tok.split("=", 1)[1])
                continue
            if tok.startswith("--deselect"):
                self.raw_filters.append(tok)
                continue
            if re.match(r"^-[km]=?.+", tok):
                self.raw_filters.append(tok)
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


def _workflow_job_map(texts: dict[str, str]) -> dict[str, WorkflowJob]:
    """Map '<workflow path>:<job key>' to parsed jobs."""
    out: dict[str, WorkflowJob] = {}
    for wf, text in sorted(texts.items()):
        for job in workflow_jobs(text):
            out[f"{wf}:{job.key}"] = job
    return out


def _active_continue_on_error_lines(job_text: str) -> list[tuple[int, str]]:
    """
    Truthy or opaque `continue-on-error` controls in a job body.

    `continue-on-error: false` is not fail-open. Expressions and unknown literals
    are treated as active for required security jobs because the floor tier cannot
    prove they are false under every runtime condition.
    """
    active: list[tuple[int, str]] = []
    for line_no, line in enumerate(job_text.splitlines(), 1):
        m = re.match(r"^\s*continue-on-error:\s*(.+?)\s*(?:#.*)?$", line)
        if not m:
            continue
        value = m.group(1).strip().strip("'\"")
        if value.lower() in {"false", "0", "no"}:
            continue
        active.append((line_no, value))
    return active


_SECURITY_JOB_NAME_RE = re.compile(
    r"(security|secret|vulnerabil|scan|audit|sast|bandit|codeql|trufflehog|gitleaks|semgrep|snyk)",
    re.I,
)

_SCANNER_COMMAND_PATTERNS: dict[str, re.Pattern[str]] = {
    "bandit": re.compile(r"(?:^|[;&|]\s*)(?:python\s+-m\s+)?bandit(?:\s|$)", re.I),
    "pip-audit": re.compile(
        r"(?:^|[;&|]\s*)(?:python\s+-m\s+pip_audit|pip-audit)(?:\s|$)",
        re.I,
    ),
    "trufflehog": re.compile(r"(?:^|[;&|]\s*)trufflehog(?:\s|$)", re.I),
    "gitleaks": re.compile(r"(?:^|[;&|]\s*)gitleaks(?:\s|$)", re.I),
    "semgrep": re.compile(r"(?:^|[;&|]\s*)semgrep(?:\s|$)", re.I),
    "snyk": re.compile(r"(?:^|[;&|]\s*)snyk(?:\s|$)", re.I),
    "safety": re.compile(r"(?:^|[;&|]\s*)safety(?:\s|$)", re.I),
}

_SCANNER_ACTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "codeql": re.compile(r"^-?\s*uses:\s*github/codeql-action/(?:init|analyze)@", re.I),
    "trufflehog": re.compile(r"^-?\s*uses:\s*trufflesecurity/trufflehog@", re.I),
    "gitleaks": re.compile(r"^-?\s*uses:\s*gitleaks/gitleaks-action@", re.I),
    "semgrep": re.compile(r"^-?\s*uses:\s*(?:returntocorp/semgrep-action|semgrep/semgrep-action)@", re.I),
    "snyk": re.compile(r"^-?\s*uses:\s*snyk/actions/", re.I),
}


def _workflow_name(text: str) -> str:
    """Top-level workflow `name:`, or an empty string when absent."""
    for line in text.splitlines():
        if line.strip() and _indent(line) != 0:
            continue
        m = re.match(r"^name:\s*(.+?)\s*$", line)
        if m:
            return m.group(1).strip().strip("'\"")
    return ""


def _logical_shell_lines(text: str) -> list[tuple[int, str]]:
    """
    Non-comment logical lines, with shell backslash continuations collapsed.

    The fail-open bugs this invariant guards are often split across YAML block
    scalars: the scanner command appears on one line and `|| true` on a later
    continuation. Line-based grep misses that class.
    """
    out: list[tuple[int, str]] = []
    parts: list[str] = []
    start = 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if not parts and stripped.startswith("#"):
            continue
        if not parts:
            start = line_no
        if stripped.endswith("\\"):
            parts.append(stripped[:-1].rstrip())
            continue
        parts.append(stripped)
        out.append((start, " ".join(parts)))
        parts = []
        start = 0
    if parts:
        out.append((start, " ".join(parts)))
    return out


def _scanner_kinds_in_line(line: str) -> set[str]:
    stripped = line.strip()
    if stripped.startswith("#"):
        return set()
    found = {
        kind for kind, pattern in _SCANNER_COMMAND_PATTERNS.items()
        if pattern.search(stripped)
    }
    found.update(
        kind for kind, pattern in _SCANNER_ACTION_PATTERNS.items()
        if pattern.search(stripped)
    )
    return found


def _scanner_kinds_in_job(job_text: str) -> set[str]:
    found: set[str] = set()
    for _, line in _logical_shell_lines(job_text):
        found.update(_scanner_kinds_in_line(line))
    return found


def discover_security_scan_jobs(texts: dict[str, str]) -> dict[str, set[str]]:
    """
    Gate-like security jobs derived from actual workflow text.

    A job is discovered if it invokes a known security scanner/action, or if its
    workflow/job naming says it is a security scan. The second rule is what makes
    an unrecognised new security-scan job fail as UNCLASSIFIED instead of being
    silently absent from SECURITY_SCAN_GATE_JOBS.
    """
    discovered: dict[str, set[str]] = {}
    for wf, text in sorted(texts.items()):
        wf_name = _workflow_name(text)
        for job in workflow_jobs(text):
            job_id = f"{wf}:{job.key}"
            kinds = _scanner_kinds_in_job(job.text)
            label = f"{wf} {wf_name} {job.key} {job.name}"
            if kinds or _SECURITY_JOB_NAME_RE.search(label):
                discovered[job_id] = kinds
    return discovered


def _scanner_target_failures(
    job_id: str, line_no: int, line: str, kinds: set[str]
) -> list[str]:
    failures: list[str] = []
    if "bandit" in kinds and not re.search(
        r"\bbandit\b.*(?:^|\s)-r\s+(?![-;&|]|$)\S+", line
    ):
        failures.append(
            f"{job_id} line {line_no} runs Bandit without a concrete `-r` target. "
            "A scanner that scans no source can post green while proving nothing."
        )
    if "pip-audit" in kinds and not re.search(
        r"\bpip-audit\b.*(?:^|\s)(?:-r|--requirement)\s+(?![-;&|]|$)\S+",
        line,
    ):
        failures.append(
            f"{job_id} line {line_no} runs pip-audit without a requirements file. "
            "This gate must audit the repo manifest, not an implicit or empty "
            "environment."
        )
    return failures


def _security_gate_job_failures(job_id: str, job: WorkflowJob) -> list[str]:
    scanner_kinds = _scanner_kinds_in_job(job.text)
    failures: list[str] = []
    for line_no, value in _active_continue_on_error_lines(job.text):
        failures.append(
            f"{job_id} line {line_no} has continue-on-error: {value}. A blocking "
            "security scanner that continues after failure can post green while "
            "findings exist."
        )

    if not scanner_kinds:
        failures.append(
            f"{job_id} is classified or named as a security scan gate but no "
            "known scanner command/action was found. That can mean a new scanner "
            "needs classification, or the job scans nothing."
        )
        return failures

    pipefail_seen = False
    for line_no, line in _logical_shell_lines(job.text):
        low = line.lower()
        if re.search(r"(?:^|[;&|]\s*)set\b.*\bpipefail\b", low):
            pipefail_seen = True
        if re.search(r"(?:^|[;&|]\s*)set\s+\+e\b", low):
            failures.append(
                f"{job_id} line {line_no} disables `set -e` inside a blocking "
                "security gate. Scanner non-zero exits must be allowed to fail "
                "the step directly."
            )
        if re.search(r"(?:^|[;&|]\s*)exit\s+0\b", low):
            failures.append(
                f"{job_id} line {line_no} contains `exit 0`. A blocking security "
                "gate must not be able to short-circuit scanner failure to green."
            )
        if re.search(r"\bgrep\s+-q\b", low):
            failures.append(
                f"{job_id} line {line_no} uses `grep -q` in a scanner gate. "
                "Scanner exit status, not a grep-only summary check, must decide "
                "whether the gate is green."
            )

        kinds = _scanner_kinds_in_line(line)
        if not kinds:
            continue
        if "||" in line:
            failures.append(
                f"{job_id} line {line_no} uses `||` around a security scanner. "
                "Blocking gates must rely on the scanner exit code instead of a "
                "shell fallback."
            )
        if "| tee" in low and not pipefail_seen:
            failures.append(
                f"{job_id} line {line_no} pipes scanner output through `tee` "
                "without an earlier `set -o pipefail`; the job would otherwise "
                "observe tee's exit code instead of the scanner's."
            )
        failures.extend(_scanner_target_failures(job_id, line_no, line, kinds))

    if "trufflehog" in scanner_kinds and re.search(
        r"^\s*-?\s*uses:\s*trufflesecurity/trufflehog@", job.text, re.M | re.I
    ):
        if not re.search(r"^\s*path:\s*\S+", job.text, re.M):
            failures.append(
                f"{job_id} runs the TruffleHog action without `with.path`; this "
                "gate must name the tree it scans."
            )
        for key in ("base", "head"):
            if re.search(rf"^\s*{key}:\s*\S+", job.text, re.M):
                failures.append(
                    f"{job_id} pins TruffleHog `with.{key}`. On push events the "
                    "pinned action can collapse to BASE == HEAD and fail before "
                    "scanning; let the action derive the event range."
                )
    if "codeql" in scanner_kinds:
        has_init = re.search(r"github/codeql-action/init@", job.text, re.I)
        has_analyze = re.search(r"github/codeql-action/analyze@", job.text, re.I)
        if not has_init or not has_analyze:
            failures.append(
                f"{job_id} is a CodeQL security job but does not run both init "
                "and analyze actions, so analysis may never execute."
            )
    return failures


def _security_scan_gate_failures(
    texts: dict[str, str],
    classified: dict[str, tuple[str, ...]] | None = None,
    advisory: dict[str, str] | None = None,
) -> list[str]:
    if classified is None:
        classified = SECURITY_SCAN_GATE_JOBS
    if advisory is None:
        advisory = ADVISORY_ONLY_SECURITY_JOBS

    jobs = _workflow_job_map(texts)
    discovered = discover_security_scan_jobs(texts)
    failures: list[str] = []

    unexpected_advisory = sorted(set(advisory) - set(classified))
    for job_id in unexpected_advisory:
        failures.append(
            f"ADVISORY_ONLY_SECURITY_JOBS contains {job_id}, but that job is not "
            "classified as a security gate candidate."
        )

    for job_id in sorted(set(classified) - set(jobs)):
        failures.append(
            f"{job_id} is classified as a security scan gate but is missing from "
            "the workflow tree. Update SECURITY_SCAN_GATE_JOBS only when the "
            "workflow job is renamed or deliberately removed."
        )

    for job_id in sorted(set(discovered) - set(classified) - set(advisory)):
        failures.append(
            f"{job_id} looks like a security scan job but is not classified in "
            "SECURITY_SCAN_GATE_JOBS or ADVISORY_ONLY_SECURITY_JOBS. New security "
            "scan jobs must be deliberately classified before they can be read as "
            "enforced."
        )

    for job_id in sorted((set(classified) & set(jobs)) | set(discovered)):
        if job_id in advisory:
            continue
        job = jobs.get(job_id)
        if job is None:
            continue
        expected_contexts = classified.get(job_id)
        if expected_contexts:
            contexts = job.check_contexts()
            missing_contexts = [
                context for context in expected_contexts if context not in contexts
            ]
            for context in missing_contexts:
                failures.append(
                    f"{job_id} was expected to post check context {context!r}, "
                    f"but the parsed contexts are {contexts!r}. Refresh "
                    "SECURITY_SCAN_GATE_JOBS if the job name changed."
                )
        failures.extend(_security_gate_job_failures(job_id, job))

    return failures


def _required_security_scanner_coverage(
    texts: dict[str, str], required: set[str]
) -> dict[str, list[str]]:
    covered: dict[str, list[str]] = {}
    for wf, text in sorted(texts.items()):
        for job in workflow_jobs(text):
            contexts = [ctx for ctx in job.check_contexts() if ctx in required]
            if not contexts:
                continue
            for kind in _scanner_kinds_in_job(job.text):
                covered.setdefault(kind, []).append(
                    f"{wf}:{job.key} via {contexts}"
                )
    return covered


# ---------------------------------------------------------------------------
# The REQUIRED-context fixture, and its expiry (INV-5)
# ---------------------------------------------------------------------------

_FIXTURE_KEYS = (
    "repo", "branch", "observed_at", "max_age_days", "refresh_command",
    "github_actions_app_id", "required_checks", "_trust_root",
)

# ---------------------------------------------------------------------------
# THE TRUST ROOT  (Codex review, PR #15)
#
# The honest answer, stated once and not softened anywhere below.
#
# `.github/required-status-checks.json` is a COMMITTED READ-BACK of a mutable
# remote setting. Everything this floor tier does with it is checking the file
# against itself and against the workflow tree:
#
#   PROVEN offline —
#     * the fixture is well-formed, names this repo's default branch, and is
#       within its declared expiry (INV-5);
#     * every required GitHub-Actions context in it is produced by a job that
#       exists in the tree, so none is a phantom;
#     * every test file is collected by a job whose check name appears in it
#       (INV-3);
#     * no deselection filter hides a test from such a job.
#
#   ASSUMED, and NOT provable here —
#     * that the file faithfully reflects what branch protection ACTUALLY
#       requires on master right now.
#
# That assumption is load-bearing and it is irreducible in this tier: the floor
# contract is stdlib-only and offline, and reading branch protection needs an
# authenticated API call with admin scope. If the file were wrong — or edited to
# add `MCP server end-to-end smoke test` — every check here would still pass and
# the orphan INV-3 exists to catch would be credited by a job that gates nothing.
# `test_fixture_manipulation_is_undetectable_offline` demonstrates exactly that,
# on purpose, so the gap is executable rather than a paragraph someone skims.
#
# Per DONE.md floor entry 9(d) a property that was not observed must not be
# rendered as a success, so this statement travels with every message these
# invariants emit, and the fixture must carry its own `_trust_root` declaration
# or it is NOT OBSERVED.
# ---------------------------------------------------------------------------

TRUST_STATEMENT = (
    "TRUST ROOT: what is PROVEN here is that .github/required-status-checks.json "
    "is fresh, well-formed and coherent with the workflow tree; what is ASSUMED "
    "is that it matches live branch protection on "
    f"{DEFAULT_BRANCH!r}. This tier is offline and cannot call the protection "
    "API, so the assumption is not checkable here — it holds only because a "
    "human or a privileged job refreshed the file."
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

    # The fixture must declare its own trust root. A read-back that does not say
    # which part of it is assumed reads as though all of it were observed, which
    # is the 9(d) failure this whole section exists to prevent.
    trust = data["_trust_root"]
    if not isinstance(trust, dict):
        problems.append(
            f"_trust_root must be an object naming what is proven and what is "
            f"assumed, got {type(trust).__name__}"
        )
    else:
        for field in ("proven", "assumed"):
            value = trust.get(field)
            if not isinstance(value, list) or not value:
                problems.append(
                    f"_trust_root.{field} must be a non-empty list. A read-back "
                    f"with nothing listed under {field!r} is claiming either "
                    f"total proof or total ignorance; neither is true."
                )
        if not str(trust.get("verified_by", "")).strip():
            problems.append(
                "_trust_root.verified_by must name WHO or WHAT refreshed this "
                "file. An assumption with no owner cannot be re-checked."
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


REQUIRED_CUSTODY_FLOOR_FILES = frozenset({
    "tests/test_mcp_httpx_custody_floor.py",
    "tests/test_mcp_hosted_authority_floor.py",
})


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
        "not a pass:\n  - " + "\n  - ".join(problems) + "\n\n" + TRUST_STATEMENT
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
        + "\n\n" + TRUST_STATEMENT
    )


def test_custody_floor_files_are_present_and_collected_by_required_floor_context() -> None:
    test_files = set(_repo_test_files())
    missing = sorted(REQUIRED_CUSTODY_FLOOR_FILES - test_files)
    assert not missing, (
        "custody floor file(s) disappeared from the tree; this is not a global "
        "collection-count check, it anchors the named custody invariants:\n  - "
        + "\n  - ".join(missing)
    )

    required, problems = required_contexts()
    assert not problems, (
        "custody floor collection not observed because required contexts could "
        "not be read:\n  - " + "\n  - ".join(problems)
    )
    credited, rejected = credited_invocations(workflow_texts(), required)
    floor_invocations = [
        inv for _wf, ctx, inv in credited
        if ctx == "floor-invariants"
    ]
    assert floor_invocations, (
        "no required floor-invariants pytest invocation was credited; rejected:\n  - "
        + ("\n  - ".join(rejected) if rejected else "(none)")
    )

    uncollected = sorted(
        rel for rel in REQUIRED_CUSTODY_FLOOR_FILES
        if not any(inv.collects(rel) for inv in floor_invocations)
    )
    assert not uncollected, (
        "custody floor file(s) exist but are not collected by required "
        "floor-invariants:\n  - " + "\n  - ".join(uncollected)
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
        + "\n  - ".join(problems) + "\n\n" + TRUST_STATEMENT
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
        "_trust_root": {
            "proven": ["fixture is fresh and coherent with the workflow tree"],
            "assumed": ["that it matches live branch protection on master"],
            "why_irreducible_here": "offline tier cannot call the protection API",
            "verified_by": "human refresh",
        },
    }
    assert validate_required_checks(good, today) == [], validate_required_checks(good, today)

    # --- the trust-root declaration is itself validated -------------------
    # Named explicitly, not just via the _FIXTURE_KEYS loop below: dropping
    # "_trust_root" from that tuple made every other assertion here still pass,
    # because the real fixture happened to carry the key. That mutation
    # SURVIVED until this line existed. What must be pinned is the REQUIREMENT,
    # not the current file's compliance with it.
    without_trust = {k: v for k, v in good.items() if k != "_trust_root"}
    assert validate_required_checks(without_trust, today) == [
        "missing required key '_trust_root'"
    ], (
        "a fixture with no declared trust root must be NOT OBSERVED. Without "
        "this, the read-back can go back to presenting a trusted input as a "
        "verified one."
    )

    # A fixture may not claim total proof by leaving `assumed` empty, and an
    # assumption with no owner cannot be re-checked.
    no_assumed = {**good, "_trust_root": {**good["_trust_root"], "assumed": []}}
    aprobs = validate_required_checks(no_assumed, today)
    assert len(aprobs) == 1 and "_trust_root.assumed" in aprobs[0], aprobs
    assert "total proof" in aprobs[0], aprobs

    no_proven = {**good, "_trust_root": {**good["_trust_root"], "proven": []}}
    pprobs = validate_required_checks(no_proven, today)
    assert len(pprobs) == 1 and "_trust_root.proven" in pprobs[0], pprobs

    no_owner = {**good, "_trust_root": {**good["_trust_root"], "verified_by": "  "}}
    oprobs = validate_required_checks(no_owner, today)
    assert len(oprobs) == 1 and "verified_by" in oprobs[0], oprobs

    not_object = {**good, "_trust_root": "we checked it"}
    nprobs = validate_required_checks(not_object, today)
    assert len(nprobs) == 1 and "must be an object" in nprobs[0], nprobs

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


def test_security_scan_gate_jobs_fail_closed_and_are_classified() -> None:
    """
    Security scanners must fail closed and be discovered from the workflow tree.

    The offline fixture can prove only workflow-tree coherence, not live branch
    protection. SECURITY_SCAN_GATE_JOBS therefore records the queue policy claim:
    these jobs are security gates or candidates to become required gates, so a
    scanner failure must be able to turn the job red before branch protection can
    safely rely on it. The discovery pass prevents the allowlist from shrinking
    into a literal that never sees newly-added scan jobs.
    """
    assert SECURITY_SCAN_GATE_JOBS, (
        "INV-6 examined ZERO security scan jobs. If the security workflow has no "
        "required gate candidates, either remove this invariant with a reason or "
        "name the advisory-only jobs explicitly."
    )
    texts = workflow_texts()
    discovered = discover_security_scan_jobs(texts)
    assert discovered, (
        f"INV-6 parsed {len(texts)} workflow file(s) but discovered ZERO "
        "security scan jobs. That is not a pass; either the repo lost every "
        "scanner or discover_security_scan_jobs() no longer understands the "
        "workflow syntax."
    )
    failures = _security_scan_gate_failures(texts)
    assert not failures, (
        "security scan gate job(s) are fail-open, missing, or unclassified "
        f"({len(discovered)} job(s) discovered; "
        f"{len(SECURITY_SCAN_GATE_JOBS)} classified; advisory-only exceptions: "
        f"{sorted(ADVISORY_ONLY_SECURITY_JOBS)}):\n  - "
        + "\n  - ".join(failures)
    )


def test_security_scanners_are_aggregated_into_a_required_context() -> None:
    """
    The direct security_scan.yml contexts are not required by branch protection.

    This cannot be changed by a repo patch. What this patch can do is make an
    existing required context run the blocking scanner class, and fail if that
    aggregate is later removed.
    """
    required, problems = required_contexts()
    assert not problems, (
        "INV-6 NOT OBSERVED — the required-status-context fixture is unusable, "
        "so no statement about required security scanner aggregation can be made:"
        "\n  - " + "\n  - ".join(problems) + "\n\n" + TRUST_STATEMENT
    )

    coverage = _required_security_scanner_coverage(workflow_texts(), required)
    missing = [
        f"{kind} ({reason})"
        for kind, reason in sorted(REQUIRED_SECURITY_SCANNERS.items())
        if kind not in coverage
    ]
    assert not missing, (
        "security scanner class(es) are not covered by any existing REQUIRED "
        f"context (required contexts from fixture: {sorted(required)}). Direct "
        "security_scan.yml contexts are recorded as not required in "
        ".github/required-status-checks.json, so these scanners must be folded "
        "into an existing required context until branch protection is changed:\n"
        "  - " + "\n  - ".join(missing) + "\n\nCoverage observed:\n  - "
        + "\n  - ".join(
            f"{kind}: {jobs}" for kind, jobs in sorted(coverage.items())
        )
        + "\n\n" + TRUST_STATEMENT
    )


def test_inv6_fail_closed_positive_controls() -> None:
    """The INV-6 detectors must flag the fail-open class, not just today's file."""
    bad_job = (
        "on:\n"
        "  pull_request:\n"
        "    branches: [master]\n"
        "jobs:\n"
        "  dependency-audit:\n"
        "    name: Dependency vulnerability audit\n"
        "    runs-on: ubuntu-latest\n"
        "    continue-on-error: true\n"
        "    steps:\n"
        "      - name: Audit dependencies\n"
        "        run: |\n"
        "          set +e\n"
        "          pip-audit -r requirements.txt --format json -o out.json || true\n"
        "          grep -q CVE out.txt\n"
        "          exit 0\n"
    )
    job_id = ".github/workflows/security_scan.yml:dependency-audit"
    failures = _security_scan_gate_failures(
        {".github/workflows/security_scan.yml": bad_job},
        classified={job_id: ("Dependency vulnerability audit",)},
    )
    assert any("continue-on-error" in f for f in failures), failures
    assert any("uses `||` around a security scanner" in f for f in failures), failures
    assert any("disables `set -e`" in f for f in failures), failures
    assert any("grep -q" in f for f in failures), failures
    assert any("exit 0" in f for f in failures), failures
    assert _active_continue_on_error_lines(
        "job:\n  continue-on-error: false\n"
    ) == []

    no_target = bad_job.replace(
        "pip-audit -r requirements.txt --format json -o out.json || true",
        "pip-audit --format json -o out.json",
    ).replace("    continue-on-error: true\n", "")
    target_failures = _security_scan_gate_failures(
        {".github/workflows/security_scan.yml": no_target},
        classified={job_id: ("Dependency vulnerability audit",)},
    )
    assert any("without a requirements file" in f for f in target_failures), (
        target_failures
    )

    empty_bandit = (
        "jobs:\n"
        "  bandit:\n"
        "    name: Bandit static analysis\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          set -euo pipefail\n"
        "          bandit -r\n"
    )
    bandit_failures = _security_scan_gate_failures(
        {".github/workflows/security_scan.yml": empty_bandit},
        classified={
            ".github/workflows/security_scan.yml:bandit": (
                "Bandit static analysis",
            )
        },
    )
    assert any("without a concrete `-r` target" in f for f in bandit_failures), (
        bandit_failures
    )

    pinned_trufflehog = (
        "jobs:\n"
        "  secrets-check:\n"
        "    name: Check for committed secrets\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: trufflesecurity/trufflehog@34339eaf08bf5c2a27dbd969812127721f3743ed\n"
        "        with:\n"
        "          path: ./\n"
        "          base: ${{ github.event.repository.default_branch }}\n"
        "          head: HEAD\n"
        "          extra_args: --only-verified\n"
    )
    trufflehog_failures = _security_scan_gate_failures(
        {".github/workflows/security_scan.yml": pinned_trufflehog},
        classified={
            ".github/workflows/security_scan.yml:secrets-check": (
                "Check for committed secrets",
            )
        },
    )
    assert any("with.base" in f for f in trufflehog_failures), trufflehog_failures
    assert any("with.head" in f for f in trufflehog_failures), trufflehog_failures


def test_inv6_discovers_new_security_jobs_and_classification_shrink() -> None:
    """New gate-like jobs and a shrunken classifier must go red."""
    new_job = (
        "name: Security Scan\n"
        "on:\n"
        "  pull_request:\n"
        "    branches: [master]\n"
        "jobs:\n"
        "  new-security-audit:\n"
        "    name: New dependency security audit\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: |\n"
        "          pip-audit -r requirements.txt || true\n"
    )
    failures = _security_scan_gate_failures(
        {".github/workflows/security_extra.yml": new_job},
        classified={},
    )
    assert any("not classified" in f for f in failures), failures
    assert any("uses `||` around a security scanner" in f for f in failures), failures

    shrink = {
        job_id: contexts
        for job_id, contexts in SECURITY_SCAN_GATE_JOBS.items()
        if job_id != ".github/workflows/security_scan.yml:bandit"
    }
    shrink_failures = _security_scan_gate_failures(
        workflow_texts(), classified=shrink
    )
    assert any(
        ".github/workflows/security_scan.yml:bandit" in f and "not classified" in f
        for f in shrink_failures
    ), (
        "INV-6 classifier population shrink survived: removing the real Bandit "
        "gate from SECURITY_SCAN_GATE_JOBS must be detected by workflow discovery. "
        f"Failures: {shrink_failures}"
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
# INV-4 — a strict xfail must not sit under anything that can skip it
# ---------------------------------------------------------------------------
# CODEX FINDING 2 (2026-07-26), fixed here: the first implementation propagated
# only CLASS and FUNCTION decorators. Probe: a module-level
# `pytestmark = pytest.mark.skipif(not _api_key, reason=...)` plus a
# `@pytest.mark.xfail(strict=True)` on a function gave pytest exit 0 / 1 skipped
# while the guard returned `findings=[]` and `conditional_skip=0` — the whole
# floor tier stayed green (14 passed) with the evasion sitting in the tree. So
# the "a check that never runs" invariant missed the commonest way to skip a
# whole module.
#
# SKIP-PROPAGATION PATHS **HANDLED** (each with a positive control below):
#   (a) function decorator                     @pytest.mark.skipif(...)
#   (b) class decorator, inherited by methods  @pytest.mark.skipif(...) on class
#   (c) MODULE-level `pytestmark = <mark>`                    <- Codex finding 2
#   (d) MODULE-level `pytestmark = [<mark>, ...]` / tuple     <- Codex finding 2
#   (e) CLASS-body `pytestmark = ...` (same two shapes)
#   (f) `pytestmark += [...]` and `pytestmark: list = [...]`
#   (g) unconditional `@pytest.mark.skip` / `pytest.mark.skip(...)`, which also
#       short-circuits the xfail (bare attribute form included)
#   (h) `skipif(<always-true literal>)`, e.g. `skipif(True, ...)`
#   Not flagged, deliberately: `skipif(False, ...)` never skips, and a NON-strict
#   xfail claims nothing.
#
# SKIP-PROPAGATION PATHS **NOT HANDLED**, BY NAME. None is silently ignored;
# each is surfaced as NOT-OBSERVED by the invariant named against it, so an
# unenumerated evasion cannot read as absence:
#   1. `conftest.py` collection hooks — `pytest_collection_modifyitems` /
#      `pytest_collection_modify*` can attach a skip to any item at runtime.
#      -> surfaced by `test_inv4_unmodelled_skip_paths_are_surfaced`.
#   2. `addopts` in pytest.ini / setup.cfg / pyproject.toml / tox.ini carrying
#      `-k` or `-m`, which DESELECTS rather than skips (an unevaluated xfail
#      either way).
#      -> surfaced by `test_no_deselection_filter_hides_tests_from_a_required_context`
#         (unconditional: deselection is also a hole in INV-3's collection model).
#   3. `-k` / `-m` / `--deselect` in the workflow's own pytest command.
#      -> same invariant as (2).
#   4. A fixture (or module-level code) raising `pytest.skip(...)` — including
#      `pytest.skip(..., allow_module_level=True)`.
#   5. `pytest.importorskip(...)`.
#   6. Dynamic marks: `item.add_marker(...)` / `request.node.add_marker(...)`,
#      and marks built via `getattr(pytest.mark, name)`.
#   7. Per-parameter marks: `pytest.param(..., marks=pytest.mark.skip)`.
#      (4)-(7) -> surfaced by `test_inv4_unmodelled_skip_paths_are_surfaced`.
#   8. `xfail_strict = true` in pytest config, which makes EVERY plain xfail
#      strict without the token `strict=True` appearing anywhere — so the mark
#      walk below would under-count strict xfails.
#      -> surfaced UNCONDITIONALLY by `xfail_strict_config()`, asserted inside
#         INV-4 itself; the repo's real config is checked, not a synthetic one.
#   9. `--deselect` in the workflow command (recorded verbatim by
#      `PytestInvocation.raw_filters`, surfaced with the -k/-m filters).
#   Genuinely unmodelled and NOT surfaced: an `if:` condition on the workflow job
#   or step, which can skip a required job's steps at runtime while the check-run
#   still reports success.

def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _is_strict_xfail(mark: ast.AST) -> bool:
    if not isinstance(mark, ast.Call):
        return False
    if not _dotted(mark.func).endswith("mark.xfail"):
        return False
    for kw in mark.keywords:
        if kw.arg == "strict":
            return isinstance(kw.value, ast.Constant) and kw.value.value is True
    return False


def _skip_kind(mark: ast.AST) -> str | None:
    """
    Why this mark can stop a strict xfail from ever being evaluated, or None.

    `skipif(False, ...)` returns None: it never skips, so the xfail is still
    evaluated. `skipif(True, ...)` and a bare/called `skip` DO always skip.
    """
    if not isinstance(mark, ast.Call):
        # Bare attribute form: `@pytest.mark.skip` with no parentheses.
        return "unconditional skip" if _dotted(mark).endswith("mark.skip") else None
    dotted = _dotted(mark.func)
    if dotted.endswith("mark.skip"):
        return "unconditional skip"
    if not dotted.endswith("mark.skipif"):
        return None
    cond = mark.args[0] if mark.args else None
    if cond is None:
        for kw in mark.keywords:
            if kw.arg == "condition":
                cond = kw.value
    if cond is None:
        return None
    if isinstance(cond, ast.Constant):
        return "skipif(<always-true literal>)" if cond.value else None
    return "conditional skipif"


def _pytestmark_assignments(body: list[ast.stmt]) -> tuple[list[ast.AST], list[str]]:
    """
    Marks contributed by `pytestmark = ...` in a module or class body.

    Handles `= <mark>`, `= [<mark>, ...]`, `= (<mark>, ...)`, `+= [...]` and the
    annotated form. Returns ``(marks, unmodelled)``; `unmodelled` names any
    element this parser cannot classify (e.g. a comprehension or a bare Name),
    so an opaque pytestmark reads as NOT-OBSERVED rather than as no mark.
    """
    marks: list[ast.AST] = []
    unmodelled: list[str] = []
    for node in body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AugAssign):
            targets, value = [node.target], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "pytestmark" for t in targets):
            continue
        elts = list(value.elts) if isinstance(value, (ast.List, ast.Tuple)) else [value]
        for elt in elts:
            if isinstance(elt, (ast.Call, ast.Attribute)):
                marks.append(elt)
            else:
                unmodelled.append(
                    f"line {getattr(elt, 'lineno', '?')}: a pytestmark element is "
                    f"{type(elt).__name__}, not a `pytest.mark.*` reference — this "
                    f"parser cannot tell whether it is a skip"
                )
    return marks, unmodelled


def strict_xfail_under_skip(source: str, label: str) -> tuple[list[str], dict]:
    """
    Every strict xfail that something in scope can prevent from being evaluated.

    Returns ``(findings, stats)``. Marks are collected from function decorators,
    class decorators (inherited by methods), and `pytestmark` assignments at
    module and class scope — the last of which is Codex finding 2. Each finding
    names the PROVENANCE of the skip, because "there is a skip somewhere above
    you" is not actionable.

    ``stats["unmodelled"]`` is non-empty when a `pytestmark` element could not be
    classified; callers must treat that as NOT-OBSERVED, never as clean.
    """
    stats = {
        "strict_xfail": 0,
        "skip_mark": 0,
        "module_pytestmark": 0,
        "class_pytestmark": 0,
        "functions": 0,
        "unmodelled": [],
    }
    findings: list[str] = []
    tree = ast.parse(source)

    def count(marks: list[ast.AST]) -> None:
        stats["strict_xfail"] += sum(1 for m in marks if _is_strict_xfail(m))
        stats["skip_mark"] += sum(1 for m in marks if _skip_kind(m))

    def scan(node: ast.AST, inherited: list[tuple[ast.AST, str]], owner: str) -> None:
        body = list(getattr(node, "body", []))
        pm_marks, pm_unmodelled = _pytestmark_assignments(body)
        stats["unmodelled"].extend(f"{label}:{u}" for u in pm_unmodelled)
        if pm_marks:
            key = "module_pytestmark" if isinstance(node, ast.Module) else "class_pytestmark"
            stats[key] += len(pm_marks)
            count(pm_marks)
        where = "module-level `pytestmark`" if isinstance(node, ast.Module) else (
            f"class-body `pytestmark` on {owner.rstrip(':')}"
        )
        scope = inherited + [(m, where) for m in pm_marks]

        for child in body:
            if isinstance(child, ast.ClassDef):
                decs = list(child.decorator_list)
                count(decs)
                scan(
                    child,
                    scope + [(d, f"decorator on class {owner}{child.name}") for d in decs],
                    f"{owner}{child.name}::",
                )
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                own = list(child.decorator_list)
                count(own)
                stats["functions"] += 1
                all_marks = scope + [(d, "decorator on the function") for d in own]
                if not any(_is_strict_xfail(m) for m, _ in all_marks):
                    continue
                skips = [
                    f"{_skip_kind(m)} via {prov}"
                    for m, prov in all_marks
                    if _skip_kind(m)
                ]
                if not skips:
                    continue
                findings.append(
                    f"{label}:{child.lineno} {owner}{child.name} carries "
                    f"xfail(strict=True) while {len(skips)} skip mark(s) apply to "
                    f"it — {'; '.join(skips)}. A skip short-circuits xfail "
                    f"evaluation, so the strict tripwire can NEVER fire: it "
                    f"advertises rigour it cannot deliver, and reads as a passing "
                    f"rigorous test. Fix: drop strict=True and report the "
                    f"not-observed state loudly, or remove the skip so the xfail "
                    f"can actually be evaluated."
                )

    scan(tree, [], "")
    return findings, stats


def test_no_strict_xfail_under_a_skip() -> None:
    test_files = _repo_test_files()
    assert test_files, "INV-4 found ZERO test files — the detector measured nothing."

    findings: list[str] = []
    unmodelled: list[str] = []
    totals = {
        "strict_xfail": 0, "skip_mark": 0, "module_pytestmark": 0,
        "class_pytestmark": 0, "functions": 0,
    }
    parsed = 0
    unparsed: list[str] = []
    for rel in test_files:
        path = ROOT / rel
        try:
            src = path.read_text(encoding="utf-8")
            found, stats = strict_xfail_under_skip(src, rel)
        except (SyntaxError, UnicodeDecodeError) as exc:
            # A file we could not read is NOT-OBSERVED, never a pass (floor 9(d)).
            unparsed.append(f"{rel}: {exc}")
            continue
        parsed += 1
        findings.extend(found)
        unmodelled.extend(stats["unmodelled"])
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
    assert not unmodelled, (
        "INV-4 NOT OBSERVED — a `pytestmark` element could not be classified, so "
        "whether a skip applies is unknown and must not be read as 'no skip':\n"
        "  - " + "\n  - ".join(unmodelled)
    )
    # `xfail_strict = true` in config would make this walk under-count strict
    # xfails, so it invalidates the whole invariant rather than one file.
    global_strict = xfail_strict_config(_config_texts())
    assert not global_strict, (
        "INV-4 NOT OBSERVED — pytest config turns strictness on globally:\n  - "
        + "\n  - ".join(global_strict)
    )
    # Work-done, with units named (floor 9(a)).
    assert totals["functions"], (
        f"INV-4 parsed {parsed} test file(s) but found ZERO test functions. The "
        f"AST walk measured nothing — not a pass."
    )
    assert not findings, (
        f"strict xfail(s) that can never be evaluated ({parsed} file(s) parsed; "
        f"{totals['functions']} function(s), {totals['strict_xfail']} strict-xfail "
        f"mark(s), {totals['skip_mark']} skip mark(s), "
        f"{totals['module_pytestmark']} module-level and "
        f"{totals['class_pytestmark']} class-body pytestmark entr(y/ies) "
        f"examined):\n  - " + "\n  - ".join(findings)
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
    findings, stats = strict_xfail_under_skip(bad, "<control>")
    assert len(findings) == 1, (
        "INV-4 positive control FAILED: the detector did not flag the exact "
        "pre-fix shape of tests/test_smoke_e2e.py::TestHostedFallback (a "
        "class-level conditional skipif with a method-level strict xfail). A "
        f"detector blind to the original defect proves nothing. Got: {findings}"
    )
    assert "conditional skipif via decorator on class TestHostedFallback" in findings[0]
    assert stats["strict_xfail"] == 1 and stats["skip_mark"] == 1, stats
    assert stats["module_pytestmark"] == 0 and stats["class_pytestmark"] == 0, stats
    assert stats["functions"] == 1 and stats["unmodelled"] == [], stats

    # NEGATIVE controls — the detector must not cry wolf.
    ok_non_strict = bad.replace("strict=True", "strict=False")
    assert strict_xfail_under_skip(ok_non_strict, "<c>")[0] == [], (
        "INV-4 false positive: a NON-strict xfail under a skip is honest — it "
        "claims nothing — and must not be flagged."
    )
    ok_no_skip = bad.replace(
        "@pytest.mark.skipif(not _api_key, reason='no key')\n", ""
    )
    assert strict_xfail_under_skip(ok_no_skip, "<c>")[0] == [], (
        "INV-4 false positive: a strict xfail with no skip above it CAN be "
        "evaluated and must not be flagged."
    )
    ok_literal = bad.replace("not _api_key", "False")
    assert strict_xfail_under_skip(ok_literal, "<c>")[0] == [], (
        "INV-4 false positive: `skipif(False, ...)` never skips, so the strict "
        "xfail is still evaluated."
    )


def test_inv4_module_level_pytestmark_codex_probe() -> None:
    """
    Codex finding 2, frozen as a test.

    The probe module below produced `pytest ... -> exit 0, 1 skipped` (observed:
    `SKIPPED [1] ...:7: no key`) while the pre-fix guard returned
    `([], {'strict_xfail': 1, 'conditional_skip': 0})` — a strict tripwire that
    can never fire, invisible to the invariant whose whole purpose is to catch
    exactly that.
    """
    probe = (
        "import pytest\n"
        "\n"
        "_api_key = None\n"
        "pytestmark = pytest.mark.skipif(not _api_key, reason='no key')\n"
        "\n"
        "\n"
        "@pytest.mark.xfail(reason='BLOCKED: hosted /v1/detect returns 404', strict=True)\n"
        "def test_verify_returns_real_detection():\n"
        "    assert False\n"
    )
    findings, stats = strict_xfail_under_skip(probe, "<probe>")
    assert len(findings) == 1, (
        "INV-4 missed Codex's probe: a module-level `pytestmark` skipif is the "
        "commonest way to skip a whole module and must propagate to every test "
        f"function in it. Got: {findings}"
    )
    assert "<probe>:8 test_verify_returns_real_detection" in findings[0], findings
    assert "conditional skipif via module-level `pytestmark`" in findings[0], findings
    assert stats["module_pytestmark"] == 1, stats
    assert stats["strict_xfail"] == 1 and stats["skip_mark"] == 1, stats

    # (d) the LIST form of module-level pytestmark.
    as_list = probe.replace(
        "pytestmark = pytest.mark.skipif(not _api_key, reason='no key')",
        "pytestmark = [pytest.mark.asyncio,\n"
        "              pytest.mark.skipif(not _api_key, reason='no key')]",
    )
    lf, lstats = strict_xfail_under_skip(as_list, "<probe>")
    assert len(lf) == 1 and "module-level `pytestmark`" in lf[0], lf
    assert lstats["module_pytestmark"] == 2, lstats

    # (d) tuple form, and (f) the augmented / annotated forms.
    for variant, why in (
        ("pytestmark = (pytest.mark.skipif(not _api_key, reason='k'),)", "tuple"),
        ("pytestmark += [pytest.mark.skipif(not _api_key, reason='k')]", "+="),
        ("pytestmark: list = [pytest.mark.skipif(not _api_key, reason='k')]", "annotated"),
    ):
        src = probe.replace(
            "pytestmark = pytest.mark.skipif(not _api_key, reason='no key')", variant
        )
        assert len(strict_xfail_under_skip(src, "<v>")[0]) == 1, why

    # (e) CLASS-BODY pytestmark — same evasion one level down.
    class_body = (
        "import pytest\n"
        "_api_key = None\n"
        "class TestHostedFallback:\n"
        "    pytestmark = [pytest.mark.skipif(not _api_key, reason='no key')]\n"
        "\n"
        "    @pytest.mark.xfail(reason='404', strict=True)\n"
        "    def test_x(self):\n"
        "        assert False\n"
    )
    cf, cstats = strict_xfail_under_skip(class_body, "<cls>")
    assert len(cf) == 1, cf
    assert "class-body `pytestmark` on TestHostedFallback" in cf[0], cf
    assert cstats["class_pytestmark"] == 1 and cstats["module_pytestmark"] == 0, cstats

    # (g) unconditional skip, called and bare, also short-circuits the xfail.
    for variant in ("pytest.mark.skip(reason='x')", "pytest.mark.skip"):
        src = probe.replace(
            "pytest.mark.skipif(not _api_key, reason='no key')", variant
        )
        f, _ = strict_xfail_under_skip(src, "<u>")
        assert len(f) == 1 and "unconditional skip" in f[0], (variant, f)

    # (h) an always-true literal condition always skips.
    always = probe.replace("not _api_key", "True")
    af, _ = strict_xfail_under_skip(always, "<a>")
    assert len(af) == 1 and "always-true literal" in af[0], af

    # NEGATIVE CONTROLS — each must produce NO finding, so the assertions above
    # are pinned to the defect rather than to a detector that flags everything.
    never = probe.replace("not _api_key", "False")
    assert strict_xfail_under_skip(never, "<n>")[0] == [], (
        "module-level `skipif(False)` never skips."
    )
    non_strict = probe.replace("strict=True", "strict=False")
    assert strict_xfail_under_skip(non_strict, "<n>")[0] == [], (
        "a non-strict xfail under a module-level skip claims nothing."
    )
    no_mark = probe.replace(
        "pytestmark = pytest.mark.skipif(not _api_key, reason='no key')\n", ""
    )
    assert strict_xfail_under_skip(no_mark, "<n>")[0] == [], (
        "no skip in scope means the strict xfail can be evaluated."
    )
    other_var = probe.replace("pytestmark =", "not_pytestmark =")
    assert strict_xfail_under_skip(other_var, "<n>")[0] == [], (
        "only the magic name `pytestmark` propagates; a differently-named module "
        "variable holding a mark does nothing and must not be flagged."
    )

    # NOT-OBSERVED control — an opaque pytestmark element must be reported, not
    # silently read as 'no skip'.
    opaque = probe.replace(
        "pytestmark = pytest.mark.skipif(not _api_key, reason='no key')",
        "pytestmark = [m for m in _marks]",
    )
    _, ostats = strict_xfail_under_skip(opaque, "<o>")
    assert len(ostats["unmodelled"]) == 1, ostats
    assert "ListComp" in ostats["unmodelled"][0], ostats


# ---------------------------------------------------------------------------
# Companion surfaces — the evasions INV-3 / INV-4 do NOT model, named out loud
# ---------------------------------------------------------------------------
# Detection is AST-based, not textual. This file's own control fixtures contain
# `pytest.skip(`, `add_marker(`, `pytest.param(marks=...)` etc. inside STRING
# literals; a regex over source text flags them and the check becomes
# permanently red for the wrong reason (observed while building this). Real code
# only, therefore.

_DESELECT_OPT = re.compile(r"(?:^|\s)(?:-[km](?:\s|=)|--deselect)")

# Config files whose contents can deselect or skip tests in EVERY module.
GLOBAL_SKIP_SURFACES = (
    "conftest.py", "pytest.ini", "setup.cfg", "pyproject.toml", "tox.ini",
)


def deselection_filters(
    config_texts: dict[str, str], workflow_commands: dict[str, str]
) -> list[str]:
    """
    Every `-k` / `-m` / `--deselect` that can remove tests from a required run.

    `PytestInvocation.collects()` models targets, `--ignore` and `python_files`
    only. It does NOT model deselection, so a required job could collect a file
    and then deselect every test in it while INV-3 still called the file covered.
    Unconditional: this is a live hole in INV-3's model whether or not any strict
    xfail exists, so it is surfaced as NOT-OBSERVED rather than assumed absent.
    """
    out: list[str] = []
    for rel, text in sorted(config_texts.items()):
        for m in re.finditer(r"^\s*addopts\s*=\s*(.+)$", text, re.M):
            if _DESELECT_OPT.search(" " + m.group(1)):
                out.append(
                    f"{rel} addopts carries a deselection filter "
                    f"(-k/-m/--deselect): {m.group(1).strip()!r}. INV-3's collection "
                    f"model does not know about deselection, so it would still "
                    f"report the deselected files as covered."
                )
    for label, cmd in sorted(workflow_commands.items()):
        if _DESELECT_OPT.search(" " + cmd):
            out.append(
                f"{label} runs pytest with a deselection filter "
                f"(-k/-m/--deselect): {cmd.strip()!r}. INV-3 would still credit the "
                f"files it names as covered."
            )
    return out


def xfail_strict_config(config_texts: dict[str, str]) -> list[str]:
    """
    `xfail_strict = true` anywhere in pytest config makes EVERY xfail strict.

    INV-4 identifies a strict xfail by an explicit `strict=True` keyword. If the
    config turns strictness on globally, that identification under-counts and the
    invariant would report clean while strict tripwires sit under skips. Reported
    as NOT-OBSERVED rather than silently tolerated.
    """
    out: list[str] = []
    rx = re.compile(r"^\s*xfail_strict\s*[=:]\s*(\S+)", re.M)
    for rel, text in sorted(config_texts.items()):
        for m in rx.finditer(text):
            if m.group(1).strip("\"' ,").lower() in ("true", "1", "yes", "on"):
                out.append(
                    f"{rel} sets xfail_strict={m.group(1)!r}, so EVERY "
                    f"`@pytest.mark.xfail` is strict. INV-4 detects strictness by "
                    f"an explicit `strict=True` keyword, so it under-counts under "
                    f"this setting and cannot certify the tree. Fix: either drop "
                    f"the global setting, or extend `_is_strict_xfail()` to treat a "
                    f"bare xfail as strict when it is enabled."
                )
    return out


def unmodelled_skip_mechanisms(source: str) -> list[str]:
    """
    Skip mechanisms present as REAL CODE that INV-4's mark walk cannot see.

    AST-based on purpose (see the note at the top of this section). Returns
    deduplicated human names; a parse failure is itself reported, never treated
    as absence.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, UnicodeDecodeError) as exc:
        return [f"source could not be parsed ({exc}), so its skip paths are unknown"]
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
            node.name.startswith("pytest_collection_modify")
        ):
            found.add(
                f"collection hook `{node.name}` (can attach a skip to any item at "
                f"collection time)"
            )
            continue
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted(node.func)
        if dotted.endswith(".add_marker"):
            found.add("dynamic mark via `add_marker(...)`")
        elif dotted.endswith("pytest.skip"):
            found.add("runtime `pytest.skip(...)` (fixture body or module level)")
        elif dotted.endswith("pytest.importorskip"):
            found.add("`pytest.importorskip(...)`")
        elif dotted.endswith("pytest.param") and any(
            kw.arg == "marks" for kw in node.keywords
        ):
            found.add("per-parameter `marks=` on `pytest.param(...)`")
        elif dotted == "getattr" and node.args and _dotted(node.args[0]) == "pytest.mark":
            found.add("mark built dynamically via `getattr(pytest.mark, ...)`")
    return sorted(found)


def unmodelled_skip_surfaces(
    file_sources: dict[str, str], config_sources: dict[str, str]
) -> tuple[list[str], dict]:
    """
    Unmodelled skip mechanisms that could be hiding a strict xfail.

    Returns ``(surfaces, counts)``. Per-file mechanisms are reported only for
    files that carry a REAL strict-xfail mark (determined by the AST walk, not by
    the token ``strict=True``), because that is the only situation in which the
    evasion matters — ordinary use of `importorskip` is not a defect. Config-file
    mechanisms apply to every module, so they are reported whenever the tree
    carries a strict xfail anywhere.
    """
    with_strict: dict[str, str] = {}
    for rel, src in file_sources.items():
        try:
            if strict_xfail_under_skip(src, rel)[1]["strict_xfail"]:
                with_strict[rel] = src
        except (SyntaxError, UnicodeDecodeError):
            continue
    counts = {
        "files": len(file_sources),
        "files_with_strict_xfail": len(with_strict),
        # AST-determined, so a `strict=True` living inside a STRING literal (this
        # file's own control fixtures) is correctly excluded.
        "strict_xfail_files": sorted(with_strict),
    }
    if not with_strict:
        return [], counts
    out: list[str] = []
    for rel, src in sorted(with_strict.items()):
        for name in unmodelled_skip_mechanisms(src):
            out.append(f"{rel} carries a strict xfail AND uses {name}")
    for rel, src in sorted(config_sources.items()):
        if not rel.endswith(".py"):
            continue
        for name in unmodelled_skip_mechanisms(src):
            out.append(
                f"{rel} uses {name}; it applies to EVERY module, and strict "
                f"xfail(s) exist in {sorted(with_strict)}"
            )
    return out, counts


def _config_texts() -> dict[str, str]:
    return {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in GLOBAL_SKIP_SURFACES
        if (ROOT / name).is_file()
    }


def _credited_commands() -> dict[str, str]:
    required, problems = required_contexts()
    assert not problems, "NOT OBSERVED:\n  - " + "\n  - ".join(problems)
    credited, _ = credited_invocations(workflow_texts(), required)
    assert credited, "no required-context pytest invocation found to inspect."
    return {
        f"{wf} ({ctx})": " ".join(
            ["pytest"] + inv.targets
            + [f"--ignore={i}" for i in inv.ignores]
            + inv.raw_filters
        )
        for wf, ctx, inv in credited
    }


def test_no_deselection_filter_hides_tests_from_a_required_context() -> None:
    """
    INV-3's collection model does not understand `-k` / `-m` / `--deselect`.

    NOT vacuous: evaluated against the repo's real pytest.ini / setup.cfg addopts
    and the real pytest commands of the REQUIRED contexts.
    """
    configs = _config_texts()
    assert configs, (
        f"none of {GLOBAL_SKIP_SURFACES} found at the repo root — this check "
        f"measured nothing, which is not a pass."
    )
    commands = _credited_commands()
    surfaces = deselection_filters(configs, commands)
    assert not surfaces, (
        f"deselection filter(s) that INV-3's collection model cannot see "
        f"({len(configs)} config file(s) and {len(commands)} required pytest "
        f"command(s) examined):\n  - " + "\n  - ".join(surfaces)
    )


def test_deselection_filter_positive_control() -> None:
    """The deselection detector must flag each form, and only those forms."""
    strict_ini = {"pytest.ini": "[pytest]\naddopts = -m 'not slow'\n"}
    got = deselection_filters(strict_ini, {})
    assert len(got) == 1 and "addopts carries a deselection filter" in got[0], got
    for opt in ("-k not_smoke", "-k=not_smoke", "-m 'not slow'", "--deselect tests/x.py"):
        got = deselection_filters({}, {"wf (unit-tests)": f"pytest tests {opt}"})
        assert len(got) == 1 and "deselection filter" in got[0], (opt, got)
    # NEGATIVE controls — the repo's real config and command must not trip it, and
    # neither may an option that merely starts with the same letters.
    assert deselection_filters(
        {"pytest.ini": "[pytest]\naddopts = -p no:cacheprovider\n"},
        {"wf (unit-tests)": "pytest proxy/tests tests --ignore=x -v --timeout=120"},
    ) == []
    assert deselection_filters({}, {"wf": "pytest tests --maxfail=1 --keep-going"}) == []
    assert deselection_filters(_config_texts(), _credited_commands()) == []

    # xfail_strict detector — same family, same shape of proof.
    for value in ("true", "True", "1", "yes"):
        got = xfail_strict_config({"pytest.ini": f"[pytest]\nxfail_strict = {value}\n"})
        assert len(got) == 1 and "under-counts" in got[0], (value, got)
    assert xfail_strict_config(
        {"pyproject.toml": 'xfail_strict = "true"\n'}
    ) != [], "the TOML spelling must be caught too"
    for value in ("false", "0", "no"):
        assert xfail_strict_config(
            {"pytest.ini": f"[pytest]\nxfail_strict = {value}\n"}
        ) == [], value
    assert xfail_strict_config({"pytest.ini": "[pytest]\naddopts = -p no:x\n"}) == []
    assert xfail_strict_config(_config_texts()) == [], (
        "the repo's real pytest config must not enable global xfail strictness "
        "without INV-4 being taught about it."
    )
    # And the parser must actually be recording the filters it is asked about.
    assert PytestInvocation(shlex.split("pytest tests -k not_smoke")).raw_filters == [
        "-k", "not_smoke",
    ]
    assert PytestInvocation(shlex.split("pytest tests -m slow")).raw_filters == [
        "-m", "slow",
    ]
    assert PytestInvocation(
        shlex.split("pytest tests --deselect tests/x.py::test_y")
    ).raw_filters == ["--deselect"]
    assert PytestInvocation(shlex.split("pytest tests -v --timeout=120")).raw_filters == []


def test_inv4_unmodelled_skip_paths_are_surfaced() -> None:
    """
    The evasions INV-4 does not model must be NAMED, not assumed absent.

    CONDITIONAL and, today, VACUOUS on the real tree: the repo carries ZERO real
    strict-xfail marks (tests/test_smoke_e2e.py deliberately uses strict=False —
    see 15cd3a1), so there is nothing for these mechanisms to hide and the check
    reports nothing. That vacuity is asserted explicitly below rather than left
    implicit, and non-vacuity is proven by
    `test_inv4_unmodelled_surface_positive_control`, which drives the same
    detector with synthetic input for every named mechanism. The moment anyone
    adds a real `strict=True`, this becomes live for that file.
    """
    file_sources = {
        rel: (ROOT / rel).read_text(encoding="utf-8") for rel in _repo_test_files()
    }
    assert file_sources, "no test files discovered — the check measured nothing."
    surfaces, counts = unmodelled_skip_surfaces(file_sources, _config_texts())
    assert not surfaces, (
        f"INV-4 NOT OBSERVED — mechanism(s) that can stop a test from running "
        f"which INV-4's mark walk cannot see ({counts['files']} test file(s) "
        f"examined, {counts['files_with_strict_xfail']} carrying a strict xfail). "
        f"These are enumerated, not hidden; each must be resolved or explicitly "
        f"modelled:\n  - " + "\n  - ".join(surfaces)
    )
    assert counts["files"] == len(_repo_test_files())
    assert counts["files_with_strict_xfail"] == 0, (
        f"{counts['files_with_strict_xfail']} test file(s) now carry a real "
        f"strict-xfail mark. That is allowed, but this invariant's vacuity note "
        f"is now out of date: re-read it, confirm the per-file surface really did "
        f"run for those files, and update the count. Files (AST-determined): "
        f"{counts['strict_xfail_files']}"
    )


def test_inv4_unmodelled_surface_positive_control() -> None:
    """The unmodelled-path detector must flag each named evasion (proves it works)."""
    strict = "import pytest\n@pytest.mark.xfail(strict=True)\ndef test_a(): pass\n"
    no_strict = "import pytest\ndef test_a(): pass\n"

    # No REAL strict xfail anywhere => nothing to hide => silent, by design.
    quiet, counts = unmodelled_skip_surfaces(
        {"tests/t.py": no_strict + "def f():\n    pytest.skip('x')\n"},
        {"conftest.py": "def pytest_collection_modifyitems(items):\n    pass\n"},
    )
    assert quiet == [] and counts["files_with_strict_xfail"] == 0, (quiet, counts)

    # A strict xfail written only INSIDE A STRING must not count as a real mark —
    # this file's own control fixtures are exactly that shape, and a textual check
    # made this invariant permanently red for the wrong reason.
    in_string, s_counts = unmodelled_skip_surfaces(
        {"tests/t.py": "SRC = '@pytest.mark.xfail(strict=True)'\nimport pytest\n"
                       "def f():\n    pytest.skip('x')\n"},
        {},
    )
    assert in_string == [] and s_counts["files_with_strict_xfail"] == 0, in_string

    # conftest hook, applying to every module.
    hook, hcounts = unmodelled_skip_surfaces(
        {"tests/t.py": strict},
        {"conftest.py": "def pytest_collection_modifyitems(items):\n    pass\n"},
    )
    assert hcounts["files_with_strict_xfail"] == 1, hcounts
    assert len(hook) == 1 and "pytest_collection_modifyitems" in hook[0], hook
    assert "applies to EVERY module" in hook[0], hook

    # Per-file mechanisms, each flagged by name.
    for snippet, needle in (
        ("def fx():\n    pytest.skip('nope')\n", "runtime `pytest.skip"),
        ("np = pytest.importorskip('numpy')\n", "importorskip"),
        ("def h(item):\n    item.add_marker(pytest.mark.skip)\n", "add_marker"),
        ("@pytest.mark.parametrize('x', [pytest.param(1, marks=pytest.mark.skip)])\n"
         "def test_b(x): pass\n", "per-parameter `marks=`"),
        ("m = getattr(pytest.mark, 'skip')\n", "getattr(pytest.mark"),
    ):
        got, gc = unmodelled_skip_surfaces({"tests/t.py": strict + snippet}, {})
        assert gc["files_with_strict_xfail"] == 1, (snippet, gc)
        assert len(got) == 1 and needle in got[0], (snippet, got)

    # NEGATIVE control — a clean file with a strict xfail is not flagged.
    assert unmodelled_skip_surfaces({"tests/t.py": strict}, {})[0] == []
    # NEGATIVE control — `add_marker` on something that is not a mark call, and a
    # `getattr` unrelated to pytest.mark, must not be flagged.
    assert unmodelled_skip_mechanisms("x = getattr(os.path, 'join')\n") == []
    # NOT-OBSERVED control — an unparseable source is reported, never silent.
    broken = unmodelled_skip_mechanisms("def (:\n")
    assert len(broken) == 1 and "could not be parsed" in broken[0], broken


# ---------------------------------------------------------------------------
# THE TRUST ROOT, made executable  (Codex review, PR #15)
#
# Codex's finding was not that a check is wrong — INV-3 and INV-5 do what they
# claim. It was that the GUARANTEE rests on a committed fixture, and expiry plus
# "the job exists" cross-checks prove the file is fresh and coherent, NOT that
# branch protection actually requires those contexts.
#
# The decision taken, stated plainly rather than engineered around: offline, the
# trust root is IRREDUCIBLE. The floor contract is stdlib-only with no network,
# and reading branch protection needs an authenticated admin-scope API call. So
# the correct outcome is not a more confident PASS — it is a declared assumption
# that travels with every verdict these invariants produce.
# ---------------------------------------------------------------------------

def test_the_trust_root_is_declared_and_names_what_is_assumed() -> None:
    """
    The fixture must say which part of itself is observed and which is trusted.

    Floor entry 9(d): a property that was not observed must not be rendered as a
    success. A read-back that lists only its contents reads as though all of it
    were verified — the reader cannot tell that the central claim (this matches
    live protection) was never checked.
    """
    data = json.loads(REQUIRED_CHECKS_FIXTURE.read_text(encoding="utf-8"))
    trust = data.get("_trust_root")
    assert isinstance(trust, dict), (
        f"{REQUIRED_CHECKS_FIXTURE.name} has no _trust_root declaration. It is a "
        "claim about a mutable remote setting; without a declared boundary its "
        "freshness checks read as proof of correctness."
    )

    assert trust.get("proven"), "_trust_root.proven is empty"
    assert trust.get("assumed"), (
        "_trust_root.assumed is EMPTY — that asserts the fixture is fully "
        "verified offline, which is false. The one thing this tier cannot check "
        "is whether the file matches live branch protection."
    )
    # The assumption must actually be the load-bearing one, not a token entry.
    assumed_text = " ".join(trust["assumed"]).lower()
    assert "branch protection" in assumed_text, (
        "_trust_root.assumed does not name the branch-protection assumption, "
        f"which is the only one that matters here: {trust['assumed']}"
    )
    assert str(trust.get("why_irreducible_here", "")).strip(), (
        "_trust_root must say WHY the assumption cannot be discharged in this "
        "tier, or a future reader will assume it was simply overlooked."
    )
    assert str(trust.get("verified_by", "")).strip(), (
        "_trust_root.verified_by must name who refreshes this file."
    )

    # And the statement the invariants emit must agree with the fixture.
    assert "ASSUMED" in TRUST_STATEMENT and "PROVEN" in TRUST_STATEMENT, (
        "TRUST_STATEMENT must distinguish the two; it is what gets rendered."
    )
    assert DEFAULT_BRANCH in TRUST_STATEMENT


def test_trust_statement_travels_with_every_fixture_dependent_verdict() -> None:
    """
    A named assumption is only surfaced if it reaches the reader.

    Every invariant that consumes the fixture must carry TRUST_STATEMENT in the
    message it emits, so a failure never reads as "the gate is broken" when the
    real content is "the gate rests on something nobody re-checked".
    """
    source = Path(__file__).read_text(encoding="utf-8")
    consumers = (
        "test_every_test_file_is_collectable_by_a_required_context",
        "test_required_context_fixture_is_fresh_and_wellformed",
    )
    for name in consumers:
        start = source.index(f"def {name}(")
        end = source.find("\ndef ", start + 1)
        body = source[start:end if end != -1 else len(source)]
        assert "TRUST_STATEMENT" in body, (
            f"{name} consumes the required-context fixture but does not render "
            "TRUST_STATEMENT. Its verdict would present a trusted input as a "
            "verified one."
        )


def test_fixture_manipulation_is_undetectable_offline() -> None:
    """
    The gap, executed. This test PASSES by demonstrating the hole.

    Codex's exact scenario: the fixture is edited to add the smoke-test context.
    The orphan INV-3 exists to catch is then credited by a job that gates
    nothing, and every offline check still passes — because "is this context
    really required?" is precisely the question no offline check can ask.

    Pinning it as a test rather than a comment means nobody can later read the
    green floor tier as proof that branch protection is what the file says.
    """
    real = json.loads(REQUIRED_CHECKS_FIXTURE.read_text(encoding="utf-8"))
    smoke_context = "MCP server end-to-end smoke test"

    # Precondition: the context is NOT required today, and IS produced by a job
    # that triggers on master. That combination is what makes it dangerous.
    assert smoke_context not in {c["context"] for c in real["required_checks"]}, (
        "precondition changed: the smoke-test context is now recorded as "
        "required. Re-derive this demonstration rather than deleting it."
    )
    produced = set()
    for _wf, text in workflow_texts().items():
        for job in workflow_jobs(text):
            produced |= set(job.check_contexts())
    assert smoke_context in produced, (
        "precondition changed: no job produces the smoke-test context, so this "
        f"demonstration no longer models the risk. Produced: {sorted(produced)}"
    )

    # The manipulation: one line added to a committed JSON file.
    tampered = {
        **real,
        "required_checks": real["required_checks"]
        + [{"context": smoke_context, "app_id": real["github_actions_app_id"]}],
    }

    problems = validate_required_checks(tampered, date.today())
    assert problems == [], (
        "the tampered fixture was rejected by the offline validator, which would "
        f"be a stronger guarantee than claimed: {problems}. If a real defence "
        "now exists, update _trust_root and this test to describe it."
    )

    # And it changes what INV-3 credits: the smoke job becomes a gate.
    tampered_required = {str(c["context"]) for c in tampered["required_checks"]}
    credited, _rejected = credited_invocations(workflow_texts(), tampered_required)
    credited_contexts = {ctx for _wf, ctx, _inv in credited}
    assert smoke_context in credited_contexts, (
        "the tampered fixture did not change what INV-3 credits, so this "
        "demonstration is not exercising the risk it documents. Credited: "
        f"{sorted(credited_contexts)}"
    )

    # THE POINT: no offline check distinguishes the tampered file from the real
    # one. This is the assumption, not a defect to be fixed here.
    assert True, (
        "unreachable — retained so the intent is explicit: offline, a fixture "
        "that LIES is indistinguishable from one that is correct."
    )
