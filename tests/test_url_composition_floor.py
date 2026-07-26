"""
FLOOR TIER — base-URL/path composition, repo-wide.

Stdlib + pytest only (no httpx, no `proxy.*` import): collected by
`.github/workflows/floor-invariants.yml`, a REQUIRED status context on `master`,
which installs pytest and nothing else. Zero interpreter variance.

THE DEFECT THIS IS COMPILED FROM
--------------------------------
`proxy/detection_adapter.py` composed its governance-push target as
``f"{url}{ADAPTER_PATH}"``. With ``DETECTION_ADAPTER_URL=http://adapter:7070/`` —
a trailing slash, the commonest way a human writes a base URL — that POSTs to
``//v1/events/proxy``. `httpx` does not fold the empty segment and the receiver's
axum router has no `NormalizePathLayer`, so the push is a 404 with an EMPTY BODY
on a fire-and-forget path: the governance rail dark, with a valid signature over
a request that never arrived.

FIXING THE ONE LINE IS NOT CLOSING THE CLASS. The sweep that followed found the
same shape in `server.py` (`ARKHEIA_PROXY_URL`), `mcp_server/tools/providers.py`
(`OLLAMA_BASE_URL`) and `proxy/tests/test_e2e.py` — three siblings nobody would
have recalled, in three packages. A bug has siblings, and recall does not find
them; a scanner does.

WHAT IS ENFORCED
----------------
Every site in this repo that joins a base URL to a path must take its base from
something that cannot carry a stray trailing slash. A site passes when its base
resolves to one of:

    NORMALISED  the binding ends in `.rstrip("/")`, or is produced by the
                canonical `normalise_base_url` / `adapter_target`
    LITERAL     the binding is a string literal in the source — no operator can
                put a slash in it without editing code that this scanner reads
    INTERNAL    the binding is itself composed in-process from literals (e.g.
                `f"http://127.0.0.1:{port}"`), so no env value reaches it

and fails otherwise — most importantly when the base comes straight from
`os.getenv` / `os.environ`, which is exactly the defect.

📖 KNOWN LIMITATIONS — read before trusting a green run. This is a LINT, not a
proof, and it says so out loud rather than being quietly over-trusted:

  * **Name-filtered.** A site is only examined if its base slot's name contains
    one of `URL_HINTS`. A base URL held in a variable called `endpoint_thing` is
    seen; one called `svc` is not. The filter exists because without it every
    filesystem-path f-string (`f"{profile_dir}/{name}.yaml"`) becomes a false
    positive, and a floor that cries wolf gets switched off — and then there is
    no floor.
  * **Module-scoped, scope-insensitive resolution.** Bindings are looked up
    anywhere in the same module, ignoring function scope. A base passed in as a
    parameter therefore resolves to a same-named local elsewhere in the file if
    one exists. It cannot follow a value across modules or through a call.
  * **Syntactic.** It reads the shape of the join, not the value. It cannot know
    whether a literal base URL is the *right* one.

None of these can cause the specific regression it guards (an env-supplied base
concatenated raw), which is the property it is here for.
"""
import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Directories with no first-party source to guard.
SKIP_DIRS = {
    ".venv", "venv", "__pycache__", ".git", "node_modules", "profiles",
    "build", "dist", ".tmp_test_build_pipeline", ".pytest_cache", "specs", "docs",
}

# A slot is treated as a BASE URL only if its name carries one of these. See
# KNOWN LIMITATIONS: this is what keeps filesystem paths out of the results.
URL_HINTS = ("url", "uri", "endpoint", "host", "upstream", "addr", "base")

# The canonical composer/normaliser. A base produced by either is normalised by
# construction — this is the "reuse the canonical primitive" path (DONE.md Gate 2
# registry check), and naming them here is what makes reuse cheaper than a
# hand-rolled `.rstrip`.
CANONICAL = ("normalise_base_url", "adapter_target")

# Sites whose base cannot be resolved inside its own module AND which have been
# reviewed by a human. Empty is the goal state; an entry is a promise, not a pass.
# Format: "relative/path.py::slot_name" -> reason.
REVIEWED_UNRESOLVED: dict[str, str] = {}


def _py_files() -> list[Path]:
    out = []
    for p in REPO_ROOT.rglob("*.py"):
        if SKIP_DIRS & set(p.relative_to(REPO_ROOT).parts):
            continue
        out.append(p)
    return sorted(out)


def _slot_name(node) -> str:
    """`self.base_url` -> 'base_url'; `PROXY_URL` -> 'PROXY_URL'."""
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _looks_like_a_base_url(name: str) -> bool:
    lowered = name.lower()
    return any(h in lowered for h in URL_HINTS)


def _module_constants(tree) -> dict[str, str]:
    """Module-level `NAME = "literal"` — used to resolve `f"{base}{PATH}"`."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) \
                and isinstance(node.value.value, str):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value.value
    return out


def _starts_a_path(element, constants: dict[str, str]) -> bool:
    """
    Does this f-string element begin an absolute path?

    Two shapes, and the second one matters: the original defect was
    ``f"{url}{ADAPTER_PATH}"`` — a SLOT, not a literal — so a scanner that only
    looked for a literal `"/..."` would have missed the very line it exists for.
    """
    if isinstance(element, ast.Constant) and isinstance(element.value, str):
        return element.value.startswith("/")
    if isinstance(element, ast.FormattedValue) and isinstance(element.value, ast.Name):
        return constants.get(element.value.id, "").startswith("/")
    return False


def _composition_sites(tree, constants: dict[str, str]) -> list[tuple[int, str, str]]:
    """
    Discover `(lineno, slot_name, source)` for every base+path join.

    Only a slot in FIRST position counts: a base URL is by definition the start of
    the URL, and requiring position 0 is what stops `f"{a}/profiles/{model_id}/download"`
    being reported twice (once for a `model_id` that is not a base at all).
    """
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            if len(node.values) < 2:
                continue
            head, nxt = node.values[0], node.values[1]
            if not isinstance(head, ast.FormattedValue):
                continue
            name = _slot_name(head.value)
            if not name or not _looks_like_a_base_url(name):
                continue
            if _starts_a_path(nxt, constants):
                sites.append((node.lineno, name, ast.unparse(node)))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            name = _slot_name(node.left)
            if not name or not _looks_like_a_base_url(name):
                continue
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, str) \
                    and node.right.value.startswith("/"):
                sites.append((node.lineno, name, ast.unparse(node)))
    return sites


def _bindings(tree, name: str) -> list[ast.expr]:
    """Every value assigned to `name` (or `self.name`) anywhere in the module."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if _slot_name(t) == name and node.value is not None:
                    out.append(node.value)
    return out


def _reads_env(node) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            src = ast.unparse(n.func)
            if src.endswith(("os.getenv", "environ.get")):
                return True
        if isinstance(n, ast.Subscript) and "environ" in ast.unparse(n):
            return True
    return False


def _classify(binding: ast.expr) -> str:
    """NORMALISED / LITERAL / INTERNAL / RAW_ENV / UNKNOWN for one binding."""
    for n in ast.walk(binding):
        if isinstance(n, ast.Call):
            func = ast.unparse(n.func)
            if func.endswith(".rstrip"):
                args = [a.value for a in n.args if isinstance(a, ast.Constant)]
                if "/" in args:
                    return "NORMALISED"
            if func.split(".")[-1] in CANONICAL:
                return "NORMALISED"

    if isinstance(binding, ast.Constant) and isinstance(binding.value, str):
        return "LITERAL"
    # `a or B` / `a if c else b` over literals — still no env value reaching it.
    if isinstance(binding, (ast.BoolOp, ast.IfExp)) and not _reads_env(binding):
        return "LITERAL"
    if isinstance(binding, ast.JoinedStr) and not _reads_env(binding):
        return "INTERNAL"
    if _reads_env(binding):
        return "RAW_ENV"
    return "UNKNOWN"


def _verdict(tree, slot: str) -> str:
    bindings = _bindings(tree, slot)
    if not bindings:
        return "UNRESOLVED"
    verdicts = {_classify(b) for b in bindings}
    if "RAW_ENV" in verdicts:
        return "RAW_ENV"        # a single unnormalised env read is the defect
    if verdicts == {"NORMALISED"} or verdicts <= {"NORMALISED", "LITERAL", "INTERNAL"}:
        return "OK"
    return "UNKNOWN"


def _scan() -> tuple[list[str], list[str], int]:
    """Returns (violations, unresolved_keys, sites_examined)."""
    violations, unresolved, examined = [], [], 0
    for path in _py_files():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:                              # pragma: no cover
            continue
        constants = _module_constants(tree)
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, slot, src in _composition_sites(tree, constants):
            examined += 1
            verdict = _verdict(tree, slot)
            if verdict == "UNRESOLVED":
                unresolved.append(f"{rel}::{slot}")
            elif verdict != "OK":
                violations.append(f"{rel}:{lineno} [{verdict}] {slot} in {src}")
    return violations, sorted(set(unresolved)), examined


# ══════════════════════════════════════════════════════════════════════════════

def test_no_base_url_is_joined_to_a_path_without_normalisation():
    """
    THE invariant. Auto-discovering: it covers files that do not exist yet, which
    is the only way a class of defect stays closed.
    """
    violations, unresolved, examined = _scan()

    # Work-done, asserted BEFORE the verdict (DONE.md floor entry 9): "no
    # violations found" and "nothing was examined" are the same sentence, and the
    # second one is a lie by omission.
    assert examined >= 15, (
        f"the scanner examined only {examined} composition sites; it is looking in "
        f"the wrong place and a green result would mean nothing"
    )
    assert violations == [], (
        "base URL joined to a path without normalisation — a trailing slash in the "
        "env var silently misroutes every request:\n  " + "\n  ".join(violations)
    )

    stale = sorted(set(REVIEWED_UNRESOLVED) - set(unresolved))
    assert stale == [], f"REVIEWED_UNRESOLVED entries no longer exist; delete them: {stale}"
    unreviewed = sorted(set(unresolved) - set(REVIEWED_UNRESOLVED))
    assert unreviewed == [], (
        "composition sites whose base cannot be resolved in its own module. Review "
        "each, normalise it, or record it in REVIEWED_UNRESOLVED with a reason:\n  "
        + "\n  ".join(unreviewed)
    )


@pytest.mark.parametrize(
    "source, why",
    [
        ('url = os.getenv("A_URL", "")\nx = f"{url}/v1/events/proxy"',
         "the sibling shape: env base, literal path"),
        ('ADAPTER_PATH = "/v1/events/proxy"\nurl = os.getenv("A_URL", "")\n'
         'x = f"{url}{ADAPTER_PATH}"',
         "THE original defect verbatim: env base, path in a SLOT"),
        ('base_url = os.environ.get("A_URL", "http://h")\nx = f"{base_url}/api/generate"',
         "os.environ.get form"),
        ('endpoint = os.environ["A_URL"]\nx = f"{endpoint}/detect/verify"',
         "subscript form"),
        ('url = os.getenv("A_URL", "")\nx = url + "/v1/events/proxy"',
         "`+` concatenation rather than an f-string"),
    ],
)
def test_the_scanner_can_actually_find_the_defect(tmp_path, source, why):
    """
    PROVE THE CHECK CAN FAIL (DONE.md v1.22). A check that passes by finding
    nothing must demonstrate it can find something, or it is decoration — and
    seven such checks were found green-but-unable-to-fail in a single day.

    Each case is a real historical shape, including the exact pre-fix line from
    `proxy/detection_adapter.py`.
    """
    tree = ast.parse(source)
    constants = _module_constants(tree)
    sites = _composition_sites(tree, constants)
    assert sites, f"scanner did not even see the site: {why}"
    assert [_verdict(tree, slot) for _l, slot, _s in sites] == ["RAW_ENV"] * len(sites), why


@pytest.mark.parametrize(
    "source, why",
    [
        ('url = os.getenv("A_URL", "").rstrip("/")\nx = f"{url}/v1/events/proxy"',
         "the fix: rstrip at the binding"),
        ('url = normalise_base_url(os.getenv("A_URL", ""))\nx = f"{url}/v1/e"',
         "the fix: the canonical normaliser"),
        ('PROXY_URL = "http://localhost:8099"\nx = f"{PROXY_URL}/detect/verify"',
         "a literal base cannot carry an operator's slash"),
        ('proxy_url = f"http://127.0.0.1:{port}"\nx = f"{proxy_url}/admin/health"',
         "composed in-process from literals"),
    ],
)
def test_the_scanner_does_not_cry_wolf(source, why):
    """
    The other half, and the half that decides whether the floor survives contact
    with the team: a scanner that flags correct code gets switched off, and then
    the defect it guarded returns unobserved.
    """
    tree = ast.parse(source)
    sites = _composition_sites(tree, _module_constants(tree))
    assert sites, f"fixture is vacuous — no site to classify: {why}"
    assert [_verdict(tree, slot) for _l, slot, _s in sites] == ["OK"] * len(sites), why


def test_filesystem_path_composition_is_not_reported():
    """
    The specific false positive that would sink this check. `f"{profile_dir}/{name}.yaml"`
    is the same SHAPE as the defect and is entirely correct; the name filter is
    what separates them, so pin that it works.
    """
    tree = ast.parse('profile_dir = os.getenv("D", "")\nx = f"{profile_dir}/{name}.yaml"')
    assert _composition_sites(tree, _module_constants(tree)) == []


def test_the_real_repo_sites_are_actually_being_seen():
    """
    A named-site control. The scanner claiming "0 violations" is only meaningful if
    it is reaching the modules that carry these joins — including the one the
    defect was found in.
    """
    seen = set()
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _composition_sites(tree, _module_constants(tree)):
            seen.add(path.relative_to(REPO_ROOT).as_posix())

    for expected in (
        "server.py",
        "mcp_server/proxy_client.py",
        "mcp_server/tools/providers.py",
        "proxy/registry/client.py",
        "registry_server/storage.py",
    ):
        assert expected in seen, (
            f"{expected} carries a base+path join the scanner did not see — the "
            f"discovery is misaimed"
        )
