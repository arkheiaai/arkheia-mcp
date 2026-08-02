"""
FLOOR INVARIANTS — F20 encrypted-profile decryption + dynamic key load.

Floor-tier contract: **stdlib only** (``ast`` + ``pathlib``). Imports no
third-party package, imports no project module, opens no socket, starts no app.
It reasons over source text, so it runs under a bare ``pytest`` with zero project
dependencies and has zero interpreter variance. It is executed by the
``floor-invariants`` CI job, which is bound to the default branch (``master``)
and therefore actually gates a pull request — see the note at the bottom of this
docstring about the two workflows that do not.

WHY THESE EXIST — real defects, this repo, at base 3037f0c
----------------------------------------------------------
**INV-1 — the writer is built before anything decides.**
``proxy/main.py`` built the ``AuditWriter`` at step 3, loaded the profile
decryption key at step 1b and authenticated every encrypted profile at step 1.
Both of those are governed decisions and neither could be receipted, because no
writer existed yet. That is not a forgotten call site — it is an ordering that
makes the call site impossible, and an ordering will drift back the moment
someone moves a block for an unrelated reason. This invariant fails the build if
a decision site is ever placed above the writer again. It is checked
**statically**, on purpose: a static check cannot be skipped, runs in
milliseconds, and knows a fact no integration test can assert without booting an
app.

**INV-2 — the decision vocabulary stays closed.**
An open-vocabulary status string is how a governance stream drifts into
unqueryability one caller at a time. Every ``outcome`` / ``key_source`` /
``revocation_state`` passed at a production call site must be one of the
constants in ``proxy/audit/decision_journal.py``, never a bare literal.

**INV-3 — the receipt builders carry an ALLOW-LIST, not a deny-list.**
DONE.md v1.22 clause 5: where a boundary strips fields, name what may pass. A
list of forbidden fields fails open — the next field anyone adds sails through
because nobody thought to forbid it. So this invariant does not look for ``key``
or ``plaintext``; it enumerates the value FORMS a receipt field may take, and
fails on anything else. A parameter annotated ``bytes`` may appear only inside
one of the non-reversible wrappers (``key_id`` / ``ciphertext_id`` / ``len``);
that rule is derived from the annotation, so a new secret-bearing parameter is
constrained the day it is added rather than the day someone remembers it.

**INV-4 — every one of the above proves it can find something.**
DONE.md v1.19: a check whose pass condition is "found nothing" cannot
distinguish clean from blind. Each analyser here is run against a synthetic
violation in the same file, and each asserts a non-zero examined population.

**INV-11/12 — plaintext custody is policy-driven and receipted.**
The plaintext guard must not key only on ``glob("*.yaml.enc")``. Deleting or
renaming encrypted files is exactly the bypass, so ``ProfileRouter`` must refuse
plaintext from policy/trust state, and an explicit plaintext opt-in must leave a
profile-authentication receipt naming the opt-in. Audited plaintext development
is an explicit mode, and startup must carry encrypted inventory seen before key
resolution into the router policy so a key-fetch outage cannot be followed by a
silent plaintext load after an unlink/rename race.

WHAT THIS FILE DELIBERATELY DOES NOT CLAIM
------------------------------------------
``security_scan.yml`` and ``smoke-test.yml`` in this repo trigger on ``main`` /
``staging`` while the default branch is ``master``, so they never gate any pull
request. That is a real hole, it is **not fixed here**, and it is not counted as
enforcement anywhere in this branch: it is already owned by PR #15
(``sweep/mcp-ci-enforcement-holes``), which is open. The only correctly-bound
required contexts on ``master`` today are ``floor-invariants`` and
``unit-tests`` — this file runs in the first, the F20 receipt suites in the
second, and nothing on this branch is claimed to be gated by anything else.
"""
from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAIN = ROOT / "proxy" / "main.py"
JOURNAL = ROOT / "proxy" / "audit" / "decision_journal.py"
ROUTER = ROOT / "proxy" / "router" / "profile_router.py"

#: Production roots scanned for call sites. Test directories are excluded — a
#: test may legitimately construct an off-taxonomy value to prove it is refused.
PROD_DIRS = ("proxy", "mcp_server", "registry_server", "scripts")

#: The receipt builders whose field values are allow-listed.
BUILDERS = (
    "build_key_load_record",
    "build_profile_auth_record",
    "build_profile_rollback_record",
)

#: Keyword arguments whose value must come from the closed taxonomy.
TAXONOMY_KWARGS = {
    "outcome": (
        "KEY_LOAD_OUTCOMES",
        "PROFILE_AUTH_OUTCOMES",
        "PROFILE_ROLLBACK_OUTCOMES",
    ),
    "key_source": ("KEY_SOURCES",),
    "revocation_state": ("REVOCATION_STATES",),
}

#: The only calls a receipt field's value may be produced by. Each is
#: non-reversible or purely structural.
ALLOWED_VALUE_CALLS = frozenset({"key_id", "ciphertext_id", "hosted_origin",
                                 "len", "sorted"})

#: Calls that are permitted to receive a ``bytes``-annotated parameter directly.
#: ``hosted_origin`` is absent deliberately: it takes a URL, not key material.
SECRET_SAFE_WRAPPERS = frozenset({"key_id", "ciphertext_id", "len"})


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _prod_python_files() -> list[Path]:
    out: list[Path] = []
    for d in PROD_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*.py")):
            if "tests" in p.parts or p.name.startswith("test_"):
                continue
            out.append(p)
    return out


def _frozenset_members(tree: ast.Module) -> dict[str, set[str]]:
    """
    Every ``NAME = frozenset({A, B, ...})`` in the journal module, resolved to
    the STRING VALUES of the constants it names.

    Parsed rather than imported: the floor tier installs nothing but pytest, and
    a floor check that needs the package importable is a floor check that stops
    running the day an import breaks.
    """
    literals: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and isinstance(node.value, ast.Constant):
                if isinstance(node.value.value, str):
                    literals[target.id] = node.value.value

    sets: dict[str, set[str]] = {}
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1):
            continue
        target = node.targets[0]
        call = node.value
        if not (isinstance(target, ast.Name) and isinstance(call, ast.Call)):
            continue
        if not (isinstance(call.func, ast.Name) and call.func.id == "frozenset"):
            continue
        members: set[str] = set()
        for arg in call.args:
            elts = getattr(arg, "elts", []) or getattr(arg, "keys", [])
            for elt in elts:
                if isinstance(elt, ast.Name) and elt.id in literals:
                    members.add(literals[elt.id])
                elif isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    members.add(elt.value)
        sets[target.id] = members
    return sets


def _constant_names(tree: ast.Module) -> dict[str, str]:
    """``NAME -> "value"`` for module-level string constants."""
    out: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str):
                out[t.id] = node.value.value
    return out


# ---------------------------------------------------------------------------
# INV-1 — the audit writer is constructed before anything that decides
# ---------------------------------------------------------------------------

#: Constructions/calls in the lifespan that TAKE a governed decision. Each must
#: appear after the writer. Discovered by name in the AST, not by line matching.
DECISION_SITES = ("ProfileRouter", "DynamicKeyLoader", "_resolve_profile_key")

#: The sites the lifespan MUST contain. Without this, a rename drops a site from
#: DECISION_SITES silently and the ordering check becomes a permanent pass over a
#: shrinking population — the "looked in the wrong place" failure of v1.19.
REQUIRED_IN_LIFESPAN = ("ProfileRouter", "_resolve_profile_key")


def _lifespan_ordering(tree: ast.Module) -> tuple[int | None, dict[str, int]]:
    """``(writer_line, {decision_site: first_line})`` inside ``lifespan``."""
    lifespan = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) \
                and node.name == "lifespan":
            lifespan = node
            break
    if lifespan is None:
        return None, {}

    writer_line: int | None = None
    sites: dict[str, int] = {}
    for node in ast.walk(lifespan):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.id if isinstance(node.func, ast.Name) else None
        if name == "AuditWriter":
            writer_line = node.lineno if writer_line is None else min(writer_line, node.lineno)
        elif name in DECISION_SITES:
            sites[name] = min(sites.get(name, node.lineno), node.lineno)
    return writer_line, sites


def test_inv1_audit_writer_is_constructed_before_every_decision_site():
    """
    THE INVARIANT THIS WHOLE BRANCH EXISTS FOR.

    Fails against ``origin/master``, where ``AuditWriter`` is built at line ~125
    and ``ProfileRouter`` at line ~64.
    """
    writer_line, sites = _lifespan_ordering(_parse(MAIN))

    assert writer_line is not None, (
        "no AuditWriter(...) construction found inside lifespan() in proxy/main.py — "
        "either the rail was removed or this check is looking in the wrong place; "
        "both are failures, and 'found nothing' is never a pass"
    )
    assert sites, (
        "no governed decision site found inside lifespan(). Expected at least one "
        f"of {DECISION_SITES}. A scan that examines nothing cannot clear anything."
    )
    missing = [name for name in REQUIRED_IN_LIFESPAN if name not in sites]
    assert not missing, (
        f"the lifespan no longer calls {missing}. Either the site moved out of "
        f"lifespan() or it was renamed and this list was not — and a renamed site "
        f"is one this ordering check silently stops looking for."
    )

    late = {name: line for name, line in sites.items() if line < writer_line}
    assert not late, (
        f"the AuditWriter is constructed at line {writer_line}, AFTER the governed "
        f"decision site(s) {late}. A decision taken before the writer exists cannot "
        f"be receipted at all — this is the exact ordering that made F20's "
        f"receipted axis fail. Move the writer up, do not add a second rail."
    )


def test_inv1_negative_self_test_detects_a_reintroduced_late_writer():
    """v1.19 clause 1: the check must be shown detecting a known-bad input."""
    broken = ast.parse(
        "async def lifespan(app):\n"
        "    router = ProfileRouter('x')\n"
        "    writer = AuditWriter(log_path='y')\n"
    )
    writer_line, sites = _lifespan_ordering(broken)
    assert writer_line == 3 and sites == {"ProfileRouter": 2}
    assert [n for n, ln in sites.items() if ln < writer_line] == ["ProfileRouter"]


def test_inv1_negative_self_test_detects_a_removed_writer():
    """The other blindness: a writer deleted entirely must not read as ordered."""
    broken = ast.parse("async def lifespan(app):\n    router = ProfileRouter('x')\n")
    writer_line, sites = _lifespan_ordering(broken)
    assert writer_line is None and sites == {"ProfileRouter": 2}


# ---------------------------------------------------------------------------
# INV-2 — the decision vocabulary is closed
# ---------------------------------------------------------------------------

def _enclosing_params(tree: ast.Module) -> dict[int, tuple[str, set[str]]]:
    """``lineno -> (function name, its parameter names)`` for every statement."""
    out: dict[int, tuple[str, set[str]]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            params = _param_names(node)
            for child in ast.walk(node):
                lineno = getattr(child, "lineno", None)
                if lineno is not None:
                    out.setdefault(lineno, (node.name, params))
    return out


def _taxonomy_violations(tree: ast.Module, sets: dict[str, set[str]],
                         constants: dict[str, str],
                         targets: set[str]) -> tuple[list[str], int, set[str]]:
    """
    ``(violations, sites_examined, forwarders)`` for calls to ``targets``.

    A keyword whose value is a **parameter of the enclosing function** is a
    FORWARDER, not a violation — the constant is supplied by that function's own
    callers. The enclosing function's name is returned so the caller can widen
    ``targets`` and check those call sites too, rather than declaring a
    pass-through helper clean and stopping there.
    """
    violations: list[str] = []
    examined = 0
    forwarders: set[str] = set()
    enclosing = _enclosing_params(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = node.func.id if isinstance(node.func, ast.Name) else (
            node.func.attr if isinstance(node.func, ast.Attribute) else None
        )
        if fname not in targets:
            continue
        for kw in node.keywords:
            if kw.arg not in TAXONOMY_KWARGS:
                continue
            examined += 1
            allowed: set[str] = set()
            for set_name in TAXONOMY_KWARGS[kw.arg]:
                allowed |= sets.get(set_name, set())
            if isinstance(kw.value, ast.Name):
                owner, params = enclosing.get(kw.value.lineno, ("", set()))
                if kw.value.id in params:
                    forwarders.add(owner)
                    continue
                value = constants.get(kw.value.id)
                if value is None:
                    violations.append(
                        f"line {kw.value.lineno}: {kw.arg}={kw.value.id} is neither a "
                        f"module-level constant of decision_journal nor a parameter "
                        f"forwarded from an enclosing function"
                    )
                elif value not in allowed:
                    violations.append(
                        f"line {kw.value.lineno}: {kw.arg}={kw.value.id} "
                        f"({value!r}) is outside the closed taxonomy"
                    )
            else:
                violations.append(
                    f"line {kw.value.lineno}: {kw.arg}= is not a taxonomy constant "
                    f"(got {type(kw.value).__name__}). A bare literal is how a "
                    f"governed vocabulary drifts open one caller at a time."
                )
    return violations, examined, forwarders


def test_inv2_every_production_call_site_uses_the_closed_taxonomy():
    journal_tree = _parse(JOURNAL)
    sets = _frozenset_members(journal_tree)
    constants = _constant_names(journal_tree)

    assert sets.get("KEY_LOAD_OUTCOMES"), "taxonomy sets did not parse — blind, not clean"
    assert len(sets["KEY_LOAD_OUTCOMES"]) >= 7
    assert len(sets.get("PROFILE_AUTH_OUTCOMES", ())) >= 8

    trees = {path: _parse(path) for path in _prod_python_files()}

    # Widen the target set to a fixed point: a helper that forwards a taxonomy
    # keyword is followed to ITS call sites, so a pass-through cannot launder a
    # bare literal one frame further out.
    targets = set(BUILDERS)
    all_violations: list[str] = []
    total_examined = 0
    for _ in range(5):
        all_violations, total_examined = [], 0
        widened: set[str] = set()
        for path, tree in trees.items():
            violations, examined, forwarders = _taxonomy_violations(
                tree, sets, constants, targets
            )
            total_examined += examined
            widened |= forwarders
            all_violations += [f"{path.relative_to(ROOT)}:{v}" for v in violations]
        if widened <= targets:
            break
        targets |= widened

    assert total_examined >= 8, (
        f"only {total_examined} taxonomy-bearing arguments found across production "
        f"source. This scan passes by finding nothing, so a population floor is "
        f"what distinguishes clean from blind."
    )
    assert not all_violations, "closed-taxonomy violations:\n  " + "\n  ".join(all_violations)


def test_inv2_negative_self_test_detects_a_bare_literal_and_an_unknown_constant():
    journal_tree = _parse(JOURNAL)
    sets = _frozenset_members(journal_tree)
    constants = _constant_names(journal_tree)

    broken = ast.parse(
        "build_key_load_record(outcome='looks_fine', key_source=KEY_SOURCE_NONE,\n"
        "                      revocation_state=SOMETHING_ELSE)\n"
    )
    violations, examined, forwarders = _taxonomy_violations(
        broken, sets, constants, set(BUILDERS)
    )
    assert examined == 3
    assert len(violations) == 2
    assert any("not a taxonomy constant" in v for v in violations)
    assert any("SOMETHING_ELSE" in v for v in violations)
    assert forwarders == set()


def test_inv2_negative_self_test_follows_a_forwarding_helper_to_its_callers():
    """
    The pass-through case, which is where a closed vocabulary usually leaks: a
    helper takes ``outcome`` as a parameter and hands it on. The helper is not a
    violation — but the analyser must NAME it, so the caller widens the scan
    instead of stopping at a clean-looking frame.
    """
    journal_tree = _parse(JOURNAL)
    sets = _frozenset_members(journal_tree)
    constants = _constant_names(journal_tree)

    src = ast.parse(
        "def _forward(outcome):\n"
        "    return build_profile_auth_record(outcome=outcome)\n"
        "\n"
        "def caller():\n"
        "    return _forward(outcome='invented_on_the_spot')\n"
    )
    violations, _examined, forwarders = _taxonomy_violations(
        src, sets, constants, set(BUILDERS)
    )
    assert violations == [] and forwarders == {"_forward"}

    # Widened, the literal is caught.
    violations, _examined, _f = _taxonomy_violations(
        src, sets, constants, set(BUILDERS) | {"_forward"}
    )
    assert len(violations) == 1 and "not a taxonomy constant" in violations[0]


# ---------------------------------------------------------------------------
# INV-3 — the receipt builders carry an allow-list of value forms
# ---------------------------------------------------------------------------

def _bytes_parameters(fn: ast.FunctionDef) -> set[str]:
    """Parameters whose annotation mentions ``bytes``. Derived, not enumerated."""
    out: set[str] = set()
    args = list(fn.args.args) + list(fn.args.kwonlyargs) + list(fn.args.posonlyargs)
    for arg in args:
        if arg.annotation is not None and "bytes" in ast.unparse(arg.annotation):
            out.add(arg.arg)
    return out


def _param_names(fn: ast.FunctionDef) -> set[str]:
    args = list(fn.args.args) + list(fn.args.kwonlyargs) + list(fn.args.posonlyargs)
    return {a.arg for a in args}


def _validate_value(expr: ast.AST, params: set[str], secret_params: set[str],
                    module_constants: set[str], inside_safe_wrapper: bool) -> list[str]:
    """
    ALLOW-LIST. Returns the reasons this value expression is not a permitted form.

    Permitted:
      * a literal constant;
      * a module-level STRING constant of the taxonomy module (``EVENT_KEY_LOAD``,
        ``RISK_LEVEL``) — a fixed literal under a name;
      * a bare parameter name that is NOT bytes-annotated;
      * a bytes-annotated parameter, but only inside key_id/ciphertext_id/len;
      * a call to one of ALLOWED_VALUE_CALLS;
      * a conditional whose branches are themselves permitted (the test position
        is unconstrained — truthiness discloses nothing).

    Everything else — attributes, f-strings, concatenation, comprehensions,
    arbitrary calls — is refused. That is the point: a deny-list would let the
    next field anyone invents through.
    """
    problems: list[str] = []

    if isinstance(expr, ast.Constant):
        return problems

    if isinstance(expr, ast.Name):
        if expr.id in secret_params and not inside_safe_wrapper:
            problems.append(
                f"line {expr.lineno}: bytes-annotated parameter {expr.id!r} used "
                f"directly as a receipt value; it may appear only inside "
                f"{sorted(SECRET_SAFE_WRAPPERS)}"
            )
        elif expr.id not in params and expr.id not in module_constants:
            problems.append(
                f"line {expr.lineno}: name {expr.id!r} is neither a parameter of "
                f"the builder nor a module-level string constant, so its content "
                f"is not accounted for by this allow-list"
            )
        return problems

    if isinstance(expr, ast.IfExp):
        problems += _validate_value(expr.body, params, secret_params,
                                    module_constants, inside_safe_wrapper)
        problems += _validate_value(expr.orelse, params, secret_params,
                                    module_constants, inside_safe_wrapper)
        return problems

    if isinstance(expr, ast.Call):
        fname = expr.func.id if isinstance(expr.func, ast.Name) else None
        if fname not in ALLOWED_VALUE_CALLS:
            problems.append(
                f"line {expr.lineno}: value produced by {ast.unparse(expr.func)!r}, "
                f"which is not in the permitted set {sorted(ALLOWED_VALUE_CALLS)}"
            )
            return problems
        safe = fname in SECRET_SAFE_WRAPPERS
        for arg in list(expr.args) + [kw.value for kw in expr.keywords]:
            problems += _validate_value(arg, params, secret_params,
                                        module_constants, safe)
        return problems

    problems.append(
        f"line {getattr(expr, 'lineno', 0)}: value form "
        f"{type(expr).__name__} is not permitted in a receipt field"
    )
    return problems


def _builder_violations(tree: ast.Module) -> tuple[list[str], int]:
    problems: list[str] = []
    fields = 0
    module_constants = set(_constant_names(tree))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.FunctionDef) and node.name in BUILDERS):
            continue
        params = _param_names(node)
        secret = _bytes_parameters(node)
        for stmt in ast.walk(node):
            if not (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Dict)):
                continue
            for key, value in zip(stmt.value.keys, stmt.value.values):
                fields += 1
                label = key.value if isinstance(key, ast.Constant) else "<computed>"
                for problem in _validate_value(value, params, secret,
                                               module_constants, False):
                    problems.append(f"{node.name}[{label!r}] {problem}")
    return problems, fields


def test_inv3_every_receipt_field_is_a_permitted_value_form():
    problems, fields = _builder_violations(_parse(JOURNAL))
    assert fields >= 20, (
        f"only {fields} receipt fields examined — the builders were not found, so "
        f"this check is blind rather than clean"
    )
    assert not problems, "receipt-field allow-list violations:\n  " + "\n  ".join(problems)


def test_inv3_the_bytes_parameters_are_discovered_not_enumerated():
    """
    The rule that makes INV-3 fail closed: which parameters are secret-bearing is
    read off the annotations, so a new ``bytes`` argument is constrained the day
    it is added.
    """
    tree = _parse(JOURNAL)
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in BUILDERS:
            found[node.name] = _bytes_parameters(node)
    assert found["build_key_load_record"] == {"key"}
    assert found["build_profile_auth_record"] == {"ciphertext", "key"}
    assert found["build_profile_rollback_record"] == set()


def test_inv3_negative_self_test_detects_a_leaking_field():
    """Four synthetic leaks, each a form a deny-list would have missed."""
    broken = ast.parse(
        "def build_key_load_record(*, outcome: str, key: 'Optional[bytes]' = None,\n"
        "                          hosted_url: 'Optional[str]' = None) -> dict:\n"
        "    return {\n"
        "        'outcome': outcome,\n"
        "        'raw_key': key,\n"
        "        'debug': f'{key!r}',\n"
        "        'echo': repr(key),\n"
        "        'sneaky': key.hex(),\n"
        "    }\n"
    )
    problems, fields = _builder_violations(broken)
    assert fields == 5
    assert len(problems) == 4, problems
    assert any("'raw_key'" in p and "directly as a receipt value" in p for p in problems)
    assert any("'debug'" in p and "JoinedStr" in p for p in problems)
    assert any("'echo'" in p and "repr" in p for p in problems)
    assert any("'sneaky'" in p for p in problems)


def test_inv3_negative_self_test_has_a_passing_control_row():
    """
    DONE.md v1.15 clause 5: a table whose every row asserts failure cannot
    discriminate. A builder built only from permitted forms must come back clean.
    """
    ok = ast.parse(
        "def build_key_load_record(*, outcome: str, key: 'Optional[bytes]' = None,\n"
        "                          hosted_url: 'Optional[str]' = None) -> dict:\n"
        "    return {\n"
        "        'event_type': 'profile_key.load',\n"
        "        'outcome': outcome,\n"
        "        'key_id': key_id(key) if key else None,\n"
        "        'key_length_bytes': len(key) if key else None,\n"
        "        'hosted_origin': hosted_origin(hosted_url) if hosted_url else None,\n"
        "    }\n"
    )
    problems, fields = _builder_violations(ok)
    assert fields == 5
    assert problems == []


# ---------------------------------------------------------------------------
# INV-4 — the receipted decisions have not silently lost their emitters
# ---------------------------------------------------------------------------

def test_inv4_both_governed_decisions_still_have_a_production_emitter():
    """
    A receipt suite green against code that no longer emits is the failure mode
    this catches: the emitters must exist in PRODUCTION source, not only in the
    tests that assert on them.
    """
    emitters: dict[str, list[str]] = {b: [] for b in BUILDERS}
    for path in _prod_python_files():
        if path == JOURNAL:
            continue          # its own definitions are not call sites
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                    and node.func.id in BUILDERS:
                emitters[node.func.id].append(
                    f"{path.relative_to(ROOT)}:{node.lineno}"
                )

    for builder, sites in emitters.items():
        assert sites, (
            f"{builder} has NO production call site. The decision it describes is "
            f"being taken and not recorded — which is precisely the state this "
            f"branch was opened to fix."
        )
    assert len(emitters["build_key_load_record"]) >= 4, emitters
    assert len(emitters["build_profile_auth_record"]) >= 2, emitters
    assert len(emitters["build_profile_rollback_record"]) >= 1, emitters


def test_inv4_negative_self_test_detects_an_emitter_with_no_call_sites():
    """The scan must be able to report absence, or its presence proves nothing."""
    tree = ast.parse("x = 1\n")
    found = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id in BUILDERS]
    assert found == []


# ---------------------------------------------------------------------------
# INV-11 / INV-12 — plaintext custody is policy-driven and receipted
# ---------------------------------------------------------------------------

def _class_method(tree: ast.Module, class_name: str, method_name: str):
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef) or node.name != class_name:
            continue
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and child.name == method_name:
                return child
    return None


def _assigned_value(fn: ast.AST, target_name: str) -> ast.AST | None:
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == target_name:
                return node.value
    return None


def _loaded_names(node: ast.AST) -> set[str]:
    return {
        child.id for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _loaded_attrs(node: ast.AST) -> set[str]:
    return {
        child.attr for child in ast.walk(node)
        if isinstance(child, ast.Attribute) and isinstance(child.ctx, ast.Load)
    }


def _calls_attr(node: ast.AST, attr: str) -> bool:
    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and child.func.attr == attr
        for child in ast.walk(node)
    )


def _is_plaintext_requires_opt_in_guard(fn: ast.AST) -> bool:
    returns = [node.value for node in ast.walk(fn)
               if isinstance(node, ast.Return) and node.value is not None]
    if len(returns) != 1:
        return False
    value = returns[0]
    if isinstance(value, ast.BoolOp):
        return False
    if isinstance(value, ast.Constant) and isinstance(value.value, bool):
        return False
    return (
        isinstance(value, ast.Compare)
        and isinstance(value.left, ast.Name)
        and value.left.id == "policy_state"
        and len(value.ops) == 1
        and isinstance(value.ops[0], ast.NotEq)
        and len(value.comparators) == 1
        and isinstance(value.comparators[0], ast.Name)
        and value.comparators[0].id == "PLAINTEXT_POLICY_DEVELOPMENT"
    )


def _is_encrypted_inventory_prescan(node: ast.AST) -> bool:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "any"
    ):
        return False
    return any(
        isinstance(child, ast.Call)
        and isinstance(child.func, ast.Attribute)
        and child.func.attr == "glob"
        and isinstance(child.func.value, ast.Name)
        and child.func.value.id == "profiles_dir"
        and child.args
        and isinstance(child.args[0], ast.Constant)
        and child.args[0].value == "*.yaml.enc"
        for child in ast.walk(node)
    )


def _plaintext_policy_guard_violations(tree: ast.Module) -> list[str]:
    violations: list[str] = []
    init = _class_method(tree, "ProfileRouter", "__init__")
    policy_state = _class_method(tree, "ProfileRouter", "_plaintext_policy_state")
    requires_opt_in = _class_method(tree, "ProfileRouter", "_plaintext_requires_opt_in")
    load_all = _class_method(tree, "ProfileRouter", "load_all")

    if init is None:
        return ["ProfileRouter.__init__ missing"]
    if policy_state is None:
        violations.append("ProfileRouter._plaintext_policy_state missing")
    if requires_opt_in is None:
        violations.append("ProfileRouter._plaintext_requires_opt_in missing")
    if load_all is None:
        violations.append("ProfileRouter.load_all missing")
        return violations

    init_params = {arg.arg for arg in init.args.args}
    if "encrypted_profile_policy" not in init_params:
        violations.append("ProfileRouter.__init__ has no encrypted_profile_policy parameter")
    if "plaintext_development_mode" not in init_params:
        violations.append("ProfileRouter.__init__ has no plaintext_development_mode parameter")

    if policy_state is not None:
        attrs = _loaded_attrs(policy_state)
        if "_encrypted_profile_policy" not in attrs:
            violations.append("plaintext policy state ignores explicit encrypted-profile policy")
        if "_decryption_key" not in attrs:
            violations.append("plaintext policy state ignores trusted decryption-key state")
        if "_plaintext_development_mode" not in attrs:
            violations.append("plaintext policy state ignores explicit development mode")

    if requires_opt_in is not None and not _is_plaintext_requires_opt_in_guard(requires_opt_in):
        violations.append(
            "plaintext opt-in helper is not a live comparison against the development policy"
        )

    requires_value = _assigned_value(load_all, "plaintext_requires_opt_in")
    if requires_value is None:
        violations.append("load_all does not assign plaintext_requires_opt_in")
    elif not _calls_attr(requires_value, "_plaintext_requires_opt_in"):
        violations.append(
            "plaintext_requires_opt_in is not derived from the plaintext policy helper"
        )

    refusing_value = _assigned_value(load_all, "refusing_plaintext")
    if refusing_value is None:
        violations.append("load_all does not assign refusing_plaintext")
    else:
        names = _loaded_names(refusing_value)
        if "enc_files" in names:
            violations.append(
                "refusing_plaintext reads enc_files directly; unlink/rename of "
                "*.yaml.enc must not be the authority"
            )
        if "plaintext_requires_opt_in" not in names:
            violations.append("refusing_plaintext is not gated by plaintext_requires_opt_in")

    return violations


def _main_router_policy_wiring_violations(tree: ast.Module) -> list[str]:
    violations: list[str] = []
    lifespan = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) \
                and node.name == "lifespan":
            lifespan = node
            break
    if lifespan is None:
        return ["lifespan missing from proxy/main.py"]

    calls = [
        node for node in ast.walk(lifespan)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "ProfileRouter"
    ]
    if not calls:
        return ["lifespan does not construct ProfileRouter"]
    if not any(
        any(kw.arg == "encrypted_profile_policy" for kw in call.keywords)
        for call in calls
    ):
        violations.append(
            "lifespan constructs ProfileRouter without encrypted_profile_policy; "
            "cold-start unlink/rename plants would fall back to directory inventory"
        )
    if not any(
        any(kw.arg == "plaintext_development_mode" for kw in call.keywords)
        for call in calls
    ):
        violations.append(
            "lifespan constructs ProfileRouter without plaintext_development_mode; "
            "audited development plaintext would be implicit and silent"
        )

    encrypted_policy = _assigned_value(lifespan, "encrypted_profile_policy")
    if encrypted_policy is None:
        violations.append("lifespan does not assign encrypted_profile_policy")
    elif "encrypted_inventory_seen" not in _loaded_names(encrypted_policy):
        violations.append(
            "encrypted_profile_policy does not carry encrypted inventory seen "
            "before key resolution; key-fetch outage plus unlink/rename can reopen plaintext"
        )
    inventory_seen = _assigned_value(lifespan, "encrypted_inventory_seen")
    if inventory_seen is None:
        violations.append("lifespan does not assign encrypted_inventory_seen before key load")
    elif not _is_encrypted_inventory_prescan(inventory_seen):
        violations.append(
            "encrypted_inventory_seen is not a real profiles_dir.glob('*.yaml.enc') pre-scan"
        )

    plaintext_development = _assigned_value(lifespan, "plaintext_development_mode")
    if plaintext_development is None:
        violations.append("lifespan does not assign plaintext_development_mode")
    return violations


def _builder_calls_with_outcome(tree: ast.Module, outcome_name: str) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "build_profile_auth_record"):
            continue
        for kw in node.keywords:
            if kw.arg == "outcome" and isinstance(kw.value, ast.Name) \
                    and kw.value.id == outcome_name:
                calls.append(node)
    return calls


def _keyword_names(call: ast.Call) -> set[str]:
    return {kw.arg for kw in call.keywords if kw.arg}


def _plaintext_receipt_violations(router_tree: ast.Module,
                                  journal_tree: ast.Module) -> list[str]:
    constants = _constant_names(journal_tree)
    violations: list[str] = []

    if constants.get("PROFILE_AUTH_PLAINTEXT_REJECTED") != "plaintext_rejected_by_policy":
        violations.append("plaintext refusal outcome still names encrypted-dir inventory")
    if "PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN" not in constants:
        violations.append("plaintext opt-in outcome constant missing")

    rejected = _builder_calls_with_outcome(router_tree, "PROFILE_AUTH_PLAINTEXT_REJECTED")
    if not rejected:
        violations.append("router does not build a plaintext-refusal receipt")
    elif not any("plaintext_policy_state" in _keyword_names(call) for call in rejected):
        violations.append("plaintext-refusal receipt does not name the policy state")

    opt_in = _builder_calls_with_outcome(
        router_tree, "PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN"
    )
    if not opt_in:
        violations.append("router does not build a plaintext opt-in receipt")
    else:
        required = {
            "plaintext_profile_names",
            "plaintext_opt_in_env",
            "plaintext_policy_state",
        }
        if not any(required <= _keyword_names(call) for call in opt_in):
            violations.append(
                "plaintext opt-in receipt does not carry profile names, env name "
                "and policy state"
            )

    return violations


def test_inv11_plaintext_refusal_is_not_keyed_to_the_enc_file_glob():
    violations = (
        _plaintext_policy_guard_violations(_parse(ROUTER))
        + _main_router_policy_wiring_violations(_parse(MAIN))
    )
    assert not violations, "plaintext policy guard violations:\n  " + "\n  ".join(violations)


def test_inv11_negative_self_test_detects_the_old_enc_glob_guard():
    broken = ast.parse(
        "class ProfileRouter:\n"
        "    def __init__(self, profile_dir, decryption_key=None):\n"
        "        self._decryption_key = decryption_key\n"
        "    def load_all(self):\n"
        "        enc_files = sorted(path.glob('*.yaml.enc'))\n"
        "        plaintext_allowed = False\n"
        "        refusing_plaintext = bool(enc_files) and not plaintext_allowed\n"
    )
    violations = _plaintext_policy_guard_violations(broken)
    assert any("encrypted_profile_policy" in v for v in violations)
    assert any("plaintext_development_mode" in v for v in violations)
    assert any("enc_files directly" in v for v in violations)


def test_inv11_negative_self_test_detects_startup_not_passing_policy():
    broken = ast.parse(
        "async def lifespan(app):\n"
        "    profile_router = ProfileRouter('profiles', audit_writer=audit_writer)\n"
    )
    violations = _main_router_policy_wiring_violations(broken)
    assert any("without encrypted_profile_policy" in v for v in violations)
    assert any("without plaintext_development_mode" in v for v in violations)
    assert any("encrypted_profile_policy" in v for v in violations)


def test_inv11_negative_self_test_detects_startup_dropping_pre_key_inventory():
    broken = ast.parse(
        "async def lifespan(app):\n"
        "    decryption_key, _status = await _resolve_profile_key(audit_writer, profiles_dir)\n"
        "    encrypted_profile_policy = require_flag or decryption_key is not None\n"
        "    plaintext_development_mode = allow_plaintext\n"
        "    profile_router = ProfileRouter(\n"
        "        'profiles', audit_writer=audit_writer,\n"
        "        encrypted_profile_policy=encrypted_profile_policy,\n"
        "        plaintext_development_mode=plaintext_development_mode,\n"
        "    )\n"
    )
    violations = _main_router_policy_wiring_violations(broken)
    assert any("before key resolution" in v for v in violations)


def test_inv11_negative_self_test_detects_dead_plaintext_requires_guard():
    broken = ast.parse(
        "class ProfileRouter:\n"
        "    def __init__(self, profile_dir, decryption_key=None,\n"
        "                 encrypted_profile_policy=False, plaintext_development_mode=False):\n"
        "        self._decryption_key = decryption_key\n"
        "        self._encrypted_profile_policy = encrypted_profile_policy\n"
        "        self._plaintext_development_mode = plaintext_development_mode\n"
        "    def _plaintext_policy_state(self, enc_files):\n"
        "        if self._encrypted_profile_policy:\n"
        "            return PLAINTEXT_POLICY_ENCRYPTED_PROFILE_POLICY\n"
        "        if self._decryption_key is not None:\n"
        "            return PLAINTEXT_POLICY_TRUSTED_DECRYPTION_KEY\n"
        "        if self._plaintext_development_mode:\n"
        "            return PLAINTEXT_POLICY_DEVELOPMENT\n"
        "        return PLAINTEXT_POLICY_UNMARKED_PLAINTEXT_DIRECTORY\n"
        "    @staticmethod\n"
        "    def _plaintext_requires_opt_in(policy_state):\n"
        "        return False and policy_state != PLAINTEXT_POLICY_DEVELOPMENT\n"
        "    def load_all(self):\n"
        "        plaintext_requires_opt_in = self._plaintext_requires_opt_in(policy_state)\n"
        "        refusing_plaintext = plaintext_requires_opt_in and not plaintext_allowed\n"
    )
    violations = _plaintext_policy_guard_violations(broken)
    assert any("not a live comparison" in v for v in violations)


def test_inv11_negative_self_test_detects_dead_encrypted_inventory_prescan():
    broken = ast.parse(
        "async def lifespan(app):\n"
        "    encrypted_inventory_seen = False\n"
        "    decryption_key, _status = await _resolve_profile_key(audit_writer, profiles_dir)\n"
        "    encrypted_profile_policy = require_flag or decryption_key is not None or encrypted_inventory_seen\n"
        "    plaintext_development_mode = allow_plaintext\n"
        "    profile_router = ProfileRouter(\n"
        "        'profiles', audit_writer=audit_writer,\n"
        "        encrypted_profile_policy=encrypted_profile_policy,\n"
        "        plaintext_development_mode=plaintext_development_mode,\n"
        "    )\n"
    )
    violations = _main_router_policy_wiring_violations(broken)
    assert any("not a real" in v for v in violations)


def test_inv12_plaintext_refusal_and_opt_in_are_both_receipted():
    violations = _plaintext_receipt_violations(_parse(ROUTER), _parse(JOURNAL))
    assert not violations, "plaintext receipt violations:\n  " + "\n  ".join(violations)


def test_inv12_negative_self_test_detects_opt_in_without_receipt():
    journal = ast.parse(
        "PROFILE_AUTH_PLAINTEXT_REJECTED = 'plaintext_rejected_by_policy'\n"
    )
    router = ast.parse(
        "def load_all(self):\n"
        "    self.decision_journal.record(build_profile_auth_record(\n"
        "        outcome=PROFILE_AUTH_PLAINTEXT_REJECTED,\n"
        "        skipped_profile_names=['plain.yaml'],\n"
        "        plaintext_policy_state=state,\n"
        "    ))\n"
    )
    violations = _plaintext_receipt_violations(router, journal)
    assert any("opt-in outcome constant missing" in v for v in violations)
    assert any("plaintext opt-in receipt" in v for v in violations)


def test_inv12_negative_self_test_detects_refusal_receipt_still_named_for_enc_dir():
    journal = ast.parse(
        "PROFILE_AUTH_PLAINTEXT_REJECTED = 'plaintext_rejected_encrypted_dir'\n"
        "PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN = 'plaintext_allowed_explicit_opt_in'\n"
    )
    router = ast.parse(
        "def load_all(self):\n"
        "    self.decision_journal.record(build_profile_auth_record(\n"
        "        outcome=PROFILE_AUTH_PLAINTEXT_REJECTED,\n"
        "        skipped_profile_names=['plain.yaml'],\n"
        "        plaintext_policy_state=state,\n"
        "    ))\n"
        "    self.decision_journal.record(build_profile_auth_record(\n"
        "        outcome=PROFILE_AUTH_PLAINTEXT_ALLOWED_OPT_IN,\n"
        "        plaintext_profile_names=['plain.yaml'],\n"
        "        plaintext_opt_in_env='ARKHEIA_ALLOW_PLAINTEXT_PROFILES',\n"
        "        plaintext_policy_state=state,\n"
        "    ))\n"
    )
    violations = _plaintext_receipt_violations(router, journal)
    assert any("encrypted-dir inventory" in v for v in violations)


# ---------------------------------------------------------------------------
# INV-6 / INV-7 — the F20 path's dependency is DECLARED, at a consistent floor
# ---------------------------------------------------------------------------
#
# The recorded ground was "cryptography is undeclared in the root
# requirements.txt while build_release.py imports it at module import time, so
# anything deploying it crashes at import". Re-derived against reality on a clean
# Python 3.12 venv built from requirements.txt alone: it does NOT crash.
# `mcp==1.28.1` -> `PyJWT[crypto]>=2.10.1` -> `cryptography>=3.4.0` supplies it
# transitively. The ground as written is overstated, and saying so is the point
# of re-deriving it.
#
# What IS true is sharper and worse-shaped: this distribution's only crypto
# dependency was satisfied by an *extra of a transitive dependency*, at a floor
# of >=3.4.0 while proxy/requirements.txt pins >=48.0.1 for named CVEs. A
# resolver is free to install a vulnerable version, `pip-audit -r
# requirements.txt` never sees the package at all, and an `mcp` bump that drops
# PyJWT removes it entirely. Two invariants, both auto-discovering:
#
#   INV-6  no package may carry different version floors in different
#          requirements files — the drift IS the vulnerability window;
#   INV-7  every third-party module the F20 build path imports at module-import
#          time is declared by the distribution that ships that path.
#
# The GENERAL form of INV-7 across all distributions is PR #27
# (sweep/mcp-declared-dependency-floor), open and not merged. INV-7 here is
# scoped to this flow's own entry points and does not duplicate it.

#: Entry points shipped by the ROOT distribution that reach the F20 crypto path.
F20_ENTRY_POINTS = ("scripts/build_release.py", "scripts/encrypt_profiles.py")

#: Modules that ship with CPython. Anything imported that is neither stdlib nor
#: an intra-repo package is a third-party dependency that must be declared.
def _stdlib_names() -> frozenset[str]:
    import sys
    return frozenset(getattr(sys, "stdlib_module_names", frozenset())) | frozenset({
        "__future__",
    })


def _requirements_files() -> list[Path]:
    out = []
    for p in sorted(ROOT.rglob("requirements*.txt")):
        if "node_modules" in p.parts or ".venv" in p.parts:
            continue
        out.append(p)
    return out


def _parse_requirements(path: Path) -> dict[str, str]:
    """
    ``{normalised name: MINIMUM version}``. Comments and blank lines ignored.

    The **minimum** is the invariant's subject, not the operator. ``mcp==1.28.1``
    and ``mcp>=1.28.1`` admit the same lowest version, and the lowest version an
    install may resolve to is the whole of the vulnerability window; whether a
    distribution additionally caps the top is a legitimate policy difference and
    is deliberately not constrained here. Comparing the raw spec string instead
    would flag that difference as drift — a false positive, and a floor that
    cries wolf gets switched off.
    """
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        for sep in (">=", "==", "~=", ">"):
            if sep in line:
                name, _, spec = line.partition(sep)
                base = name.split("[", 1)[0].strip().lower().replace("_", "-")
                out[base] = spec.strip().split(",")[0].strip()
                break
        else:
            base = line.split("[", 1)[0].strip().lower().replace("_", "-")
            if base:
                out[base] = ""
    return out


def test_inv6_no_package_carries_different_version_floors_in_different_files():
    files = _requirements_files()
    assert len(files) >= 3, (
        f"only {len(files)} requirements files discovered — the glob is wrong, "
        f"and a wrong glob is indistinguishable from a consistent estate"
    )

    declared: dict[str, dict[str, str]] = {}
    for path in files:
        for name, spec in _parse_requirements(path).items():
            declared.setdefault(name, {})[str(path.relative_to(ROOT))] = spec

    shared = {n: d for n, d in declared.items() if len(d) > 1}
    assert len(shared) >= 5, (
        f"only {len(shared)} packages appear in more than one file; this check "
        f"passes by finding nothing, so its population is pinned"
    )

    divergent = {
        name: specs for name, specs in shared.items()
        if len({s for s in specs.values()}) > 1
    }
    assert not divergent, (
        "a package is declared with different version floors in different "
        "distributions. Whichever file is looser is the one an install will "
        "resolve against, and the CVE pin in the stricter file buys nothing:\n  "
        + "\n  ".join(f"{n}: {s}" for n, s in sorted(divergent.items()))
    )


def test_inv6_negative_self_test_detects_a_divergent_floor(tmp_path):
    a = tmp_path / "requirements.txt"
    b = tmp_path / "sub-requirements.txt"
    a.write_text("cryptography>=3.4.0\nhttpx>=0.27.1\nmcp>=1.28.1\n")
    b.write_text("cryptography>=48.0.1  # CVE pin\nhttpx>=0.27.1\nmcp==1.28.1\n")
    parsed = {p.name: _parse_requirements(p) for p in (a, b)}
    # Caught: different minimums.
    assert parsed["requirements.txt"]["cryptography"] == "3.4.0"
    assert parsed["sub-requirements.txt"]["cryptography"] == "48.0.1"
    # Control row — must NOT be flagged: same minimum, different operator, and an
    # identical spec. A table whose every row asserts failure cannot discriminate.
    assert parsed["requirements.txt"]["httpx"] == parsed["sub-requirements.txt"]["httpx"]
    assert parsed["requirements.txt"]["mcp"] == parsed["sub-requirements.txt"]["mcp"]


def _module_import_time_imports(path: Path) -> set[str]:
    """Top-level (module-import-time) imports only. A function-local import is a
    different risk and is not this invariant's subject."""
    names: set[str] = set()
    tree = _parse(path)
    for node in tree.body:
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def _intra_repo_closure(entry: Path) -> set[Path]:
    """Every intra-repo module reachable from ``entry`` by module-import-time
    imports. This is what actually executes when the entry point is run."""
    seen: set[Path] = set()
    queue = [entry]
    while queue:
        current = queue.pop()
        if current in seen or not current.is_file():
            continue
        seen.add(current)
        tree = _parse(current)
        for node in tree.body:
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            for mod in modules:
                candidate = ROOT / Path(*mod.split("."))
                for target in (candidate.with_suffix(".py"), candidate / "__init__.py"):
                    if target.is_file():
                        queue.append(target)
    return seen


def test_inv7_the_f20_build_path_declares_every_dependency_it_imports():
    declared = _parse_requirements(ROOT / "requirements.txt")
    stdlib = _stdlib_names()

    reached: set[Path] = set()
    for rel in F20_ENTRY_POINTS:
        entry = ROOT / rel
        assert entry.is_file(), f"{rel} is missing — INV-7 went blind, not clean"
        reached |= _intra_repo_closure(entry)

    assert len(reached) >= 3, (
        f"the import closure of {F20_ENTRY_POINTS} reached only {len(reached)} "
        f"module(s); a closure that walks nowhere cannot clear anything"
    )

    third_party: dict[str, str] = {}
    for module in sorted(reached):
        for name in _module_import_time_imports(module):
            if name in stdlib:
                continue
            if (ROOT / name).is_dir() or (ROOT / f"{name}.py").is_file():
                continue          # intra-repo
            third_party[name.lower().replace("_", "-")] = str(module.relative_to(ROOT))

    assert third_party, (
        "no third-party import found anywhere on the F20 build path. That is "
        "implausible — profile_crypto.py imports `cryptography` — so this check "
        "is broken rather than the code being clean."
    )

    missing = {n: src for n, src in third_party.items() if n not in declared}
    assert not missing, (
        "the F20 build path imports packages the ROOT distribution does not "
        "declare. They may resolve today via some other package's extra, at a "
        "version floor nobody chose:\n  "
        + "\n  ".join(f"{n}  (imported by {src})" for n, src in sorted(missing.items()))
    )
    assert "cryptography" in third_party, (
        "cryptography was not discovered on the F20 build path — the closure "
        "walk stopped short, so a clean result here means nothing"
    )


def test_inv7_negative_self_test_detects_an_undeclared_import(tmp_path):
    declared = _parse_requirements(ROOT / "requirements.txt")
    fake = tmp_path / "m.py"
    fake.write_text("import cryptography\nimport a_package_nobody_declared\n")
    imported = {n.lower().replace("_", "-") for n in _module_import_time_imports(fake)}
    assert "cryptography" in declared          # positive control
    assert "a-package-nobody-declared" in imported
    assert "a-package-nobody-declared" not in declared


# ---------------------------------------------------------------------------
# INV-8 — no field read from a decision record reaches a log sink
# ---------------------------------------------------------------------------
#
# Earned by CodeQL on PR #34: two HIGH
# ``py/clear-text-logging-sensitive-data`` alerts on this very module. A decision
# record is built from arguments that include key material, so every field read
# out of one carries that lineage — and static analysis is right to refuse to
# distinguish the safe fields from the unsafe ones inside a single dict. Today's
# fields are all taxonomy constants; the field someone adds next year might not
# be, and that is one line away from stdout.
#
# The rule is therefore structural rather than a judgement about which fields are
# safe: inside the taxonomy module, an argument to a logging call may not be a
# subscript or ``.get()`` on a dict. Labels go through ``_label`` / ``_uuid_label``,
# which return module-level literals.

LOG_CALL_ATTRS = frozenset({"debug", "info", "warning", "error", "exception",
                            "critical", "log"})

#: Resolvers that launder a record field into a module-owned literal.
LOG_SANITISERS = frozenset({"_label", "_uuid_label"})


def _record_field_log_violations(tree: ast.Module) -> tuple[list[str], int]:
    """``(violations, logging calls examined)``."""
    violations: list[str] = []
    examined = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in LOG_CALL_ATTRS):
            continue
        examined += 1
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                bad = None
                if isinstance(sub, ast.Subscript):
                    bad = ast.unparse(sub)
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) \
                        and sub.func.attr == "get":
                    bad = ast.unparse(sub)
                if bad is None:
                    continue
                # Permitted only when wrapped by a declared sanitiser.
                wrapped = any(
                    isinstance(outer, ast.Call)
                    and isinstance(outer.func, ast.Name)
                    and outer.func.id in LOG_SANITISERS
                    and sub in list(ast.walk(outer))
                    for outer in ast.walk(arg)
                )
                if not wrapped:
                    violations.append(
                        f"line {sub.lineno}: {bad} is read from a record and passed "
                        f"straight to a log call; route it through "
                        f"{sorted(LOG_SANITISERS)}"
                    )
    return violations, examined


def test_inv8_no_record_field_is_logged_unresolved():
    violations, examined = _record_field_log_violations(_parse(JOURNAL))
    assert examined >= 2, (
        f"only {examined} logging calls found in {JOURNAL.name} — this check "
        f"passes by finding nothing, so its population is pinned"
    )
    assert not violations, (
        "a decision-record field reaches a log sink unresolved:\n  "
        + "\n  ".join(violations)
    )


def test_inv8_negative_self_test_detects_a_raw_field_in_a_log_call():
    broken = ast.parse(
        "logger.error('a=%s b=%s c=%s', out.get('outcome'), out['key_id'],\n"
        "             _label(out.get('event_type'), EVENT_TYPES))\n"
    )
    violations, examined = _record_field_log_violations(broken)
    assert examined == 1
    assert len(violations) == 2, violations
    assert any("out.get('outcome')" in v for v in violations)
    assert any("out['key_id']" in v for v in violations)
    # Control: the sanitised argument is NOT flagged, so the check discriminates
    # rather than merely forbidding.
    assert not any("event_type" in v for v in violations)


# ---------------------------------------------------------------------------
# INV-9 / INV-10 — the rail has exactly ONE door, and that door stamps
# ---------------------------------------------------------------------------
#
# Earned by Codex on PR #34, in this branch, against the fix itself: ``proxy/
# main.py`` has four posture branches that call ``emit(build_key_load_record(...))``
# **directly**, and ``DecisionJournal.record`` was the only code that stamped
# ``decision_id`` / ``decided_at``. So the branch that actually fires in
# production wrote a hash-chained row with no decision identity and
# ``receipt_deferred_ms: null`` — a record that looks like evidence and is not
# one. The deferral mechanism was real and the production path never reached it.
#
# The fix is structural: ``stamp_decision`` runs inside ``emit``, and ``emit`` is
# the only route to a writer. These two invariants are what keep that true for a
# FIFTH branch nobody has written yet:
#
#   INV-9   every receipt a production module builds is consumed by ``emit(...)``
#           or ``<journal>.record(...)`` — it cannot be handed anywhere else;
#   INV-10  on the governance path, the only ``.write(...)`` call is the one
#           inside ``emit`` — so nothing can go round the stamping.
#
# The governance path is DISCOVERED (modules that import the decision taxonomy),
# never enumerated, so a new module joins the invariant the day it imports.

#: Calls that legitimately consume a freshly built receipt.
RECEIPT_CONSUMERS = frozenset({"emit", "record"})


def _governance_path_files() -> list[Path]:
    """Production modules that import ``proxy.audit.decision_journal``, plus the
    module itself. Discovered from the import graph, not a hand-kept list."""
    out: list[Path] = [JOURNAL]
    for path in _prod_python_files():
        if path == JOURNAL:
            continue
        tree = _parse(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module \
                    and node.module.endswith("audit.decision_journal"):
                out.append(path)
                break
    return out


def _unconsumed_receipts(tree: ast.Module) -> tuple[list[str], int]:
    """
    ``(violations, builder call sites examined)``.

    A builder call is consumed when it is a direct argument of a consumer, or
    when its result is bound to a name that a consumer is passed in the same
    function. Anything else — logged, returned bare, stored on an attribute,
    handed to a writer — is a receipt that can reach disk without being stamped.
    """
    violations: list[str] = []
    examined = 0

    for fn in [n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        # Names a consumer is handed anywhere in this function.
        consumed_names: set[str] = set()
        # Builder calls passed straight into a consumer.
        consumed_calls: set[int] = set()
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            fname = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else None
            )
            if fname not in RECEIPT_CONSUMERS:
                continue
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                if isinstance(arg, ast.Name):
                    consumed_names.add(arg.id)
                elif isinstance(arg, ast.Call):
                    consumed_calls.add(id(arg))

        # Names bound from a builder call.
        bound: dict[int, str] = {}
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) \
                    and isinstance(node.value.func, ast.Name) \
                    and node.value.func.id in BUILDERS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        bound[id(node.value)] = target.id

        for node in ast.walk(fn):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in BUILDERS):
                continue
            examined += 1
            if id(node) in consumed_calls:
                continue
            name = bound.get(id(node))
            if name is not None and name in consumed_names:
                continue
            violations.append(
                f"line {node.lineno}: {node.func.id}(...) inside {fn.name}() is not "
                f"consumed by {sorted(RECEIPT_CONSUMERS)}. A receipt that reaches "
                f"the rail by another route is not stamped with its decision "
                f"identity — the exact defect Codex reproduced on PR #34"
            )
    return violations, examined


def test_inv9_every_built_receipt_is_consumed_by_the_stamping_path():
    files = _governance_path_files()
    assert len(files) >= 3, (
        f"only {len(files)} module(s) discovered on the governance path; the "
        f"import walk is wrong, and a wrong walk reads exactly like a clean estate"
    )

    violations: list[str] = []
    examined = 0
    for path in files:
        found, count = _unconsumed_receipts(_parse(path))
        examined += count
        violations += [f"{path.relative_to(ROOT)}:{v}" for v in found]

    assert examined >= 6, (
        f"only {examined} receipt-builder call sites examined across the "
        f"governance path — this check passes by finding nothing, so its "
        f"population is pinned"
    )
    assert not violations, "unconsumed receipts:\n  " + "\n  ".join(violations)


def test_inv9_negative_self_test_detects_a_receipt_that_goes_round_the_door():
    broken = ast.parse(
        "async def fifth_branch(writer):\n"
        "    record = build_key_load_record(outcome=KEY_LOAD_UNAVAILABLE)\n"
        "    await writer.write(record)\n"
    )
    violations, examined = _unconsumed_receipts(broken)
    assert examined == 1 and len(violations) == 1
    assert "not consumed" in violations[0]


def test_inv9_negative_self_test_has_passing_control_rows():
    """
    DONE.md v1.15 clause 5. Both legitimate shapes must come back clean, or the
    check merely forbids rather than discriminates.
    """
    direct = ast.parse(
        "async def branch(writer):\n"
        "    return await emit(writer, build_key_load_record(outcome=X))\n"
    )
    bound = ast.parse(
        "async def branch(self):\n"
        "    record = build_profile_auth_record(outcome=X)\n"
        "    return self.decision_journal.record(record)\n"
    )
    for tree in (direct, bound):
        violations, examined = _unconsumed_receipts(tree)
        assert examined == 1 and violations == []


def _writes_outside_emit(path: Path) -> tuple[list[str], int]:
    """
    ``(violations, awaited .write() call sites examined)`` for one module.

    Only **awaited** ``.write(...)`` counts. ``AuditWriter.write`` is a coroutine,
    so that is exactly the shape of a rail write; a synchronous ``f.write(...)``
    to a file is a different act and flagging it would make this floor cry wolf,
    which is how a floor gets switched off.
    """
    tree = _parse(path)
    inside_emit: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == "emit":
            for child in ast.walk(node):
                inside_emit.add(id(child))

    awaited: set[int] = {
        id(node.value) for node in ast.walk(tree) if isinstance(node, ast.Await)
    }

    violations: list[str] = []
    examined = 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "write" and id(node) in awaited):
            continue
        examined += 1
        if id(node) in inside_emit:
            continue
        violations.append(
            f"line {node.lineno}: {ast.unparse(node.func)}(...) writes to a rail "
            f"outside emit(). emit() is where a record is stamped with its "
            f"decision identity; a write that goes round it lands unstamped"
        )
    return violations, examined


def test_inv10_the_governance_path_writes_to_the_rail_only_through_emit():
    violations: list[str] = []
    examined = 0
    for path in _governance_path_files():
        found, count = _writes_outside_emit(path)
        examined += count
        violations += [f"{path.relative_to(ROOT)}:{v}" for v in found]

    assert examined >= 1, (
        "no .write(...) call found anywhere on the governance path. The one "
        "inside emit() must exist, so finding none means this check is blind"
    )
    assert not violations, "writes that bypass the stamping door:\n  " + "\n  ".join(violations)


def test_inv10_negative_self_test_detects_a_write_that_bypasses_emit(tmp_path):
    module = tmp_path / "m.py"
    module.write_text(
        "async def emit(writer, record):\n"
        "    await writer.write(record)\n"
        "\n"
        "async def fifth_branch(writer, record):\n"
        "    await writer.write(record)\n"
        "\n"
        "def save(path, blob):\n"
        "    with open(path, 'w') as f:\n"
        "        f.write(blob)\n",
        encoding="utf-8",
    )
    violations, examined = _writes_outside_emit(module)
    # Two control rows, so the check discriminates rather than banning the word
    # "write": the awaited write INSIDE emit is clean, and a synchronous file
    # write is not this invariant's subject at all.
    assert examined == 2 and len(violations) == 1
    assert "line 5" in violations[0]


# ---------------------------------------------------------------------------
# INV-5 — this file's own subject matter still exists
# ---------------------------------------------------------------------------

def test_inv5_the_files_this_floor_reasons_about_are_present():
    """
    A path that moved turns every check above into a permanent pass. Assert the
    subjects exist and are non-trivial before believing anything they said.
    """
    for path in (MAIN, JOURNAL):
        assert path.is_file(), f"{path} is missing — every check in this file went blind"
        assert len(path.read_text(encoding="utf-8").splitlines()) > 50
    assert len(_prod_python_files()) >= 20, (
        "the production file scan found almost nothing; a mistyped root is "
        "indistinguishable from a clean estate"
    )
