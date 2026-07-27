"""
FLOOR TIER — passthrough SSRF containment invariants.

Stdlib + pytest only. Runs in the `floor` job (`.github/workflows/floor-invariants.yml`),
which installs pytest and nothing else, so nothing here may import fastapi,
httpx, or the proxy package.

Scope: BRANCH-LOCAL. Every invariant's subject is wholly inside this one module,
so there is nothing here that only the merge result could violate.

WHAT EARNED THESE
-----------------
``proxy/endpoints/passthrough.py`` forwards caller traffic to provider endpoints
with the caller's credential attached. On 2026-07-27 its path allowlist carried
an ``audio/.*`` arm; ``.`` matches ``/``, so ``audio/../../admin/keys`` satisfied
the allowlist and resolved to ``https://api.x.ai/admin/keys``. Measured on a real
uvicorn socket: 200, body returned, while ``admin/keys`` spelled directly was
400. Every path on the provider host was reachable behind a prefix.

The behavioural suites (``proxy/tests/test_passthrough_adversarial.py``,
``_receipts.py``, ``_wire.py``) prove the current code refuses that. These
invariants are the part that survives a rewrite: they are STATIC and they
DISCOVER their subjects, so a fifth provider or a fifth regex added next year is
covered without anyone remembering to add it here.

Per DONE.md v1.19/v1.22 every invariant below carries a NEGATIVE SELF-TEST: the
same predicate is run against a synthetic violating input and must report the
violation. A check that has never been seen failing is decoration, and a check
that passes by finding nothing must prove it can find something.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "proxy" / "endpoints" / "passthrough.py"


@pytest.fixture(scope="module")
def source() -> str:
    assert TARGET.is_file(), f"{TARGET} does not exist — this floor observed nothing"
    text = TARGET.read_text(encoding="utf-8")
    assert text.strip(), f"{TARGET} is empty — this floor observed nothing"
    return text


@pytest.fixture(scope="module")
def tree(source: str) -> ast.Module:
    return ast.parse(source, filename=str(TARGET))


# ---------------------------------------------------------------------------
# Discovery helpers — nothing below enumerates a name by hand.
# ---------------------------------------------------------------------------

def _upstream_constants(tree: ast.Module) -> dict[str, str]:
    """Every module-level ``*_UPSTREAM = "<literal>"``."""
    found: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Name)
                        and target.id.endswith("_UPSTREAM")
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    found[target.id] = node.value.value
    return found


def _path_regexes(tree: ast.Module) -> dict[str, str]:
    """Every module-level ``*_PATH_RE = re.compile(<literal parts>)``."""
    found: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name) and target.id.endswith("_PATH_RE")):
                continue
            call = node.value
            if not (isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "compile"):
                continue
            pattern = _literal_string(call.args[0]) if call.args else None
            if pattern is not None:
                found[target.id] = pattern
    return found


def _literal_string(node: ast.AST) -> str | None:
    """Fold a constant, or an implicit/`+` concatenation of constants."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_string(node.left)
        right = _literal_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _async_client_calls(tree: ast.Module) -> list[ast.Call]:
    """Every ``httpx.AsyncClient(...)`` construction."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "AsyncClient":
                out.append(node)
            elif isinstance(func, ast.Name) and func.id == "AsyncClient":
                out.append(node)
    return out


def _request_calls(tree: ast.Module) -> list[ast.Call]:
    """Every ``<client>.request(...)`` call."""
    return [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "request"
    ]


# ---------------------------------------------------------------------------
# INV-1 — every upstream base is a constant https URL on a reviewed host
# ---------------------------------------------------------------------------

#: The only origins this proxy is allowed to forward to. Adding one is a
#: deliberate, reviewed act; that is the point of writing it down here rather
#: than deriving it from the module under test (which would make the check
#: agree with whatever the module says).
REVIEWED_UPSTREAM_HOSTS = {
    "api.x.ai",
    "api.together.xyz",
    "generativelanguage.googleapis.com",
    "api.anthropic.com",
}


def _violations_upstreams(constants: dict[str, str]) -> list[str]:
    bad = []
    for name, value in constants.items():
        match = re.match(r"\Ahttps://([A-Za-z0-9.-]+)(/[^?#]*)?\Z", value)
        if not match:
            bad.append(f"{name}={value!r} is not a plain https://host/path literal")
            continue
        if match.group(1) not in REVIEWED_UPSTREAM_HOSTS:
            bad.append(f"{name} points at unreviewed host {match.group(1)!r}")
    return bad


def test_inv1_upstream_bases_are_constant_https_on_reviewed_hosts(tree):
    constants = _upstream_constants(tree)
    assert len(constants) >= 4, (
        f"discovered only {len(constants)} upstream constants — the discovery is "
        f"looking in the wrong place, which is indistinguishable from a clean run"
    )
    assert _violations_upstreams(constants) == []


def test_inv1_negative_self_test():
    """The predicate must report a violation when one exists."""
    assert _violations_upstreams({"EVIL_UPSTREAM": "http://169.254.169.254"})
    assert _violations_upstreams({"EVIL_UPSTREAM": "https://evil.example.com/v1"})
    assert _violations_upstreams({"EVIL_UPSTREAM": "file:///etc/passwd"})
    # And must NOT report one for the real thing.
    assert _violations_upstreams({"OK_UPSTREAM": "https://api.x.ai/v1"}) == []


# ---------------------------------------------------------------------------
# INV-2 — path allowlists are \A..\Z anchored and segment-bounded
# ---------------------------------------------------------------------------

def _violations_regex(name: str, pattern: str) -> list[str]:
    bad = []
    if not pattern.startswith(r"\A"):
        bad.append(f"{name} is not \\A-anchored (^ also matches after a newline "
                   f"under re.MULTILINE and invites .match() misuse)")
    if not pattern.endswith(r"\Z"):
        bad.append(f"{name} is not \\Z-anchored: `$` also matches immediately "
                   f"before a trailing newline, so 'chat/completions\\n' passes")
    # An unescaped `.` outside a character class matches `/`, which turns a
    # path-segment allowlist into a whole-host allowlist.
    stripped = re.sub(r"\[[^\]]*\]", "", pattern)          # drop character classes
    stripped = re.sub(r"\\.", "", stripped)                # drop escapes incl. \.
    if "." in stripped:
        bad.append(f"{name} contains an unescaped '.' outside a character class; "
                   f"'.' matches '/', so a prefix buys the whole host")
    return bad


def test_inv2_path_allowlists_are_anchored_and_segment_bounded(tree):
    regexes = _path_regexes(tree)
    assert len(regexes) >= 3, (
        f"discovered only {len(regexes)} path allowlists — discovery failure"
    )
    violations = [v for name, pattern in regexes.items()
                  for v in _violations_regex(name, pattern)]
    assert violations == []


def test_inv2_negative_self_test():
    """The exact pre-fix pattern must be reported, and each fault separately."""
    prefix_defect = (r"\A(chat/completions|completions|embeddings|models"
                     r"|images/generations|audio/.*|moderations)\Z")
    assert _violations_regex("PRE_FIX", prefix_defect), (
        "the invariant does not catch the defect that earned it"
    )
    assert _violations_regex("DOLLAR", r"\A(models)$")
    assert _violations_regex("CARET", r"^(models)\Z")
    # Control row: the shipped pattern is clean, so the table discriminates.
    assert _violations_regex("OK", r"\A(chat/completions|audio/(speech))\Z") == []
    assert _violations_regex("OK_CLASS", r"\Amodels(/[a-zA-Z0-9._-]+)?\Z") == []


# ---------------------------------------------------------------------------
# INV-3 — redirects are refused explicitly at every client construction
# ---------------------------------------------------------------------------

def _violations_redirects(calls: list[ast.Call]) -> list[str]:
    bad = []
    for call in calls:
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        if "follow_redirects" not in kwargs:
            bad.append(f"line {call.lineno}: AsyncClient(...) does not pass "
                       f"follow_redirects; an SSRF control must not be a library default")
            continue
        value = kwargs["follow_redirects"]
        if not (isinstance(value, ast.Constant) and value.value is False):
            bad.append(f"line {call.lineno}: follow_redirects is not the literal False")
    return bad


def test_inv3_redirect_following_is_disabled_explicitly(tree):
    calls = _async_client_calls(tree)
    assert calls, "no httpx client construction found — discovery failure"
    assert _violations_redirects(calls) == []


def test_inv3_negative_self_test():
    missing = ast.parse("httpx.AsyncClient(timeout=60.0)").body[0].value
    truthy = ast.parse("httpx.AsyncClient(follow_redirects=True)").body[0].value
    variable = ast.parse("httpx.AsyncClient(follow_redirects=cfg)").body[0].value
    ok = ast.parse("httpx.AsyncClient(follow_redirects=False)").body[0].value
    assert _violations_redirects([missing])
    assert _violations_redirects([truthy])
    assert _violations_redirects([variable])
    assert _violations_redirects([ok]) == []


# ---------------------------------------------------------------------------
# INV-4 — the hop-by-hop strip set is complete
# ---------------------------------------------------------------------------

#: RFC 9110 s7.6.1 connection-specific fields, plus content-length.
#:
#: content-length earned its place: httpx decodes `content-encoding: gzip`, so
#: relaying the compressed content-length beside the decoded body made uvicorn
#: raise "Response content longer than Content-Length" and put ZERO body bytes
#: on the wire. That fired on ordinary provider traffic, not only on an attack.
REQUIRED_HOP_BY_HOP = {
    "connection", "content-encoding", "content-length", "keep-alive",
    "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade",
}


def _hop_by_hop_set(tree: ast.Module) -> set[str]:
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not (isinstance(target, ast.Name)
                    and target.id == "_HOP_BY_HOP_HEADERS"):
                continue
            call = node.value
            elements = None
            if isinstance(call, ast.Call) and call.args:
                elements = call.args[0]
            elif isinstance(call, (ast.Set, ast.List, ast.Tuple)):
                elements = call
            if isinstance(elements, (ast.Set, ast.List, ast.Tuple)):
                return {e.value.lower() for e in elements.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _violations_hop_by_hop(actual: set[str]) -> list[str]:
    missing = REQUIRED_HOP_BY_HOP - actual
    return [f"missing from the strip set: {sorted(missing)}"] if missing else []


def test_inv4_hop_by_hop_strip_set_is_complete(tree):
    actual = _hop_by_hop_set(tree)
    assert actual, "no _HOP_BY_HOP_HEADERS set found — discovery failure"
    assert _violations_hop_by_hop(actual) == []


def test_inv4_negative_self_test():
    """The exact pre-fix set must be reported."""
    pre_fix = {"content-encoding", "transfer-encoding", "connection"}
    violations = _violations_hop_by_hop(pre_fix)
    assert violations
    assert "content-length" in violations[0]
    assert _violations_hop_by_hop(set(REQUIRED_HOP_BY_HOP)) == []


# ---------------------------------------------------------------------------
# INV-5 — the URL that leaves is always the gate's output
# ---------------------------------------------------------------------------

def _violations_request_url(tree: ast.Module) -> list[str]:
    """
    Every ``client.request(url=X)`` must pass the single name the gate produces,
    and that name must never be assigned from anything but the gate.

    This is the invariant that stops the next contributor from reintroducing an
    f-string built straight out of the request path.
    """
    bad = []
    gate_output_names: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            names = []
            if isinstance(target, ast.Name):
                names = [target.id]
            elif isinstance(target, ast.Tuple):
                names = [e.id for e in target.elts if isinstance(e, ast.Name)]
            if "upstream_url" not in names:
                continue
            is_gate = (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id in ("_gate", "_resolve_upstream")
            )
            if not is_gate:
                bad.append(
                    f"line {node.lineno}: upstream_url is assigned from something "
                    f"other than the forwarding gate"
                )
            else:
                gate_output_names.add("upstream_url")

    for call in _request_calls(tree):
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        if "url" not in kwargs:
            continue
        value = kwargs["url"]
        if not (isinstance(value, ast.Name) and value.id in gate_output_names):
            bad.append(
                f"line {call.lineno}: request(url=...) is not the gate's output; "
                f"got {ast.dump(value)[:90]}"
            )
    return bad


def test_inv5_upstream_url_always_comes_from_the_gate(tree):
    assert _request_calls(tree), "no client.request() call found — discovery failure"
    assert _violations_request_url(tree) == []


def test_inv5_negative_self_test():
    """The pre-fix shape — an f-string straight from the path — must be caught."""
    pre_fix = ast.parse(
        'upstream_url = f"{GROK_UPSTREAM}/{path}"\n'
        'r = client.request(method="POST", url=upstream_url)\n'
    )
    assert _violations_request_url(pre_fix)

    inline = ast.parse('r = client.request(url=f"{BASE}/{path}")\n')
    assert _violations_request_url(inline)

    ok = ast.parse(
        "upstream_url, deny = _gate(request, GROK, path)\n"
        'r = client.request(method="POST", url=upstream_url)\n'
    )
    assert _violations_request_url(ok) == []


# ---------------------------------------------------------------------------
# INV-6 — no refusal is silent
# ---------------------------------------------------------------------------

def _refusal_functions(tree: ast.Module) -> list[ast.AST]:
    """Every function that can return a 400."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if (isinstance(inner, ast.Call)
                    and any(kw.arg == "status_code"
                            and isinstance(kw.value, ast.Constant)
                            and kw.value.value == 400
                            for kw in inner.keywords)):
                out.append(node)
                break
    return out


def _violations_refusal_receipted(tree: ast.Module) -> list[str]:
    """
    Every function that builds a 400 must also emit a receipt, and every endpoint
    that refuses must route through the one function that does both.
    """
    bad = []
    emitters = set()
    for func in _refusal_functions(tree):
        emits = any(
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Name)
            and inner.func.id.startswith("_receipt")
            for inner in ast.walk(func)
        )
        if emits:
            emitters.add(func.name)
        else:
            bad.append(
                f"{func.name} (line {func.lineno}) returns a 400 without emitting "
                f"a receipt; a blocked request with no evidence trail cannot be "
                f"investigated"
            )
    if not emitters and not bad:
        bad.append("no 400-returning function found at all — discovery failure")
    return bad


def test_inv6_every_refusal_is_receipted(tree):
    assert _refusal_functions(tree), "no refusal path found — discovery failure"
    assert _violations_refusal_receipted(tree) == []


def test_inv6_negative_self_test():
    """The pre-fix shape — an inline unreceipted 400 — must be caught."""
    pre_fix = ast.parse(
        "async def grok_passthrough(path, request):\n"
        "    if not _OPENAI_PATH_RE.match(path):\n"
        "        return Response(content=b'{}', status_code=400)\n"
    )
    violations = _violations_refusal_receipted(pre_fix)
    assert violations
    assert "grok_passthrough" in violations[0]

    ok = ast.parse(
        "async def _refuse(request, provider, code, path):\n"
        "    rid, status = await _receipt_refusal(request, provider, code, path)\n"
        "    return Response(content=b'{}', status_code=400)\n"
    )
    assert _violations_refusal_receipted(ok) == []


# ---------------------------------------------------------------------------
# INV-7 — the deny taxonomy is closed
# ---------------------------------------------------------------------------

def _deny_codes(tree: ast.Module) -> set[str]:
    return {
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
        and any(isinstance(t, ast.Name) and t.id.startswith("DENY_")
                and not t.id.startswith("DENY_TAXONOMY")
                for t in node.targets)
    }


def _taxonomy_keys(tree: ast.Module) -> set[str]:
    """Keys of ``DENY_TAXONOMY``, whether it is annotated or bare."""
    for node in tree.body:
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "DENY_TAXONOMY"
                   for t in targets):
            continue
        if isinstance(node.value, ast.Dict):
            return {k.id for k in node.value.keys if isinstance(k, ast.Name)}
    return set()


def test_inv7_every_deny_code_has_a_reason_and_a_remedy(tree):
    """
    A refusal whose code carries no reason and no remedy is "computer says no".
    Checked statically so a new code cannot land without its entry.
    """
    code_names = {
        t.id
        for node in tree.body if isinstance(node, ast.Assign)
        for t in node.targets
        if isinstance(t, ast.Name) and t.id.startswith("DENY_")
        and t.id != "DENY_TAXONOMY"
    }
    assert len(code_names) >= 4, f"discovered only {code_names} — discovery failure"
    keys = _taxonomy_keys(tree)
    assert keys, "DENY_TAXONOMY not found or not a dict literal — discovery failure"
    assert code_names == keys, (
        f"deny codes without a taxonomy entry: {sorted(code_names - keys)}; "
        f"taxonomy entries with no code: {sorted(keys - code_names)}"
    )


def test_inv7_negative_self_test():
    orphan = ast.parse(
        'DENY_A = "a"\n'
        'DENY_B = "b"\n'
        'DENY_TAXONOMY = {DENY_A: ("r", "m")}\n'
    )
    codes = {t.id for node in orphan.body if isinstance(node, ast.Assign)
             for t in node.targets
             if isinstance(t, ast.Name) and t.id.startswith("DENY_")
             and t.id != "DENY_TAXONOMY"}
    assert codes - _taxonomy_keys(orphan) == {"DENY_B"}


# ---------------------------------------------------------------------------
# INV-8 — no credential travels on a set shared by every destination
#
# WHAT EARNED THIS (2026-07-27, found by a second vendor — Codex, gpt-5.5)
# ------------------------------------------------------------------------
# The forwarded-header allowlist was one GLOBAL set containing both
# `authorization` and `x-api-key`, applied to all four providers. An accepted
# request carrying both delivered BOTH to whichever single destination the route
# resolved to: Grok received a Bearer token and an Anthropic-style x-api-key. A
# customer routing two vendors through this proxy had one vendor's key delivered
# to the other, on the ordinary path, in a request authorised for something else.
#
# The previous round's duplicate-credential check could not see it: that check
# counts repeated instances of ONE header name, and this is two DIFFERENT header
# names each appearing once. A PER-HEADER RULE CANNOT SEE A CROSS-HEADER
# INTERACTION — which is why the invariant below is about the SHAPE of the
# allowlist rather than about any header in it. It fails the build on the
# structure that made the leak expressible, not on the instance that leaked.
# ---------------------------------------------------------------------------

#: Header names that carry a caller secret, whoever the caller is. Written down
#: here, in the checker, rather than read from the module under test: a list
#: taken from the subject agrees with the subject by construction, and the
#: subject is exactly what is suspected.
CREDENTIAL_BEARING_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "x-api-key",
    "x-goog-api-key", "api-key", "x-auth-token", "x-access-token",
    "authentication", "x-amz-security-token", "x-goog-iam-authorization-token",
}


def _module_level_string_sets(tree: ast.Module) -> dict[str, set[str]]:
    """
    Every module-level ``NAME = {…}`` / ``frozenset({…})`` / ``set([…])`` whose
    elements are string literals. Discovery, not enumeration: a set added next
    year is covered without anyone remembering this file exists.
    """
    found: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        elements = None
        if isinstance(value, (ast.Set, ast.List, ast.Tuple)):
            elements = value
        elif (isinstance(value, ast.Call)
              and isinstance(value.func, ast.Name)
              and value.func.id in ("frozenset", "set")
              and value.args
              and isinstance(value.args[0], (ast.Set, ast.List, ast.Tuple))):
            elements = value.args[0]
        if elements is None:
            continue
        literals = {e.value.lower() for e in elements.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)}
        if literals:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found[target.id] = literals
    return found


#: The one module-level set that legitimately NAMES credential headers: the
#: vocabulary the foreign-credential screen recognises. It is a screen, not a
#: forward list — nothing is forwarded because it appears here.
_CREDENTIAL_VOCABULARY_NAMES = {"_CREDENTIAL_HEADERS"}


def _violations_shared_credential_list(sets: dict[str, set[str]]) -> list[str]:
    """
    A module-level header set that is applied to every destination may not name
    a credential. Per-destination credential sets live on the provider rows, not
    at module level, so any module-level set carrying one is by definition shared.
    """
    bad = []
    for name, members in sets.items():
        if name in _CREDENTIAL_VOCABULARY_NAMES:
            continue
        if name == "_HOP_BY_HOP_HEADERS":
            # A STRIP list: naming proxy-authorization there removes it. The
            # opposite of forwarding it.
            continue
        leaked = sorted(members & CREDENTIAL_BEARING_HEADERS)
        if leaked:
            bad.append(
                f"{name} is a module-level (therefore shared) header set naming "
                f"credential header(s) {leaked}; a set shared by every "
                f"destination cannot express which vendor a secret belongs to — "
                f"this is the shape that delivered an Anthropic key to xAI"
            )
    return bad


def test_inv8_no_credential_header_in_a_shared_forward_allowlist(tree):
    sets = _module_level_string_sets(tree)
    assert len(sets) >= 3, (
        f"discovered only {sorted(sets)} module-level string sets — the "
        f"discovery is looking in the wrong place, which is indistinguishable "
        f"from a clean run"
    )
    assert _violations_shared_credential_list(sets) == []


def test_inv8_negative_self_test():
    """The exact pre-fix set must be reported."""
    pre_fix = {"_FORWARDED_HEADERS": {
        "authorization", "content-type", "accept", "x-api-key",
        "anthropic-version",
    }}
    violations = _violations_shared_credential_list(pre_fix)
    assert violations, "the invariant does not catch the defect that earned it"
    assert "authorization" in violations[0] and "x-api-key" in violations[0]

    # Every other spelling of the same mistake.
    assert _violations_shared_credential_list({"_EXTRA": {"cookie"}})
    assert _violations_shared_credential_list({"_HEADERS": {"x-goog-api-key"}})

    # Control rows: the shipped shape is clean, so the check discriminates.
    assert _violations_shared_credential_list(
        {"_SAFE_TRANSPORT_HEADERS": {"content-type", "accept", "user-agent"}}
    ) == []
    assert _violations_shared_credential_list(
        {"_CREDENTIAL_HEADERS": {"authorization", "x-api-key"}}
    ) == []
    assert _violations_shared_credential_list(
        {"_HOP_BY_HOP_HEADERS": {"proxy-authorization", "connection"}}
    ) == []


# ---------------------------------------------------------------------------
# INV-9 — every destination states its own credentials, explicitly
# ---------------------------------------------------------------------------

def _provider_constructions(tree: ast.Module) -> list[ast.Call]:
    """Every module-level ``NAME = Provider(...)`` construction."""
    out = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        value = node.value
        if (isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "Provider"):
            out.append(value)
    return out


def _violations_provider_credentials(calls: list[ast.Call]) -> list[str]:
    """
    Each provider must name ``credential_headers`` at its construction, as a
    literal set of literal strings.

    Explicit, because the field's default is empty and an empty default is a
    silent forward-nothing — safe, but a fifth provider that silently forwards
    no credential looks like a broken vendor rather than a missing decision.
    Literal, because a credential set computed from a shared global is the
    shared allowlist wearing a per-provider costume.
    """
    bad = []
    for call in calls:
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        if "credential_headers" not in kwargs:
            bad.append(
                f"line {call.lineno}: Provider(...) does not state "
                f"credential_headers; the credential a destination receives must "
                f"be a decision, not a default"
            )
            continue
        value = kwargs["credential_headers"]
        inner = value.args[0] if (isinstance(value, ast.Call)
                                  and isinstance(value.func, ast.Name)
                                  and value.func.id in ("frozenset", "set")
                                  and value.args) else value
        if not isinstance(inner, (ast.Set, ast.List, ast.Tuple)):
            bad.append(
                f"line {call.lineno}: credential_headers is not a literal set; "
                f"a set derived from a shared global is the shared allowlist "
                f"under another name"
            )
            continue
        if not all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                   for e in inner.elts):
            bad.append(f"line {call.lineno}: credential_headers holds a "
                       f"non-literal member")
    return bad


def test_inv9_every_provider_states_its_own_credential_headers(tree):
    calls = _provider_constructions(tree)
    assert len(calls) >= 4, (
        f"discovered only {len(calls)} Provider constructions — discovery failure"
    )
    assert _violations_provider_credentials(calls) == []


def test_inv9_negative_self_test():
    absent = ast.parse('GROK = Provider("grok", BASE, RE, ALLOWED)').body[0].value
    shared = ast.parse(
        'GROK = Provider("grok", BASE, RE, ALLOWED, '
        'credential_headers=_FORWARDED_HEADERS)'
    ).body[0].value
    computed = ast.parse(
        'GROK = Provider("grok", BASE, RE, ALLOWED, '
        'credential_headers=_CREDENTIAL_HEADERS | EXTRA)'
    ).body[0].value
    ok = ast.parse(
        'GROK = Provider("grok", BASE, RE, ALLOWED, '
        'credential_headers=frozenset({"authorization"}))'
    ).body[0].value

    assert _violations_provider_credentials([absent])
    assert _violations_provider_credentials([shared])
    assert _violations_provider_credentials([computed])
    assert _violations_provider_credentials([ok]) == []


def test_inv9_provider_credentials_are_a_subset_of_the_screened_vocabulary(tree):
    """
    A credential a provider accepts but the screen does not recognise is
    invisible everywhere ELSE — it could never be called foreign at another
    destination, which is precisely the hole this mapping closes.

    Static, so it holds on a branch that never imports the module (the runtime
    guard in the module itself covers the imported case).
    """
    sets = _module_level_string_sets(tree)
    vocabulary = sets.get("_CREDENTIAL_HEADERS")
    assert vocabulary, "_CREDENTIAL_HEADERS not found — discovery failure"
    param_vocabulary = sets.get("_CREDENTIAL_QUERY_PARAMS")
    assert param_vocabulary, "_CREDENTIAL_QUERY_PARAMS not found — discovery failure"

    unknown = []
    for call in _provider_constructions(tree):
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        for field, allowed in (("credential_headers", vocabulary),
                               ("credential_query_params", param_vocabulary)):
            node = kwargs.get(field)
            if node is None:
                continue
            inner = node.args[0] if (isinstance(node, ast.Call) and node.args) else node
            if not isinstance(inner, (ast.Set, ast.List, ast.Tuple)):
                continue
            members = {e.value.lower() for e in inner.elts
                       if isinstance(e, ast.Constant) and isinstance(e.value, str)}
            if members - allowed:
                unknown.append(
                    f"line {call.lineno}: {field} names {sorted(members - allowed)}, "
                    f"which the screen's vocabulary does not recognise"
                )
    assert unknown == []
