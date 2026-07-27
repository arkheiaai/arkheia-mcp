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


# ---------------------------------------------------------------------------
# INV-10 — every credential channel the provider table declares is COUNTED
#
# WHAT EARNED THIS (2026-07-27, found by a second vendor — Codex, gpt-5.5, in
# the fix for the defect that earned INV-8)
# ------------------------------------------------------------------------
# INV-8's own commit message said "a per-header rule cannot see a cross-header
# interaction" — and the gate it shipped counted credential HEADERS, so it could
# not see a header <-> QUERY-PARAMETER interaction either. On Gemini, which
# genuinely accepts `authorization`, `x-goog-api-key` AND `?key=`, a bearer plus
# a `?key=` passed the screen and BOTH left for Google; `?key=FIRST&key=SECOND`
# passed and collapsed to the last value, discarding a credential the caller
# sent. The insight was right and the implementation stopped one category short
# of it.
#
# So the invariant is not about headers, and not about query parameters. It is
# that EVERY CHANNEL A DESTINATION DECLARES IS ONE THE SCREEN CAN READ. A
# `Provider` field naming a credential channel that no channel row reads is a
# credential the screen cannot count, and an uncounted credential is a second
# secret on the wire. Both sides are DISCOVERED — the fields from the dataclass,
# the channels from the table — so a sixth channel added next year fails the
# build without anyone remembering this file exists.
# ---------------------------------------------------------------------------

def _provider_credential_fields(tree: ast.Module) -> set[str]:
    """Every ``Provider`` field whose name declares a credential channel."""
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Provider":
            return {
                stmt.target.id
                for stmt in node.body
                if isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id.startswith("credential_")
            }
    return set()


def _channel_rows(tree: ast.Module) -> list[ast.Call]:
    """Every ``CredentialChannel(...)`` row of the module-level channel table."""
    for node in tree.body:
        # Annotated or bare: the table carries a type annotation today, and a
        # discovery that only understood one spelling would report an empty
        # table — which reads exactly like a clean run.
        if isinstance(node, ast.AnnAssign):
            targets = [node.target]
        elif isinstance(node, ast.Assign):
            targets = node.targets
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == "CREDENTIAL_CHANNELS"
                   for t in targets):
            continue
        value = node.value
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return [e for e in value.elts
                    if isinstance(e, ast.Call)
                    and isinstance(e.func, ast.Name)
                    and e.func.id == "CredentialChannel"]
    return []


def _channel_argument(call: ast.Call, position: int, keyword: str) -> str | None:
    """A ``CredentialChannel`` argument, positional or keyword, as a name."""
    node = None
    for kw in call.keywords:
        if kw.arg == keyword:
            node = kw.value
    if node is None and len(call.args) > position:
        node = call.args[position]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _channelled_fields(rows: list[ast.Call]) -> set[str]:
    return {
        name for name in
        (_channel_argument(row, 2, "provider_field") for row in rows)
        if name is not None
    }


def _violations_channel_coverage(declared: set[str], channelled: set[str]) -> list[str]:
    bad = []
    uncounted = sorted(declared - channelled)
    if uncounted:
        bad.append(
            f"Provider declares credential channel(s) {uncounted} that no "
            f"CredentialChannel row reads; a channel the screen cannot read is a "
            f"credential it cannot count, and an uncounted credential is a "
            f"second secret on the wire — this is the shape that let a bearer "
            f"and a ?key= both reach Google"
        )
    orphan = sorted(channelled - declared)
    if orphan:
        bad.append(
            f"CredentialChannel row(s) name provider field(s) {orphan} that "
            f"Provider does not declare; the screen would read nothing there"
        )
    return bad


def test_inv10_every_declared_credential_channel_is_counted(tree):
    declared = _provider_credential_fields(tree)
    assert len(declared) >= 2, (
        f"discovered only {sorted(declared)} credential fields on Provider — the "
        f"discovery is looking in the wrong place, which is indistinguishable "
        f"from a clean run"
    )
    rows = _channel_rows(tree)
    assert len(rows) >= 2, (
        f"discovered only {len(rows)} credential channel rows — discovery failure"
    )
    assert _violations_channel_coverage(declared, _channelled_fields(rows)) == []


def test_inv10_negative_self_test():
    """The exact pre-fix shape — a query channel nothing counts — is reported."""
    pre_fix = _violations_channel_coverage(
        {"credential_headers", "credential_query_params"},
        {"credential_headers"},
    )
    assert pre_fix, "the invariant does not catch the defect that earned it"
    assert "credential_query_params" in pre_fix[0]

    # A channel row pointing at a field that does not exist is the other error.
    assert _violations_channel_coverage({"credential_headers"},
                                        {"credential_headers", "credential_cookies"})

    # Control row: matched sets are clean, so the check discriminates.
    assert _violations_channel_coverage(
        {"credential_headers", "credential_query_params"},
        {"credential_headers", "credential_query_params"},
    ) == []


def test_inv10_channel_rows_are_parsed_from_the_real_module(tree):
    """
    The table above is only worth anything if the parse found the real rows.
    Pins what each row must carry, so a row that silently loses its
    provider_field cannot read as coverage.
    """
    rows = _channel_rows(tree)
    names = {_channel_argument(row, 0, "name") for row in rows}
    assert names == {"header", "query"}, f"channel names discovered: {sorted(names)}"
    for row in rows:
        assert _channel_argument(row, 2, "provider_field"), (
            f"a CredentialChannel row at line {row.lineno} names no provider_field"
        )
        assert _channel_argument(row, 1, "vocabulary"), (
            f"a CredentialChannel row at line {row.lineno} names no vocabulary"
        )


# ---------------------------------------------------------------------------
# INV-11 — the multiplicity decision is taken over the CHANNEL TABLE, never
#          over one channel's contents
# ---------------------------------------------------------------------------
# INV-10 says every channel is readable. This says the decision actually reads
# them: the function that refuses a second credential must derive its count by
# iterating the table, and must not reach into any single channel's vocabulary
# directly — reaching into one is what a per-channel rule looks like, and a
# per-channel rule is blind to the interaction between channels by construction.

def _function_defs(tree: ast.Module) -> dict[str, ast.AST]:
    return {
        node.name: node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _called_names(node: ast.AST) -> set[str]:
    return {
        inner.func.id for inner in ast.walk(node)
        if isinstance(inner, ast.Call) and isinstance(inner.func, ast.Name)
    }


def _decision_closure(tree: ast.Module, deny_constant: str) -> list[ast.AST]:
    """
    Every module-level function reachable from the one that returns
    ``deny_constant`` — the whole of the code that takes that decision.
    """
    defs = _function_defs(tree)
    roots = [
        node for node in defs.values()
        if any(isinstance(inner, ast.Return)
               and isinstance(inner.value, ast.Name)
               and inner.value.id == deny_constant
               for inner in ast.walk(node))
    ]
    seen: dict[str, ast.AST] = {}
    frontier = list(roots)
    while frontier:
        node = frontier.pop()
        name = getattr(node, "name", None)
        if name in seen:
            continue
        if name is not None:
            seen[name] = node
        for called in _called_names(node):
            if called in defs and called not in seen:
                frontier.append(defs[called])
    return list(seen.values())


def _iterates(node: ast.AST, table_name: str) -> bool:
    """Does this function iterate ``table_name`` — as a for-loop or a comprehension?"""
    for inner in ast.walk(node):
        iterated = None
        if isinstance(inner, (ast.For, ast.AsyncFor)):
            iterated = inner.iter
        elif isinstance(inner, ast.comprehension):
            iterated = inner.iter
        if isinstance(iterated, ast.Name) and iterated.id == table_name:
            return True
    return False


def _violations_multiplicity_shape(
    closure: list[ast.AST], table_name: str, channel_vocabularies: set[str]
) -> list[str]:
    bad = []
    if not closure:
        return ["no function returns the multiplicity deny code at all — "
                "discovery failure, which is indistinguishable from a clean run"]
    if not any(_iterates(node, table_name) for node in closure):
        bad.append(
            f"nothing on the multiplicity decision path iterates {table_name}; "
            f"a count taken over one channel cannot see a credential arriving on "
            f"another, which is how a bearer and a ?key= were both forwarded"
        )
    for node in closure:
        used = {
            inner.id for inner in ast.walk(node)
            if isinstance(inner, ast.Name) and inner.id in channel_vocabularies
        }
        if used:
            bad.append(
                f"{getattr(node, 'name', '?')} reaches into channel "
                f"vocabular(ies) {sorted(used)} directly instead of going "
                f"through {table_name}; that is a per-channel rule, and a "
                f"per-channel rule is blind to the interaction between channels"
            )
    return bad


def test_inv11_the_multiplicity_decision_spans_every_channel(tree):
    rows = _channel_rows(tree)
    vocabularies = {
        name for name in (_channel_argument(row, 1, "vocabulary") for row in rows)
        if name is not None
    }
    assert len(vocabularies) >= 2, (
        f"discovered only {sorted(vocabularies)} channel vocabularies — "
        f"discovery failure"
    )
    closure = _decision_closure(tree, "DENY_MULTIPLE_CREDENTIALS")
    assert closure, "no multiplicity decision found — discovery failure"
    assert _violations_multiplicity_shape(
        closure, "CREDENTIAL_CHANNELS", vocabularies) == []


def test_inv11_negative_self_test():
    """The exact pre-fix screen must be reported, and each fault separately."""
    pre_fix = ast.parse(
        "def _credential_header_counts(request):\n"
        "    seen = {}\n"
        "    for raw_key, _ in request.headers.raw:\n"
        "        key = raw_key.decode('latin-1').lower()\n"
        "        if key in _CREDENTIAL_HEADERS:\n"
        "            seen[key] = seen.get(key, 0) + 1\n"
        "    return seen\n"
        "def _screen_credentials(request, provider):\n"
        "    counts = _credential_header_counts(request)\n"
        "    if len(counts) > 1:\n"
        "        return DENY_MULTIPLE_CREDENTIALS\n"
        "    return None\n"
    )
    vocabularies = {"_CREDENTIAL_HEADERS", "_CREDENTIAL_QUERY_PARAMS"}
    violations = _violations_multiplicity_shape(
        _decision_closure(pre_fix, "DENY_MULTIPLE_CREDENTIALS"),
        "CREDENTIAL_CHANNELS", vocabularies,
    )
    assert violations, "the invariant does not catch the defect that earned it"
    assert any("iterates CREDENTIAL_CHANNELS" in v for v in violations)
    assert any("_CREDENTIAL_HEADERS" in v for v in violations)

    # A screen that iterates the table but still reaches into one channel.
    half_fixed = ast.parse(
        "def _screen_credentials(request, provider):\n"
        "    n = 0\n"
        "    for channel in CREDENTIAL_CHANNELS:\n"
        "        n += len(channel.read(request))\n"
        "    if any(k in _CREDENTIAL_HEADERS for k in request.headers.raw):\n"
        "        return DENY_MULTIPLE_CREDENTIALS\n"
        "    return None\n"
    )
    assert _violations_multiplicity_shape(
        _decision_closure(half_fixed, "DENY_MULTIPLE_CREDENTIALS"),
        "CREDENTIAL_CHANNELS", vocabularies,
    )

    # A module where nothing takes the decision at all is a discovery failure,
    # not a pass.
    assert _violations_multiplicity_shape([], "CREDENTIAL_CHANNELS", vocabularies)

    # Control row: the shipped shape is clean, so the check discriminates.
    ok = ast.parse(
        "def _credential_presentations(request):\n"
        "    found = []\n"
        "    for channel in CREDENTIAL_CHANNELS:\n"
        "        for name in channel.read(request):\n"
        "            if name in channel.vocabulary:\n"
        "                found.append((channel.name, name))\n"
        "    return found\n"
        "def _screen_credentials(request, provider):\n"
        "    if len(_credential_presentations(request)) > 1:\n"
        "        return DENY_MULTIPLE_CREDENTIALS\n"
        "    return None\n"
    )
    assert _violations_multiplicity_shape(
        _decision_closure(ok, "DENY_MULTIPLE_CREDENTIALS"),
        "CREDENTIAL_CHANNELS", vocabularies,
    ) == []


# ---------------------------------------------------------------------------
# INV-12 — a credential channel is read through a MULTIPLICITY-PRESERVING
#          accessor, everywhere in this module
# ---------------------------------------------------------------------------
# `?key=FIRST&key=SECOND` reached Google as SECOND alone, because
# `dict(request.query_params)` keeps the last of any repeated name. That is the
# same mechanism as the `Authorization` last-wins defect round 1 fixed, in
# another spelling, and it is invisible to any rule stated in terms of WHICH
# names are credentials — the credential was recognised; the second copy of it
# was thrown away before anyone counted.
#
# So: every read of the caller's headers or query string in this module goes
# through the accessor that keeps repeats. A screen cannot count what the reader
# already discarded.

#: object -> the ONLY accessors that preserve repeats. An allow-list, never a
#: deny-list: a deny-list fails open on the next accessor anyone reaches for.
MULTIPLICITY_PRESERVING = {
    "headers": {"raw"},
    "query_params": {"multi_items"},
}


def _caller_input_reads(tree: ast.Module) -> list[tuple[int, str, str]]:
    """Every ``request.<headers|query_params>.<accessor>`` in the module."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        parent = node.value
        if not (isinstance(parent, ast.Attribute)
                and parent.attr in MULTIPLICITY_PRESERVING
                and isinstance(parent.value, ast.Name)
                and parent.value.id == "request"):
            continue
        found.append((node.lineno, parent.attr, node.attr))
    return found


def _collapsing_conversions(tree: ast.Module) -> list[tuple[int, str]]:
    """``dict(request.headers)`` / ``dict(request.query_params)``."""
    found = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "dict"
                and node.args):
            continue
        arg = node.args[0]
        if (isinstance(arg, ast.Attribute)
                and arg.attr in MULTIPLICITY_PRESERVING
                and isinstance(arg.value, ast.Name)
                and arg.value.id == "request"):
            found.append((node.lineno, arg.attr))
    return found


def _violations_multiplicity_preserving(tree: ast.Module) -> list[str]:
    bad = []
    for lineno, obj, accessor in _caller_input_reads(tree):
        if accessor not in MULTIPLICITY_PRESERVING[obj]:
            bad.append(
                f"line {lineno}: request.{obj}.{accessor} collapses repeats; a "
                f"second copy of a credential is discarded before anything can "
                f"count it. Use "
                f"{'/'.join(sorted(MULTIPLICITY_PRESERVING[obj]))}"
            )
    for lineno, obj in _collapsing_conversions(tree):
        bad.append(
            f"line {lineno}: dict(request.{obj}) keeps the LAST of any repeated "
            f"name — this is exactly how ?key=FIRST&key=SECOND became SECOND"
        )
    return bad


def test_inv12_caller_input_is_read_multiplicity_preserving(tree):
    reads = _caller_input_reads(tree)
    assert len(reads) >= 4, (
        f"discovered only {len(reads)} reads of the caller's headers/query "
        f"string — the discovery is looking in the wrong place, which is "
        f"indistinguishable from a clean run"
    )
    assert {obj for _l, obj, _a in reads} == set(MULTIPLICITY_PRESERVING), (
        "both caller-input channels must be read somewhere in this module; "
        "finding only one means the scan is blind to the other"
    )
    assert _violations_multiplicity_preserving(tree) == []


def test_inv12_negative_self_test():
    """Every pre-fix spelling must be reported, and the shipped one must not."""
    keys = ast.parse("names = request.query_params.keys()")
    assert _violations_multiplicity_preserving(keys)

    items = ast.parse("pairs = request.headers.items()")
    assert _violations_multiplicity_preserving(items)

    conversion = ast.parse("params = dict(request.query_params)")
    violations = _violations_multiplicity_preserving(conversion)
    assert violations
    assert "SECOND" in violations[0]

    header_conversion = ast.parse("h = dict(request.headers)")
    assert _violations_multiplicity_preserving(header_conversion)

    # Control rows: the shipped spellings are clean, so the check discriminates.
    assert _violations_multiplicity_preserving(
        ast.parse("for k, _ in request.headers.raw:\n    pass\n")
    ) == []
    assert _violations_multiplicity_preserving(
        ast.parse("for k, v in request.query_params.multi_items():\n    pass\n")
    ) == []
