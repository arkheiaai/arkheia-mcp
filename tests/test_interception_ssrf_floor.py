"""
FLOOR TIER — /v1/* interception: SSRF, framing and receipt invariants.

Runs in the required ``floor-invariants`` CI job under a BARE pytest with zero
project dependencies, so it carries no interpreter variance and cannot be
skipped by a paths filter. Everything here is static analysis of
``proxy/middleware/interception.py``.

Each invariant was earned by a defect measured on this flow (see the PR), and
each obeys DONE.md v1.19 / v1.22 / v1.23:

  * it **discovers** its subjects rather than enumerating them, and asserts the
    discovered count is non-zero — "found nothing" must never be confusable
    with "looked in the wrong place";
  * it carries a **negative self-test** that runs the same checker over the
    EXACT pre-fix source and asserts it goes red — a check that has never been
    seen failing is decoration;
  * it carries a **control** it must NOT flag, so it cannot pass by flagging
    everything.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = REPO_ROOT / "proxy" / "middleware" / "interception.py"


@pytest.fixture(scope="module")
def source() -> str:
    assert TARGET.is_file(), f"target module missing: {TARGET}"
    text = TARGET.read_text(encoding="utf-8")
    assert len(text) > 2000, "target module is implausibly small; wrong file?"
    return text


@pytest.fixture(scope="module")
def tree(source: str) -> ast.Module:
    return ast.parse(source)


def _module_constant(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) \
                and node.target.id == name:
            return node.value
    return None


def _func(tree: ast.Module, name: str):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


# ---------------------------------------------------------------------------
# INV-1 — one prefix constant, used by both the gate and the confinement
# ---------------------------------------------------------------------------

def _bare_prefix_literals(tree: ast.Module) -> list[int]:
    """
    Line numbers of a bare ``"/v1/"`` literal outside the one constant.

    AST-based on purpose: a text scan flags the prose in this module's own
    docstring, and a scanner that cries wolf gets switched off (DONE.md v1.22
    "comment-aware scanners"). A docstring is never the exact string "/v1/", so
    working on parsed constants is comment-awareness by construction.
    """
    declared = _module_constant(tree, "INTERCEPT_PREFIX")
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "/v1/" \
                and node is not declared:
            hits.append(node.lineno)
    return sorted(hits)


class TestInv1SinglePrefixConstant:
    """
    The prefix that AUTHORISES interception and the prefix the forwarded request
    must STAY under are the same statement. Two literals can drift apart, and
    when they do the gate approves a request the forward no longer describes —
    which is precisely how ``/v1/../admin/keys`` was authorised.
    """

    def test_the_constant_exists_and_is_the_only_literal(self, source, tree):
        const = _module_constant(tree, "INTERCEPT_PREFIX")
        assert isinstance(const, ast.Constant) and const.value == "/v1/"
        assert _bare_prefix_literals(tree) == [], (
            "a second '/v1/' literal can drift from INTERCEPT_PREFIX"
        )

    def test_the_constant_is_actually_used_more_than_once(self, tree):
        uses = [n for n in ast.walk(tree)
                if isinstance(n, ast.Name) and n.id == "INTERCEPT_PREFIX"]
        assert len(uses) >= 2, (
            f"INTERCEPT_PREFIX referenced {len(uses)}x — a constant used once "
            f"is a literal with a longer name"
        )

    def test_negative_self_test_the_pre_fix_source_is_flagged(self):
        """The literal pre-fix gate, which had no constant at all."""
        prefix = "/v1/"
        pre_fix = ast.parse(
            'if not request.url.path.startswith("' + prefix + '"):\n'
            "    pass\n"
        )
        assert _bare_prefix_literals(pre_fix) == [1]

    def test_control_a_compliant_line_is_not_flagged(self):
        compliant = ast.parse(
            "INTERCEPT_PREFIX = \"/v1/\"\n"
            "if not request.url.path.startswith(INTERCEPT_PREFIX):\n"
            "    pass\n"
        )
        assert _bare_prefix_literals(compliant) == []


# ---------------------------------------------------------------------------
# INV-2 — every AsyncClient passes follow_redirects=False explicitly
# ---------------------------------------------------------------------------

def _async_clients(tree: ast.Module) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = getattr(f, "attr", None) or getattr(f, "id", None)
            if name == "AsyncClient":
                out.append(node)
    return out


def _clients_without_explicit_no_redirect(tree: ast.Module) -> list[ast.Call]:
    bad = []
    for call in _async_clients(tree):
        ok = any(
            kw.arg == "follow_redirects"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in call.keywords
        )
        if not ok:
            bad.append(call)
    return bad


class TestInv2RedirectsNeverFollowed:
    """
    A followed 302 is a cross-host relay with the caller's credential attached —
    ``Location: http://169.254.169.254/`` and the gate's whole post-condition is
    bypassed by the origin. Today that is prevented by an ``httpx`` DEFAULT. A
    third party's default is not a control we own; it can change on a bump.
    """

    def test_every_client_is_explicit(self, tree):
        clients = _async_clients(tree)
        assert len(clients) >= 1, "no AsyncClient discovered — wrong file?"
        assert _clients_without_explicit_no_redirect(tree) == []

    def test_negative_self_test_the_pre_fix_source_is_flagged(self):
        pre_fix = ast.parse("async with httpx.AsyncClient() as client:\n    pass\n")
        assert len(_clients_without_explicit_no_redirect(pre_fix)) == 1

    def test_control_an_explicit_client_is_not_flagged(self):
        good = ast.parse(
            "async with httpx.AsyncClient(follow_redirects=False) as client:\n"
            "    pass\n"
        )
        assert _clients_without_explicit_no_redirect(good) == []
        assert len(_async_clients(good)) == 1


# ---------------------------------------------------------------------------
# INV-3 — the hop-by-hop set is complete
# ---------------------------------------------------------------------------

#: RFC 9110 §7.6.1, plus the non-standard ``proxy-connection`` every real proxy
#: must also strip.
RFC_9110_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}


def _declared_hop_by_hop(tree: ast.Module) -> set[str]:
    node = _module_constant(tree, "HOP_BY_HOP_HEADERS")
    if node is None:
        return set()
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Set, ast.List, ast.Tuple)):
            return {e.value.lower() for e in sub.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _missing_hop_by_hop(declared: set[str]) -> set[str]:
    return RFC_9110_HOP_BY_HOP - declared


class TestInv3HopByHopComplete:
    """
    Pre-fix, exactly ONE header (``host``) was dropped, so
    ``proxy-authenticate: Basic realm=internal-corp`` — an internal-topology
    disclosure — reached the provider, along with ``upgrade`` / ``te`` /
    ``trailer`` / ``keep-alive``. Measured on the wire, not inferred.
    """

    def test_the_set_is_complete(self, tree):
        declared = _declared_hop_by_hop(tree)
        assert len(declared) >= len(RFC_9110_HOP_BY_HOP), (
            f"only {len(declared)} hop-by-hop names declared"
        )
        assert _missing_hop_by_hop(declared) == set()

    def test_negative_self_test_the_pre_fix_strip_set_is_flagged(self):
        """The exact pre-fix behaviour: drop 'host' and nothing else."""
        assert _missing_hop_by_hop({"host"}) == RFC_9110_HOP_BY_HOP

    def test_control_the_complete_set_is_not_flagged(self):
        assert _missing_hop_by_hop(set(RFC_9110_HOP_BY_HOP)) == set()


# ---------------------------------------------------------------------------
# INV-4 — the URL handed to the client is always the gate's output
# ---------------------------------------------------------------------------

def _request_url_arguments(tree: ast.Module) -> list[ast.AST]:
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "request":
            for kw in node.keywords:
                if kw.arg == "url":
                    out.append(kw.value)
    return out


#: The one function allowed to produce a destination — the only place the
#: post-condition runs.
GATE_FUNCTION = "_resolve_upstream"


def _ungated_urls(tree: ast.Module) -> list[str]:
    """
    Every ``client.request(url=...)`` whose value did not come out of the gate.

    Two ways to bypass it, both covered: build the URL inline at the call site,
    or bind it to a name that was assigned from anything other than
    ``_resolve_upstream`` — which is exactly what the pre-fix code did
    (``target_url = upstream_url.rstrip("/") + request.url.path``). A checker
    that only looked for inline f-strings would have passed the original
    defect.
    """
    bad: list[str] = []
    for arg in _request_url_arguments(tree):
        if not isinstance(arg, ast.Name):
            bad.append(ast.dump(arg)[:60])
            continue
        sources = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == arg.id:
                        sources.append(node.value)
        if not sources:
            bad.append(f"{arg.id} (never assigned in this module)")
            continue
        for src in sources:
            gated = (isinstance(src, ast.Call)
                     and (getattr(src.func, "id", None) == GATE_FUNCTION
                          or getattr(src.func, "attr", None) == GATE_FUNCTION))
            if not gated:
                bad.append(f"{arg.id} <- {type(src).__name__}")
    return bad


class TestInv4UrlComesFromTheGate:
    """
    ``_resolve_upstream`` is the only place a destination is produced and the
    only place ``_confine`` runs. A ``url=f"{base}{path}"`` at the call site
    reintroduces the original defect while leaving the gate in the file, looking
    like it still governs.
    """

    def test_every_request_url_is_a_gated_name(self, tree):
        args = _request_url_arguments(tree)
        assert len(args) >= 1, "no client.request(url=...) discovered — wrong file?"
        assert _ungated_urls(tree) == []

    def test_negative_self_test_the_exact_pre_fix_construction_is_flagged(self):
        """Verbatim shape of the defect this invariant was earned by."""
        pre_fix = ast.parse(
            'target_url = upstream_url.rstrip("/") + request.url.path\n'
            "await client.request(method=m, url=target_url, content=b)\n"
        )
        assert _ungated_urls(pre_fix) == ["target_url <- BinOp"]

    def test_negative_self_test_an_inline_url_is_flagged(self):
        pre_fix = ast.parse(
            'await client.request(method=m, url=f"{base}{path}", content=b)\n'
        )
        assert len(_ungated_urls(pre_fix)) == 1

    def test_control_a_gated_name_is_not_flagged(self):
        good = ast.parse(
            "target_url = _resolve_upstream(upstream_url, path, query)\n"
            "await client.request(method=m, url=target_url, content=b)\n"
        )
        assert _ungated_urls(good) == []
        assert len(_request_url_arguments(good)) == 1


# ---------------------------------------------------------------------------
# INV-5 — every deny code carries a reason AND a remedy
# ---------------------------------------------------------------------------

def _deny_codes(tree: ast.Module) -> dict[str, int]:
    """deny code -> number of message strings it declares."""
    node = _module_constant(tree, "DENY_CODES")
    if not isinstance(node, ast.Dict):
        return {}
    out: dict[str, int] = {}
    for key, value in zip(node.keys, node.values):
        if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
            continue
        n = 0
        if isinstance(value, (ast.Tuple, ast.List)):
            n = sum(1 for e in value.elts
                    if isinstance(e, ast.Constant)
                    and isinstance(e.value, str) and e.value.strip())
        out[key.value] = n
    return out


def _codes_missing_guidance(codes: dict[str, int]) -> list[str]:
    return sorted(k for k, n in codes.items() if n < 2)


class TestInv5EveryRefusalIsLegible:
    """
    DONE.md Gate 9: every adverse verdict shows its reason and states what would
    clear it. ``{"error": "arkheia_refused"}`` is "computer says no", and for a
    trust product that is indistinguishable from a malfunction.
    """

    def test_every_code_has_reason_and_remedy(self, tree):
        codes = _deny_codes(tree)
        assert len(codes) >= 3, f"only {len(codes)} deny codes discovered"
        assert _codes_missing_guidance(codes) == []

    def test_negative_self_test_a_bare_code_is_flagged(self):
        assert _codes_missing_guidance({"path_escapes_prefix": 0}) == ["path_escapes_prefix"]
        assert _codes_missing_guidance({"reason_only": 1}) == ["reason_only"]

    def test_control_a_complete_code_is_not_flagged(self):
        assert _codes_missing_guidance({"good": 2}) == []


# ---------------------------------------------------------------------------
# INV-6 — the post-condition's expectations are verifier-owned
# ---------------------------------------------------------------------------

REQUIRED_AUTHORITY_CHECKS = {"scheme", "host", "port"}


def _base_attributes_compared(func: ast.AST) -> set[str]:
    """Attributes of the CONFIG-derived ``base`` the post-condition compares."""
    found = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id == "base":
            found.add(node.attr)
    return found


def _string_literals(func: ast.AST, skip_docstring: bool = False) -> list[str]:
    doc = ast.get_docstring(func, clean=False) if skip_docstring else None
    return [n.value for n in ast.walk(func)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and n.value != doc]


class TestInv6VerifierOwnedExpectations:
    """
    DONE.md standing principle: a verifier never takes its parameters from the
    artifact it is verifying. Every expectation in ``_confine`` must come from
    the configured base, and the authority must be checked in all three parts —
    a host check that omits the port approves ``127.0.0.1:9999``.
    """

    def test_all_three_authority_parts_are_compared_against_base(self, tree):
        confine = _func(tree, "_confine")
        assert confine is not None, "_confine missing — the post-condition is gone"
        compared = _base_attributes_compared(confine)
        assert REQUIRED_AUTHORITY_CHECKS <= compared, (
            f"_confine compares only {sorted(compared)} against the configured "
            f"base; missing {sorted(REQUIRED_AUTHORITY_CHECKS - compared)}"
        )

    def test_no_hardcoded_host_in_the_post_condition(self, tree):
        confine = _func(tree, "_confine")
        for literal in _string_literals(confine, skip_docstring=True):
            assert "://" not in literal and "." not in literal.strip("/. "), (
                f"_confine carries a hardcoded destination {literal!r}"
            )

    def test_negative_self_test_a_partial_check_is_flagged(self):
        weak = ast.parse(
            "def _confine(target, base):\n"
            "    if target.host != base.host:\n"
            "        raise Refusal()\n"
        )
        compared = _base_attributes_compared(_func(weak, "_confine"))
        assert not REQUIRED_AUTHORITY_CHECKS <= compared
        assert sorted(REQUIRED_AUTHORITY_CHECKS - compared) == ["port", "scheme"]

    def test_control_a_full_check_is_not_flagged(self):
        good = ast.parse(
            "def _confine(target, base):\n"
            "    if target.scheme != base.scheme: raise Refusal()\n"
            "    if target.host != base.host: raise Refusal()\n"
            "    if target.port != base.port: raise Refusal()\n"
        )
        compared = _base_attributes_compared(_func(good, "_confine"))
        assert REQUIRED_AUTHORITY_CHECKS <= compared


# ---------------------------------------------------------------------------
# INV-7 — every adverse verdict emits a receipt
# ---------------------------------------------------------------------------

ADVERSE_MARKERS = ("arkheia_refused", "arkheia_blocked")


def _adverse_functions_without_emit(tree: ast.Module) -> list[str]:
    bad = []
    seen = 0
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        literals = _string_literals(node, skip_docstring=True)
        if not any(m in lit for m in ADVERSE_MARKERS for lit in literals):
            continue
        seen += 1
        emits = any(
            isinstance(c, ast.Call) and getattr(c.func, "id", None) == "_emit"
            for c in ast.walk(node)
        )
        if not emits:
            bad.append(node.name)
    return bad


class TestInv7EveryAdverseVerdictIsReceipted:
    """
    A block with no evidence trail cannot be investigated or contested. Pre-fix
    the middleware had no audit call site at all: a hundred withheld answers
    left an empty directory, and "refused a hundred times" was indistinguishable
    from "was never asked".
    """

    def test_every_adverse_path_emits(self, tree):
        functions = [n.name for n in ast.walk(tree)
                     if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and any(m in lit for m in ADVERSE_MARKERS
                             for lit in _string_literals(n, skip_docstring=True))]
        assert len(functions) >= 1, "no adverse-verdict function discovered"
        assert _adverse_functions_without_emit(tree) == []

    def test_negative_self_test_an_unreceipted_refusal_is_flagged(self):
        pre_fix = ast.parse(
            "def dispatch(self):\n"
            '    return Response(content=\'{"error":"arkheia_blocked"}\')\n'
        )
        assert _adverse_functions_without_emit(pre_fix) == ["dispatch"]

    def test_control_a_receipted_refusal_is_not_flagged(self):
        good = ast.parse(
            "async def dispatch(self):\n"
            "    await _emit(request, record)\n"
            '    return Response(content=\'{"error":"arkheia_blocked"}\')\n'
        )
        assert _adverse_functions_without_emit(good) == []


# ---------------------------------------------------------------------------
# INV-8 — the response body is relayed, never concatenated into
# ---------------------------------------------------------------------------

def _body_concatenations(tree: ast.Module) -> list[int]:
    """``b"..." + response_body`` / ``response_body + b"..."`` — banner injection."""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            names = {getattr(side, "id", None) for side in (node.left, node.right)}
            consts = [side for side in (node.left, node.right)
                      if isinstance(side, ast.Constant)
                      and isinstance(side.value, (bytes, str))]
            if "response_body" in names and consts:
                hits.append(node.lineno)
    return hits


class TestInv8BodyIsNeverMutated:
    """
    Prepending ``b"[ARKHEIA WARNING: HIGH RISK DETECTED] "`` to a JSON
    completion produces bytes no parser accepts, so the warn path destroyed the
    answer it was meant to deliver. ``proxy/endpoints/detect.py::_signal``
    already rules against the pattern, naming this module.
    """

    def test_the_module_does_not_concatenate_into_the_body(self, tree):
        assert _body_concatenations(tree) == []

    def test_negative_self_test_the_exact_pre_fix_line_is_flagged(self):
        pre_fix = ast.parse(
            'content=b"[ARKHEIA WARNING: HIGH RISK DETECTED] " + response_body\n'
        )
        assert _body_concatenations(pre_fix) == [1]

    def test_control_relaying_the_body_is_not_flagged(self):
        good = ast.parse("content=response_body\n")
        assert _body_concatenations(good) == []


# ---------------------------------------------------------------------------
# INV-9 — response framing headers are dropped as a PAIR
# ---------------------------------------------------------------------------

def _response_owned(tree: ast.Module) -> set[str]:
    node = _module_constant(tree, "RESPONSE_OWNED_HEADERS")
    if node is None:
        return set()
    for sub in ast.walk(node):
        if isinstance(sub, (ast.Set, ast.List, ast.Tuple)):
            return {e.value.lower() for e in sub.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def _framing_pair_broken(owned: set[str]) -> bool:
    return ("content-encoding" in owned) != ("content-length" in owned)


class TestInv9FramingHeadersDroppedTogether:
    """
    httpx advertises ``accept-encoding: gzip`` on every upstream request and
    transparently decodes the reply. Dropping ``content-encoding`` while
    relaying ``content-length`` therefore describes the COMPRESSED body over
    decompressed bytes — the sibling flow served EMPTY bodies with a server-side
    RuntimeError on the NORMAL path (PR #31). Either both go or neither does.
    """

    def test_both_are_owned(self, tree):
        owned = _response_owned(tree)
        assert len(owned) >= 2, f"only {sorted(owned)} declared response-owned"
        assert not _framing_pair_broken(owned)

    def test_negative_self_test_the_pre_fix_asymmetry_is_flagged(self):
        assert _framing_pair_broken({"content-encoding"}) is True

    def test_control_the_pair_is_not_flagged(self):
        assert _framing_pair_broken({"content-length", "content-encoding"}) is False
        assert _framing_pair_broken(set()) is False
