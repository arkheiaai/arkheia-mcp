"""
FLOOR TIER — governance detection-adapter push.

Stdlib + pytest only (no httpx, no respx, no `proxy.*` import): this file is
collected by `.github/workflows/floor-invariants.yml`, a REQUIRED status context
on `master`, which installs pytest and nothing else. Zero interpreter variance.

Each invariant here is compiled from a defect that was REAL in this file, per the
Compounding Floor: defect -> invariant -> deterministic check.

  F-1  The signing string is the RECEIVER's. This module shipped signing
       `f"{ts}.{body}"` against a receiver that verifies
       `"POST\\n{path}\\n{ts}\\n{sha256_hex(body)}"`. Every push was a guaranteed 401.

  F-2  A failed governance push is never logged below WARNING. The 4xx was a
       `logger.debug`, which is how the sibling rail (proxy -> Synesis ingest)
       stayed dark for twenty days behind a swallowed `400 MISSING_EVENT_ID`.

  F-3  No unsigned send, and one key source. Every outbound POST carries signing
       headers; the secret comes from one env var with no default and no on-disk
       cache (the sibling flow derived a "machine-bound" key from `sha256(b"")`).

  F-4  No deprecated `asyncio.get_event_loop()`. It raises on Python 3.14 and the
       broad `except` swallowed that at debug level, so `schedule_push` did
       nothing at all from sync code while looking healthy.

  F-5  The target is COMPOSED IN ONE PLACE and the base URL is never concatenated
       raw. `f"{url}{ADAPTER_PATH}"` against
       `DETECTION_ADAPTER_URL=http://adapter:7070/` posts to `//v1/events/proxy`,
       which the receiver's router 404s with an EMPTY BODY on a fire-and-forget
       path. One character in one env var, and the rail this branch was opened to
       repair is dark again.

  F-6  Every failure log names the TARGET. A 404 with no body and no address is
       the least diagnosable line a governance rail can emit.

EVERY CHECK IS STRUCTURAL (AST), NOT TEXTUAL. The first draft of F-1 was a
substring search and it fired on this module's own docstring, which QUOTES the
defective construction. A floor that cannot tell code from prose cries wolf, and
a floor that cries wolf gets switched off.

Every test also asserts it MEASURED something before it asserts a verdict —
"a measurement gate must fail when it measures nothing" (DONE.md floor entry 9).
"""
import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE = REPO_ROOT / "proxy" / "detection_adapter.py"

# The receiver's construction, decomposed. From
# arkheia-synesis/services/detection-adapter/src/hmac_auth.rs::verify:
#     format!("POST\n{}\n{}\n{}", path, headers.timestamp, body_hash)
EXPECTED_SIGNING_LITERALS = ["POST\n", "\n", "\n"]
EXPECTED_SIGNING_SLOTS = ["ADAPTER_PATH", "ts", "body_hash"]


@pytest.fixture(scope="module")
def tree() -> ast.Module:
    assert MODULE.is_file(), f"{MODULE} is missing — the flow this floor guards is gone"
    text = MODULE.read_text(encoding="utf-8")
    assert len(text) > 500, "module is implausibly small; the gate would measure nothing"
    return ast.parse(text)


def _calls(node):
    return [n for n in ast.walk(node) if isinstance(n, ast.Call)]


def _chain(node) -> str:
    """`logger.debug` -> 'logger.debug'; `asyncio.get_event_loop` -> the full path."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _const_args(call):
    return [a.value for a in call.args if isinstance(a, ast.Constant)]


# ── F-1: the signing string is the receiver's ────────────────────────────────

def test_signing_string_is_structurally_the_receivers_construction(tree):
    """
    Decompose the f-string in `_sign_headers` and compare it to the receiver's
    `format!` literal-by-literal and slot-by-slot. Structural, so the docstring
    that quotes the OLD construction cannot satisfy or break it.
    """
    fn = _func(tree, "_sign_headers")
    assert fn is not None, "_sign_headers is gone — measured nothing"

    fstrings = [n for n in ast.walk(fn) if isinstance(n, ast.JoinedStr)]
    assert len(fstrings) == 1, f"expected one f-string in _sign_headers, found {len(fstrings)}"

    literals = [
        p.value for p in fstrings[0].values
        if isinstance(p, ast.Constant) and isinstance(p.value, str)
    ]
    slots = [
        _chain(p.value) for p in fstrings[0].values if isinstance(p, ast.FormattedValue)
    ]
    assert literals == EXPECTED_SIGNING_LITERALS, (
        f"signing string literals drifted from the receiver's: {literals!r}"
    )
    assert slots == EXPECTED_SIGNING_SLOTS, (
        f"signing string slots drifted from the receiver's: {slots!r}"
    )


def test_the_signed_path_is_the_endpoint_the_receiver_mounts(tree):
    """`handlers.rs` passes the literal "/v1/events/proxy" into `verify`."""
    values = [
        n.value.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "ADAPTER_PATH" for t in n.targets)
        and isinstance(n.value, ast.Constant)
    ]
    assert values == ["/v1/events/proxy"], f"ADAPTER_PATH is {values!r}"


def test_the_body_hash_is_taken_over_the_bytes_that_are_sent(tree):
    """
    `body_hash = hashlib.sha256(body).hexdigest()` — over `body`, the same name
    passed as the POST `content`. Signing a re-serialised copy would verify
    locally and 401 on the wire.
    """
    fn = _func(tree, "_sign_headers")
    sha_calls = [c for c in _calls(fn) if _chain(c.func) == "hashlib.sha256"]
    assert len(sha_calls) == 1, f"expected one sha256 of the body, found {len(sha_calls)}"
    assert [a.id for a in sha_calls[0].args if isinstance(a, ast.Name)] == ["body"]


# ── F-2: failures are visible ────────────────────────────────────────────────

def test_no_failure_on_this_rail_is_logged_below_warning(tree):
    """
    A governance record that did not land does not exist. Debug level is
    indistinguishable from silence in production — how a rail stays dark for weeks.
    """
    logger_calls = [c for c in _calls(tree) if _chain(c.func).startswith("logger.")]
    assert logger_calls, "measured nothing — no logger calls found at all"

    below_warning = sorted(
        {_chain(c.func) for c in logger_calls if _chain(c.func) in ("logger.debug", "logger.info")}
    )
    assert below_warning == [], f"governance push failures must be visible; found {below_warning}"

    # positive control: the module really does log failures, loudly
    errors = [c for c in logger_calls if _chain(c.func) == "logger.error"]
    assert len(errors) >= 4, f"expected the failure paths to log at ERROR; found {len(errors)}"


def test_the_failure_marker_is_stable_and_actually_used(tree):
    """The operator-facing grep handle. Renaming it silently breaks alerting."""
    assigned = [
        n.value.value
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "FAILURE_MARKER" for t in n.targets)
        and isinstance(n.value, ast.Constant)
    ]
    assert assigned == ["GOVERNANCE_PUSH_FAILED"], f"FAILURE_MARKER is {assigned!r}"

    loads = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Name) and n.id == "FAILURE_MARKER" and isinstance(n.ctx, ast.Load)
    ]
    assert len(loads) >= 4, f"marker defined but barely used ({len(loads)} loads)"


def test_every_failure_branch_of_push_event_logs_at_error(tree):
    """
    Originally: the two branches that were `debug` — the non-2xx branch and the
    transport handler. Rewritten to DISCOVER handlers rather than pin their count.

    The count-of-one form failed the moment a second, legitimate handler was added
    (the malformed-URL guard), and a floor whose only failure mode is "someone
    added a branch" teaches the next author to relax it. Discovering every handler
    is strictly stronger: a third one, added a year from now, is covered without
    anyone remembering this file exists.
    """
    fn = _func(tree, "push_event")
    assert fn is not None, "push_event is gone — measured nothing"

    handlers = [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]
    assert len(handlers) >= 2, (
        f"expected at least the transport and config handlers, found {len(handlers)}"
    )
    for h in handlers:
        assert [c for c in _calls(h) if _chain(c.func) == "logger.error"], (
            f"the except handler at line {h.lineno} swallows its failure without "
            f"an ERROR — that is how a rail goes dark"
        )

    # the >=400 branch
    compares = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Compare)
        and _chain(n.left).endswith("status_code")
        and any(isinstance(o, ast.GtE) for o in n.ops)
    ]
    assert len(compares) == 1, "the non-2xx guard is missing or duplicated"
    bound = compares[0].comparators[0]
    assert isinstance(bound, ast.Constant) and bound.value == 400, (
        f"the rejection threshold is {ast.dump(bound)}, not >= 400"
    )


# ── F-3: no unsigned send, one key source ────────────────────────────────────

def test_every_outbound_post_is_signed(tree):
    posts = [c for c in _calls(tree) if _chain(c.func).endswith(".post")]
    assert len(posts) == 1, f"expected exactly one outbound POST, found {len(posts)}"
    kwargs = {k.arg for k in posts[0].keywords}
    assert "headers" in kwargs, "an outbound POST carries no signing headers"
    assert "content" in kwargs, "body must be the RAW signed bytes, not re-encoded json="


def test_the_secret_has_exactly_one_source_and_no_default(tree):
    """
    One env var, no default, no on-disk cache, no derivation. Structural, so the
    docstring that DISCUSSES key material cannot trip it.
    """
    getenvs = [c for c in _calls(tree) if _chain(c.func) == "os.getenv"]
    names = sorted(_const_args(c)[0] for c in getenvs if _const_args(c))
    assert names == [
        "DETECTION_ADAPTER_HMAC_SECRET",
        "DETECTION_ADAPTER_KEY_ID",
        "DETECTION_ADAPTER_URL",
    ], f"config surface changed: {names!r}"

    secret_reads = [c for c in getenvs if _const_args(c)[:1] == ["DETECTION_ADAPTER_HMAC_SECRET"]]
    assert len(secret_reads) == 1, f"the secret is read {len(secret_reads)} times"
    assert _const_args(secret_reads[0]) == ["DETECTION_ADAPTER_HMAC_SECRET", ""], (
        "the signing secret must have an EMPTY default — a non-empty one is a shipped key"
    )

    # no file or derivation path anywhere in the module
    banned = {"open", "expanduser", "pbkdf2_hmac", "getpass"}
    found = sorted({_chain(c.func).split(".")[-1] for c in _calls(tree)} & banned)
    assert found == [], f"unexpected key-material path: {found!r}"


def test_missing_config_returns_before_any_network_call(tree):
    """
    The guard must be an EARLY RETURN, not a branch that falls through, so no
    reordering can leave an unsigned request reachable.
    """
    fn = _func(tree, "push_event")
    skips = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Return) and "SKIPPED" in ast.dump(n)
    ]
    posts = [
        c.lineno for c in ast.walk(fn)
        if isinstance(c, ast.Call) and _chain(c.func).endswith(".post")
    ]
    assert len(skips) == 1, f"expected one unconfigured early-return, found {len(skips)}"
    assert len(posts) == 1, f"expected one POST inside push_event, found {len(posts)}"
    assert skips[0] < posts[0], "the unconfigured guard does not precede the send"


# ── F-4: dispatch actually dispatches ────────────────────────────────────────

def test_no_deprecated_get_event_loop(tree):
    banned = [c for c in _calls(tree) if _chain(c.func) == "asyncio.get_event_loop"]
    assert banned == [], "asyncio.get_event_loop() is back; use get_running_loop()"

    ok = [c for c in _calls(tree) if _chain(c.func) == "asyncio.get_running_loop"]
    assert len(ok) == 1, "get_running_loop() not found — the gate measured nothing"


# ── F-5: one composer, and no raw concatenation of the base URL ──────────────

def test_the_post_target_is_a_name_not_an_inline_concatenation(tree):
    """
    The POST target must be a plain NAME (`target`), computed once by the
    normalising composer — never an f-string or `+` assembled at the call site.

    Structural on purpose: this is the exact shape of the defect. `f"{url}{ADAPTER_PATH}"`
    reads as obviously correct and is wrong for every base URL a human would
    naturally write. Requiring a pre-computed name means the composition cannot be
    re-inlined without failing here.
    """
    posts = [c for c in _calls(tree) if _chain(c.func).endswith(".post")]
    assert len(posts) == 1, f"expected exactly one outbound POST, found {len(posts)}"
    target = posts[0].args[0] if posts[0].args else None
    assert isinstance(target, ast.Name), (
        "the POST target is composed inline; it must come from the single "
        f"normalising composer, got {type(target).__name__}"
    )


def test_the_base_url_is_never_joined_to_a_path_by_raw_concatenation(tree):
    """
    Auto-discovering: ANY f-string or `+` in this module that puts a slot directly
    before a literal beginning with "/" is the defect's shape, wherever it appears.
    The one legitimate join lives in `adapter_target`, which normalises first.
    """
    composer = _func(tree, "adapter_target")
    assert composer is not None, "adapter_target is gone — measured nothing"
    exempt = {id(n) for n in ast.walk(composer)}

    offenders = []
    for node in ast.walk(tree):
        if id(node) in exempt:
            continue
        if isinstance(node, ast.JoinedStr):
            parts = node.values
            for a, b in zip(parts, parts[1:]):
                if (
                    isinstance(a, ast.FormattedValue)
                    and isinstance(b, ast.Constant)
                    and isinstance(b.value, str)
                    and b.value.startswith("/")
                ):
                    offenders.append((node.lineno, ast.unparse(node)))
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            right = node.right
            if isinstance(right, ast.Constant) and isinstance(right.value, str) \
                    and right.value.startswith("/"):
                offenders.append((node.lineno, ast.unparse(node)))

    assert offenders == [], (
        f"raw base-URL/path concatenation outside adapter_target: {offenders}"
    )

    # Positive control: the scanner CAN find this shape — prove it against the
    # pre-fix construction rather than trusting an empty result (DONE.md: a check
    # that passes by finding nothing must prove it can find something).
    probe = ast.parse('x = f"{url}/v1/events/proxy"')
    found = [
        n for n in ast.walk(probe)
        if isinstance(n, ast.JoinedStr)
        for a, b in zip(n.values, n.values[1:])
        if isinstance(a, ast.FormattedValue) and isinstance(b, ast.Constant)
        and isinstance(b.value, str) and b.value.startswith("/")
    ]
    assert found, "the scanner cannot detect the very defect it guards — it is decoration"


def test_a_malformed_url_is_its_own_outcome_and_not_folded_into_skipped(tree):
    """
    `SKIPPED` is silent by design ("nobody asked for this rail"). Filing a typo
    under it would be fail-SILENT wearing a fail-open badge, so the misconfigured
    state must exist as a distinct member.
    """
    members = {
        t.id
        for n in ast.walk(tree)
        if isinstance(n, ast.ClassDef) and n.name == "PushOutcome"
        for s in n.body
        if isinstance(s, ast.Assign)
        for t in s.targets
        if isinstance(t, ast.Name)
    }
    assert {"SKIPPED", "MISCONFIGURED", "DELIVERED", "REJECTED", "FAILED"} <= members, (
        f"PushOutcome lost a state: {sorted(members)}"
    )


def test_the_startup_guard_exists_and_raises(tree):
    """
    Invalid config must be refusable at BOOT. A guard that only warns would leave
    the operator to discover the fault one lost push at a time.
    """
    fn = _func(tree, "validate_config_or_raise")
    assert fn is not None, "the startup guard is gone — measured nothing"
    raises = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Raise) and "RuntimeError" in ast.dump(n)
    ]
    assert raises, "validate_config_or_raise never raises — it cannot fail a boot"


# ── F-6: every failure log names the target ──────────────────────────────────

def test_every_failure_log_in_push_event_names_the_target(tree):
    """
    A 404 from axum has an EMPTY BODY. Without the attempted address the operator
    reads "GOVERNANCE_PUSH_FAILED ... HTTP 404: " and learns nothing at all.

    Discovered, not enumerated: every `logger.error` inside `push_event` must
    interpolate `target` (or, for the branch where no target could be composed,
    the exception carrying the offending value).
    """
    fn = _func(tree, "push_event")
    errors = [c for c in _calls(fn) if _chain(c.func) == "logger.error"]
    assert len(errors) >= 3, f"expected the three failure paths to log; found {len(errors)}"

    for call in errors:
        names = {a.id for a in call.args if isinstance(a, ast.Name)}
        assert names & {"target", "exc"}, (
            f"the ERROR at line {call.lineno} names neither the attempted target "
            f"nor the offending config value"
        )


def test_the_receipt_records_the_composed_target(tree):
    """
    The durable half. `adapter_url` must be fed the composed target, not the raw
    base URL, or the forensic record cannot distinguish a misroute from a refusal.
    """
    fn = _func(tree, "push_event")
    record = _func(fn, "_record")
    assert record is not None, "_record is gone — measured nothing"
    assert "target" in {a.arg for a in record.args.args}, (
        "_record does not take the target, so the receipt cannot name the address used"
    )

    keys = [
        (k.value, v)
        for n in ast.walk(record) if isinstance(n, ast.Dict)
        for k, v in zip(n.keys, n.values)
        if isinstance(k, ast.Constant) and k.value == "adapter_url"
    ]
    assert len(keys) == 1, f"expected one adapter_url field, found {len(keys)}"
    assert isinstance(keys[0][1], ast.Name) and keys[0][1].id == "target", (
        "adapter_url is not the composed target"
    )


def test_fire_and_forget_tasks_report_their_own_failure(tree):
    """A task whose exception nobody retrieves is another flavour of silence."""
    cbs = [c for c in _calls(tree) if _chain(c.func).endswith("add_done_callback")]
    assert len(cbs) == 1, f"expected one done-callback registration, found {len(cbs)}"
    assert [a.id for a in cbs[0].args if isinstance(a, ast.Name)] == ["_log_task_result"]
    assert _func(tree, "_log_task_result") is not None
