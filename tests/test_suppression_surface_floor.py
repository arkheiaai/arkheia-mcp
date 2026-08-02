"""
FLOOR — a false-positive suppression gate cannot land invisible or unbounded.

Stdlib + pytest only (`ast`, `pathlib`, `re`), no project imports, so this runs in the
required `floor-invariants` job with zero dependency and zero interpreter variance.

WHAT EARNED IT (2026-07-27, F7 run-to-ground)
---------------------------------------------
`proxy/detection/features.py` holds the only two functions in the detector that turn a
would-be finding into LOW. Every defect found in them was a variant of one shape: a
decision NOT to report something, taken on a value nobody validated, and then not
written down.

  * `float("nan") >= 1` is False, so a NaN `output_tokens` fell through to SUPPRESS.
    `False` coerced to 0.0 and suppressed. So did a negative count.
  * `is_function_call` was read for TRUTHINESS, so the string "false" suppressed a
    9999-token generative response.
  * `signals.get("token_count", inf) < max_tokens` raises TypeError for a None or
    string token_count; the raise escaped into the engine's blanket handler and reached
    the caller as `error="no_computable_features"` — a determinate benign-sounding cause
    standing in for a crash.
  * the suppression REASON died inside features.py: `DetectionResult` dropped it and
    `/detect/verify` dropped the whole `metrics` dict, so no caller, no audit row and no
    governance push could say why a LOW was a LOW.
  * a suppression carried no `gate_action`, so "a suppression can never authorize a
    block" depended on every consumer remembering a `.get(..., "advise")` default.

Six invariants, all DISCOVERING (never enumerating): a third gate added next year is
covered without anyone remembering this file exists. Per DONE.md v1.19/v1.22 each
carries a negative self-test that feeds it the exact pre-fix shape and requires it to
flag, and per invariant 9 each asserts its own work-done count is non-zero — "found
nothing" must never be confusable with "looked in the wrong place".

RED RUN (executed against origin/master @ 3037f0c): 5 failed, 10 passed. INV-1's
`metrics` sub-keys were already correct there — correctly green, since the metrics dict
was never the defect.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
FEATURES = _ROOT / "proxy" / "detection" / "features.py"
ENGINE = _ROOT / "proxy" / "detection" / "engine.py"
DETECT = _ROOT / "proxy" / "endpoints" / "detect.py"
PASSTHROUGH = _ROOT / "proxy" / "endpoints" / "passthrough.py"
INTERCEPTION = _ROOT / "proxy" / "middleware" / "interception.py"
MCP_SERVER = _ROOT / "mcp_server" / "server.py"
PROXY_CLIENT = _ROOT / "mcp_server" / "proxy_client.py"

#: The field every consumer must be able to read to tell a suppressed verdict from a
#: scored clean one. One name, checked at six boundaries.
MARKER = "gate_reason"

#: Keys a gate's own return dict must carry.
REQUIRED_GATE_KEYS = {
    "risk", "confidence", "gate_action", "evidence_depth_limited",
    "detection_method", "metrics",
}
REQUIRED_GATE_METRIC_KEYS = {"features_used", "gate_reason"}

#: Names of the module functions that decide a suppression. Discovered, not listed.
GATE_NAME_RE = re.compile(r"^check_[a-z0-9_]+_gate$")


# ---------------------------------------------------------------------------
# Analysers — take SOURCE TEXT so the negative self-tests can feed them a
# synthetic pre-fix shape rather than trusting the invariant's own description.
# ---------------------------------------------------------------------------

def _parse(src: str) -> ast.Module:
    return ast.parse(src)


def _dict_keys(node: ast.Dict) -> set[str]:
    return {k.value for k in node.keys
            if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def _dict_value(node: ast.Dict, key: str):
    for k, v in zip(node.keys, node.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    return None


def find_gates(src: str) -> dict[str, ast.FunctionDef]:
    """Every module-level `check_*_gate`."""
    return {n.name: n for n in _parse(src).body
            if isinstance(n, ast.FunctionDef) and GATE_NAME_RE.match(n.name)}


def gate_return_dicts(fn: ast.FunctionDef) -> list[ast.Dict]:
    return [n.value for n in ast.walk(fn)
            if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]


def declared_suppressed_methods(src: str) -> set[str]:
    """The closed taxonomy, read from the module rather than repeated here."""
    for n in _parse(src).body:
        if isinstance(n, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SUPPRESSED_DETECTION_METHODS"
            for t in n.targets
        ):
            if isinstance(n.value, (ast.Tuple, ast.List, ast.Set)):
                return {e.value for e in n.value.elts if isinstance(e, ast.Constant)}
    return set()


_ORDERED = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)


def _is_get_call(node) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get")


def unvalidated_names(fn: ast.FunctionDef) -> set[str]:
    """Locals bound DIRECTLY to a `.get()` result and never rebound through any other
    call. Binding to `_usable_count(...)` (or any other function) clears the taint —
    the point is the raw mapping read, not the variable name.
    """
    from_get: set[str] = set()
    from_other_call: set[str] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if not isinstance(t, ast.Name):
                continue
            if _is_get_call(node.value):
                from_get.add(t.id)
            elif isinstance(node.value, ast.Call):
                from_other_call.add(t.id)
    return from_get - from_other_call


def raw_signal_comparisons(fn: ast.FunctionDef) -> list[str]:
    """ORDERED comparisons (`<`, `<=`, `>`, `>=`) against an unvalidated mapping read.

    Two shapes, because the campaign proved the first check missed the second:
      inline   `signals.get("token_count", inf) < max_tokens`   (the pre-fix line)
      via name  `tc = signals.get("token_count")` … `tc < max_tokens`

    Restricted to ORDERED operators on purpose. `==` / `!=` / `is` never raise across
    types, so flagging `action != "suppress"` would make this a rule that forbids
    everything — and a floor that cries wolf gets switched off.
    """
    tainted = unvalidated_names(fn)
    hits = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, _ORDERED) for op in node.ops):
            continue
        for operand in [node.left, *node.comparators]:
            if _is_get_call(operand) or (
                isinstance(operand, ast.Name) and operand.id in tainted
            ):
                hits.append(ast.unparse(node))
                break
    return hits


def classdef_fields(src: str, class_name: str) -> set[str]:
    for n in _parse(src).body:
        if isinstance(n, ast.ClassDef) and n.name == class_name:
            return {t.target.id for t in n.body
                    if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)}
    return set()


def call_kwargs(src: str, callee: str) -> list[set[str]]:
    """Keyword names of every `callee(...)` call in the module."""
    out = []
    for node in ast.walk(_parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == callee:
            out.append({kw.arg for kw in node.keywords if kw.arg})
    return out


def function_return_dict_keys(src: str, fn_name: str) -> list[set[str]]:
    out = []
    for node in ast.walk(_parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            for r in ast.walk(node):
                if isinstance(r, ast.Return) and isinstance(r.value, ast.Dict):
                    out.append(_dict_keys(r.value))
    return out


def call_dict_kwarg_keys(src: str, callee: str, kwarg: str) -> list[set[str]]:
    """Keys of the dict literal passed as `callee(..., kwarg={...})`."""
    out = []
    for node in ast.walk(_parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == callee:
            for kw in node.keywords:
                if kw.arg == kwarg and isinstance(kw.value, ast.Dict):
                    out.append(_dict_keys(kw.value))
    return out


def scored_return_dicts(src: str) -> list[ast.Dict]:
    """The return dicts of `classify_with_profile` that are NOT a gate short-circuit —
    i.e. the SCORED verdict."""
    for node in _parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "classify_with_profile":
            return [n.value for n in ast.walk(node)
                    if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict)]
    return []


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def features_src() -> str:
    return FEATURES.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def engine_src() -> str:
    return ENGINE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def detect_src() -> str:
    return DETECT.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# INV-0 — the subjects exist. Without this every invariant below is vacuous.
# ---------------------------------------------------------------------------

def test_inv0_the_contract_this_floor_checks_against_has_not_gone_quiet(features_src):
    """The declarations above ARE the contract. Emptying one would leave every
    invariant below passing over nothing — the quietest way to switch a floor off."""
    assert len(REQUIRED_GATE_KEYS) >= 6, REQUIRED_GATE_KEYS
    assert len(REQUIRED_GATE_METRIC_KEYS) >= 2, REQUIRED_GATE_METRIC_KEYS
    assert MARKER and isinstance(MARKER, str)
    assert GATE_NAME_RE.match("check_mode_gate"), (
        "the discovery pattern no longer matches a known gate name"
    )


def test_inv0_the_files_and_the_gates_are_actually_found(features_src):
    for p in (FEATURES, ENGINE, DETECT, PASSTHROUGH, INTERCEPTION, MCP_SERVER, PROXY_CLIENT):
        assert p.exists(), f"floor pointed at a path that does not exist: {p}"
    gates = find_gates(features_src)
    assert len(gates) >= 2, (
        f"expected at least the two known suppression gates, discovered {sorted(gates)} "
        "— either they were renamed out of discovery or this floor is looking in the "
        "wrong place, which is indistinguishable from a clean bill of health"
    )
    for name, fn in gates.items():
        assert gate_return_dicts(fn), f"{name} returns no dict literal; nothing to check"


# ---------------------------------------------------------------------------
# INV-1 — every gate return states the full marker set
# ---------------------------------------------------------------------------

def test_inv1_every_gate_return_carries_the_required_keys(features_src):
    checked = 0
    for name, fn in find_gates(features_src).items():
        for d in gate_return_dicts(fn):
            keys = _dict_keys(d)
            missing = REQUIRED_GATE_KEYS - keys
            assert not missing, f"{name} suppression dict is missing {sorted(missing)}"
            metrics = _dict_value(d, "metrics")
            assert isinstance(metrics, ast.Dict), f"{name} metrics is not a dict literal"
            mmissing = REQUIRED_GATE_METRIC_KEYS - _dict_keys(metrics)
            assert not mmissing, f"{name} metrics is missing {sorted(mmissing)}"
            checked += 1
    assert checked >= 2, f"only {checked} gate returns examined"


def test_inv1_negative_self_test():
    """The pre-fix shape: a gate dict with no gate_action and no gate_reason."""
    src = (
        "def check_new_thing_gate(profile, signals):\n"
        "    return {'risk': 'LOW', 'confidence': 0.0, 'evidence_depth_limited': True,\n"
        "            'detection_method': 'x', 'metrics': {'features_used': 0}}\n"
    )
    fn = find_gates(src)["check_new_thing_gate"]
    d = gate_return_dicts(fn)[0]
    assert REQUIRED_GATE_KEYS - _dict_keys(d) == {"gate_action"}
    assert REQUIRED_GATE_METRIC_KEYS - _dict_keys(_dict_value(d, "metrics")) == \
        {"gate_reason"}


# ---------------------------------------------------------------------------
# INV-2 — the suppression vocabulary is closed
# ---------------------------------------------------------------------------

def test_inv2_every_gate_method_is_in_the_declared_closed_set(features_src):
    declared = declared_suppressed_methods(features_src)
    assert len(declared) >= 2, (
        "SUPPRESSED_DETECTION_METHODS is missing or empty; the closed taxonomy is what "
        "lets a consumer ask 'was this scored?' without string-matching"
    )
    checked = 0
    for name, fn in find_gates(features_src).items():
        for d in gate_return_dicts(fn):
            v = _dict_value(d, "detection_method")
            assert isinstance(v, ast.Constant), (
                f"{name} builds detection_method dynamically; the taxonomy stops being "
                "closed the moment it is computed"
            )
            assert v.value in declared, (
                f"{name} emits detection_method={v.value!r}, not in {sorted(declared)}"
            )
            checked += 1
    assert checked >= 2


def test_inv2_negative_self_test():
    src = (
        "SUPPRESSED_DETECTION_METHODS = ('a', 'b')\n"
        "def check_rogue_gate(profile, signals):\n"
        "    return {'detection_method': 'quietly_dropped', 'metrics': {}}\n"
    )
    declared = declared_suppressed_methods(src)
    d = gate_return_dicts(find_gates(src)["check_rogue_gate"])[0]
    assert _dict_value(d, "detection_method").value not in declared


# ---------------------------------------------------------------------------
# INV-3 — a suppression can never carry block authority
# ---------------------------------------------------------------------------

def test_inv3_every_gate_states_gate_action_advise(features_src):
    checked = 0
    for name, fn in find_gates(features_src).items():
        for d in gate_return_dicts(fn):
            v = _dict_value(d, "gate_action")
            assert isinstance(v, ast.Constant) and v.value == "advise", (
                f"{name} does not state gate_action='advise'. The gates return BEFORE "
                "resolve_gate_action is consulted, so containment would rest on every "
                "consumer remembering a .get(..., 'advise') default."
            )
            checked += 1
    assert checked >= 2


def test_inv3_negative_self_test():
    src = ("def check_bad_gate(p, s):\n"
           "    return {'gate_action': 'block', 'metrics': {}}\n")
    d = gate_return_dicts(find_gates(src)["check_bad_gate"])[0]
    assert _dict_value(d, "gate_action").value != "advise"


# ---------------------------------------------------------------------------
# INV-4 — the marker survives to every consumer boundary
# ---------------------------------------------------------------------------

def test_inv4_the_marker_reaches_all_six_boundaries(engine_src, detect_src):
    boundaries = {
        "DetectionResult field":
            MARKER in classdef_fields(engine_src, "DetectionResult"),
        "DetectionResult(...) call":
            any(MARKER in kws for kws in call_kwargs(engine_src, "DetectionResult")),
        "VerifyResponse field":
            MARKER in classdef_fields(detect_src, "VerifyResponse"),
        "VerifyResponse(...) call":
            any(MARKER in kws for kws in call_kwargs(detect_src, "VerifyResponse")),
        "_audit_record() return":
            any(MARKER in keys
                for keys in function_return_dict_keys(detect_src, "_audit_record")),
        "schedule_push(payload=...)":
            any(MARKER in keys
                for keys in call_dict_kwarg_keys(detect_src, "schedule_push", "payload")),
    }
    # Work-done: every boundary must have been LOCATED, not merely 'not violated'.
    assert len(classdef_fields(engine_src, "DetectionResult")) > 0
    assert len(classdef_fields(detect_src, "VerifyResponse")) > 0
    assert function_return_dict_keys(detect_src, "_audit_record"), \
        "_audit_record not found — this invariant examined nothing"
    assert call_dict_kwarg_keys(detect_src, "schedule_push", "payload"), \
        "no schedule_push(payload={...}) found — this invariant examined nothing"

    missing = sorted(k for k, ok in boundaries.items() if not ok)
    assert not missing, (
        f"the suppression marker {MARKER!r} does not reach: {missing}. A gate decided "
        "not to report something and that consumer cannot tell."
    )


def test_inv4_negative_self_test():
    """The pre-fix shape at each of the four detect.py/engine.py boundaries."""
    engine_pre = (
        "class DetectionResult:\n"
        "    risk_level: str\n"
        "    evidence_depth_limited: bool = True\n"
        "def f():\n"
        "    return DetectionResult(risk_level='LOW', evidence_depth_limited=True)\n"
    )
    detect_pre = (
        "class VerifyResponse:\n"
        "    risk_level: str\n"
        "def h():\n"
        "    r = VerifyResponse(risk_level='LOW')\n"
        "    schedule_push(payload={'risk_level': 'LOW'})\n"
        "def _audit_record(a, b, c):\n"
        "    return {'risk_level': 'LOW'}\n"
    )
    assert MARKER not in classdef_fields(engine_pre, "DetectionResult")
    assert not any(MARKER in k for k in call_kwargs(engine_pre, "DetectionResult"))
    assert MARKER not in classdef_fields(detect_pre, "VerifyResponse")
    assert not any(MARKER in k for k in call_kwargs(detect_pre, "VerifyResponse"))
    assert not any(MARKER in k
                   for k in function_return_dict_keys(detect_pre, "_audit_record"))
    assert not any(MARKER in k
                   for k in call_dict_kwarg_keys(detect_pre, "schedule_push", "payload"))
    # ...and the control: the analysers DO find it when it is there.
    assert MARKER in classdef_fields(
        engine_pre.replace("risk_level: str", f"risk_level: str\n    {MARKER}: str"),
        "DetectionResult")


# ---------------------------------------------------------------------------
# INV-5 — the marker must DISCRIMINATE
# ---------------------------------------------------------------------------

def test_inv5_a_scored_verdict_never_carries_the_marker(features_src):
    dicts = scored_return_dicts(features_src)
    assert dicts, "classify_with_profile returns no dict literal; nothing examined"
    checked = 0
    for d in dicts:
        keys = _dict_keys(d)
        if "features_triggered" not in keys:
            continue                      # a gate short-circuit re-returned, not scored
        assert MARKER not in keys, "the SCORED verdict carries the suppression marker"
        metrics = _dict_value(d, "metrics")
        if isinstance(metrics, ast.Dict):
            assert MARKER not in _dict_keys(metrics), (
                "the SCORED verdict's metrics carry a gate_reason; the marker would "
                "stop distinguishing 'not scored' from 'scored clean'"
            )
        checked += 1
    assert checked >= 1, "no scored return examined"


def test_inv5_negative_self_test():
    src = ("def classify_with_profile(p, s):\n"
           "    return {'risk': 'LOW', 'features_triggered': [],\n"
           "            'metrics': {'gate_reason': 'token_count_below_80'}}\n")
    d = scored_return_dicts(src)[0]
    assert MARKER in _dict_keys(_dict_value(d, "metrics"))


# ---------------------------------------------------------------------------
# INV-6 — a gate never compares an unvalidated signal
# ---------------------------------------------------------------------------

def test_inv6_no_gate_compares_a_raw_get_result(features_src):
    gates = find_gates(features_src)
    assert gates, "no gate discovered; this invariant examined nothing"
    offenders = {}
    for name, fn in gates.items():
        hits = raw_signal_comparisons(fn)
        if hits:
            offenders[name] = hits
    assert not offenders, (
        "a suppression gate compares the raw result of a .get() call: "
        f"{offenders}. `signals.get('token_count', inf) < max_tokens` raises TypeError "
        "for a None or string count and the raise reaches the caller mislabelled as "
        "error='no_computable_features'. Route the value through the shared count "
        "validator first."
    )


def test_inv6_negative_self_test_inline_shape():
    """The verbatim pre-fix line."""
    src = (
        "def check_mode_gate(profile, signals):\n"
        "    triggers = {}\n"
        "    max_tokens = triggers.get('token_count_max', 80)\n"
        "    if signals.get('token_count', float('inf')) < max_tokens:\n"
        "        return {'risk': 'LOW'}\n"
        "    return None\n"
    )
    hits = raw_signal_comparisons(find_gates(src)["check_mode_gate"])
    assert len(hits) == 1
    assert "signals.get('token_count'" in hits[0]


def test_inv6_negative_self_test_via_a_local_name():
    """MUTANT M17's shape, and the reason this invariant was strengthened: the first
    version of INV-6 only looked at inline `.get()` operands, so reverting the fix to
    `tc = signals.get(...)` on one line and comparing `tc` on the next walked straight
    past it. The mutation campaign returned M17 as KILLED_BY_OTHER — the runtime tests
    caught it, this floor did not — which is exactly the signal the campaign exists to
    produce."""
    src = (
        "def check_mode_gate(profile, signals):\n"
        "    token_count = signals.get('token_count', float('inf'))\n"
        "    if token_count < 80:\n"
        "        return {'risk': 'LOW'}\n"
        "    return None\n"
    )
    fn = find_gates(src)["check_mode_gate"]
    assert unvalidated_names(fn) == {"token_count"}
    assert raw_signal_comparisons(fn) == ["token_count < 80"]


def test_inv6_control_it_does_not_flag_a_validated_comparison():
    """The control row that PASSES — otherwise INV-6 is a rule that forbids everything."""
    src = (
        "def check_mode_gate(profile, signals):\n"
        "    tc = _usable_count(signals.get('token_count'))\n"
        "    if tc is not None and tc < 80:\n"
        "        return {'risk': 'LOW'}\n"
        "    return None\n"
    )
    fn = find_gates(src)["check_mode_gate"]
    assert unvalidated_names(fn) == set(), "validation through a call must clear taint"
    assert raw_signal_comparisons(fn) == []


def test_inv6_control_it_does_not_flag_an_equality_comparison():
    """Second control. `!=` / `==` cannot raise across types, so the live
    `action = tool_cfg.get("action", "suppress")` … `if action != "suppress"` is not a
    finding. A floor that cries wolf gets switched off, and then there is no floor."""
    src = (
        "def check_mode_gate(profile, signals):\n"
        "    action = tool_cfg.get('action', 'suppress')\n"
        "    if action != 'suppress':\n"
        "        return None\n"
        "    return {'risk': 'LOW'}\n"
    )
    fn = find_gates(src)["check_mode_gate"]
    assert unvalidated_names(fn) == {"action"}          # tainted, correctly
    assert raw_signal_comparisons(fn) == []             # but not an ordered compare


# ---------------------------------------------------------------------------
# INV-7 — every wrapper / passthrough / interception surface can carry the
# provider's empty-output fact to the same detector gate.
# ---------------------------------------------------------------------------

EMPTY_METADATA_KEYS = {"usage", "output_tokens", "is_function_call"}


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Await):
        node = node.value
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _call_has_empty_metadata(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg in EMPTY_METADATA_KEYS:
            return True
        if kw.arg is None:
            return True
    return False


def _verify_calls_missing_empty_metadata(src: str) -> tuple[int, list[str]]:
    """Calls that send model output to the detector but cannot carry zero-output facts."""
    offenders: list[str] = []
    checked = 0
    for node in ast.walk(_parse(src)):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name not in {"verify", "_verify_hosted", "_detect_and_audit"}:
            continue
        checked += 1
        if not _call_has_empty_metadata(node):
            offenders.append(f"line {node.lineno}: {ast.unparse(node)}")
    return checked, offenders


def _hard_empty_truthiness_guards(src: str) -> list[str]:
    """Truthiness guards where `response_text == ""` cannot reach screening."""
    offenders: list[str] = []

    def bare_response_text(node: ast.AST) -> bool:
        return isinstance(node, ast.Name) and node.id == "response_text"

    def bad_test(node: ast.AST) -> bool:
        if bare_response_text(node):
            return True
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return bare_response_text(node.operand)
        if isinstance(node, ast.BoolOp):
            return any(bad_test(v) for v in node.values)
        return False

    for node in ast.walk(_parse(src)):
        if isinstance(node, ast.If) and bad_test(node.test):
            offenders.append(f"line {node.lineno}: {ast.unparse(node.test)}")
    return offenders


def test_inv7_empty_output_metadata_reaches_all_runtime_surfaces():
    sources = {
        "mcp_server/server.py": MCP_SERVER.read_text(encoding="utf-8"),
        "mcp_server/proxy_client.py": PROXY_CLIENT.read_text(encoding="utf-8"),
        "proxy/endpoints/detect.py": DETECT.read_text(encoding="utf-8"),
        "proxy/endpoints/passthrough.py": PASSTHROUGH.read_text(encoding="utf-8"),
        "proxy/middleware/interception.py": INTERCEPTION.read_text(encoding="utf-8"),
    }

    checked = 0
    soft_empty: dict[str, list[str]] = {}
    hard_empty: dict[str, list[str]] = {}
    for rel, src in sources.items():
        n, offenders = _verify_calls_missing_empty_metadata(src)
        checked += n
        if offenders:
            soft_empty[rel] = offenders
        guards = _hard_empty_truthiness_guards(src)
        if guards:
            hard_empty[rel] = guards

    assert checked >= 10, (
        f"only discovered {checked} detector calls across the wrapper/passthrough/"
        "interception surfaces. The empty-output floor would be passing over an "
        "empty or near-empty population."
    )
    assert not soft_empty, (
        "soft-empty suppression is unreachable on these detector calls because "
        f"provider output metadata is not forwarded: {soft_empty}"
    )
    assert not hard_empty, (
        "hard-empty suppression is unreachable behind truthiness guards that skip "
        f"response_text == '': {hard_empty}"
    )


def test_inv7_negative_self_test_soft_empty_offender_is_measured():
    src = (
        "async def wrapper(prompt, response_text, model_id):\n"
        "    return await proxy.verify(prompt=prompt, response=response_text, model_id=model_id)\n"
    )
    checked, offenders = _verify_calls_missing_empty_metadata(src)
    assert checked == 1
    assert offenders and "proxy.verify" in offenders[0]


def test_inv7_negative_self_test_hard_empty_guard_is_measured():
    src = (
        "async def route(response_text):\n"
        "    if response_text:\n"
        "        return await _detect_and_audit(request, prompt, response_text, model_id)\n"
        "    return 'SKIP'\n"
    )
    offenders = _hard_empty_truthiness_guards(src)
    assert offenders == ["line 2: response_text"]


def test_inv7_control_empty_string_can_reach_screening_when_metadata_is_present():
    src = (
        "async def route(response_text, output_tokens):\n"
        "    if response_text is not None or _is_zero_count(output_tokens):\n"
        "        return await _detect_and_audit(\n"
        "            request, prompt, response_text or '', model_id,\n"
        "            output_tokens=output_tokens,\n"
        "        )\n"
    )
    checked, offenders = _verify_calls_missing_empty_metadata(src)
    assert checked == 1
    assert offenders == []
    assert _hard_empty_truthiness_guards(src) == []
