"""
Tests for ProxyClient — local proxy + hosted API fallback.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_server.proxy_client import ProxyClient, _unavailable


@pytest.fixture
def client_with_key():
    """ProxyClient with hosted API key configured."""
    return ProxyClient(
        base_url="http://localhost:8098",
        hosted_url="https://arkheia-proxy-production.up.railway.app",
        api_key="ak_live_testkey",
    )


@pytest.fixture
def client_no_key():
    """ProxyClient without hosted API key."""
    return ProxyClient(
        base_url="http://localhost:8098",
        api_key=None,
    )


class TestLocalProxy:
    """Tests for local proxy path."""

    @pytest.mark.asyncio
    async def test_local_success(self, client_with_key):
        """Local proxy returns result — no hosted fallback."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "risk_level": "LOW",
            "confidence": 0.85,
            "features_triggered": ["word_count"],
            "detection_id": "det_abc123",
            "evidence_depth_limited": False,
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await client_with_key.verify("prompt", "response text", "gpt-4o")

        assert result["risk_level"] == "LOW"
        assert result["confidence"] == 0.85

    @pytest.mark.asyncio
    async def test_evidence_limited_local_escalates_to_hosted_with_routing_receipt(
        self, client_with_key
    ):
        """
        A local evidence-limited LOW is not a clean verdict. With a hosted key,
        the client must route onward and receipt both legs so the caller can see
        why the hosted verdict won.
        """
        local_response = MagicMock()
        local_response.json.return_value = {
            "risk_level": "LOW",
            "confidence": 0.0,
            "features_triggered": [],
            "detection_id": "det_local_limited",
            "detection_method": "tool_surface_suppressed",
            "evidence_depth_limited": True,
        }
        local_response.raise_for_status = MagicMock()

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "HIGH",
            "confidence": 0.93,
            "features_triggered": ["entropy_anomaly"],
            "detection_id": "det_hosted_real",
            "detection_method": "profile_ensemble",
            "evidence_depth_limited": False,
        }
        hosted_response.raise_for_status = MagicMock()

        calls = []

        async def mock_post(url, **kwargs):
            calls.append(url)
            if "/detect/verify" in url:
                return local_response
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "fabricated claim", "gpt-4o")

        assert result["risk_level"] == "HIGH"
        assert result["source"] == "hosted"
        assert result["detection_id"] == "det_hosted_real"
        assert result["routing"] == {
            "attempted_sources": ["local", "hosted"],
            "route_errors": [],
            "fallback_reason": "local_evidence_limited",
        }
        assert len(calls) == 2

    @pytest.mark.asyncio
    async def test_local_connect_error_falls_back_to_hosted(self, client_with_key):
        """Local proxy down → falls back to hosted API."""
        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "MEDIUM",
            "confidence": 0.72,
            "detection_id": "det_hosted123",
            "features_triggered": ["structural_anomaly"],
            "detection_method": "profile_ensemble",
            "evidence_depth_limited": True,
        }
        hosted_response.raise_for_status = MagicMock()

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/detect/verify" in url:
                raise httpx.ConnectError("Connection refused")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "MEDIUM"
        assert result["confidence"] == 0.72
        assert result.get("source") == "hosted"
        assert result["routing"] == {
            "attempted_sources": ["local", "hosted"],
            "route_errors": ["proxy_unavailable"],
            "fallback_reason": "proxy_unavailable",
        }
        assert call_count == 2  # local failed, then hosted

    @pytest.mark.asyncio
    async def test_local_down_no_api_key(self, client_no_key):
        """Local proxy down + no API key → no_detection_available."""
        async def mock_post(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_no_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "no_detection_available"
        assert result["routing"] == {
            "attempted_sources": ["local"],
            "route_errors": ["proxy_unavailable"],
            "fallback_reason": "proxy_unavailable",
        }

    @pytest.mark.asyncio
    async def test_local_error_field_survives_without_hosted_key(self, client_no_key):
        """A local UNKNOWN reason must not be dropped while normalising shape."""
        local_response = MagicMock()
        local_response.json.return_value = {
            "risk_level": "UNKNOWN",
            "confidence": 0.0,
            "features_triggered": [],
            "detection_id": "det_engine",
            "error": "engine_error",
            "evidence_depth_limited": True,
        }
        local_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=local_response):
            result = await client_no_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "engine_error"
        assert result["source"] == "local"
        assert result["routing"] == {
            "attempted_sources": ["local"],
            "route_errors": ["engine_error"],
            "fallback_reason": "engine_error",
        }

    @pytest.mark.asyncio
    async def test_local_http_error_falls_back_to_hosted_with_routing_receipt(
        self, client_with_key
    ):
        """Local service HTTP failure should not stop hosted fail-safe routing."""
        local_503 = httpx.Response(
            503,
            request=httpx.Request("POST", "http://localhost:8098/detect/verify"),
        )
        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "MEDIUM",
            "confidence": 0.61,
            "features_triggered": ["semantic_drift"],
            "detection_id": "det_hosted_after_503",
            "detection_method": "profile_ensemble",
            "evidence_depth_limited": False,
        }
        hosted_response.raise_for_status = MagicMock()

        async def mock_post(url, **kwargs):
            if "/detect/verify" in url:
                raise httpx.HTTPStatusError(
                    "Service unavailable",
                    request=local_503.request,
                    response=local_503,
                )
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "MEDIUM"
        assert result["source"] == "hosted"
        assert result["routing"] == {
            "attempted_sources": ["local", "hosted"],
            "route_errors": ["proxy_http_error_503"],
            "fallback_reason": "proxy_http_error_503",
        }

    @pytest.mark.asyncio
    async def test_both_detection_paths_failed_is_receipted(self, client_with_key):
        """When neither backend scores, aggregate the fail-safe and keep specifics."""
        call_count = 0

        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/detect/verify" in url:
                raise httpx.ConnectError("Connection refused")
            raise httpx.TimeoutException("Hosted read timed out")

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "all_detection_paths_failed"
        assert result["source"] == "unavailable"
        assert result["routing"] == {
            "attempted_sources": ["local", "hosted"],
            "route_errors": ["proxy_unavailable", "hosted_timeout"],
            "fallback_reason": "proxy_unavailable",
        }
        assert call_count == 2


    @pytest.mark.asyncio
    async def test_local_timeout_falls_back_to_hosted(self, client_with_key):
        """Local proxy timeout → falls back to hosted API (not just ConnectError)."""
        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "LOW",
            "confidence": 0.80,
            "detection_id": "det_timeout_fb",
            "features_triggered": [],
            "detection_method": "structural",
            "evidence_depth_limited": False,
        }
        hosted_response.raise_for_status = MagicMock()

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/detect/verify" in url:
                raise httpx.TimeoutException("Read timed out")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "LOW"
        assert result.get("source") == "hosted"
        assert call_count == 2  # local timed out, then hosted

    @pytest.mark.asyncio
    async def test_circuit_breaker_flips_after_local_failure(self, client_with_key):
        """After local proxy fails, _local_available should flip to False."""
        assert client_with_key._local_available is True  # starts optimistic

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "LOW",
            "confidence": 0.5,
            "detection_id": "det_cb",
            "features_triggered": [],
            "detection_method": None,
            "evidence_depth_limited": True,
        }
        hosted_response.raise_for_status = MagicMock()

        async def mock_post(url, **kwargs):
            if "/detect/verify" in url:
                raise httpx.ConnectError("Connection refused")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            await client_with_key.verify("prompt", "response", "gpt-4o")

        # Circuit breaker should now be open — local marked unavailable
        assert client_with_key._local_available is False, \
            "_local_available should be False after ConnectError fallback"

    @pytest.mark.asyncio
    async def test_hosted_generic_http_error(self, client_with_key):
        """Hosted API returns 500 → generic error, not auth or quota."""
        client_with_key._local_available = False

        response_500 = httpx.Response(500, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Server error", request=response_500.request, response=response_500)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "hosted_http_error_500"


class TestHostedFallback:
    """Tests for hosted API fallback path."""

    @pytest.mark.asyncio
    async def test_hosted_maps_response_format(self, client_with_key):
        """Hosted response format is mapped to local format."""
        # Force local to fail
        client_with_key._local_available = False

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "detection_id": "det_xyz",
            "risk": "HIGH",
            "confidence": 0.95,
            "evidence_depth_limited": False,
            "model": "gpt-4o",
            "detection_method": "profile_ensemble",
            "features_triggered": ["entropy_anomaly", "structural_anomaly"],
            "timestamp": "2026-03-28T00:00:00Z",
        }
        hosted_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=hosted_response):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "HIGH"  # mapped from "risk"
        assert result["confidence"] == 0.95
        assert result["detection_id"] == "det_xyz"
        assert result["features_triggered"] == ["entropy_anomaly", "structural_anomaly"]
        assert result["source"] == "hosted"

    @pytest.mark.asyncio
    async def test_hosted_fallback_receives_structural_usage_metadata(self, client_with_key):
        """Local failure must not strand the zero-output signal before hosted scoring."""
        client_with_key._local_available = False

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "LOW",
            "confidence": 0.0,
            "features_triggered": [],
            "detection_id": "det_empty_hosted",
            "detection_method": "empty_output_suppressed",
            "evidence_depth_limited": True,
        }
        hosted_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=hosted_response) as post:
            await client_with_key.verify(
                "prompt",
                "",
                "gpt-4o",
                usage={"completion_tokens": 0},
                output_tokens=0,
                is_function_call=False,
            )

        payload = post.call_args.kwargs["json"]
        assert payload["usage"] == {"completion_tokens": 0}
        assert payload["output_tokens"] == 0
        assert payload["is_function_call"] is False

    @pytest.mark.asyncio
    async def test_hosted_auth_failure(self, client_with_key):
        """Hosted API returns 401 → auth error."""
        client_with_key._local_available = False

        response_401 = httpx.Response(401, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Unauthorized", request=response_401.request, response=response_401)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["error"] == "hosted_auth_failed"

    @pytest.mark.asyncio
    async def test_hosted_quota_exceeded(self, client_with_key):
        """Hosted API returns 429 → quota error."""
        client_with_key._local_available = False

        response_429 = httpx.Response(429, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Rate limited", request=response_429.request, response=response_429)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["error"] == "hosted_quota_exceeded"


class TestAuditLog:
    """Tests for audit log (local only)."""

    @pytest.mark.asyncio
    async def test_audit_log_success(self, client_with_key):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "events": [{"risk_level": "LOW"}],
            "summary": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            result = await client_with_key.get_audit_log()

        assert len(result["events"]) == 1

    @pytest.mark.asyncio
    async def test_audit_log_unavailable(self, client_with_key):
        async def mock_get(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            result = await client_with_key.get_audit_log()

        assert result["events"] == []
        assert result["error"] == "proxy_unavailable"


class TestNeverRaises:
    """Contract: ProxyClient methods never raise."""

    @pytest.mark.asyncio
    async def test_verify_never_raises(self, client_with_key):
        async def explode(*args, **kwargs):
            raise RuntimeError("Catastrophic failure")

        with patch("httpx.AsyncClient.post", side_effect=explode):
            result = await client_with_key.verify("p", "r", "m")

        assert result["risk_level"] == "UNKNOWN"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_audit_never_raises(self, client_with_key):
        async def explode(*args, **kwargs):
            raise RuntimeError("Catastrophic failure")

        with patch("httpx.AsyncClient.get", side_effect=explode):
            result = await client_with_key.get_audit_log()

        assert result["events"] == []
        assert "error" in result


# ===========================================================================
# VERDICT SHAPE PARITY  (Codex review, PR #17 finding 1)
#
# The defect: the transparency fields (`detection_method`,
# `evidence_depth_limited`, `source`) were added to the hosted SUCCESS path
# only. Reproduced before the fix — 8 of 9 reachable return paths omitted all
# four transparency fields, including the LOCAL SUCCESS path, which returned
# the local proxy's body verbatim:
#
#   local_success    MISSING ['detection_id','detection_method',
#                             'evidence_depth_limited','source']
#   local_timeout    MISSING (same)      hosted_401   MISSING (same)
#   local_connect    MISSING (same)      hosted_429   MISSING (same)
#   local_unexpected MISSING (same)      hosted_500   MISSING (same)
#   local_http_error MISSING (same)
#   => 3 distinct field sets across 9 paths
#
# Consequence: a fail-open UNKNOWN reached MCP callers with
# `evidence_depth_limited` ABSENT. `result.get("evidence_depth_limited")` then
# returns None — falsy — which reads as "full evidence was available". The
# unmeasured verdict is rendered as a measured one, which is the precise
# failure this PR set out to close, surviving on the degraded branch.
#
# Two checks, doing different jobs:
#   * test_every_return_path_routes_through_the_constructor — STATIC and
#     DISCOVERY-driven. Finds the detection surface by walking the call graph
#     from `verify`, then requires every `return` in it to route through the
#     single constructor. This is what catches a NEW path: a future author
#     cannot add a tenth return that omits fields, because a bare dict literal
#     fails regardless of which fields it happens to contain.
#   * test_all_reachable_paths_have_identical_field_sets — RUNTIME. Drives the
#     real paths through a stubbed transport and compares key sets. This is
#     what proves the constructor is actually reached at run time rather than
#     merely referenced in the source.
#
# Neither alone is sufficient: the static check cannot see runtime behaviour,
# and the runtime check enumerates outcomes a human chose.
# ===========================================================================

import ast
from pathlib import Path

from mcp_server.proxy_client import (
    DETECTION_FIELDS,
    ROUTED_DETECTION_FIELDS,
    _detection_response,
)

_SRC_PATH = Path(__file__).resolve().parents[1] / "mcp_server" / "proxy_client.py"

#: The one function permitted to build a verdict dict.
_CONSTRUCTOR = "_detection_response"

#: Entry point the detection surface is discovered FROM. Not a list of paths —
#: the paths are derived by following calls out of this one.
_SURFACE_ROOT = "verify"


def _callee_name(node):
    """Bare callee name of a Call (``f()`` or ``self.f()``), else None."""
    if isinstance(node, ast.Await):
        node = node.value
    if not isinstance(node, ast.Call):
        return None
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _functions_by_name(tree):
    out = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.setdefault(n.name, n)
    return out


def _discover_surface(tree):
    """
    Every function reachable from ``verify`` by a direct call, transitively.

    Discovery, not declaration: a new private helper that ``verify`` delegates
    to joins the surface automatically and is held to the same contract.
    """
    funcs = _functions_by_name(tree)
    assert _SURFACE_ROOT in funcs, (
        f"detection entry point {_SURFACE_ROOT!r} not found in {_SRC_PATH} — "
        "the surface cannot be discovered, so this check is examining nothing."
    )
    surface, work = set(), [_SURFACE_ROOT]
    while work:
        name = work.pop()
        if name in surface:
            continue
        surface.add(name)
        for sub in ast.walk(funcs[name]):
            callee = _callee_name(sub)
            if callee and callee in funcs and callee != _CONSTRUCTOR:
                work.append(callee)
    return surface, funcs


def _return_is_compliant(fn, ret, surface):
    """
    A return carries the full verdict shape iff its value is
      (a) a call to the constructor, or
      (b) a call to another surface function (delegation), or
      (c) a name bound in this function ONLY from (a)/(b).
    A dict literal, a passthrough of a parsed HTTP body, or a bare name of
    unknown provenance is non-compliant — that is the point.
    """
    v = ret.value
    if v is None:
        return False, "bare `return` — no verdict at all"
    callee = _callee_name(v)
    if callee == _CONSTRUCTOR:
        return True, ""
    if callee in surface:
        return True, ""
    if isinstance(v, ast.Name):
        bindings = [
            a.value for a in ast.walk(fn)
            if isinstance(a, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == v.id for t in a.targets)
        ]
        if bindings and all(
            _callee_name(b) == _CONSTRUCTOR or _callee_name(b) in surface
            for b in bindings
        ):
            return True, ""
        return False, (
            f"returns name `{v.id}`, which is not bound from "
            f"{_CONSTRUCTOR}() or a surface call"
        )
    if isinstance(v, ast.Dict):
        keys = [k.value for k in v.keys if isinstance(k, ast.Constant)]
        return False, (
            f"builds a verdict as a DICT LITERAL with keys {sorted(keys)} — "
            "per-path literals are how the transparency fields went missing"
        )
    return False, f"returns a {type(v).__name__}, not a {_CONSTRUCTOR}() call"


class TestVerdictShapeParity:
    """Every detection return path carries the same field set."""

    def test_constructor_emits_exactly_the_declared_contract(self):
        """
        DETECTION_FIELDS must describe what the constructor actually builds.
        Without this, the constant could drift from the code and every other
        assertion here would be checking against a stale contract.
        """
        built = _detection_response(source="unit-test")
        assert set(built) == set(DETECTION_FIELDS), (
            "DETECTION_FIELDS has drifted from _detection_response():\n"
            f"  declared but not built: {sorted(set(DETECTION_FIELDS) - set(built))}\n"
            f"  built but not declared: {sorted(set(built) - set(DETECTION_FIELDS))}"
        )
        routed = _detection_response(
            source="unit-test",
            routing={
                "attempted_sources": ["local"],
                "route_errors": [],
                "fallback_reason": None,
            },
        )
        assert set(routed) == set(ROUTED_DETECTION_FIELDS), (
            "ROUTED_DETECTION_FIELDS has drifted from routed verdict output:\n"
            f"  declared but not built: {sorted(set(ROUTED_DETECTION_FIELDS) - set(routed))}\n"
            f"  built but not declared: {sorted(set(routed) - set(ROUTED_DETECTION_FIELDS))}"
        )
        # Positive control: the routed contract is not empty, and it really does
        # carry the fields whose absence was the defect plus the route receipt.
        assert {"evidence_depth_limited", "detection_method", "source"} <= set(
            ROUTED_DETECTION_FIELDS
        ), f"the transparency fields are not in the contract: {ROUTED_DETECTION_FIELDS}"
        assert "routing" in ROUTED_DETECTION_FIELDS

    def test_degraded_defaults_say_nothing_was_measured(self):
        """
        Field PRESENCE is not enough — the value has to be honest. A degraded
        verdict defaulting to `evidence_depth_limited=False` would be worse
        than omitting the field, because it asserts full evidence.
        """
        degraded = _unavailable("proxy_unavailable")
        assert degraded["evidence_depth_limited"] is True, (
            "a verdict from a path that reached NO detector must be marked "
            "evidence-limited; False here claims evidence that does not exist."
        )
        assert degraded["risk_level"] == "UNKNOWN"
        assert degraded["confidence"] == 0.0
        assert degraded["detection_method"] is None
        assert degraded["source"] == "unavailable"
        assert degraded["error"] == "proxy_unavailable"

    def test_every_return_path_routes_through_the_constructor(self):
        """
        STATIC + DISCOVERY. Enumerates the detection surface by following calls
        out of `verify`, then holds every return in it to the constructor. A
        NEW return path is caught by construction — this does not consult a
        hardcoded list of paths.
        """
        tree = ast.parse(_SRC_PATH.read_text(encoding="utf-8"), str(_SRC_PATH))
        surface, funcs = _discover_surface(tree)

        returns_seen = 0
        violations = []
        for name in sorted(surface):
            fn = funcs[name]
            for node in ast.walk(fn):
                if not isinstance(node, ast.Return):
                    continue
                returns_seen += 1
                ok, why = _return_is_compliant(fn, node, surface)
                if not ok:
                    violations.append(f"  {name}() line {node.lineno}: {why}")

        # Floor entry 9(a): the gate must fail when it measured nothing, and
        # must name the units of work it did.
        assert len(surface) > 1, (
            f"discovered only {surface} — the call graph walk found no "
            "delegates, so this check would pass over almost nothing."
        )
        assert returns_seen >= 9, (
            f"discovered surface {sorted(surface)} with only {returns_seen} "
            "return statements. The known shape of this module is ~17 returns "
            "across 4 functions; a collapse to near-zero means discovery "
            "broke, not that the code got simpler."
        )
        assert not violations, (
            f"VERDICT SHAPE PARITY VIOLATED — {len(violations)} of "
            f"{returns_seen} returns in the detection surface "
            f"{sorted(surface)} do not route through {_CONSTRUCTOR}():\n"
            + "\n".join(violations)
            + f"\n\nEvery verdict must be built by {_CONSTRUCTOR}() so it "
            "cannot omit a field by forgetting it."
        )

    @pytest.mark.asyncio
    async def test_all_reachable_paths_have_identical_field_sets(self):
        """
        RUNTIME. Drives each reachable outcome and compares key sets. Proves the
        constructor is actually reached, which the static check cannot show.
        """
        results = {}

        def _resp(payload, status=200):
            m = MagicMock()
            m.json.return_value = payload
            m.status_code = status
            if status >= 400:
                m.raise_for_status.side_effect = httpx.HTTPStatusError(
                    "err", request=MagicMock(), response=m
                )
            else:
                m.raise_for_status = MagicMock()
            return m

        local_ok = _resp({"risk_level": "LOW", "confidence": 0.8,
                          "features_triggered": ["f"], "detection_id": "d",
                          "detection_method": "profile",
                          "evidence_depth_limited": False})
        hosted_ok = _resp({"risk": "MEDIUM", "confidence": 0.7,
                           "features_triggered": ["g"], "detection_id": "h",
                           "detection_method": "ensemble",
                           "evidence_depth_limited": False})

        async def local_then(second):
            first = {"n": 0}
            async def post(url, **kw):
                first["n"] += 1
                if first["n"] == 1:
                    raise httpx.ConnectError("down")
                if isinstance(second, Exception):
                    raise second
                return second
            return post

        # --- success paths -------------------------------------------------
        c = ProxyClient("http://local", api_key="k")
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=local_ok):
            results["local_success"] = await c.verify("p", "r", "m")

        c = ProxyClient("http://local", api_key="k")
        with patch("httpx.AsyncClient.post", side_effect=await local_then(hosted_ok)):
            results["hosted_success"] = await c.verify("p", "r", "m")

        # --- local degraded paths ------------------------------------------
        for nm, exc in (
            ("local_timeout", httpx.TimeoutException("t")),
            ("local_connect", httpx.ConnectError("c")),
            ("local_unexpected", RuntimeError("boom")),
        ):
            c = ProxyClient("http://local", api_key=None)
            with patch("httpx.AsyncClient.post", side_effect=exc):
                results[nm] = await c.verify("p", "r", "m")

        c = ProxyClient("http://local", api_key=None)
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock,
                   return_value=_resp({}, 503)):
            results["local_http_error"] = await c.verify("p", "r", "m")

        # --- hosted degraded paths -----------------------------------------
        for nm, status in (("hosted_401", 401), ("hosted_429", 429),
                           ("hosted_500", 500)):
            c = ProxyClient("http://local", api_key="k")
            with patch("httpx.AsyncClient.post",
                       side_effect=await local_then(_resp({}, status))):
                results[nm] = await c.verify("p", "r", "m")

        c = ProxyClient("http://local", api_key="k")
        with patch("httpx.AsyncClient.post",
                   side_effect=await local_then(httpx.TimeoutException("t"))):
            results["hosted_timeout"] = await c.verify("p", "r", "m")

        # --- the assertion --------------------------------------------------
        assert len(results) >= 9, (
            f"only exercised {sorted(results)} — too few paths for parity to "
            "mean anything."
        )
        shapes = {}
        for nm, r in results.items():
            shapes.setdefault(tuple(sorted(r)), []).append(nm)
        assert len(shapes) == 1, (
            f"{len(shapes)} DIFFERENT field sets across {len(results)} paths — "
            "a caller cannot read a field that only some paths carry:\n"
            + "\n".join(
                f"  {list(k)}\n      paths: {sorted(v)}" for k, v in shapes.items()
            )
        )
        only = list(shapes)[0]
        assert set(only) == set(ROUTED_DETECTION_FIELDS), (
            f"paths agree on {sorted(only)} but the declared contract is "
            f"{sorted(ROUTED_DETECTION_FIELDS)}"
        )

        # Positive controls — parity alone would pass if every path returned
        # the same WRONG thing, and an absence assertion needs its mirror.
        for nm, r in results.items():
            assert "evidence_depth_limited" in r, f"{nm} lost the field"
        degraded = {k: v for k, v in results.items() if v["error"] is not None}
        assert len(degraded) == 8, (
            f"expected 8 degraded outcomes, got {sorted(degraded)} — the "
            "failure injection is not reaching the error branches."
        )
        for nm, r in degraded.items():
            assert r["evidence_depth_limited"] is True, (
                f"{nm}: degraded path claims full evidence"
            )
            assert r["risk_level"] == "UNKNOWN", f"{nm}: degraded path banded"
        for nm in ("local_success", "hosted_success"):
            assert results[nm]["evidence_depth_limited"] is False, (
                f"{nm}: backend reported full evidence but the client "
                "overwrote it with the degraded default — the field would be "
                "a constant, not a measurement."
            )
            assert results[nm]["error"] is None, f"{nm} carries an error"
            assert results[nm]["risk_level"] in ("LOW", "MEDIUM")
