"""
F10 — /v1/* interception: does BLOCK actually block and WARN actually warn?

Driven through the real middleware in a real ASGI app. Every assertion pins a
positively computed expected value; there is no ``assert result`` and no
``isinstance(x, object)`` in this file. Where a behaviour is a product decision
rather than a defect, the test pins the CURRENT behaviour and says so in its
docstring, so the decision stays visible instead of dissolving into "it works".
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
import uuid as _uuid

import httpx
import pytest
from fastapi import FastAPI
from starlette.responses import JSONResponse

from proxy.detection.engine import DetectionResult
from proxy.middleware.interception import AIInterceptionMiddleware

UPSTREAM_BODY = b'{"choices":[{"message":{"content":"THE-MODEL-ANSWER"}}]}'
REQ = {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}


# ---------------------------------------------------------------------------
# App builder
# ---------------------------------------------------------------------------

def _result(risk: str, gate_action: str = "advise") -> DetectionResult:
    return DetectionResult(
        risk_level=risk,
        confidence=0.8,
        features_triggered=["unique_word_ratio"],
        model_id="gpt-4o",
        profile_version="1.0",
        timestamp=datetime.now(timezone.utc).isoformat(),
        detection_id=str(_uuid.uuid4()),
        gate_action=gate_action,
    )


class _Engine:
    def __init__(self, risk: str, gate_action: str = "advise", raises: bool = False):
        self.risk = risk
        self.gate_action = gate_action
        self.raises = raises
        self.calls: list[tuple[str, str, str]] = []

    async def verify(self, prompt, response, model_id):
        self.calls.append((prompt, response, model_id))
        if self.raises:
            raise RuntimeError("simulated engine crash")
        return _result(self.risk, self.gate_action)


def build(
    risk: str = "LOW",
    action: str = "warn",
    *,
    engine: Optional[object] = "default",
    gate_action: str = "advise",
    raises: bool = False,
    upstream_url: str = "",
    audit=None,
    upstream_body: bytes = UPSTREAM_BODY,
    upstream_status: int = 200,
):
    """A FastAPI app with the middleware attached, plus its stub engine."""
    app = FastAPI()

    @app.post("/v1/chat/completions")
    async def chat():
        return JSONResponse(json.loads(UPSTREAM_BODY))

    @app.get("/health")
    async def health():
        return {"ok": True}

    app.add_middleware(AIInterceptionMiddleware)

    eng = _Engine(risk, gate_action, raises) if engine == "default" else engine
    app.state.engine = eng

    class _Detection:
        pass

    det = _Detection()
    det.upstream_url = upstream_url
    det.high_risk_action = action
    det.unknown_action = "pass"

    class _Settings:
        pass

    st = _Settings()
    st.detection = det
    app.state.settings = st
    if audit is not None:
        app.state.audit_writer = audit
    return app, eng


def client(app) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    )


# ---------------------------------------------------------------------------
# BLOCK
# ---------------------------------------------------------------------------

class TestBlockActuallyBlocks:

    async def test_block_withholds_every_byte_of_the_flagged_answer(self):
        """
        The point of a block is that the flagged content does not reach the
        caller. Asserted as an absence over the RAW bytes, with the positive
        control below proving the probe can see that content when it is served.
        """
        app, _ = build(risk="HIGH", action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"THE-MODEL-ANSWER" not in r.content, (
            "the flagged answer was served despite a configured block"
        )

    async def test_positive_control_the_same_probe_sees_the_answer_when_passed(self):
        """Without this, the absence assertion above proves nothing."""
        app, _ = build(risk="LOW", action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"THE-MODEL-ANSWER" in r.content

    async def test_block_body_is_exactly_the_documented_refusal(self):
        app, _ = build(risk="HIGH", action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        payload = json.loads(r.content)
        assert payload["error"] == "arkheia_blocked"
        assert payload["risk_level"] == "HIGH"
        assert r.headers["x-arkheia-risk"] == "HIGH"
        assert r.headers["content-type"].startswith("application/json")

    async def test_block_is_attributable_to_a_detection_id(self):
        """
        A refusal a caller cannot quote back is a refusal nobody can
        investigate or contest. The id must be on the response AND must be the
        id the engine actually produced for this request.
        """
        eng = _Engine("HIGH")
        app, _ = build(risk="HIGH", action="block", engine=eng)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        surfaced = r.headers.get("x-arkheia-detection-id")
        assert surfaced, "a block carries no detection id"
        assert json.loads(r.content).get("detection_id") == surfaced

    async def test_block_states_what_would_clear_it(self):
        """
        DONE.md Gate 9 legibility: every NO carries its reason and a route to
        yes. ``{"error":"arkheia_blocked"}`` alone is "computer says no".
        """
        app, _ = build(risk="HIGH", action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        payload = json.loads(r.content)
        assert payload.get("reason"), "no reason on an adverse verdict"
        assert payload.get("remedy"), "no route to yes on an adverse verdict"

    @pytest.mark.parametrize("risk", ["LOW", "MEDIUM", "UNKNOWN"])
    async def test_block_never_fires_below_high(self, risk):
        app, _ = build(risk=risk, action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content
        assert r.headers["x-arkheia-risk"] == risk

    async def test_block_status_code_is_pinned(self):
        """
        CURRENT BEHAVIOUR, PINNED — NOT ENDORSED. A block is served as HTTP 200,
        so at the transport layer it is indistinguishable from a completion; a
        client that does not read the body or the risk header treats a refusal
        as a success. Changing this breaks provider-SDK compatibility in ways
        only the product owner can weigh, so it is REPORTED, not decided. See
        the PR's adjudication list.
        """
        app, _ = build(risk="HIGH", action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# WARN
# ---------------------------------------------------------------------------

class TestWarnActuallyWarns:

    async def test_warn_surfaces_the_verdict_without_corrupting_the_payload(self):
        """
        The pre-fix implementation prepended ``b"[ARKHEIA WARNING: HIGH RISK
        DETECTED] "`` to the body, which turns a JSON completion into bytes no
        JSON parser accepts. The repo already ruled against this pattern twice:
        ``proxy/endpoints/detect.py::_signal`` says in terms "we never prepend
        to the body (that pattern in interception.py corrupts responses and
        400-loops sessions)", and the operator's own local proxy had the inline
        prepend REMOVED for the same reason.

        A warning that destroys the response is not a warning, it is an outage.
        """
        app, _ = build(risk="HIGH", action="warn")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        json.loads(r.content)                     # must not raise
        assert r.content == UPSTREAM_BODY
        assert r.headers["x-arkheia-risk"] == "HIGH"

    async def test_warn_is_machine_readable_not_only_prose(self):
        app, _ = build(risk="HIGH", action="warn")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers.get("x-arkheia-action") == "warn"
        assert r.headers.get("x-arkheia-detection-id")

    async def test_warn_does_not_withhold_the_answer(self):
        app, _ = build(risk="HIGH", action="warn")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"THE-MODEL-ANSWER" in r.content


# ---------------------------------------------------------------------------
# Pass-through and the detector contract
# ---------------------------------------------------------------------------

class TestPassAndDetectorContract:

    @pytest.mark.parametrize("risk", ["LOW", "MEDIUM", "HIGH", "UNKNOWN"])
    async def test_risk_header_is_the_engine_verdict_verbatim(self, risk):
        app, _ = build(risk=risk, action="pass")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-risk"] == risk
        assert r.content == UPSTREAM_BODY

    async def test_engine_receives_the_prompt_and_the_response_it_must_score(self):
        eng = _Engine("LOW")
        app, _ = build(engine=eng)
        async with client(app) as c:
            await c.post("/v1/chat/completions", json=REQ)
        assert len(eng.calls) == 1
        prompt, response, model_id = eng.calls[0]
        assert prompt == "hi"
        assert response == UPSTREAM_BODY.decode()
        assert model_id == "gpt-4o"

    async def test_engine_absent_is_declared_not_silently_low(self):
        """
        ``UNAVAILABLE`` must never be collapsed into ``LOW``: "we could not
        assess" and "we assessed it as safe" are different statements.
        """
        app, _ = build(engine=None)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-risk"] == "UNAVAILABLE"
        assert r.content == UPSTREAM_BODY

    async def test_non_v1_path_is_untouched(self):
        app, _ = build()
        async with client(app) as c:
            r = await c.get("/health")
        assert "x-arkheia-risk" not in r.headers
        assert r.json() == {"ok": True}

    async def test_gate_action_is_not_consulted_by_the_transport_block(self):
        """
        CURRENT BEHAVIOUR, PINNED — AND FLAGGED AS A DIVERGENCE.

        ``proxy/endpoints/detect.py`` documents two non-interchangeable signals
        and states the rule explicitly: *"a consumer MUST hard-block ONLY when
        gate_action == 'block'"*, because ``action`` is policy INTENT and
        "keying enforcement off `action` OVER-BLOCKS on profiles that never
        earned it -- do not."

        This middleware is the only place in the product that actually blocks
        transport, and it keys entirely off ``high_risk_action``. So the one
        enforcing site enforces on the signal the codebase says must not be
        enforced on: an unvalidated profile (``gate_action == "advise"``, the
        default for every profile lacking precision/f1) can still hard-block.

        Aligning it would DISABLE blocking for customers relying on it today.
        That is a product/authority decision — REPORTED, not taken. This test
        keeps it visible and will fail the moment the behaviour changes, so the
        change cannot land silently either way.
        """
        app, _ = build(risk="HIGH", action="block", gate_action="advise")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" in r.content


# ---------------------------------------------------------------------------
# Fail-open
# ---------------------------------------------------------------------------

class TestFailOpen:

    async def test_detector_crash_still_delivers_the_real_answer(self):
        app, _ = build(risk="HIGH", action="block", raises=True)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-risk"] == "ERROR"
        assert r.content == UPSTREAM_BODY, (
            f"fail-open served {r.content!r} instead of the answer it was "
            f"meant to let through"
        )

    async def test_detector_crash_does_not_block(self):
        """Fail-open by contract: detection degrades, it never blocks."""
        app, _ = build(risk="HIGH", action="block", raises=True)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------

class TestPromptExtraction:

    async def test_multimodal_content_blocks_are_flattened_to_their_text(self):
        eng = _Engine("LOW")
        app, _ = build(engine=eng)
        async with client(app) as c:
            await c.post("/v1/chat/completions", json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": "alpha"},
                    {"type": "image_url", "image_url": {"url": "http://x/i.png"}},
                    {"type": "text", "text": "beta"},
                ]}],
            })
        assert eng.calls[0][0] == "alpha beta"

    async def test_unparseable_body_scores_as_unknown_model_not_a_crash(self):
        eng = _Engine("LOW")
        app, _ = build(engine=eng)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions",
                             content=b"<<<not json>>>",
                             headers={"content-type": "application/json"})
        assert eng.calls[0][2] == "unknown"
        assert eng.calls[0][0] == ""
        assert r.headers["x-arkheia-risk"] == "LOW"


# ---------------------------------------------------------------------------
# Reported gaps, pinned so they cannot quietly change or quietly persist
# ---------------------------------------------------------------------------

class TestReportedGaps:

    async def test_unknown_action_config_is_never_consulted(self):
        """
        CURRENT BEHAVIOUR, PINNED — a REPORTED defect, not fixed here.

        ``detection.unknown_action`` exists in ``proxy/config.py`` and is read
        by ``proxy/endpoints/detect.py::_determine_action`` for UNKNOWN
        verdicts. This middleware forces ``action = "pass"`` for everything that
        is not HIGH, so the setting is dead on the only path that can actually
        enforce. An operator who sets ``unknown_action: block`` gets silence.

        Wiring it would turn a previously inert setting into a live blocking
        control on existing deployments — an authority decision, REPORTED not
        taken. The test fails the moment it starts being honoured, so the
        change cannot land unnoticed either.
        """
        app, _ = build(risk="UNKNOWN", action="block")
        app.state.settings.detection.unknown_action = "block"
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content
        assert r.headers["x-arkheia-action"] == "pass"

    async def test_the_passthrough_surface_is_outside_this_middleware(self):
        """
        CURRENT BEHAVIOUR, PINNED — a REPORTED coverage gap.

        ``proxy/endpoints/passthrough.py`` serves ``/proxy/<provider>/v1/*`` and
        forwards to four real providers. Those paths do not start with ``/v1/``,
        so with ``interception_enabled: true`` the proxy still relays that
        traffic with NO detection and NO receipt. "The proxy intercepts
        API-driven AI traffic" is true only of one of its two forwarding
        surfaces.
        """
        app, _ = build()

        @app.post("/proxy/grok/v1/chat/completions")
        async def grok():
            return {"choices": [{"message": {"content": "unscored"}}]}

        async with client(app) as c:
            r = await c.post("/proxy/grok/v1/chat/completions", json=REQ)
        assert "x-arkheia-risk" not in r.headers


# ---------------------------------------------------------------------------
# The destination resolver, driven directly
# ---------------------------------------------------------------------------

import httpx as _httpx  # noqa: E402
import pytest as _pytest  # noqa: E402

from proxy.middleware.interception import (  # noqa: E402
    InterceptionRefusal,
    _check_raw_path,
    _confine,
    _forward_headers,
    _resolve_upstream,
)
from starlette.datastructures import Headers  # noqa: E402


class TestDestinationResolver:
    """
    Driven at the boundary that OWNS the decision, not only through the live
    route.

    Some arms of the post-condition cannot be tripped by a caller today —
    ``httpx`` will not let an appended path move the authority, which is the
    good news of this flow and is measured on a real socket in
    ``test_interception_wire.py``. But "cannot be tripped today" is what makes
    a check decoration, and the mutation campaign said so: five arms survived
    every wire attack. They are now driven directly with a base and a target
    that disagree — exactly the skew a per-tenant or per-provider upstream
    would introduce, which is the direction this config is heading.
    """

    def test_a_base_with_a_path_component_confines_to_that_subtree(self):
        url = _resolve_upstream("http://up.internal:8080/api", "/v1/chat", "")
        assert str(url) == "http://up.internal:8080/api/v1/chat"

    def test_a_path_that_reaches_a_sibling_subtree_is_refused(self):
        """
        With a base path, ``startswith`` and "contains" stop agreeing: the
        resolved ``/api/zzz/api/v1/x`` CONTAINS ``/api/v1/`` while starting
        somewhere else entirely.
        """
        with _pytest.raises(InterceptionRefusal) as exc:
            _resolve_upstream("http://up.internal:8080/api",
                              "/v1/../zzz/api/v1/x", "")
        assert exc.value.deny_code == "path_escapes_prefix"

    def test_the_base_path_is_part_of_the_expectation(self):
        """A confinement that forgot the base path would refuse the legal case."""
        url = _resolve_upstream("http://up.internal:8080/api", "/v1/ok", "")
        assert url.path == "/api/v1/ok"

    @_pytest.mark.parametrize("scheme_url", [
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/_stats",
        "ftp://internal/",
        "data:text/plain,x",
    ])
    def test_a_non_http_upstream_is_refused_before_any_client_exists(self, scheme_url):
        """
        ``file://`` and ``gopher://`` as a forwarding destination are not
        transport misconfigurations, they are exfiltration and
        protocol-smuggling primitives. Refused on the CONFIG, before a client
        is constructed.
        """
        with _pytest.raises(InterceptionRefusal) as exc:
            _resolve_upstream(scheme_url, "/v1/x", "")
        assert exc.value.deny_code == "upstream_scheme_not_allowed"

    def test_userinfo_appearing_in_the_resolved_url_is_refused(self):
        """
        Skewed directly: a target whose authority carries credentials the
        configured base does not. Unreachable through the live route today
        (asserted on the wire); load-bearing the moment the base is composed
        from anything richer than a literal.
        """
        with _pytest.raises(InterceptionRefusal) as exc:
            _confine(_httpx.URL("http://user:pw@up.internal:8080/v1/x"),
                     _httpx.URL("http://up.internal:8080"))
        assert exc.value.deny_code == "path_escapes_prefix"

    def test_control_a_base_that_legitimately_carries_userinfo_is_allowed(self):
        """
        The comparison is verifier-owned, not a blanket ban: an upstream
        configured WITH credentials must keep working, or the check is an
        outage rather than a control.
        """
        _confine(_httpx.URL("http://user:pw@up.internal:8080/v1/x"),
                 _httpx.URL("http://user:pw@up.internal:8080"))

    @_pytest.mark.parametrize("target,base", [
        ("https://up.internal:8080/v1/x", "http://up.internal:8080"),   # scheme
        ("http://other.internal:8080/v1/x", "http://up.internal:8080"),  # host
        ("http://up.internal:9999/v1/x", "http://up.internal:8080"),     # port
    ])
    def test_every_authority_part_is_compared_against_the_configured_base(
        self, target, base
    ):
        with _pytest.raises(InterceptionRefusal):
            _confine(_httpx.URL(target), _httpx.URL(base))

    def test_the_legal_destination_is_not_refused(self):
        """Control: the post-condition must not reject the thing it exists for."""
        _confine(_httpx.URL("http://up.internal:8080/v1/x"),
                 _httpx.URL("http://up.internal:8080"))


class TestRawPathPreCondition:
    """
    ``_confine`` inspects the URL httpx BUILT, and httpx leaves ``%2f`` /
    ``%5c`` / ``%2e`` percent-encoded. So a double-encoded escape passes the
    post-condition while a lenient origin decodes it and escapes anyway. This
    pre-condition is the only thing that sees those, and the mutation campaign
    proved the wire corpus alone could not tell.
    """

    @_pytest.mark.parametrize("path", [
        "/v1/%2e%2e/admin",          # single-decoded by uvicorn from %252e
        "/v1/..%2fadmin",
        "/v1/..%2Fadmin",            # uppercase — matching must be case-folded
        "/v1/..%5cadmin",
        "/v1/..\\..\\admin",         # literal backslash, no encoding at all
        "/v1/x\x00.evil",
    ])
    def test_encoded_separators_and_backslashes_are_refused(self, path):
        with _pytest.raises(InterceptionRefusal) as exc:
            _check_raw_path(path)
        assert exc.value.deny_code == "unsafe_path_encoding"

    @_pytest.mark.parametrize("path", [
        "/v1/chat/completions",
        "/v1/messages",
        "/v1/models/gpt-4o",
        "/v1/files/file-abc123",
    ])
    def test_control_ordinary_provider_paths_are_not_refused(self, path):
        _check_raw_path(path)


class TestForwardHeaderBoundary:
    """
    Framing headers, driven at the boundary. ``httpx`` HONOURS an explicit
    ``content-length`` in the header list — measured: a request built with
    ``content-length: 3`` and a ten-byte body goes out declaring 3 — so
    relaying the caller's framing is a smuggling primitive even though uvicorn
    happens to make the caller's own value truthful today.
    """

    def _headers(self, pairs):
        return Headers(raw=[(k.encode(), v.encode()) for k, v in pairs])

    def test_caller_framing_headers_are_never_relayed(self):
        out = _forward_headers(self._headers([
            ("host", "proxy.local:8098"),
            ("content-length", "3"),
            ("content-type", "application/json"),
        ]))
        names = {k.lower() for k, _ in out}
        assert "content-length" not in names
        assert "host" not in names
        assert "content-type" in names          # control: it does relay things

    def test_legitimate_repeated_headers_survive(self):
        """
        The pre-fix dict comprehension silently collapsed repeats. Refusing is
        right for a credential; dropping one of two ``accept`` values is just
        data loss.
        """
        out = _forward_headers(self._headers([
            ("accept", "application/json"), ("accept", "text/event-stream"),
        ]))
        assert sorted(v for k, v in out if k == "accept") == [
            "application/json", "text/event-stream"]


class TestFailSafeDefaults:

    async def test_a_config_with_no_high_risk_action_warns_rather_than_blocks(self):
        """
        The fallback when ``high_risk_action`` is absent must be the
        non-destructive one. A default of ``block`` would mean a deployment
        that never configured a policy silently starts withholding answers —
        and every test that sets the action explicitly would still be green.
        """
        app, _ = build(risk="HIGH")
        del app.state.settings.detection.high_risk_action
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-action"] == "warn"
        assert b"arkheia_blocked" not in r.content
        assert r.content == UPSTREAM_BODY

    async def test_a_missing_detection_config_also_warns(self):
        app, _ = build(risk="HIGH")
        del app.state.settings.detection
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-action"] == "warn"
        assert b"arkheia_blocked" not in r.content
