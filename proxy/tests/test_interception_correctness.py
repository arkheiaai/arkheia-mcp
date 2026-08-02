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
        self.calls: list[tuple[str, str, str, dict]] = []

    async def verify(self, prompt, response, model_id, **metadata):
        self.calls.append((prompt, response, model_id, metadata))
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
        return JSONResponse(json.loads(upstream_body))

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
    """
    Every case here supplies ``gate_action="block"`` — the profile-EARNED gate.
    Since round 2 the policy alone does not authorise a hard block; the unearned
    case is asserted in ``TestGateActionAuthorisesTheBlock``, which is where the
    behaviour change lives.
    """

    async def test_block_withholds_every_byte_of_the_flagged_answer(self):
        """
        The point of a block is that the flagged content does not reach the
        caller. Asserted as an absence over the RAW bytes, with the positive
        control below proving the probe can see that content when it is served.
        """
        app, _ = build(risk="HIGH", action="block", gate_action="block")
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
        app, _ = build(risk="HIGH", action="block", gate_action="block")
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
        eng = _Engine("HIGH", gate_action="block")
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
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        payload = json.loads(r.content)
        assert payload.get("reason"), "no reason on an adverse verdict"
        assert payload.get("remedy"), "no route to yes on an adverse verdict"

    @pytest.mark.parametrize("risk", ["LOW", "MEDIUM", "UNKNOWN"])
    async def test_block_never_fires_below_high(self, risk):
        app, _ = build(risk=risk, action="block", gate_action="block")
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
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.status_code == 200
        assert json.loads(r.content)["error"] == "arkheia_blocked"


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
        prompt, response, model_id, metadata = eng.calls[0]
        assert prompt == "hi"
        assert response == UPSTREAM_BODY.decode()
        assert model_id == "gpt-4o"
        assert metadata == {}

    async def test_engine_receives_completion_tokens_zero_metadata(self):
        body = b'{"choices":[{"message":{"content":""}}],"usage":{"completion_tokens":0}}'
        eng = _Engine("LOW")
        app, _ = build(engine=eng, upstream_body=body)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-risk"] == "LOW"
        assert len(eng.calls) == 1
        prompt, response, model_id, metadata = eng.calls[0]
        assert prompt == "hi"
        assert response == body.decode()
        assert model_id == "gpt-4o"
        assert metadata == {"output_tokens": 0}

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


# ---------------------------------------------------------------------------
# gate_action — the AUTHORITATIVE block signal
# ---------------------------------------------------------------------------

class TestGateActionAuthorisesTheBlock:
    """
    ``proxy/endpoints/detect.py`` documents two non-interchangeable signals and
    states the rule in terms: *"a consumer MUST hard-block ONLY when
    gate_action == 'block'"*, because ``action`` is policy INTENT and "keying
    enforcement off `action` OVER-BLOCKS on profiles that never earned it -- do
    not." ``features.py::resolve_gate_action`` returns "block" only when the
    profile declares it AND carries non-null precision + f1 within the FP
    ceiling; every other profile resolves to "advise".

    This middleware is the one place in the product that blocks TRANSPORT, and
    it used to key entirely off ``high_risk_action`` — so the single enforcing
    site enforced on the signal the codebase says must not be enforced on.

    BEHAVIOUR CHANGE, DELIBERATE AND DISCLOSED: a deployment configured
    ``high_risk_action: block`` whose model profile has NOT earned the gate now
    WARNS instead of blocking. That is the contract; it is also a live change
    for anyone relying on the old behaviour, and it is stated at the top of the
    PR body rather than buried here.
    """

    async def test_an_unearned_profile_cannot_hard_block(self):
        """policy says block, the profile never earned it — the answer flows."""
        app, _ = build(risk="HIGH", action="block", gate_action="advise")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content, (
            "an unvalidated profile (gate_action='advise') hard-blocked at "
            "transport — the one enforcing site is enforcing on policy INTENT"
        )
        assert r.content == UPSTREAM_BODY

    async def test_an_earned_profile_still_blocks(self):
        """Control: the fix must not disable blocking where it was earned."""
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" in r.content
        assert b"THE-MODEL-ANSWER" not in r.content

    async def test_the_downgrade_is_a_warn_not_a_silent_pass(self):
        """
        A configured block that the gate did not authorise is still a HIGH
        verdict the customer asked to act on. Collapsing it to ``pass`` would
        lose the warning as well as the block.
        """
        app, _ = build(risk="HIGH", action="block", gate_action="advise")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-action"] == "warn"
        assert r.headers["x-arkheia-risk"] == "HIGH"

    async def test_the_caller_is_told_why_the_configured_block_did_not_fire(self):
        """
        DONE.md Gate 9 legibility, applied to a decision that went the
        customer's way: an operator who configured ``block`` and received the
        answer must be able to see, from the response alone, that the POLICY
        wanted a block and the GATE did not authorise one. Header-only — the
        warn path may never touch the body.
        """
        app, _ = build(risk="HIGH", action="block", gate_action="advise")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers.get("x-arkheia-gate-action") == "advise", (
            "the authoritative gate signal is not surfaced, so a downgraded "
            "block is indistinguishable from a policy that never said block"
        )
        assert r.headers.get("x-arkheia-policy-action") == "block"
        assert r.content == UPSTREAM_BODY

    async def test_the_gate_signal_is_surfaced_on_an_earned_block_too(self):
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers.get("x-arkheia-gate-action") == "block"
        assert r.headers.get("x-arkheia-policy-action") == "block"

    async def test_an_earned_gate_does_not_override_a_warn_policy(self):
        """
        The gate AUTHORISES, it does not command. A customer who configured
        ``warn`` must not start being blocked because a profile earned the gate.
        """
        app, _ = build(risk="HIGH", action="warn", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content
        assert r.headers["x-arkheia-action"] == "warn"

    @pytest.mark.parametrize("gate", ["advise", "", "BLOCK", "unknown", None])
    async def test_anything_that_is_not_exactly_block_fails_closed_to_advise(
        self, gate
    ):
        """
        Fail-safe direction: the authorisation is granted only by the exact
        token. A missing, empty, mis-cased or novel value must not authorise a
        hard block — that is the direction an unvalidated profile arrives from.
        """
        app, _ = build(risk="HIGH", action="block", gate_action=gate)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content, (
            f"gate_action={gate!r} authorised a hard block"
        )

    async def test_an_engine_result_with_no_gate_action_at_all_cannot_block(self):
        """
        A third-party or older engine that returns a result object without the
        field must not be read as authorisation. ``getattr`` default, not
        ``result.gate_action``.
        """
        class _Bare:
            risk_level = "HIGH"
            confidence = 0.8
            features_triggered = []
            model_id = "gpt-4o"
            profile_version = "1.0"
            detection_id = "bare-0000"

        class _BareEngine:
            async def verify(self, prompt, response, model_id):
                return _Bare()

        app, _ = build(risk="HIGH", action="block", engine=_BareEngine())
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" not in r.content

    async def test_the_record_says_what_policy_wanted_and_what_the_gate_allowed(
        self, tmp_path
    ):
        """
        An operator whose configured block silently stopped firing needs the
        evidence row to say so. ``action_taken`` alone cannot: a downgraded
        block and an ordinary warn are both ``warn``.
        """
        from proxy.audit.writer import AuditWriter
        from proxy.tests._receipt_probe import ReceiptProbe

        log = tmp_path / "audit.jsonl"
        writer = AuditWriter(str(log))
        await writer.start()
        try:
            app, _ = build(risk="HIGH", action="block", gate_action="advise",
                           audit=writer)
            async with client(app) as c:
                r = await c.post("/v1/chat/completions", json=REQ)
        finally:
            await writer.stop()
        row = ReceiptProbe(log).require(r.headers["x-arkheia-detection-id"])
        assert row["action_taken"] == "warn"
        assert row["policy_action"] == "block", (
            "the record does not say the operator had configured a block"
        )
        assert row["gate_action"] == "advise", (
            "the record does not say why the configured block did not fire"
        )


# ---------------------------------------------------------------------------
# Fail-open
# ---------------------------------------------------------------------------

class TestFailOpen:

    async def test_detector_crash_still_delivers_the_real_answer(self):
        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       raises=True)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-risk"] == "ERROR"
        assert r.content == UPSTREAM_BODY, (
            f"fail-open served {r.content!r} instead of the answer it was "
            f"meant to let through"
        )

    async def test_detector_crash_does_not_block(self):
        """Fail-open by contract: detection degrades, it never blocks."""
        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       raises=True)
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


class TestForwardHeadersAreAnAllowList:
    """
    A DENY-list forwards every header nobody thought of. That is the same shape
    as the enumerated deny-list that let ``unverifiable`` skip a halt on a
    sibling flow: the set of things you must remember to name is unbounded, and
    the failure is silent and in the permissive direction.

    So the forward leg names what the upstream NEEDS and drops everything else.
    An unknown header is not forwarded — including one that does not exist yet.
    """

    def _headers(self, pairs):
        return Headers(raw=[(k.encode(), v.encode()) for k, v in pairs])

    def _names(self, pairs):
        return {k.lower() for k, _ in _forward_headers(self._headers(pairs))}

    #: Each of these is a real leak, and the first three are the ones the second
    #: vendor reproduced on an accepted /v1/chat/completions call.
    LEAKS = [
        ("cookie", "session=CALLER-SESSION"),
        ("x-forwarded-for", "10.1.2.3, 192.0.2.9"),
        ("x-arkheia-internal", "internal-only-token"),
        ("x-forwarded-host", "proxy.internal.corp"),
        ("x-forwarded-proto", "http"),
        ("x-real-ip", "10.1.2.3"),
        ("forwarded", "for=10.1.2.3;host=proxy.internal.corp"),
        ("x-arkheia-risk", "LOW"),
        ("referer", "https://internal.corp/admin/keys"),
        ("origin", "https://internal.corp"),
        ("user-agent", "internal-tooling/9.9 (build 1234)"),
        ("accept-encoding", "identity"),
        ("x-stainless-runtime-version", "3.12.13"),
        ("set-cookie", "a=b"),
    ]

    @pytest.mark.parametrize("name,value", LEAKS)
    def test_a_header_the_upstream_does_not_need_is_not_forwarded(self, name, value):
        assert name not in self._names([
            ("content-type", "application/json"), (name, value),
        ]), f"{name} reached the configured upstream"

    def test_an_unknown_header_nobody_thought_of_is_not_forwarded(self):
        """
        THE point of the allow-list, expressed directly: a header that no
        reviewer has ever seen must default to NOT forwarded. Under a deny-list
        this assertion is unsatisfiable without amending the deny-list first.
        """
        assert self._names([
            ("content-type", "application/json"),
            ("x-invented-2026-07-27", "surprise"),
        ]) == {"content-type"}

    #: What a provider API genuinely needs. Each entry is required by at least
    #: one upstream this proxy is configured against in practice.
    NEEDED = [
        ("authorization", "Bearer sk-test"),          # OpenAI / most providers
        ("x-api-key", "sk-ant-test"),                 # Anthropic
        ("api-key", "azure-test"),                    # Azure OpenAI
        ("anthropic-version", "2023-06-01"),          # required by Anthropic
        ("anthropic-beta", "prompt-caching-2024-07-31"),
        ("openai-organization", "org-abc"),
        ("openai-project", "proj-abc"),
        ("openai-beta", "assistants=v2"),
        ("content-type", "application/json"),
        ("accept", "text/event-stream"),              # streaming completions
        ("idempotency-key", "idem-123"),
    ]

    @pytest.mark.parametrize("name,value", NEEDED)
    def test_a_header_the_upstream_genuinely_needs_is_forwarded(self, name, value):
        """
        Control. An allow-list that forwards nothing is not a control, it is an
        outage — and it would pass every assertion above.
        """
        assert name in self._names([(name, value)]), (
            f"{name} is required by a configured upstream and was dropped"
        )

    def test_the_allow_list_is_matched_case_insensitively(self):
        assert self._names([("Content-Type", "application/json")]) == {"content-type"}

    def test_a_connection_nominated_allow_listed_header_is_still_stripped(self):
        """
        ``Connection: accept`` nominates an ALLOW-LISTED field as hop-by-hop.
        Membership of the allow-list must not override the nomination, or the
        nomination logic is dead code the allow-list happens to shadow.
        """
        assert self._names([
            ("connection", "accept, close"),
            ("accept", "application/json"),
            ("content-type", "application/json"),
        ]) == {"content-type"}

    def test_a_duplicated_credential_is_still_refused_before_filtering(self):
        """
        The refusal must not become unreachable because the allow-list runs
        first: ordering matters, and only a test can pin it.
        """
        with _pytest.raises(InterceptionRefusal) as exc:
            _forward_headers(self._headers([
                ("authorization", "Bearer LEGIT"),
                ("authorization", "Bearer ATTACKER"),
            ]))
        assert exc.value.deny_code == "duplicate_credential_header"

    def test_a_duplicated_credential_THIS_PROXY_NEVER_FORWARDS_still_refuses(self):
        """
        THE ordering case that actually distinguishes the two designs, found by
        the mutation campaign: moving the duplicate check AFTER the allow-list
        SURVIVED, because ``authorization`` / ``x-api-key`` / ``api-key`` are
        all forwardable and so still reach the check either way.

        ``proxy-authorization`` is the one that is not. It is a credential
        addressed to THIS hop, so it is never forwarded — and under the moved
        check it would never be examined either, so two of them would be
        silently tolerated. Which credential applies is exactly as ambiguous as
        it is for ``authorization``, and the ambiguity is at the door of the
        proxy's own auth layer rather than the provider's.
        """
        with _pytest.raises(InterceptionRefusal) as exc:
            _forward_headers(self._headers([
                ("proxy-authorization", "Basic LEGIT"),
                ("proxy-authorization", "Basic ATTACKER"),
            ]))
        assert exc.value.deny_code == "duplicate_credential_header"

    def test_control_a_single_unforwarded_credential_is_not_refused(self):
        """The refusal is about DUPLICATION, not about the header existing."""
        assert _forward_headers(self._headers([
            ("proxy-authorization", "Basic ONLY-ONE"),
            ("content-type", "application/json"),
        ])) == [("content-type", "application/json")]


class TestReceiptStatusIsDerivedNotAsserted:
    """
    ``_emit`` returns silently when no audit writer is configured and swallows a
    write that raises — both correct (the kill-switch-receipt ruling: the halt
    must not depend on the record landing). What was NOT correct is that the
    block and refusal bodies hard-coded ``"receipt": "enqueued"`` regardless, so
    a response asserted an evidence trail that did not exist.

    The previous round chose the word ``enqueued`` over ``recorded`` precisely
    because the rail is fire-and-forget — and then asserted it where nothing was
    enqueued at all. A response claiming evidence that does not exist is worse
    than one claiming none: the first is what an investigator acts on.

    The status must be DERIVED from what happened at the call site.
    """

    class _RaisingWriter:
        """
        A rail supplied through the documented extension point
        (``app.state.audit_writer``) whose ``write`` fails.

        NOT a monkeypatch of the shipped ``AuditWriter`` — the middleware
        duck-types this attribute, and ``_emit``'s ``except`` clause exists for
        exactly this object. The shipped writer cannot raise from ``write()``
        today; that limitation is measured separately and disclosed.
        """

        def __init__(self):
            self.calls = 0

        async def write(self, record):
            self.calls += 1
            raise OSError("audit rail unavailable")

    async def test_a_block_with_no_audit_writer_does_not_claim_a_receipt(self):
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        assert not hasattr(app.state, "audit_writer")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        status = json.loads(r.content)["receipt"]
        assert status != "enqueued", (
            "the block claimed 'enqueued' with no audit writer configured — "
            "nothing was enqueued anywhere"
        )
        assert status == "no_audit_writer"

    async def test_a_block_whose_audit_write_raised_says_so(self):
        writer = self._RaisingWriter()
        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       audit=writer)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert writer.calls == 1, "the rail was never called; the test proves nothing"
        assert json.loads(r.content)["receipt"] == "write_failed"

    async def test_the_block_still_holds_when_the_receipt_fails(self):
        """
        The kill-switch-receipt ruling, unchanged: deriving the status must not
        turn a receipt failure into a served answer.
        """
        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       audit=self._RaisingWriter())
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert b"arkheia_blocked" in r.content
        assert b"THE-MODEL-ANSWER" not in r.content

    async def test_a_warn_with_no_audit_writer_surfaces_no_receipt_header(self):
        """
        WARN delivers the upstream answer, so there is no JSON body field to
        carry receipt status. The status still has to be caller-visible; without
        this header, a warned HIGH whose audit writer was absent looked the same
        as one whose evidence trail was accepted.
        """
        app, _ = build(risk="HIGH", action="warn")
        assert not hasattr(app.state, "audit_writer")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.content == UPSTREAM_BODY
        assert r.headers["x-arkheia-action"] == "warn"
        assert r.headers["x-arkheia-receipt"] == "no_audit_writer"

    async def test_a_warn_whose_audit_write_raised_says_so_in_headers(self):
        writer = self._RaisingWriter()
        app, _ = build(risk="HIGH", action="warn", audit=writer)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert writer.calls == 1, "the rail was never called; the test proves nothing"
        assert r.content == UPSTREAM_BODY
        assert r.headers["x-arkheia-receipt"] == "write_failed"

    async def test_block_receipt_header_matches_the_body_status(self):
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        payload = json.loads(r.content)
        assert payload["receipt"] == "no_audit_writer"
        assert r.headers["x-arkheia-receipt"] == payload["receipt"]

    async def test_a_refusal_with_no_audit_writer_does_not_claim_a_receipt(self):
        app, _ = build(risk="LOW", upstream_url="file:///etc/passwd")
        assert not hasattr(app.state, "audit_writer")
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        payload = json.loads(r.content)
        assert payload["deny_code"] == "upstream_scheme_not_allowed"
        assert payload["receipt"] == "no_audit_writer"
        assert r.headers["x-arkheia-receipt"] == payload["receipt"]

    async def test_a_refusal_whose_audit_write_raised_says_so(self):
        writer = self._RaisingWriter()
        app, _ = build(risk="LOW", upstream_url="file:///etc/passwd", audit=writer)
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert writer.calls == 1
        assert json.loads(r.content)["receipt"] == "write_failed"

    async def test_the_refusal_still_holds_when_the_receipt_fails(self):
        app, _ = build(risk="LOW", upstream_url="file:///etc/passwd",
                       audit=self._RaisingWriter())
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.status_code == 400
        assert b"root:" not in r.content

    async def test_every_status_the_caller_can_see_is_from_the_closed_set(self):
        """
        The status is a machine-readable field a support tool will branch on. A
        free-form string would put us back where we started.
        """
        from proxy.middleware.interception import RECEIPT_STATUSES

        seen = set()
        app, _ = build(risk="HIGH", action="block", gate_action="block")
        async with client(app) as c:
            seen.add(json.loads((await c.post("/v1/chat/completions",
                                              json=REQ)).content)["receipt"])
        app, _ = build(risk="HIGH", action="block", gate_action="block",
                       audit=self._RaisingWriter())
        async with client(app) as c:
            seen.add(json.loads((await c.post("/v1/chat/completions",
                                              json=REQ)).content)["receipt"])
        assert len(seen) == 2, f"the two cases produced the same status: {seen}"
        assert seen <= RECEIPT_STATUSES

    async def test_every_receipt_header_the_caller_can_see_is_from_the_closed_set(self):
        from proxy.middleware.interception import RECEIPT_STATUSES

        seen = set()
        for kwargs in (
            {"risk": "HIGH", "action": "warn"},
            {"risk": "HIGH", "action": "warn", "audit": self._RaisingWriter()},
            {"risk": "HIGH", "action": "block", "gate_action": "block"},
            {"risk": "LOW", "upstream_url": "file:///etc/passwd"},
        ):
            app, _ = build(**kwargs)
            async with client(app) as c:
                seen.add((await c.post("/v1/chat/completions", json=REQ)).headers[
                    "x-arkheia-receipt"
                ])
        assert len(seen) == 2, f"the covered paths produced no status variety: {seen}"
        assert seen <= RECEIPT_STATUSES


class TestFailSafeDefaults:
    """
    Every case here supplies the EARNED gate (``gate_action="block"``) on
    purpose. Since the gate became a required conjunct, an unearned profile
    stops a block on its own — so a test that left the gate at ``advise`` would
    go green no matter what the policy default was, and the fail-safe would be
    invisible. The mutation campaign said exactly that: M43 (the absent-policy
    default flipped from ``warn`` to ``block``) SURVIVED once the gate landed,
    because nothing was left holding the block open for the policy to decide.
    """

    async def test_a_config_with_no_high_risk_action_warns_rather_than_blocks(self):
        """
        The fallback when ``high_risk_action`` is absent must be the
        non-destructive one. A default of ``block`` would mean a deployment
        that never configured a policy silently starts withholding answers —
        and every test that sets the action explicitly would still be green.
        """
        app, _ = build(risk="HIGH", gate_action="block")
        del app.state.settings.detection.high_risk_action
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-action"] == "warn"
        assert r.headers["x-arkheia-policy-action"] == "warn", (
            "the policy default is not 'warn', so an unconfigured deployment "
            "withholds answers"
        )
        assert b"arkheia_blocked" not in r.content
        assert r.content == UPSTREAM_BODY

    async def test_a_missing_detection_config_also_warns(self):
        app, _ = build(risk="HIGH", gate_action="block")
        del app.state.settings.detection
        async with client(app) as c:
            r = await c.post("/v1/chat/completions", json=REQ)
        assert r.headers["x-arkheia-action"] == "warn"
        assert r.headers["x-arkheia-policy-action"] == "warn"
        assert b"arkheia_blocked" not in r.content
