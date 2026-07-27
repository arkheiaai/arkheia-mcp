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
