"""
POST /detect/verify

The core detection endpoint. Both Product 1 (MCP Trust Server) and
Product 2 (Enterprise Proxy) depend on this endpoint.

Error contract: ALL responses are HTTP 200. Detection failures surface as
risk_level=UNKNOWN with an error field. This endpoint NEVER returns 4xx/5xx.
Detection must never crash the pipeline it monitors.
"""

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from proxy.detection_adapter import schedule_push

logger = logging.getLogger(__name__)

_ADAPTER_TENANT_ID = os.getenv("ARKHEIA_TENANT_ID", "default")

router = APIRouter()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


class VerifyRequest(BaseModel):
    prompt: str
    response: str
    model_id: str
    session_id: Optional[str] = None


class VerifyResponse(BaseModel):
    model_config = {"extra": "allow"}

    risk_level: str
    confidence: float
    features_triggered: list[str]
    model_id: str
    profile_version: str
    timestamp: str
    detection_id: str
    error: Optional[str] = None
    # Governance decision surfaced to the CALLER so a configured block is not silently
    # decorative. These two fields are NOT interchangeable:
    #   action      = POLICY INTENT (NOT authorization). The customer policy applied, from
    #                 settings.detection.high_risk_action ("block"/"warn"/"pass") -- mirrors
    #                 action_taken in the audit record. Records what policy WANTS.
    #   gate_action = AUTHORIZED action (AUTHORITATIVE). The profile-EARNED gate: "block" ONLY
    #                 when the profile validated it (features.py::resolve_gate_action); else
    #                 "advise". Per proxy/detection/features.py a consumer must hard-block ONLY
    #                 when gate_action == "block" -- keying off `action` over-blocks unearned
    #                 profiles.
    action: Optional[str] = None
    gate_action: Optional[str] = None


def _unknown(
    model_id: str = "",
    error: str = "",
    detection_id: Optional[str] = None,
) -> VerifyResponse:
    return VerifyResponse(
        risk_level="UNKNOWN",
        confidence=0.0,
        features_triggered=[],
        model_id=model_id,
        profile_version="none",
        timestamp=_now(),
        detection_id=detection_id or _uuid(),
        error=error or None,
    )


def _signal(
    http_response: Response,
    verify: VerifyResponse,
    action: str,
    gate_action: str,
) -> VerifyResponse:
    """Surface the governance decision to the CALLER so a configured block is enforceable.

    /detect/verify is advisory by contract (ALWAYS HTTP 200; it must never crash the pipeline
    it monitors), so we do NOT block transport here -- transport-level blocking lives in
    proxy/middleware/interception.py (the /v1/* enforcement path). But silently swallowing a
    configured `block` is the defect: the audit + governance trail record action_taken="block"
    while the caller receives an identical byte stream for block vs allow and cannot enforce.

    So we emit a machine-actionable signal the caller can act on, as TWO non-interchangeable
    fields (mirrored in headers for transport-layer consumers):
      - `gate_action` (X-Arkheia-Gate-Action) = the AUTHORIZED action (AUTHORITATIVE) -- the
        profile-earned gate. Per proxy/detection/features.py a consumer must hard-block ONLY
        when gate_action == "block".
      - `action` (X-Arkheia-Action) = the POLICY intent (NOT authorization) -- mirrors the
        audit action_taken. Enforcing on this over-blocks unearned / evidence-limited profiles.

    Header/structured-field signalling ONLY -- we never prepend to the body (that pattern in
    interception.py corrupts responses and 400-loops sessions).

    Coerces to str and never raises: this endpoint must never crash the pipeline it monitors,
    so signalling is best-effort -- a malformed action must not 500 an advisory 200 response.
    """
    action = str(action)
    gate_action = str(gate_action)
    verify.action = action
    verify.gate_action = gate_action
    try:
        http_response.headers["X-Arkheia-Risk"] = str(verify.risk_level)
        # X-Arkheia-Action = POLICY INTENT (not authorization); mirrors audit action_taken.
        http_response.headers["X-Arkheia-Action"] = action
        # X-Arkheia-Gate-Action = AUTHORITATIVE authorized action. Consumers hard-block ONLY
        # on this == "block" (features.py). Enforcing on X-Arkheia-Action over-blocks.
        http_response.headers["X-Arkheia-Gate-Action"] = gate_action
    except Exception as e:  # pragma: no cover - defensive; headers are best-effort
        logger.error("Failed to set Arkheia signal headers (body fields still set): %s", e)
    return verify


@router.post("/detect/verify", response_model=VerifyResponse)
async def detect_verify(req: VerifyRequest, request: Request, http_response: Response):
    """
    Verify whether an AI response shows signs of fabrication.

    Always returns HTTP 200. Detection failures surface as UNKNOWN risk.
    Audit log is written async -- does not block the response.

    TWO decision signals are surfaced to the caller, and they are NOT interchangeable:

      - gate_action / X-Arkheia-Gate-Action = the AUTHORIZED action (AUTHORITATIVE). This is
        the profile-EARNED gate: "block" ONLY when the model profile has validated a hard-block
        (see proxy/detection/features.py::resolve_gate_action); otherwise "advise". A consumer
        MUST hard-block ONLY when gate_action == "block". This is the signal to enforce on.

      - action / X-Arkheia-Action = the POLICY intent (NOT an authorization). It mirrors
        action_taken in the audit record (from settings.detection.high_risk_action, e.g.
        "block"/"warn"/"pass"). It records what the customer's policy WANTS, which on an
        unearned / evidence-limited profile can be "block" while gate_action is still "advise".
        Keying enforcement off `action` OVER-BLOCKS on profiles that never earned it -- do not.
    """
    engine = getattr(request.app.state, "engine", None)
    audit = getattr(request.app.state, "audit_writer", None)

    # Input validation -- always return 200, never raise
    if not req.model_id:
        r = _unknown(error="model_id_missing")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return _signal(http_response, r, "pass", "advise")

    if not req.response:
        r = _unknown(model_id=req.model_id, error="response_empty")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return _signal(http_response, r, "pass", "advise")

    if engine is None:
        r = _unknown(model_id=req.model_id, error="engine_unavailable")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return _signal(http_response, r, "pass", "advise")

    try:
        result = await engine.verify(req.prompt, req.response, req.model_id)
    except Exception as e:
        logger.error("Detection engine error for model=%s: %s", req.model_id, e)
        r = _unknown(model_id=req.model_id, error="engine_error")
        if audit:
            try:
                await audit.write(_audit_record(r, req, "pass"))
            except Exception as ae:
                logger.error("Audit write failed after engine error: %s", ae)
        return _signal(http_response, r, "pass", "advise")

    # Determine action taken
    settings = getattr(request.app.state, "settings", None)
    action = _determine_action(result.risk_level, settings)

    response = VerifyResponse(
        risk_level=result.risk_level,
        confidence=result.confidence,
        features_triggered=result.features_triggered,
        model_id=result.model_id,
        profile_version=result.profile_version,
        timestamp=result.timestamp,
        detection_id=result.detection_id,
        error=result.error,
    )

    # Async audit write -- does not block; never crashes the response pipeline
    if audit:
        try:
            await audit.write(_audit_record(response, req, action))
        except Exception as e:
            logger.error("Audit write failed (detection result unaffected): %s", e)

    # Push to Arkheia Governance Detection Adapter (fail-open, fire-and-forget)
    schedule_push(
        tenant_id=_ADAPTER_TENANT_ID,
        source_id=req.model_id,
        event_type="mcp_detection",
        payload={
            "detection_id": response.detection_id,
            "model_id": response.model_id,
            "risk_level": response.risk_level,
            "confidence": response.confidence,
            "features_triggered": response.features_triggered,
            "profile_version": response.profile_version,
            "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),
            "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),
            "action_taken": action,
        },
        risk_level=response.risk_level if response.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "LOW",
    )

    # Surface the governance decision to the caller: policy `action` (mirrors action_taken in
    # the audit) + profile-earned `gate_action`. Keeps HTTP 200; blocking-at-transport stays the
    # job of proxy/middleware/interception.py. Consumers hard-block only when gate_action=="block".
    return _signal(http_response, response, action, getattr(result, "gate_action", "advise"))


def _determine_action(risk_level: str, settings) -> str:
    if risk_level == "HIGH":
        action = getattr(getattr(settings, "detection", None), "high_risk_action", "warn")
        return action
    if risk_level == "UNKNOWN":
        action = getattr(getattr(settings, "detection", None), "unknown_action", "pass")
        return action
    return "pass"


def _audit_record(response: VerifyResponse, req: VerifyRequest, action: str) -> dict:
    return {
        "detection_id": response.detection_id,
        "timestamp": response.timestamp,
        "session_id": req.session_id,
        "model_id": response.model_id,
        "profile_version": response.profile_version,
        "risk_level": response.risk_level,
        "confidence": response.confidence,
        "features_triggered": response.features_triggered,
        "prompt_hash": hashlib.sha256(req.prompt.encode()).hexdigest(),
        "response_hash": hashlib.sha256(req.response.encode()).hexdigest(),
        "response_length": len(req.response),
        "action_taken": action,
        "source": "proxy",
        "error": response.error,
    }
