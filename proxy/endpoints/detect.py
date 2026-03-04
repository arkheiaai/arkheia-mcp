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

from fastapi import APIRouter, Request
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


@router.post("/detect/verify", response_model=VerifyResponse)
async def detect_verify(req: VerifyRequest, request: Request):
    """
    Verify whether an AI response shows signs of fabrication.

    Always returns HTTP 200. Detection failures surface as UNKNOWN risk.
    Audit log is written async -- does not block the response.
    """
    engine = getattr(request.app.state, "engine", None)
    audit = getattr(request.app.state, "audit_writer", None)

    # Input validation -- always return 200, never raise
    if not req.model_id:
        r = _unknown(error="model_id_missing")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return r

    if not req.response:
        r = _unknown(model_id=req.model_id, error="response_empty")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return r

    if engine is None:
        r = _unknown(model_id=req.model_id, error="engine_unavailable")
        if audit:
            await audit.write(_audit_record(r, req, "pass"))
        return r

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
        return r

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

    return response


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
