"""
Arkheia Enterprise Proxy -- Passthrough endpoints for CLI routing.

These endpoints allow the Grok and Gemini CLIs to route their traffic
through Arkheia detection without any code changes to the CLIs -- only
a config change to point their base URL at localhost:8098.

Routes:
  POST /proxy/grok/v1/{path}  -- forward to https://api.x.ai/v1/{path}
  ANY  /v1beta/{path}         -- forward to https://generativelanguage.googleapis.com/v1beta/{path}

Both endpoints:
  1. Forward the request to the upstream provider (safe headers only)
  2. Extract response text for detection
  3. Run Arkheia detection
  4. Return the provider response with X-Arkheia-Risk header
  5. Write to audit log (same record format as /detect/verify)

Fail-open: if detection fails for any reason, the provider response is returned
unchanged with X-Arkheia-Risk: ERROR. The pipeline is never blocked by detection.

Security:
  - Only allowlisted headers are forwarded upstream (no cookie/internal header leak)
  - Path segments are validated against provider-specific allowlists (SSRF mitigation)
  - Error details are never exposed to clients
"""

import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import Response

logger = logging.getLogger(__name__)

router = APIRouter()

GROK_UPSTREAM    = "https://api.x.ai/v1"
GEMINI_UPSTREAM  = "https://generativelanguage.googleapis.com/v1beta"
TOGETHER_UPSTREAM = "https://api.together.xyz/v1"

# ---------------------------------------------------------------------------
# Security: header allowlist for upstream forwarding
# ---------------------------------------------------------------------------
# Only these headers are forwarded to upstream providers. This prevents
# leaking internal cookies, auth tokens for other services, or proxy headers.
_FORWARDED_HEADERS = {
    "authorization",       # provider API key (Bearer token)
    "content-type",
    "accept",
    "user-agent",
    "x-request-id",
    "x-stainless-arch",
    "x-stainless-lang",
    "x-stainless-os",
    "x-stainless-package-version",
    "x-stainless-runtime",
    "x-stainless-runtime-version",
}

# ---------------------------------------------------------------------------
# Security: path validation for SSRF mitigation
# ---------------------------------------------------------------------------
# Only allow paths that match known provider API patterns.
# This prevents the proxy from being used to reach arbitrary URLs.
_OPENAI_PATH_RE = re.compile(
    r"^(chat/completions|completions|embeddings|models|images/generations|audio/.*|moderations)$"
)
_GEMINI_PATH_RE = re.compile(
    r"^models(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?$"
)

# ---------------------------------------------------------------------------
# Response text extractors
# ---------------------------------------------------------------------------

def _extract_openai_text(body: bytes) -> Optional[str]:
    """Extract assistant message text from an OpenAI-format chat completion."""
    try:
        data = json.loads(body)
        return data["choices"][0]["message"]["content"]
    except Exception:
        return None


def _extract_gemini_text(body: bytes) -> Optional[str]:
    """Extract response text from a Gemini generateContent response."""
    try:
        data = json.loads(body)
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Prompt extractors
# ---------------------------------------------------------------------------

def _extract_openai_prompt(body: bytes) -> str:
    try:
        data = json.loads(body)
        parts = []
        for msg in data.get("messages", []):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "text":
                            parts.append(block.get("text", ""))
        return " ".join(parts)
    except Exception:
        return ""


def _extract_gemini_prompt(body: bytes) -> str:
    try:
        data = json.loads(body)
        # Gemini format: contents[].parts[].text where role == "user"
        parts = []
        for content in data.get("contents", []):
            if content.get("role", "user") in ("user", ""):
                for part in content.get("parts", []):
                    if "text" in part:
                        parts.append(part["text"])
        return " ".join(parts)
    except Exception:
        return ""


def _extract_grok_model(body: bytes) -> str:
    try:
        return json.loads(body).get("model", "unknown")
    except Exception:
        return "unknown"


def _extract_gemini_model(path: str) -> str:
    """
    Extract model name from Gemini path.
    e.g. 'models/gemini-2.5-flash:generateContent' -> 'gemini-2.5-flash'
    """
    try:
        # path looks like 'models/gemini-2.5-flash:generateContent?key=...'
        segment = path.split("/")[-1].split(":")[0]
        return segment if segment else "unknown"
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Shared detection + audit helper
# ---------------------------------------------------------------------------

async def _detect_and_audit(
    request: Request,
    prompt: str,
    response_text: str,
    model_id: str,
) -> str:
    """
    Run detection and write audit record. Returns risk_level string.
    Never raises -- returns 'ERROR' on any failure.
    """
    engine = getattr(request.app.state, "engine", None)
    audit = getattr(request.app.state, "audit_writer", None)

    if engine is None or not response_text:
        return "UNKNOWN"

    try:
        result = await engine.verify(prompt, response_text, model_id)
        risk_level = result.risk_level

        if audit:
            record = {
                "detection_id": result.detection_id,
                "timestamp": result.timestamp,
                "session_id": None,
                "model_id": result.model_id,
                "profile_version": result.profile_version,
                "risk_level": risk_level,
                "confidence": result.confidence,
                "features_triggered": result.features_triggered,
                "prompt_hash": hashlib.sha256(prompt.encode()).hexdigest(),
                "response_hash": hashlib.sha256(response_text.encode()).hexdigest(),
                "response_length": len(response_text),
                "action_taken": "pass",
                "source": "passthrough",
                "error": result.error,
            }
            try:
                await audit.write(record)
            except Exception as e:
                logger.error("Audit write failed in passthrough: %s", e)

        return risk_level

    except Exception as e:
        logger.error("Detection failed in passthrough (model=%s): %s", model_id, e)
        return "ERROR"


# ---------------------------------------------------------------------------
# Shared forwarding helper
# ---------------------------------------------------------------------------

async def _forward(
    request: Request,
    upstream_url: str,
) -> tuple[bytes, int, dict]:
    """
    Forward the request to upstream_url. Returns (body, status_code, headers).
    Raises on network error.

    Security: only allowlisted headers are forwarded (see _FORWARDED_HEADERS).
    """
    body = await request.body()

    # Only forward safe, allowlisted headers — never cookies, internal tokens, etc.
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() in _FORWARDED_HEADERS
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        upstream_response = await client.request(
            method=request.method,
            url=upstream_url,
            content=body,
            headers=forward_headers,
            params=dict(request.query_params),
        )

    # Filter hop-by-hop headers
    skip = {"content-encoding", "transfer-encoding", "connection"}
    response_headers = {
        k: v for k, v in upstream_response.headers.items()
        if k.lower() not in skip
    }

    return upstream_response.content, upstream_response.status_code, response_headers


# ---------------------------------------------------------------------------
# Grok passthrough  --  /proxy/grok/v1/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/proxy/grok/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def grok_passthrough(path: str, request: Request):
    """
    Forward Grok CLI requests to api.x.ai with Arkheia detection.

    Configure Grok CLI:
        baseURL: "http://localhost:8098/proxy/grok/v1"
    """
    if not _OPENAI_PATH_RE.match(path):
        return Response(
            content=json.dumps({"error": "invalid_path"}).encode(),
            status_code=400,
            media_type="application/json",
        )

    upstream_url = f"{GROK_UPSTREAM}/{path}"
    logger.debug("grok_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("grok_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    # Only screen successful responses with extractable text
    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_openai_text(response_body)
        if response_text:
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("grok_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Together AI passthrough  --  /proxy/together/v1/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/proxy/together/v1/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def together_passthrough(path: str, request: Request):
    """
    Forward Together AI requests to api.together.xyz with Arkheia detection.

    Configure Together AI client:
        base_url = "http://localhost:8098/proxy/together/v1"
    """
    if not _OPENAI_PATH_RE.match(path):
        return Response(
            content=json.dumps({"error": "invalid_path"}).encode(),
            status_code=400,
            media_type="application/json",
        )

    upstream_url = f"{TOGETHER_UPSTREAM}/{path}"
    logger.debug("together_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("together_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_openai_text(response_body)
        if response_text:
            prompt = _extract_openai_prompt(request_body)
            model_id = _extract_grok_model(request_body)  # same field: "model"
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("together_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )


# ---------------------------------------------------------------------------
# Gemini passthrough  --  /v1beta/{path}
# ---------------------------------------------------------------------------

@router.api_route(
    "/v1beta/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
)
async def gemini_passthrough(path: str, request: Request):
    """
    Forward Gemini CLI requests to generativelanguage.googleapis.com with detection.

    Configure Gemini CLI:
        GEMINI_API_BASE_URL=http://localhost:8098
        GOOGLE_GENERATIVE_AI_BASE_URL=http://localhost:8098
    """
    if not _GEMINI_PATH_RE.match(path):
        return Response(
            content=json.dumps({"error": "invalid_path"}).encode(),
            status_code=400,
            media_type="application/json",
        )

    upstream_url = f"{GEMINI_UPSTREAM}/{path}"
    logger.debug("gemini_passthrough: %s %s", request.method, upstream_url)

    try:
        request_body = await request.body()
        response_body, status_code, response_headers = await _forward(request, upstream_url)
    except Exception as e:
        logger.error("gemini_passthrough: upstream error: %s", e)
        return Response(
            content=json.dumps({"error": "upstream_unavailable"}).encode(),
            status_code=502,
            media_type="application/json",
            headers={"X-Arkheia-Risk": "ERROR"},
        )

    risk_level = "SKIP"
    if status_code == 200:
        response_text = _extract_gemini_text(response_body)
        if response_text:
            prompt = _extract_gemini_prompt(request_body)
            model_id = _extract_gemini_model(path)
            risk_level = await _detect_and_audit(request, prompt, response_text, model_id)
            logger.info("gemini_passthrough: model=%s risk=%s", model_id, risk_level)

    response_headers["X-Arkheia-Risk"] = risk_level
    return Response(
        content=response_body,
        status_code=status_code,
        headers=response_headers,
    )
