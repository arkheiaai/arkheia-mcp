"""
Arkheia Enterprise Proxy -- AI Interception Middleware.

Intercepts requests to /v1/* paths, runs fabrication detection on the
upstream response, and takes action based on risk level and configuration.

All other paths (including /detect/verify, /admin/*, /audit/*) bypass
this middleware completely.
"""

import json
import logging

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Body extraction helpers (module-level, not methods)
# ---------------------------------------------------------------------------

def _extract_model_id(body: bytes) -> str:
    """Parse JSON body and return the model field. Returns 'unknown' on any error."""
    try:
        body_json = json.loads(body)
        return body_json.get("model", "unknown")
    except Exception:
        return "unknown"


def _extract_prompt(body: bytes) -> str:
    """
    Parse JSON body and extract the prompt text.

    If a 'messages' key exists, join all content fields from messages where
    role == 'user'. Otherwise return the top-level 'prompt' field.
    Returns '' on any error.
    """
    try:
        body_json = json.loads(body)
        if "messages" in body_json:
            parts = []
            for msg in body_json["messages"]:
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, str):
                        parts.append(content)
                    elif isinstance(content, list):
                        # Handle content blocks (e.g. OpenAI vision format)
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                parts.append(block.get("text", ""))
            return " ".join(parts)
        return body_json.get("prompt", "")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AIInterceptionMiddleware(BaseHTTPMiddleware):
    """
    Intercepts /v1/* requests, detects fabrication risk in the AI response,
    and optionally blocks or warns based on configured action.
    """

    async def dispatch(self, request: Request, call_next):
        # Only activate for /v1/ paths
        if not request.url.path.startswith("/v1/"):
            return await call_next(request)

        try:
            # Read the request body
            body = await request.body()

            # Extract model and prompt from request body
            model_id = _extract_model_id(body)
            prompt = _extract_prompt(body)

            # Determine upstream URL from app state settings
            app_settings = getattr(request.app.state, "settings", None)
            upstream_url = None
            if app_settings is not None:
                detection = getattr(app_settings, "detection", None)
                if detection is not None:
                    upstream_url = getattr(detection, "upstream_url", None)

            # Normalise: empty string means no upstream
            if not upstream_url:
                upstream_url = None

            # Get the response body
            if upstream_url is not None:
                # Forward mode: proxy the request to the upstream
                target_url = upstream_url.rstrip("/") + request.url.path
                if request.url.query:
                    target_url += "?" + request.url.query

                # Forward headers, dropping Host (httpx sets it from the URL)
                forward_headers = {
                    k: v for k, v in request.headers.items()
                    if k.lower() != "host"
                }

                async with httpx.AsyncClient() as client:
                    upstream_response = await client.request(
                        method=request.method,
                        url=target_url,
                        content=body,
                        headers=forward_headers,
                    )
                response_body = upstream_response.content
            else:
                # Standalone mode: let the local route handle the request
                inner_response = await call_next(request)
                # Consume the response body stream
                chunks = []
                async for chunk in inner_response.body_iterator:
                    if isinstance(chunk, str):
                        chunks.append(chunk.encode("utf-8"))
                    else:
                        chunks.append(chunk)
                response_body = b"".join(chunks)

            # Get detection engine from app state
            engine = getattr(request.app.state, "engine", None)

            if engine is None:
                return Response(
                    content=response_body,
                    headers={"X-Arkheia-Risk": "UNAVAILABLE"},
                )

            # Run detection
            result = await engine.verify(
                prompt,
                response_body.decode("utf-8", errors="replace"),
                model_id,
            )

            # Determine action
            settings = getattr(request.app.state, "settings", None)
            if result.risk_level == "HIGH":
                detection_cfg = getattr(settings, "detection", None) if settings else None
                action = getattr(detection_cfg, "high_risk_action", "warn") if detection_cfg else "warn"
            else:
                action = "pass"

            # Build and return response based on risk + action
            if result.risk_level == "HIGH" and action == "block":
                return Response(
                    content='{"error":"arkheia_blocked","risk_level":"HIGH"}',
                    status_code=200,
                    media_type="application/json",
                    headers={"X-Arkheia-Risk": "HIGH"},
                )
            elif result.risk_level == "HIGH" and action == "warn":
                return Response(
                    content=b"[ARKHEIA WARNING: HIGH RISK DETECTED] " + response_body,
                    headers={"X-Arkheia-Risk": "HIGH"},
                )
            else:
                return Response(
                    content=response_body,
                    headers={"X-Arkheia-Risk": result.risk_level},
                )

        except Exception as exc:
            logger.exception("AIInterceptionMiddleware encountered an error: %s", exc)
            # Recover gracefully: let the request through with an ERROR marker
            try:
                fallback = await call_next(request)
                chunks = []
                async for chunk in fallback.body_iterator:
                    if isinstance(chunk, str):
                        chunks.append(chunk.encode("utf-8"))
                    else:
                        chunks.append(chunk)
                fallback_body = b"".join(chunks)
                return Response(
                    content=fallback_body,
                    headers={"X-Arkheia-Risk": "ERROR"},
                )
            except Exception:
                return Response(
                    content=b"",
                    headers={"X-Arkheia-Risk": "ERROR"},
                )
