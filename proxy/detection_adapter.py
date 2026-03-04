"""
Push detection events to the Arkheia Governance Detection Adapter.
Fire-and-forget, fail-open: never raises, never blocks the caller.

Config (env vars):
  DETECTION_ADAPTER_URL          - e.g. http://detection-adapter:7070
  DETECTION_ADAPTER_HMAC_SECRET  - shared secret for HMAC-SHA256 signing
  DETECTION_ADAPTER_KEY_ID       - key identifier (default: mcp-v1)
"""
import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import os
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DETECTION_ADAPTER_URL = os.getenv("DETECTION_ADAPTER_URL", "")
DETECTION_ADAPTER_HMAC_SECRET = os.getenv("DETECTION_ADAPTER_HMAC_SECRET", "")
DETECTION_ADAPTER_KEY_ID = os.getenv("DETECTION_ADAPTER_KEY_ID", "mcp-v1")


def _sign_headers(body: bytes, secret: str, key_id: str) -> dict:
    timestamp = str(int(time.time()))
    message = f"{timestamp}.{body.decode('utf-8')}".encode()
    sig = _hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {
        "X-Arkheia-Key-Id": key_id,
        "X-Arkheia-Timestamp": timestamp,
        "X-Arkheia-Signature": sig,
        "Content-Type": "application/json",
    }


async def push_event(
    tenant_id: str,
    source_id: str,
    event_type: str,
    payload: dict[str, Any],
    risk_level: str = "LOW",
) -> None:
    """Push a detection event to the governance adapter. Fails open — never raises."""
    if not DETECTION_ADAPTER_URL or not DETECTION_ADAPTER_HMAC_SECRET:
        return

    body_dict = {
        "tenant_id": tenant_id,
        "source_id": source_id,
        "source_product": "mcp_server",
        "event_type": event_type,
        "risk_level": risk_level,
        "payload": payload,
    }
    body = json.dumps(body_dict).encode()
    headers = _sign_headers(body, DETECTION_ADAPTER_HMAC_SECRET, DETECTION_ADAPTER_KEY_ID)

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{DETECTION_ADAPTER_URL}/v1/events/proxy",
                content=body,
                headers=headers,
            )
            if resp.status_code >= 400:
                logger.debug(
                    "Detection adapter returned %s: %s",
                    resp.status_code,
                    resp.text[:200],
                )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Detection adapter push failed (fail-open): %s", exc)


def schedule_push(
    tenant_id: str,
    source_id: str,
    event_type: str,
    payload: dict[str, Any],
    risk_level: str = "LOW",
) -> None:
    """Schedule a push on the running event loop. Safe to call from async context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.ensure_future(
                push_event(tenant_id, source_id, event_type, payload, risk_level)
            )
        else:
            loop.run_until_complete(
                push_event(tenant_id, source_id, event_type, payload, risk_level)
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Detection adapter schedule_push failed: %s", exc)
