"""
HTTP client for communicating with the Arkheia Enterprise Proxy.

Used by the MCP Trust Server to call /detect/verify and /audit/log.
All methods return dicts -- never raise exceptions to the caller.
Failures surface as UNKNOWN risk with error field set.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class ProxyClient:
    """
    Thin async HTTP client wrapping the proxy's detection endpoints.

    The MCP server is a thin connector -- all intelligence is in the proxy.
    This client's only job is reliable transport with graceful failure.
    """

    def __init__(self, base_url: str, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    async def verify(
        self,
        prompt: str,
        response: str,
        model_id: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """
        POST /detect/verify

        Returns detection result dict. Never raises -- returns UNKNOWN on any error.
        """
        payload = {
            "prompt": prompt,
            "response": response,
            "model_id": model_id,
        }
        if session_id:
            payload["session_id"] = session_id

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/detect/verify",
                    json=payload,
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.TimeoutException:
            logger.warning("ProxyClient: /detect/verify timed out for model=%s", model_id)
            return _unavailable("proxy_timeout")
        except httpx.ConnectError:
            logger.warning("ProxyClient: cannot connect to proxy at %s", self.base_url)
            return _unavailable("proxy_unavailable")
        except httpx.HTTPStatusError as e:
            logger.error("ProxyClient: /detect/verify HTTP error: %s", e)
            return _unavailable(f"proxy_http_error_{e.response.status_code}")
        except Exception as e:
            logger.error("ProxyClient: /detect/verify unexpected error: %s", e)
            return _unavailable("proxy_error")

    async def get_audit_log(
        self,
        session_id: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        """
        GET /audit/log

        Returns audit log dict. Never raises -- returns empty log on any error.
        """
        params: dict = {"limit": min(limit, 500)}
        if session_id:
            params["session_id"] = session_id

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(
                    f"{self.base_url}/audit/log",
                    params=params,
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.TimeoutException:
            logger.warning("ProxyClient: /audit/log timed out")
            return _empty_log("proxy_timeout")
        except httpx.ConnectError:
            logger.warning("ProxyClient: cannot connect to proxy at %s", self.base_url)
            return _empty_log("proxy_unavailable")
        except Exception as e:
            logger.error("ProxyClient: /audit/log unexpected error: %s", e)
            return _empty_log("proxy_error")


def _unavailable(error: str) -> dict:
    """Standard UNKNOWN response when proxy is unreachable."""
    return {
        "risk_level": "UNKNOWN",
        "confidence": 0.0,
        "features_triggered": [],
        "error": error,
    }


def _empty_log(error: str) -> dict:
    return {
        "events": [],
        "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        "error": error,
    }
