"""
HTTP client for communicating with the Arkheia detection service.

Primary path: local Enterprise Proxy at /detect/verify
Fallback path: hosted API at app.arkheia.ai/v1/detect

All methods return dicts -- never raise exceptions to the caller.
Failures surface as UNKNOWN risk with error field set.
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Hosted API defaults
HOSTED_API_URL = "https://app.arkheia.ai"


class ProxyClient:
    """
    Thin async HTTP client wrapping Arkheia detection endpoints.

    Tries local proxy first (Enterprise Proxy at ARKHEIA_PROXY_URL).
    Falls back to hosted API (app.arkheia.ai/v1/detect) if local is unavailable.
    Hosted path requires an API key (ARKHEIA_API_KEY env var).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        hosted_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.hosted_url = (hosted_url or HOSTED_API_URL).rstrip("/")
        self.api_key = api_key or os.environ.get("ARKHEIA_API_KEY")
        self._local_available = True  # optimistic; flips on ConnectError

    async def verify(
        self,
        prompt: str,
        response: str,
        model_id: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """
        Detect fabrication in a model response.

        Tries local proxy first. If unavailable, falls back to hosted API.
        Never raises -- returns UNKNOWN on any error.
        """
        # Try local proxy first (if last attempt didn't fail with ConnectError)
        if self._local_available:
            result = await self._verify_local(prompt, response, model_id, session_id)
            if result.get("error") not in ("proxy_unavailable", "proxy_timeout"):
                return result
            # Local proxy down -- fall through to hosted
            self._local_available = False
            logger.info("Local proxy unavailable, falling back to hosted API at %s", self.hosted_url)

        # Fallback: hosted API
        if self.api_key:
            result = await self._verify_hosted(prompt, response, model_id)
            if result.get("error") not in ("hosted_unavailable",):
                return result
            # Hosted also failed -- try local once more in case it came back
            self._local_available = True

        # No hosted API key and local is down
        if not self.api_key:
            logger.warning("Local proxy unavailable and no ARKHEIA_API_KEY set for hosted fallback")
            return _unavailable("no_detection_available")

        return _unavailable("all_detection_paths_failed")

    async def _verify_local(
        self,
        prompt: str,
        response: str,
        model_id: str,
        session_id: Optional[str] = None,
    ) -> dict:
        """POST /detect/verify on local Enterprise Proxy."""
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

    async def _verify_hosted(
        self,
        prompt: str,
        response: str,
        model_id: str,
    ) -> dict:
        """POST /v1/detect on hosted Arkheia API (app.arkheia.ai)."""
        payload = {
            "model": model_id,
            "response": response,
            "prompt": prompt,
        }
        headers = {"X-Arkheia-Key": self.api_key}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.hosted_url}/v1/detect",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                # Map hosted response format to local format
                return {
                    "risk_level": data.get("risk", "UNKNOWN"),
                    "confidence": data.get("confidence", 0.0),
                    "features_triggered": data.get("features_triggered", []) or [],
                    "detection_id": data.get("detection_id"),
                    "detection_method": data.get("detection_method"),
                    "evidence_depth_limited": data.get("evidence_depth_limited", True),
                    "source": "hosted",
                }
        except httpx.TimeoutException:
            logger.warning("ProxyClient: hosted /v1/detect timed out for model=%s", model_id)
            return _unavailable("hosted_timeout")
        except httpx.ConnectError:
            logger.warning("ProxyClient: cannot connect to hosted API at %s", self.hosted_url)
            return _unavailable("hosted_unavailable")
        except httpx.HTTPStatusError as e:
            status = e.response.status_code
            if status == 401:
                logger.error("ProxyClient: hosted API rejected API key (401)")
                return _unavailable("hosted_auth_failed")
            if status == 429:
                logger.warning("ProxyClient: hosted API rate/quota limit (429)")
                return _unavailable("hosted_quota_exceeded")
            logger.error("ProxyClient: hosted /v1/detect HTTP error: %s", e)
            return _unavailable(f"hosted_http_error_{status}")
        except Exception as e:
            logger.error("ProxyClient: hosted /v1/detect unexpected error: %s", e)
            return _unavailable("hosted_error")

    async def get_audit_log(
        self,
        session_id: Optional[str] = None,
        limit: int = 50,
    ) -> dict:
        """
        GET /audit/log

        Returns audit log dict. Never raises -- returns empty log on any error.
        Note: audit log is only available from local proxy, not hosted API.
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
    """Standard UNKNOWN response when detection is unreachable."""
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
