"""
HTTP client for communicating with the Arkheia detection service.

Primary path: local Enterprise Proxy at /detect/verify
Fallback path: hosted API at arkheia-proxy-production.up.railway.app/v1/detect

All methods return dicts -- never raise exceptions to the caller.
Failures surface as UNKNOWN risk with error field set.
"""

import logging
import os
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Hosted API defaults
HOSTED_API_URL = "https://arkheia-proxy-production.up.railway.app"


class ProxyClient:
    """
    Thin async HTTP client wrapping Arkheia detection endpoints.

    Tries local proxy first (Enterprise Proxy at ARKHEIA_PROXY_URL).
    Falls back to hosted API (arkheia-proxy-production.up.railway.app/v1/detect) if local is unavailable.
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
        # Only when a self-hosted Arkheia proxy is configured; otherwise straight to the hosted API.
        self._local_available = bool(self.base_url)  # optimistic when set; flips on ConnectError

    async def verify(self, prompt: str, response: str, model_id: str,
                     session_id: Optional[str] = None) -> dict:
        """Detect fabrication in a model response; returns the signal only (see SIGNAL_FIELDS)."""
        return signal_only(await self._verify_any(prompt, response, model_id, session_id))

    async def _verify_any(
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
            # Hosted also failed -- try local once more in case it came back (only if one is configured)
            self._local_available = bool(self.base_url)

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
        """POST /detect/verify on a self-hosted Arkheia proxy (only when ARKHEIA_PROXY_URL is set)."""
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
                raw = resp.json()
                return {**raw, **assess(raw, "risk_level"), "source": raw.get("source", "local")}
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
        """POST /v1/detect on hosted Arkheia API (arkheia-proxy-production.up.railway.app)."""
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
                    "confidence": data.get("confidence", 0.0),
                    "detection_id": data.get("detection_id"),
                    "gate_action": data.get("gate_action"),
                    "source": "hosted",
                    **assess(data, "risk"),
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



#: The signal, and only the signal. Whatever a server sends, a caller of this package sees these
#: fields and nothing else.
SIGNAL_FIELDS = ("risk_level", "assessed", "not_assessed_reason", "candidate_alert", "confidence",
                 "detection_id", "gate_action", "source", "error")

_BANDS = ("LOW", "MEDIUM", "HIGH")


def assess(raw: dict, band_field: str) -> dict:
    """Read a server answer and fail closed: a band is passed on only when the server says it
    assessed the response and nothing else in the answer contradicts that. Anything else is
    NOT_ASSESSED, never LOW. Extra facts are read here and never passed on."""
    band = raw.get(band_field)
    clean = (
        raw.get("assessed") is True
        and band in _BANDS
        and raw.get("evidence_depth_limited") is False
        and raw.get("not_assessed_reason") is None
        and raw.get("candidate_alert") is None
        and raw.get("risk_demoted_from") is None
        and raw.get("gate_reason") is None
        and raw.get("error") is None
        and raw.get("profile_fingerprint_borrowed") in (None, False)
        and raw.get("model_supported") in (None, True)
    )
    if clean:
        return {"risk_level": band, "assessed": True}
    reason = raw.get("not_assessed_reason")
    out = {
        "risk_level": "NOT_ASSESSED",
        "assessed": False,
        "not_assessed_reason": "not_assessed" if raw.get("assessed") is False and isinstance(reason, str) and reason.strip() else "unknown",
    }
    candidate = raw.get("candidate_alert")
    if candidate in ("MEDIUM", "HIGH"):
        out["candidate_alert"] = candidate
    return out


def signal_only(result: dict) -> dict:
    """Project a verdict onto SIGNAL_FIELDS, dropping anything else a server returned."""
    return {k: result[k] for k in SIGNAL_FIELDS if k in result and result[k] is not None}


def _unavailable(error: str) -> dict:
    """Standard UNKNOWN response when detection is unreachable."""
    return {
        "risk_level": "UNKNOWN",
        "assessed": False,
        "confidence": 0.0,
        "error": error,
    }


def _empty_log(error: str) -> dict:
    return {
        "events": [],
        "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        "error": error,
    }
