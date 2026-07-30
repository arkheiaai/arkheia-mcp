"""
HTTP client for communicating with the Arkheia detection service.

Primary path: local Enterprise Proxy at /detect/verify
Fallback path: hosted API at arkheia-proxy-production.up.railway.app/v1/detect

All methods return dicts -- never raise exceptions to the caller.
Failures surface as UNKNOWN risk with error field set.
"""

import logging
import os
from typing import Any, Optional

import httpx

from arkheia_common.egress import egress_async_client
from arkheia_common.hosted_authority import (
    DEFAULT_HOSTED_API_URL,
    HostedAuthorityError,
    authorize_hosted_base_url,
    hosted_key_egress_client,
)

logger = logging.getLogger(__name__)

# Hosted API defaults
HOSTED_API_URL = DEFAULT_HOSTED_API_URL

_LOCAL_TRANSPORT_ERRORS = frozenset({
    "proxy_unavailable",
    "proxy_timeout",
    "proxy_error",
})

_HOSTED_TRANSIENT_ERRORS = frozenset({
    "hosted_unavailable",
    "hosted_timeout",
    "hosted_error",
})


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
        self._local_available = True  # optimistic; flips on ConnectError

    async def verify(
        self,
        prompt: str,
        response: str,
        model_id: str,
        session_id: Optional[str] = None,
        usage: Optional[dict[str, Any]] = None,
        output_tokens: Any = None,
        is_function_call: Any = None,
    ) -> dict:
        """
        Detect fabrication in a model response.

        Tries local proxy first. Evidence-backed local verdicts are final; local
        failures or evidence-limited local verdicts route to hosted when a key is
        configured. The returned verdict always receipts the attempted route.
        Never raises -- returns UNKNOWN on any error.
        """
        attempted_sources: list[str] = []
        route_errors: list[str] = []
        fallback_reason: Optional[str] = None
        local_result: Optional[dict] = None
        local_transport_failed = False

        # Try local proxy first (if last attempt didn't fail with ConnectError)
        if self._local_available:
            attempted_sources.append("local")
            local_result = await self._verify_local(
                prompt,
                response,
                model_id,
                session_id,
                usage=usage,
                output_tokens=output_tokens,
                is_function_call=is_function_call,
            )
            local_error = local_result.get("error")
            if local_error:
                route_errors.append(local_error)
                local_transport_failed = (
                    local_error in _LOCAL_TRANSPORT_ERRORS
                    or local_error.startswith("proxy_http_error_")
                )

            if local_transport_failed:
                # Local transport/service failure: try hosted if available.
                self._local_available = False
                fallback_reason = local_error
                logger.info(
                    "Local proxy failed with %s, falling back to hosted API at %s",
                    local_error,
                    self.hosted_url,
                )
            elif not local_error and not local_result.get("evidence_depth_limited", True):
                # Local gave an evidence-backed verdict; trust it and skip hosted.
                return _with_routing(
                    local_result,
                    attempted_sources=attempted_sources,
                    route_errors=route_errors,
                    fallback_reason=fallback_reason,
                )
            else:
                # Local returned a limited verdict. Keep it as a fallback, but
                # prefer hosted telemetry when a key is configured.
                fallback_reason = local_error or "local_evidence_limited"
        else:
            fallback_reason = "local_circuit_open"
            route_errors.append("local_circuit_open")

        # Fallback: hosted API
        if self.api_key:
            attempted_sources.append("hosted")
            hosted_result = await self._verify_hosted(
                prompt,
                response,
                model_id,
                usage=usage,
                output_tokens=output_tokens,
                is_function_call=is_function_call,
            )
            hosted_error = hosted_result.get("error")
            if hosted_error:
                route_errors.append(hosted_error)
                hosted_transient_failed = hosted_error in _HOSTED_TRANSIENT_ERRORS
                if hosted_error.startswith("hosted_http_error_"):
                    try:
                        status = int(hosted_error.removeprefix("hosted_http_error_"))
                    except ValueError:
                        hosted_transient_failed = True
                    else:
                        hosted_transient_failed = status >= 500

                if hosted_transient_failed:
                    # Hosted transient failures should not permanently suppress
                    # future local attempts. If local at least produced an
                    # application-level verdict, return it with the hosted
                    # failure receipted. If no detector measured anything, emit
                    # the aggregate fail-safe reason and keep the specifics in
                    # routing.route_errors.
                    self._local_available = True
                    if local_result is not None and not local_transport_failed:
                        return _with_routing(
                            local_result,
                            attempted_sources=attempted_sources,
                            route_errors=route_errors,
                            fallback_reason=fallback_reason,
                        )
                    if "local" in attempted_sources:
                        return _unavailable(
                            "all_detection_paths_failed",
                            routing={
                                "attempted_sources": attempted_sources,
                                "route_errors": route_errors,
                                "fallback_reason": fallback_reason,
                            },
                        )
                    return _with_routing(
                        hosted_result,
                        attempted_sources=attempted_sources,
                        route_errors=route_errors,
                        fallback_reason=fallback_reason,
                    )

            return _with_routing(
                hosted_result,
                attempted_sources=attempted_sources,
                route_errors=route_errors,
                fallback_reason=fallback_reason,
            )

        # No hosted API key. Return a local application-level verdict if one
        # exists; otherwise no detector is available.
        if local_result is not None and not local_transport_failed:
            return _with_routing(
                local_result,
                attempted_sources=attempted_sources,
                route_errors=route_errors,
                fallback_reason=fallback_reason,
            )
        if (
            local_result is not None
            and local_result.get("error") not in ("proxy_unavailable", "proxy_timeout")
        ):
            return _with_routing(
                local_result,
                attempted_sources=attempted_sources,
                route_errors=route_errors,
                fallback_reason=fallback_reason,
            )
        if not self.api_key:
            logger.warning("Local proxy unavailable and no ARKHEIA_API_KEY set for hosted fallback")
            return _unavailable(
                "no_detection_available",
                routing={
                    "attempted_sources": attempted_sources,
                    "route_errors": route_errors,
                    "fallback_reason": fallback_reason,
                },
            )

        return _unavailable(
            "all_detection_paths_failed",
            routing={
                "attempted_sources": attempted_sources,
                "route_errors": route_errors,
                "fallback_reason": fallback_reason,
            },
        )

    async def _verify_local(
        self,
        prompt: str,
        response: str,
        model_id: str,
        session_id: Optional[str] = None,
        usage: Optional[dict[str, Any]] = None,
        output_tokens: Any = None,
        is_function_call: Any = None,
    ) -> dict:
        """POST /detect/verify on local Enterprise Proxy."""
        payload = {
            "prompt": prompt,
            "response": response,
            "model_id": model_id,
        }
        if session_id:
            payload["session_id"] = session_id
        if usage is not None:
            payload["usage"] = usage
        if output_tokens is not None:
            payload["output_tokens"] = output_tokens
        if is_function_call is not None:
            payload["is_function_call"] = is_function_call

        try:
            async with egress_async_client(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{self.base_url}/detect/verify",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()
                # Normalise through the constructor rather than returning the
                # proxy's body verbatim: the local proxy is a separate service on
                # its own release cadence, so its payload is an INPUT, not the
                # contract. Passing it through unchanged is how the local success
                # path came to omit the transparency fields entirely.
                return _detection_response(
                    risk_level=data.get("risk_level", "UNKNOWN"),
                    confidence=data.get("confidence", 0.0),
                    features_triggered=data.get("features_triggered") or [],
                    detection_id=data.get("detection_id"),
                    detection_method=data.get("detection_method"),
                    # Absent => assume limited. A proxy that does not report its
                    # evidence depth has not told us it had full evidence.
                    evidence_depth_limited=data.get("evidence_depth_limited", True),
                    source="local",
                    error=data.get("error"),
                )
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
        usage: Optional[dict[str, Any]] = None,
        output_tokens: Any = None,
        is_function_call: Any = None,
    ) -> dict:
        """POST /v1/detect on hosted Arkheia API (arkheia-proxy-production.up.railway.app)."""
        payload = {
            "model": model_id,
            "response": response,
            "prompt": prompt,
        }
        if usage is not None:
            payload["usage"] = usage
        if output_tokens is not None:
            payload["output_tokens"] = output_tokens
        if is_function_call is not None:
            payload["is_function_call"] = is_function_call

        try:
            authorized = authorize_hosted_base_url(self.hosted_url)
            headers = {"X-Arkheia-Key": self.api_key}
            async with hosted_key_egress_client(timeout=self.timeout) as client:
                resp = await client.post(
                    f"{authorized.base_url}/v1/detect",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()
                # Map hosted response format to the verdict contract.
                return _detection_response(
                    risk_level=data.get("risk", "UNKNOWN"),
                    confidence=data.get("confidence", 0.0),
                    features_triggered=data.get("features_triggered") or [],
                    detection_id=data.get("detection_id"),
                    detection_method=data.get("detection_method"),
                    evidence_depth_limited=data.get("evidence_depth_limited", True),
                    source="hosted",
                    error=data.get("error"),
                )
        except HostedAuthorityError as e:
            logger.error("ProxyClient: hosted API authority rejected: %s", e)
            return _unavailable("hosted_authority_rejected")
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
            async with egress_async_client(timeout=self.timeout) as client:
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


# ---------------------------------------------------------------------------
# The verdict shape — ONE constructor, every return path.
#
# Why a constructor and not a dict literal per path: the transparency fields
# (`detection_method`, `evidence_depth_limited`, `source`) were added to the
# hosted SUCCESS path only. Every other return path — the local success path and
# all eight degraded paths — kept its own literal and silently omitted them, so a
# fail-open UNKNOWN reached MCP callers with `evidence_depth_limited` ABSENT.
# A caller reading `result.get("evidence_depth_limited")` got None, which is
# falsy, which reads as "full evidence" — the exact inversion this field exists
# to prevent.
#
# Per-path literals drift because omission is invisible. A single constructor
# makes the field set a property of the module rather than of each author:
# a new return path cannot omit a field without deleting it here, and
# `tests/test_proxy_client.py::TestVerdictShapeParity` asserts every discovered
# return path routes through this function.
# ---------------------------------------------------------------------------

#: The complete verdict contract. Every dict returned by a ProxyClient detection
#: path has exactly these keys — present, even when the value is None.
DETECTION_FIELDS = (
    "risk_level",
    "confidence",
    "features_triggered",
    "detection_id",
    "detection_method",
    "evidence_depth_limited",
    "source",
    "error",
)

ROUTED_DETECTION_FIELDS = (*DETECTION_FIELDS, "routing")


def _detection_response(
    *,
    source: str,
    risk_level: str = "UNKNOWN",
    confidence: float = 0.0,
    features_triggered: Optional[list] = None,
    detection_id: Optional[str] = None,
    detection_method: Optional[str] = None,
    evidence_depth_limited: bool = True,
    error: Optional[str] = None,
    routing: Optional[dict] = None,
) -> dict:
    """
    Build a detection verdict. The ONLY place a verdict dict is constructed.

    Defaults are the *honest degraded* values: UNKNOWN at zero confidence with
    no features and `evidence_depth_limited=True`. A path that measured nothing
    therefore says so by default, and a path that measured something has to
    state that explicitly. The inverse defaulting (assume full evidence) is what
    lets an unmeasured verdict pass as a measured one.
    """
    verdict = {
        "risk_level": risk_level,
        "confidence": confidence,
        "features_triggered": list(features_triggered or []),
        "detection_id": detection_id,
        "detection_method": detection_method,
        "evidence_depth_limited": bool(evidence_depth_limited),
        "source": source,
        "error": error,
    }
    if routing is not None:
        verdict["routing"] = {
            "attempted_sources": list(routing.get("attempted_sources") or []),
            "route_errors": list(routing.get("route_errors") or []),
            "fallback_reason": routing.get("fallback_reason"),
        }
    return verdict


def _unavailable(error: str, routing: Optional[dict] = None) -> dict:
    """
    Standard UNKNOWN verdict when detection is unreachable.

    `source="unavailable"` because no backend produced this verdict — naming the
    attempted backend here would read as "local/hosted scored it". Which path
    failed is carried by `error` (`proxy_timeout` vs `hosted_timeout`, ...).
    """
    return _detection_response(source="unavailable", error=error, routing=routing)


def _with_routing(
    result: dict,
    *,
    attempted_sources: list[str],
    route_errors: list[str],
    fallback_reason: Optional[str],
) -> dict:
    """Return an existing verdict with the route receipt made explicit."""
    return _detection_response(
        risk_level=result.get("risk_level", "UNKNOWN"),
        confidence=result.get("confidence", 0.0),
        features_triggered=result.get("features_triggered") or [],
        detection_id=result.get("detection_id"),
        detection_method=result.get("detection_method"),
        evidence_depth_limited=result.get("evidence_depth_limited", True),
        source=result.get("source", "unavailable"),
        error=result.get("error"),
        routing={
            "attempted_sources": attempted_sources,
            "route_errors": route_errors,
            "fallback_reason": fallback_reason,
        },
    )


def _empty_log(error: str) -> dict:
    return {
        "events": [],
        "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        "error": error,
    }
