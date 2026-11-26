"""
HTTP client for communicating with the Arkheia detection service.

Primary path: local Enterprise Proxy at /detect/verify
Fallback path: hosted API at arkheia-proxy-production.up.railway.app/v1/detect

All methods return dicts -- never raise exceptions to the caller.
Failures surface as UNKNOWN risk with error field set.
"""

import hashlib
import json
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
                src = raw.get("source") if isinstance(raw, dict) and raw.get("source") in ("proxy", "local") else "local"
                return verdict_fields(raw, "risk_level", model_id, src)
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
                return verdict_fields(data, "risk", model_id, "hosted")
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
                return audit_view(resp.json())
        except httpx.TimeoutException:
            logger.warning("ProxyClient: /audit/log timed out")
            return _empty_log("proxy_timeout")
        except httpx.ConnectError:
            logger.warning("ProxyClient: cannot connect to proxy at %s", self.base_url)
            return _empty_log("proxy_unavailable")
        except Exception as e:
            logger.error("ProxyClient: /audit/log unexpected error: %s", e)
            return _empty_log("proxy_error")



#: The verdict, and only the verdict. A caller sees these fields and nothing else.
SIGNAL_FIELDS = ("risk_level", "assessed", "not_assessed_reason", "candidate_alert", "confidence",
                 "detection_id", "gate_action", "source", "error")

_BANDS = ("LOW", "MEDIUM", "HIGH")
_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
_TEXT_MAX = 200
_ID_KEYS = ("profile_model_id", "model_id", "model")


def _absent(v) -> bool:
    return v is None


def _same_model(a, b) -> bool:
    return isinstance(a, str) and isinstance(b, str) and a.strip().lower() == b.strip().lower()


def _identity_conflict(raw: dict, requested_model) -> bool:
    for key in _ID_KEYS:
        if key in raw and not (isinstance(raw[key], str) and raw[key].strip()):
            return True
    ids = [raw[k] for k in _ID_KEYS if isinstance(raw.get(k), str)]
    if any(not _same_model(v, ids[0]) for v in ids):
        return True
    if requested_model is not None and any(not _same_model(v, requested_model) for v in ids):
        return True
    return False


def _candidate(raw: dict, band):
    """The candidate alert if coherent, None if absent, "invalid" otherwise."""
    cand = raw.get("candidate_alert")
    if _absent(cand):
        return None
    if cand not in ("MEDIUM", "HIGH"):
        return "invalid"
    lower = raw.get("risk_demoted_from")
    if _absent(lower):
        return cand if cand == band else "invalid"
    from_, to = _RANK.get(lower), _RANK.get(band)
    if from_ is None or to is None or not (to >= 2 and from_ == to + 1):
        return "invalid"
    return cand if cand == lower else "invalid"


def _not_assessed(reason: str, candidate=None) -> dict:
    out = {"risk_level": "NOT_ASSESSED", "assessed": False, "not_assessed_reason": reason}
    if candidate in ("MEDIUM", "HIGH"):
        out["candidate_alert"] = candidate
    return out


def assess(raw: dict, band_field: str, requested_model=None) -> dict:
    """Read a server answer and fail closed. Returns fresh verdict fields only: a band is passed
    on when the server says it assessed the response and nothing in the answer contradicts that;
    anything else is NOT_ASSESSED, never LOW."""
    if not isinstance(raw, dict):
        return _not_assessed("unknown")
    band = raw.get(band_field)
    assessed = raw.get("assessed")
    reason = raw.get("not_assessed_reason")
    if assessed is True:
        clean = (
            isinstance(band, str) and band in _BANDS
            and raw.get("evidence_depth_limited") is False
            and (_absent(raw.get("profile_fingerprint_borrowed")) or raw.get("profile_fingerprint_borrowed") is False)
            and ("model_supported" not in raw or raw.get("model_supported") is True)
            and _absent(raw.get("gate_reason"))
            and _absent(raw.get("error"))
            and not _identity_conflict(raw, requested_model)
            and _absent(raw.get("risk_demoted_from"))
            and _absent(reason)
            and _absent(raw.get("candidate_alert"))
        )
        return {"risk_level": band, "assessed": True} if clean else _not_assessed("unknown")
    cand = _candidate(raw, band)
    if cand == "invalid":
        return _not_assessed("unknown")
    if assessed is False and isinstance(reason, str) and reason.strip():
        return _not_assessed("not_assessed", cand)
    return _not_assessed("unknown", cand)


def verdict_fields(raw: dict, band_field: str, requested_model=None, source=None) -> dict:
    """The caller-facing result, built fresh: normalised verdict plus typed safe fields."""
    out = assess(raw, band_field, requested_model)
    conf = raw.get("confidence") if isinstance(raw, dict) else None
    if isinstance(conf, (int, float)) and not isinstance(conf, bool):
        out["confidence"] = float(conf)
    if isinstance(raw, dict):
        for key in ("detection_id", "gate_action"):
            v = raw.get(key)
            if isinstance(v, str) and 0 < len(v) <= _TEXT_MAX:
                out[key] = v
        err = raw.get("error")
        if isinstance(err, str) and 0 < len(err) <= _TEXT_MAX:
            out["error"] = err
    if source:
        out["source"] = source
    return out


def signal_only(result: dict) -> dict:
    """Project a result onto SIGNAL_FIELDS, dropping anything else."""
    return {k: result[k] for k in SIGNAL_FIELDS if k in result and result[k] is not None}


def _canonical(v) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _text(v):
    return v if isinstance(v, str) and len(v) <= _TEXT_MAX else None


def _record_kind(e: dict) -> str:
    if (e.get("action_taken") in ("refused", "refuse") or e.get("risk_level") == "REFUSED"
            or e.get("event_type") == "passthrough.forward_refused"):
        return "refusal"
    if isinstance(e.get("record_kind"), str):
        return e["record_kind"]
    if e.get("source") == "governance_push" or e.get("event_type") == "governance_detection_push":
        return "delivery_receipt"
    if e.get("source") in ("proxy", "passthrough", "interception"):
        return "detection"
    return "operational"


def _row_assessment(e: dict) -> dict:
    a = e.get("assessment")
    if "assessment" not in e:
        return assess(e, "risk_level")
    if not isinstance(a, dict):
        return _not_assessed("unknown")
    facts = {k: v for k, v in e.items() if k not in ("assessment", "record_kind", "read_time_fields")}
    if a.get("assessed") is True:
        return assess({**facts, "assessed": True, "not_assessed_reason": a.get("not_assessed_reason"),
                       "candidate_alert": a.get("candidate_alert")}, "risk_level")
    reason = a.get("not_assessed_reason")
    if a.get("assessed") is False and isinstance(reason, str) and reason.strip():
        cand = _candidate({"candidate_alert": a.get("candidate_alert"),
                           "risk_demoted_from": e.get("risk_demoted_from")}, e.get("risk_level"))
        if cand == "invalid":
            return _not_assessed("unknown")
        return _not_assessed("not_assessed", cand)
    return _not_assessed("unknown")


def audit_view(body) -> dict:
    """The audit log as an agent sees it: each row is built from a fixed list of typed fields
    (id, timestamp, model, record kind, verdict). Hashes are computed over this exported view."""
    events = body.get("events") if isinstance(body, dict) else None
    events = events if isinstance(events, list) else []
    rows, invalid = [], 0
    summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "NOT_ASSESSED": 0, "CANDIDATE_MEDIUM": 0, "CANDIDATE_HIGH": 0}
    for e in events:
        if not isinstance(e, dict):
            invalid += 1
            continue
        kind = _record_kind(e)
        row: dict = {"record_kind": kind}
        if _text(e.get("detection_id")) is not None:
            row["id"] = e["detection_id"]
        ts = e.get("timestamp")
        if isinstance(ts, (int, float)) and not isinstance(ts, bool):
            row["timestamp"] = ts
        elif _text(ts) is not None:
            row["timestamp"] = ts
        model = _text(e.get("model_id")) or _text(e.get("model"))
        if model:
            row["model"] = model
        if kind == "detection":
            row.update(_row_assessment(e))
            summary[row["risk_level"]] = summary.get(row["risk_level"], 0) + 1
            if row.get("candidate_alert") == "MEDIUM":
                summary["CANDIDATE_MEDIUM"] += 1
            if row.get("candidate_alert") == "HIGH":
                summary["CANDIDATE_HIGH"] += 1
        row["view_hash"] = _sha256(_canonical(row))
        rows.append(row)
    if invalid:
        summary["INVALID_ROWS"] = invalid
    out = {"events": rows, "summary": summary, "export_hash": _sha256(_canonical(rows))}
    err = _text(body.get("error")) if isinstance(body, dict) else None
    if err:
        out["error"] = err
    return out


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
