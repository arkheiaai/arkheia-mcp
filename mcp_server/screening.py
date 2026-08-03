"""
Was this response actually SCREENED? — the one question a detection verdict must answer
before any of its other fields mean anything.

WHY THIS MODULE EXISTS.

The fleet default for `run_grok` is `grok-4.20-non-reasoning` (David, 2026-07-26). There is
no detection profile for that model version, and `ProfileRouter._resolve_grok` deliberately
returns None rather than borrowing the grok-4 fingerprint — because
`"grok-4.20-non-reasoning".startswith("grok-4")` is True, and the naive resolver it replaced
silently scored 4.20 traffic against a DIFFERENT model's profile. An honest UNKNOWN is
strictly better than a borrowed fingerprint, so that behaviour stays.

But the honest UNKNOWN was arriving QUIETLY. `run_grok` returned:

    {"response": "...", "model": "grok-4.20-non-reasoning", "error": None,
     "arkheia": {"risk_level": "UNKNOWN", ..., "error": "no_profile_for_model"}}

— a successful-looking tool result with a top-level `error: None` and the "nothing was
measured" fact buried one level down, next to numeric fields (`confidence: 0.0`,
`features_triggered: []`) that a reader skims as reassuring. The product's core promise is
that inference is screened; a default path that is NOT screened must be impossible to
mistake for one that is.

THE RULE THIS ENCODES: the only honest buckets are observed-good, observed-bad, and
NOT-OBSERVED, and the third must be visible in the verdict rather than folded into either of
the first two (DONE.md floor invariant 9(d)). A verdict that errored, or that never had a
profile to run, observed nothing.

DELIBERATELY NARROW, so it does not cry wolf: only an EXPLICIT evidence-limitation counts.
Inferring "limited" from an absent field would put a warning on every single LOW, and a
warning that fires always is read as never.
"""

from __future__ import annotations

from typing import Optional

# Risk bands that mean a profile ran and reached a verdict. Anything else — UNKNOWN, an
# empty string, a missing key — means detection did not produce an assessment.
SCREENED_RISK_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})

# Plain-English gloss + what would clear it, per reason code the detection path can emit.
# Keys are the `error` values produced by proxy/detection/engine.py, proxy/endpoints/detect.py
# and mcp_server/proxy_client.py::_unavailable.
_REASONS: dict[str, tuple[str, str]] = {
    "no_profile_for_model": (
        "no detection profile exists for this model id, so nothing about this response was "
        "measured",
        "a characterisation run for this model id (labelled corpus, real model calls, "
        "held-out validation), or use a model id that already has a profile",
    ),
    "no_computable_features": (
        "a profile exists for this model but none of its features could be computed from "
        "this response",
        "a longer response, or a profile whose features do not require telemetry this path "
        "cannot supply",
    ),
    "engine_unavailable": (
        "the detection engine was not running",
        "start the detection engine and re-run",
    ),
    "engine_error": (
        "the detection engine raised while scoring this response",
        "check the proxy logs for the engine error and re-run",
    ),
    "response_empty": (
        "there was no response text to score",
        "nothing — an empty response cannot be assessed",
    ),
    "model_id_missing": (
        "no model id was supplied, so no profile could be selected",
        "pass the model id used for the call",
    ),
}

_GENERIC_REASON = (
    "detection did not complete",
    "restore the detection path and re-run, or verify by other means",
)


def _band(risk: Optional[dict]) -> str:
    if not risk:
        return ""
    return str(risk.get("risk_level") or "").strip().upper()


def is_screened(risk: Optional[dict]) -> bool:
    """
    True only when detection produced an assessment for this response.

    False for UNKNOWN, for a missing/blank band, for no verdict at all, AND for a verdict
    that carries an `error` alongside a band — `ProxyClient._unavailable()` and the hosted
    mapper both emit a band next to an error, and a scoring run that errored did not observe
    the thing it was meant to observe.
    """
    if not risk:
        return False
    if risk.get("error"):
        return False
    return _band(risk) in SCREENED_RISK_LEVELS


def unscreened_reason(risk: Optional[dict]) -> Optional[str]:
    """The machine-readable reason code when not screened, else None."""
    if is_screened(risk):
        return None
    if not risk:
        return "no_detection_result"
    return str(risk.get("error") or "") or f"risk_level_{_band(risk) or 'absent'}"


def _evidence_limited(risk: Optional[dict]) -> bool:
    """
    True only when the verdict EXPLICITLY declares limited evidence depth AND no feature
    actually fired — the `○ LOW · couldn't-assess` case check_signal.py distinguishes from
    `✓ LOW · assessed`. An ABSENT field is not evidence of a limitation (see module
    docstring: fail-loud must not become cry-wolf).
    """
    if not risk:
        return False
    if risk.get("evidence_depth_limited") is not True:
        return False
    return not (risk.get("features_triggered") or [])


def unscreened_warning(model: str, risk: Optional[dict]) -> Optional[str]:
    """
    A plain-English warning for a caller, or None when the verdict is a real assessment.

    Carries the model id, the reason code and what would clear it — never the prompt, the
    response, the detection id, or the detector's internal mechanism.
    """
    if not is_screened(risk):
        reason = unscreened_reason(risk) or "unknown"
        gloss, clears = _REASONS.get(reason, _GENERIC_REASON)
        return (
            f"NOT SCREENED for fabrication: {gloss} (model={model!r}, reason={reason}). "
            "This is a couldn't-assess, not an all-clear — do not read it as LOW or as "
            "assessed. Verify material claims against primary sources before relying on "
            f"them. What would clear it: {clears}."
        )

    if _evidence_limited(risk):
        band = _band(risk)
        return (
            f"{band} but couldn't-assess: the profile for {model!r} ran and no feature "
            "fired, on explicitly limited evidence depth. Treat as weakly evidenced rather "
            "than as a clean assessment, and verify material claims. What would clear it: a "
            "richer characterisation of this model, or a response long enough to score."
        )

    return None


def annotate_screening(provider_result: dict, risk: Optional[dict], model: str) -> dict:
    """
    Return a NEW dict: the provider result, the detection verdict under `arkheia`, plus the
    top-level screening signal. Never mutates either input, and never rewrites the verdict —
    it only adds the fact of whether that verdict is an assessment.

    Added keys:
      arkheia_screened          bool     — False means this response was NOT assessed
      arkheia_unscreened_reason str|None — machine-readable reason code
      arkheia_warning           str|None — plain English + what would clear it
    """
    return {
        **provider_result,
        "arkheia": risk,
        "arkheia_screened": is_screened(risk),
        "arkheia_unscreened_reason": unscreened_reason(risk),
        "arkheia_warning": unscreened_warning(model, risk),
    }
