"""
Provider API wrappers for the MCP Trust Server.

Each function makes a single call to an external or local model provider
and returns the raw response. Detection (arkheia_verify) is applied by
the MCP tool wrapper in server.py — NOT here.

This separation means providers.py is testable in isolation and the
detection layer is applied consistently regardless of which provider is called.

Environment variables read at call time (not import time) so the process
can start without all keys present and pick them up when they're set:
  XAI_API_KEY    — xAI / Grok
  GOOGLE_API_KEY — Google Gemini
  OLLAMA_BASE_URL — defaults to http://localhost:11434

Hook for enterprise upgrade:
  - Pull keys from a secrets manager rather than env vars
  - Add per-provider retry/circuit-breaker logic
  - Emit pre-call telemetry (tool_name, model, prompt_hash, timestamp)
    so the envelope is recorded even if the call fails
"""

import hashlib
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 60.0
_OLLAMA_TIMEOUT  = 120.0   # local models can be slow to load


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()


# Substrings that mean "your credentials were rejected", in the wording the providers
# actually use. Matched case-insensitively against the response body.
#
# This list exists because HTTP STATUS IS NOT ENOUGH. Both xAI and Google express an
# authentication failure as 400 Bad Request rather than 401, so status alone cannot
# separate "your key is dead" from "your request is malformed" — and on 2026-07-26 those
# two causes produced the identical `provider_error: http_400` from two different tools,
# which sent the investigation after a retired model id that was never the problem.
_AUTH_FAILURE_MARKERS = (
    "incorrect api key",       # xAI:    {"code":"invalid-argument","error":"Incorrect API key provided..."}
    "api key not valid",       # Google: {"error":{"message":"API key not valid...","status":"INVALID_ARGUMENT"}}
    "invalid api key",         # Together and most OpenAI-compatible surfaces
    "invalid_api_key",
    "api key expired",
    "unauthenticated",         # xAI with no Authorization header at all
    "no credentials",
    "unauthorized",
    "authentication",
)


def _classify_http_error(status_code: int, body_text: str) -> str:
    """
    Map a provider HTTP error onto a stable, ACTIONABLE error code.

    Returns "auth_failed" when the response is a credentials rejection — either by status
    (401/403, the honest encodings) or by body (400, the encoding xAI and Google actually
    use). Otherwise returns "http_<status>" unchanged.

    The body is READ but never returned: provider error bodies can echo request content and
    internal trace identifiers, and the caller only needs the classification. See
    mcp_server/tests/test_provider_defaults.py INV-4.

    Deliberately NOT a catch-all: a 400 whose body does not look like a credentials problem
    stays `http_400`. Relabelling every 400 as an auth failure would be a worse defect than
    the one this fixes — it would send an operator to rotate a perfectly good key.
    """
    if status_code in (401, 403):
        return "auth_failed"

    if status_code == 400 and body_text:
        haystack = body_text.lower()
        if any(marker in haystack for marker in _AUTH_FAILURE_MARKERS):
            return "auth_failed"

    return f"http_{status_code}"


def _err_response(model: str, prompt: str, error: str) -> dict:
    return {
        "response":    f"[provider_error: {error}]",
        "model":       model,
        "prompt_hash": _prompt_hash(prompt),
        "error":       error,
    }


# ---------------------------------------------------------------------------
# Grok (xAI) — OpenAI-compatible /v1/chat/completions
# ---------------------------------------------------------------------------

async def call_grok(
    prompt: str,
    model: str = "grok-4.20-non-reasoning",
    **kwargs: Any,
) -> dict:
    """
    Call xAI Grok chat completions API.

    DEFAULT MODEL — the grok-4.20 pair (David, 2026-07-26). The pair is
    `grok-4.20-non-reasoning` / `grok-4.20-reasoning`, deliberately chosen because both
    modes are priced identically ($1.25 in / $2.50 out per 1M tokens as reported), so
    switching mode does not change the cost model. Do NOT promote `grok-4.5` to the fleet
    default: it is the frontier tier at $2.00/$6.00 — 2.4x the output price — and is
    reserved rather than used for routine fleet work.

    Returns: {response, model, prompt_hash, error}
    """
    api_key = os.environ.get("XAI_API_KEY", "")
    if not api_key:
        return _err_response(model, prompt, "XAI_API_KEY not set")

    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            resp = await client.post(
                "https://api.x.ai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    **kwargs,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            response_text = data["choices"][0]["message"]["content"]
            return {
                "response":    response_text,
                "model":       model,
                "prompt_hash": _prompt_hash(prompt),
                "usage":       data.get("usage", {}),
                "error":       None,
            }
    except httpx.HTTPStatusError as e:
        reason = _classify_http_error(e.response.status_code, e.response.text)
        logger.error(
            "call_grok: HTTP %s (%s) for model=%s",
            e.response.status_code, reason, model,
        )
        return _err_response(model, prompt, reason)
    except Exception as e:
        logger.error("call_grok: unexpected error: %s", e)
        return _err_response(model, prompt, str(e))


# ---------------------------------------------------------------------------
# Gemini (Google) — generateContent REST API
# ---------------------------------------------------------------------------

async def call_gemini(
    prompt: str,
    model: str = "gemini-2.5-flash",
    max_output_tokens: int = 1000,
    **kwargs: Any,
) -> dict:
    """
    Call Google Gemini generateContent API.

    Note: gemini-2.5-flash and -pro are thinking models — they need
    max_output_tokens >= 1000 to produce content after thinking tokens.

    Returns: {response, model, prompt_hash, error}
    """
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if not api_key:
        return _err_response(model, prompt, "GOOGLE_API_KEY not set")

    url = (
        f"https://generativelanguage.googleapis.com/v1beta"
        f"/models/{model}:generateContent"
    )
    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            resp = await client.post(
                url,
                params={"key": api_key},
                json={
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "maxOutputTokens": max_output_tokens,
                        **kwargs,
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
            response_text = (
                data["candidates"][0]["content"]["parts"][0]["text"]
            )
            return {
                "response":    response_text,
                "model":       model,
                "prompt_hash": _prompt_hash(prompt),
                "usage":       data.get("usageMetadata", {}),
                "error":       None,
            }
    except (KeyError, IndexError) as e:
        logger.error("call_gemini: unexpected response shape: %s", e)
        return _err_response(model, prompt, f"parse_error: {e}")
    except httpx.HTTPStatusError as e:
        reason = _classify_http_error(e.response.status_code, e.response.text)
        logger.error(
            "call_gemini: HTTP %s (%s) for model=%s",
            e.response.status_code, reason, model,
        )
        return _err_response(model, prompt, reason)
    except Exception as e:
        logger.error("call_gemini: unexpected error: %s", e)
        return _err_response(model, prompt, str(e))


# ---------------------------------------------------------------------------
# Together AI — OpenAI-compatible, cloud inference
# ---------------------------------------------------------------------------

async def call_together(
    prompt: str,
    model: str = "moonshotai/Kimi-K2.5",
    max_tokens: int = 2048,
    **kwargs: Any,
) -> dict:
    """
    Call Together AI chat completions API (OpenAI-compatible).

    Default model is Kimi K2.5 — a thinking model that consumes
    100-500 tokens internally before producing output, so max_tokens
    must be >= 2048 to reliably get a response.

    Returns: {response, model, prompt_hash, usage, error}
    """
    api_key = os.environ.get("TOGETHER_API_KEY", "")
    if not api_key:
        return _err_response(model, prompt, "TOGETHER_API_KEY not set")

    try:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            resp = await client.post(
                "https://api.together.xyz/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": model,
                    "max_tokens": max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                    **kwargs,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            response_text = data["choices"][0]["message"]["content"]
            return {
                "response":    response_text,
                "model":       model,
                "prompt_hash": _prompt_hash(prompt),
                "usage":       data.get("usage", {}),
                "error":       None,
            }
    except httpx.HTTPStatusError as e:
        reason = _classify_http_error(e.response.status_code, e.response.text)
        logger.error(
            "call_together: HTTP %s (%s) for model=%s",
            e.response.status_code, reason, model,
        )
        return _err_response(model, prompt, reason)
    except Exception as e:
        logger.error("call_together: unexpected error: %s", e)
        return _err_response(model, prompt, str(e))


# ---------------------------------------------------------------------------
# Ollama — local inference, no network egress
# ---------------------------------------------------------------------------

async def call_ollama(
    prompt: str,
    model: str = "phi4:14b",
    **kwargs: Any,
) -> dict:
    """
    Call local Ollama model via /api/generate (non-streaming).

    OLLAMA_BASE_URL defaults to http://localhost:11434.
    No network egress — local eval only.

    Returns: {response, model, prompt_hash, eval_count, error}
    """
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")

    try:
        async with httpx.AsyncClient(timeout=_OLLAMA_TIMEOUT) as client:
            resp = await client.post(
                f"{base_url}/api/generate",
                json={
                    "model":  model,
                    "prompt": prompt,
                    "stream": False,
                    **kwargs,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "response":    data["response"],
                "model":       model,
                "prompt_hash": _prompt_hash(prompt),
                "eval_count":  data.get("eval_count"),
                "error":       None,
            }
    except httpx.ConnectError:
        logger.error("call_ollama: cannot connect to Ollama at %s", base_url)
        return _err_response(model, prompt, "ollama_unavailable")
    except httpx.HTTPStatusError as e:
        reason = _classify_http_error(e.response.status_code, e.response.text)
        logger.error(
            "call_ollama: HTTP %s (%s) for model=%s",
            e.response.status_code, reason, model,
        )
        return _err_response(model, prompt, reason)
    except Exception as e:
        logger.error("call_ollama: unexpected error: %s", e)
        return _err_response(model, prompt, str(e))
