"""
F2 — provider wrappers: the fleet's default model ids, and telling a dead KEY from a dead MODEL.

Runs in the REQUIRED `unit-tests` context (.github/workflows/unit-tests.yml, job `unit`,
`pytest ... mcp_server/tests ...` on push+pull_request to master). Before this file,
mcp_server/tools/providers.py had NO tests at all — every wrapper, every default and every
error path was uncovered.

WHY THESE TESTS EXIST — the incident that produced them:

  `run_grok` was returning `provider_error: http_400` and the reported diagnosis was that the
  default model id `grok-4-fast-non-reasoning` had been retired. That diagnosis could not be
  confirmed, and the reason it could not be confirmed is the defect this file fixes:

      MEASURED against api.x.ai on 2026-07-26, with the only xAI key present on this machine
      (identical in ~/.claude.json and master.env):

        POST /v1/chat/completions  {"model": "grok-4.20-non-reasoning", ...}  -> HTTP 400
        POST /v1/chat/completions  {"model": "grok-4-fast-non-reasoning"}     -> HTTP 400
        POST /v1/chat/completions  {"model": "grok-4.5", ...}                 -> HTTP 400
        GET  /v1/language-models                                              -> HTTP 400

        every one with the SAME body:
          {"code":"invalid-argument","error":"Incorrect API key provided."}

        CONTROL, a deliberately fake key:  -> HTTP 400, byte-identical body.
        CONTROL, no Authorization header:  -> HTTP 401, {"code":"unauthenticated:..."}

  So the 400 was an AUTHENTICATION failure, not a retired model — and the wrapper could not say
  so, because it collapsed every non-2xx into `http_<status>`. A dead key and a dead model id
  were indistinguishable at the only surface an operator sees. Google does the same thing
  (400 + "API key not valid" rather than 401), which is how the same symptom arrived from two
  unrelated causes on the same day.

INV-1  A model id default is not silently a retired one (asserted structurally, see also
       tests/test_retired_model_ids_floor.py which runs in the deterministic floor tier).
INV-2  An authentication failure is reported AS an authentication failure, whatever HTTP status
       the provider chose to express it with.
INV-3  A genuine bad request is still reported as a bad request — the classifier must
       DISCRIMINATE, not relabel everything as auth.
INV-4  The classification never echoes the response body or the API key into the error string.

ASSERTION DISCIPLINE: INV-2 and INV-3 are the two directions of one claim and are always tested
as a pair. A test that only proved "auth 400 -> auth_failed" would pass against a classifier
that returns "auth_failed" for every 400 ever received, which would be a worse defect than the
one being fixed — it would mislabel a real bad request as a credentials problem.
"""

from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from mcp_server.tools import providers
from mcp_server.tools.providers import (
    _classify_http_error,
    call_gemini,
    call_grok,
    call_together,
)

XAI_URL = "https://api.x.ai/v1/chat/completions"
TOGETHER_URL = "https://api.together.xyz/v1/chat/completions"


def _use_provider_key(monkeypatch, provider: str, key: str) -> None:
    monkeypatch.setattr(
        providers,
        "provider_api_key",
        lambda requested: key if requested == provider else "",
    )

# The exact bodies observed from the live APIs — not paraphrases.
XAI_BAD_KEY_BODY = {
    "code": "invalid-argument",
    "error": "Incorrect API key provided. You can obtain an API key from https://console.x.ai.",
}
XAI_NO_CREDS_BODY = {
    "code": "unauthenticated:no-credentials",
    "error": "No credentials presented.",
}
GOOGLE_BAD_KEY_BODY = {
    "error": {
        "code": 400,
        "message": "API key not valid. Please pass a valid API key.",
        "status": "INVALID_ARGUMENT",
    }
}


# ---------------------------------------------------------------------------
# INV-1 — the fleet defaults
# ---------------------------------------------------------------------------

class TestFleetDefaults:
    """
    David's instruction was to move the fleet onto the grok-4.20 pair. These pin the ids so a
    later edit cannot quietly drift them, and so the pair stays a PAIR — matched pricing across
    both modes is the whole point of choosing it, and a half-migration would break that.

    NOTE ON WHAT IS AND IS NOT PROVED HERE: these assert the ids the code uses. They do NOT
    assert that those ids exist at xAI — that is unverifiable from this machine, whose only key
    is rejected (see module docstring), and a unit test must not pretend to know it.
    """

    def test_call_grok_defaults_to_the_420_non_reasoning_model(self):
        assert (
            inspect.signature(call_grok).parameters["model"].default
            == "grok-4.20-non-reasoning"
        )

    def test_the_mcp_tool_default_matches_the_library_default(self):
        """
        Two defaults exist for the same decision — the library function and the MCP tool
        signature the agent actually calls. If they disagree, the "fleet default" is whichever
        entry point the caller happened to use.
        """
        from mcp_server import server as server_module

        tool_default = (
            inspect.signature(server_module.run_grok).parameters["model"].default
        )
        lib_default = inspect.signature(call_grok).parameters["model"].default
        assert tool_default == lib_default == "grok-4.20-non-reasoning"

    def test_no_wrapper_still_defaults_to_a_retired_grok_id(self):
        """
        Positive-control shaped: rather than asserting the absence of one string, enumerate
        every provider wrapper's default and check it against the retired set. A new wrapper
        added later is covered automatically.
        """
        retired = {
            "grok-4-fast-non-reasoning",
            "grok-4-fast-reasoning",
            "grok-3",
            "grok-3-mini",
            "grok-3-mini-fast",
        }
        checked = 0
        for name, fn in vars(providers).items():
            if not name.startswith("call_"):
                continue
            param = inspect.signature(fn).parameters.get("model")
            if param is None:
                continue
            checked += 1
            assert param.default not in retired, f"{name} defaults to retired id {param.default!r}"

        assert checked >= 4, f"expected to inspect >=4 provider wrappers, inspected {checked}"


# ---------------------------------------------------------------------------
# INV-2 / INV-3 — auth failure vs bad request, both directions
# ---------------------------------------------------------------------------

class TestAuthFailureIsDistinguishedFromBadRequest:

    @pytest.mark.parametrize(
        "status, body",
        [
            (400, XAI_BAD_KEY_BODY),        # xAI's actual shape: auth failure as a 400
            (401, XAI_NO_CREDS_BODY),       # xAI with no credentials at all
            (400, GOOGLE_BAD_KEY_BODY),     # Google's actual shape: auth failure as a 400
            (403, {"error": "Forbidden"}),
        ],
    )
    def test_authentication_failures_classify_as_auth_failed(self, status, body):
        import json

        assert _classify_http_error(status, json.dumps(body)) == "auth_failed"

    @pytest.mark.parametrize(
        "status, body, expected",
        [
            # A REAL bad request — this is the case the fix must not swallow.
            (400, '{"code":"invalid-argument","error":"Model xyz does not exist"}', "http_400"),
            (404, '{"error":"not found"}', "http_404"),
            (429, '{"error":"rate limit exceeded"}', "http_429"),
            (500, '{"error":"internal"}', "http_500"),
            (503, "", "http_503"),
        ],
    )
    def test_non_auth_failures_keep_their_status_code(self, status, body, expected):
        """
        The other direction of INV-2. Without this, `return "auth_failed"` for every error
        would pass the test above and destroy the signal it was written to create.
        """
        assert _classify_http_error(status, body) == expected

    def test_a_400_is_classified_by_its_body_not_its_status(self):
        """
        The crux, stated as one assertion pair: two responses with the IDENTICAL status code
        and different bodies must classify differently. This is what makes the fix real —
        status alone cannot separate these, which is why the original code could not.
        """
        import json

        auth = _classify_http_error(400, json.dumps(XAI_BAD_KEY_BODY))
        bad_req = _classify_http_error(400, '{"error":"Model xyz does not exist"}')

        assert auth == "auth_failed"
        assert bad_req == "http_400"
        assert auth != bad_req


# ---------------------------------------------------------------------------
# INV-2 end to end, through the real wrappers
# ---------------------------------------------------------------------------

class TestWrappersReportAuthFailure:

    @respx.mock
    @pytest.mark.asyncio
    async def test_grok_reports_auth_failed_on_the_observed_xai_body(self, monkeypatch):
        _use_provider_key(monkeypatch, "xai", "xai-test-key")
        respx.post(XAI_URL).mock(
            return_value=httpx.Response(400, json=XAI_BAD_KEY_BODY)
        )

        result = await call_grok("hi")

        assert result["error"] == "auth_failed"
        assert result["response"] == "[provider_error: auth_failed]"

    @respx.mock
    @pytest.mark.asyncio
    async def test_grok_still_reports_http_400_for_a_genuine_bad_request(self, monkeypatch):
        """Positive control paired with the test above, through the same code path."""
        _use_provider_key(monkeypatch, "xai", "xai-test-key")
        respx.post(XAI_URL).mock(
            return_value=httpx.Response(
                400, json={"code": "invalid-argument", "error": "Model xyz does not exist"}
            )
        )

        result = await call_grok("hi")

        assert result["error"] == "http_400"

    @respx.mock
    @pytest.mark.asyncio
    async def test_gemini_reports_auth_failed_on_googles_400(self, monkeypatch):
        """
        The Gemini key on this machine is genuinely invalid and is David's to rotate, so the
        wrapper's behaviour against that body is pinned here rather than live. Google returns
        400 for an invalid key instead of 401 — the reason a dead Gemini key and a dead grok
        model id presented identically.
        """
        _use_provider_key(monkeypatch, "google", "not-a-real-key")
        respx.post(
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        ).mock(return_value=httpx.Response(400, json=GOOGLE_BAD_KEY_BODY))

        result = await call_gemini("hi")

        assert result["error"] == "auth_failed"

    @respx.mock
    @pytest.mark.asyncio
    async def test_together_reports_auth_failed_on_401(self, monkeypatch):
        _use_provider_key(monkeypatch, "together", "not-a-real-key")
        respx.post(TOGETHER_URL).mock(
            return_value=httpx.Response(401, json={"error": "Invalid API key provided"})
        )

        result = await call_together("hi")

        assert result["error"] == "auth_failed"

    @respx.mock
    @pytest.mark.asyncio
    async def test_a_missing_key_is_still_distinct_from_a_rejected_one(self, monkeypatch):
        """
        Three states, three distinct reports: no key, rejected key, bad request. Collapsing
        "not set" into "auth_failed" would lose the one diagnosis an operator can act on
        immediately.
        """
        monkeypatch.delenv("XAI_API_KEY", raising=False)
        result = await call_grok("hi")
        assert result["error"] == "XAI_API_KEY not set"


# ---------------------------------------------------------------------------
# INV-4 — the classification must not leak
# ---------------------------------------------------------------------------

class TestErrorsDoNotLeak:

    @respx.mock
    @pytest.mark.asyncio
    async def test_the_api_key_never_appears_in_the_returned_error(self, monkeypatch):
        secret = "xai-SUPERSECRET-abcdef123456"
        _use_provider_key(monkeypatch, "xai", secret)
        respx.post(XAI_URL).mock(
            return_value=httpx.Response(400, json=XAI_BAD_KEY_BODY)
        )

        result = await call_grok("hi")

        blob = repr(result)
        assert secret not in blob
        assert "SUPERSECRET" not in blob

    @respx.mock
    @pytest.mark.asyncio
    async def test_the_raw_provider_body_is_not_echoed_into_the_error(self, monkeypatch):
        """
        The classifier reads the body, so it must not then hand the body back. Provider error
        bodies can carry request echoes and internal identifiers.
        """
        _use_provider_key(monkeypatch, "xai", "xai-test-key")
        respx.post(XAI_URL).mock(
            return_value=httpx.Response(
                400,
                json={"code": "invalid-argument", "error": "Incorrect API key provided.",
                      "internal_trace": "trace-id-9f3ab-INTERNAL"},
            )
        )

        result = await call_grok("hi")

        assert "INTERNAL" not in repr(result)
        assert result["error"] == "auth_failed"
