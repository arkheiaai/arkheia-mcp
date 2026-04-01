"""
Tests for ProxyClient — local proxy + hosted API fallback.
"""

import pytest
import httpx
from unittest.mock import AsyncMock, patch, MagicMock

from mcp_server.proxy_client import ProxyClient, _unavailable


@pytest.fixture
def client_with_key():
    """ProxyClient with hosted API key configured."""
    return ProxyClient(
        base_url="http://localhost:8098",
        hosted_url="https://arkheia-proxy-production.up.railway.app",
        api_key="ak_live_testkey",
    )


@pytest.fixture
def client_no_key():
    """ProxyClient without hosted API key."""
    return ProxyClient(
        base_url="http://localhost:8098",
        api_key=None,
    )


class TestLocalProxy:
    """Tests for local proxy path."""

    @pytest.mark.asyncio
    async def test_local_success(self, client_with_key):
        """Local proxy returns result — no hosted fallback."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "risk_level": "LOW",
            "confidence": 0.85,
            "features_triggered": ["word_count"],
            "detection_id": "det_abc123",
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            result = await client_with_key.verify("prompt", "response text", "gpt-4o")

        assert result["risk_level"] == "LOW"
        assert result["confidence"] == 0.85

    @pytest.mark.asyncio
    async def test_local_connect_error_falls_back_to_hosted(self, client_with_key):
        """Local proxy down → falls back to hosted API."""
        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "MEDIUM",
            "confidence": 0.72,
            "detection_id": "det_hosted123",
            "features_triggered": ["structural_anomaly"],
            "detection_method": "profile_ensemble",
            "evidence_depth_limited": True,
        }
        hosted_response.raise_for_status = MagicMock()

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/detect/verify" in url:
                raise httpx.ConnectError("Connection refused")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "MEDIUM"
        assert result["confidence"] == 0.72
        assert result.get("source") == "hosted"
        assert call_count == 2  # local failed, then hosted

    @pytest.mark.asyncio
    async def test_local_down_no_api_key(self, client_no_key):
        """Local proxy down + no API key → no_detection_available."""
        async def mock_post(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_no_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "no_detection_available"


    @pytest.mark.asyncio
    async def test_local_timeout_falls_back_to_hosted(self, client_with_key):
        """Local proxy timeout → falls back to hosted API (not just ConnectError)."""
        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "LOW",
            "confidence": 0.80,
            "detection_id": "det_timeout_fb",
            "features_triggered": [],
            "detection_method": "structural",
            "evidence_depth_limited": False,
        }
        hosted_response.raise_for_status = MagicMock()

        call_count = 0
        async def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "/detect/verify" in url:
                raise httpx.TimeoutException("Read timed out")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "LOW"
        assert result.get("source") == "hosted"
        assert call_count == 2  # local timed out, then hosted

    @pytest.mark.asyncio
    async def test_circuit_breaker_flips_after_local_failure(self, client_with_key):
        """After local proxy fails, _local_available should flip to False."""
        assert client_with_key._local_available is True  # starts optimistic

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "risk": "LOW",
            "confidence": 0.5,
            "detection_id": "det_cb",
            "features_triggered": [],
            "detection_method": None,
            "evidence_depth_limited": True,
        }
        hosted_response.raise_for_status = MagicMock()

        async def mock_post(url, **kwargs):
            if "/detect/verify" in url:
                raise httpx.ConnectError("Connection refused")
            return hosted_response

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            await client_with_key.verify("prompt", "response", "gpt-4o")

        # Circuit breaker should now be open — local marked unavailable
        assert client_with_key._local_available is False, \
            "_local_available should be False after ConnectError fallback"

    @pytest.mark.asyncio
    async def test_hosted_generic_http_error(self, client_with_key):
        """Hosted API returns 500 → generic error, not auth or quota."""
        client_with_key._local_available = False

        response_500 = httpx.Response(500, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Server error", request=response_500.request, response=response_500)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "UNKNOWN"
        assert result["error"] == "hosted_http_error_500"


class TestHostedFallback:
    """Tests for hosted API fallback path."""

    @pytest.mark.asyncio
    async def test_hosted_maps_response_format(self, client_with_key):
        """Hosted response format is mapped to local format."""
        # Force local to fail
        client_with_key._local_available = False

        hosted_response = MagicMock()
        hosted_response.json.return_value = {
            "detection_id": "det_xyz",
            "risk": "HIGH",
            "confidence": 0.95,
            "evidence_depth_limited": False,
            "model": "gpt-4o",
            "detection_method": "profile_ensemble",
            "features_triggered": ["entropy_anomaly", "structural_anomaly"],
            "timestamp": "2026-03-28T00:00:00Z",
        }
        hosted_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=hosted_response):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["risk_level"] == "HIGH"  # mapped from "risk"
        assert result["confidence"] == 0.95
        assert result["detection_id"] == "det_xyz"
        assert result["features_triggered"] == ["entropy_anomaly", "structural_anomaly"]
        assert result["source"] == "hosted"

    @pytest.mark.asyncio
    async def test_hosted_auth_failure(self, client_with_key):
        """Hosted API returns 401 → auth error."""
        client_with_key._local_available = False

        response_401 = httpx.Response(401, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Unauthorized", request=response_401.request, response=response_401)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["error"] == "hosted_auth_failed"

    @pytest.mark.asyncio
    async def test_hosted_quota_exceeded(self, client_with_key):
        """Hosted API returns 429 → quota error."""
        client_with_key._local_available = False

        response_429 = httpx.Response(429, request=httpx.Request("POST", "https://arkheia-proxy-production.up.railway.app/v1/detect"))

        async def mock_post(url, **kwargs):
            raise httpx.HTTPStatusError("Rate limited", request=response_429.request, response=response_429)

        with patch("httpx.AsyncClient.post", side_effect=mock_post):
            result = await client_with_key.verify("prompt", "response", "gpt-4o")

        assert result["error"] == "hosted_quota_exceeded"


class TestAuditLog:
    """Tests for audit log (local only)."""

    @pytest.mark.asyncio
    async def test_audit_log_success(self, client_with_key):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "events": [{"risk_level": "LOW"}],
            "summary": {"LOW": 1, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
        }
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            result = await client_with_key.get_audit_log()

        assert len(result["events"]) == 1

    @pytest.mark.asyncio
    async def test_audit_log_unavailable(self, client_with_key):
        async def mock_get(url, **kwargs):
            raise httpx.ConnectError("Connection refused")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            result = await client_with_key.get_audit_log()

        assert result["events"] == []
        assert result["error"] == "proxy_unavailable"


class TestNeverRaises:
    """Contract: ProxyClient methods never raise."""

    @pytest.mark.asyncio
    async def test_verify_never_raises(self, client_with_key):
        async def explode(*args, **kwargs):
            raise RuntimeError("Catastrophic failure")

        with patch("httpx.AsyncClient.post", side_effect=explode):
            result = await client_with_key.verify("p", "r", "m")

        assert result["risk_level"] == "UNKNOWN"
        assert "error" in result

    @pytest.mark.asyncio
    async def test_audit_never_raises(self, client_with_key):
        async def explode(*args, **kwargs):
            raise RuntimeError("Catastrophic failure")

        with patch("httpx.AsyncClient.get", side_effect=explode):
            result = await client_with_key.get_audit_log()

        assert result["events"] == []
        assert "error" in result
