"""B-346: authorized IPv6 endpoints must survive actual HTTP request construction.

These cases run in the required ``unit-tests`` job (tests/test_*.py). All
addresses are literals; requests are constructed but never sent.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

import httpx
import pytest

from arkheia_common.hosted_authority import (
    DEFAULT_HOSTED_API_URL,
    HostedAuthorityError,
    authorize_hosted_base_url,
)


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    def unexpected_resolution(*args, **kwargs):
        raise AssertionError("literal URL tests must not resolve a hostname")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_resolution)


@pytest.mark.parametrize(
    ("configured", "expected", "allow_unsafe"),
    [
        ("http://[::1]", "http://[::1]", False),
        ("http://[::1]:80/", "http://[::1]", False),
        ("http://[::1]:8098", "http://[::1]:8098", False),
        ("https://[::1]", "https://[::1]", False),
        ("https://[::1]:443/", "https://[::1]", False),
        ("https://[::1]:8443/base/", "https://[::1]:8443/base", False),
        ("https://[fd00::1]:443/", "https://[fd00::1]", False),
        ("https://[fd00::1]:8443/base/", "https://[fd00::1]:8443/base", False),
        (
            "https://[::ffff:127.0.0.1]:8443",
            "https://[::ffff:127.0.0.1]:8443",
            False,
        ),
        ("https://[FD00::AB]:8443/", "https://[fd00::ab]:8443", False),
        ("https://[2606:4700::1111]", "https://[2606:4700::1111]", True),
    ],
)
def test_authorized_ipv6_urls_are_consumable_by_httpx(configured, expected, allow_unsafe):
    """TC-1: a no-op or port-specific bracket fix fails this exact URL matrix."""
    decision = authorize_hosted_base_url(configured, allow_unsafe=allow_unsafe)
    assert decision.base_url == expected
    expected_parts = urlsplit(expected)
    assert decision.origin == f"{expected_parts.scheme}://{expected_parts.netloc}"
    expected_address = ipaddress.ip_address(expected_parts.hostname)
    expected_port = expected_parts.port
    for normalized in (decision.base_url, decision.origin):
        parsed = httpx.URL(normalized)
        assert ipaddress.ip_address(parsed.host) == expected_address
        assert parsed.port == expected_port
    for endpoint in ("/v1/detect", "/v1/profile-key"):
        request = httpx.Request("POST", f"{decision.base_url}{endpoint}")
        assert ipaddress.ip_address(request.url.host) == expected_address
        assert request.url.port == expected_port
        assert request.url.path == expected_parts.path + endpoint
    assert decision.allow_unsafe is allow_unsafe
    assert decision.self_hosted is (not allow_unsafe)


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("http://127.0.0.1:80/", "http://127.0.0.1"),
        ("http://localhost:8098/base/", "http://localhost:8098/base"),
        (DEFAULT_HOSTED_API_URL + ":443/", DEFAULT_HOSTED_API_URL),
    ],
)
def test_non_ipv6_authority_rendering_is_unchanged(configured, expected):
    """TC-2: ordinary authorities and canonical ports remain positive controls."""
    decision = authorize_hosted_base_url(configured, allow_unsafe=False)
    assert decision.base_url == expected
    assert httpx.Request("POST", decision.base_url + "/v1/detect").url.host


@pytest.mark.parametrize(
    "configured",
    [
        "https://[2606:4700::1111]",
        "http://[fd00::1]:8098",
        "https://user:password@[::1]:8098",
        "http://[::1]:65536",
        "http://[::1]:not-a-port",
        "http://[::1]:8098?key=synthetic",
        "http://[::1]:8098#fragment",
    ],
)
def test_ipv6_rendering_does_not_relax_authorization(configured):
    """TC-3: rendering must retain existing policy refusals."""
    with pytest.raises(HostedAuthorityError):
        authorize_hosted_base_url(configured, allow_unsafe=False)
