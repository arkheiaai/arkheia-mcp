"""
Authority policy for hosted Arkheia API egress.

Both hosted detection verification and hosted profile-key loading send
``X-Arkheia-Key``. This module is the shared chokepoint that decides whether a
configured hosted URL is allowed to receive that header.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit


DEFAULT_HOSTED_API_URL = "https://arkheia-proxy-production.up.railway.app"
ALLOW_UNSAFE_HOSTED_URL_ENV = "ARKHEIA_ALLOW_UNSAFE_HOSTED_URL"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_SELF_HOSTED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)


@dataclass(frozen=True)
class HostedAuthorityDecision:
    """The normalized hosted base URL and whether unsafe opt-in was used."""

    base_url: str
    origin: str
    allow_unsafe: bool = False
    self_hosted: bool = False


class HostedAuthorityError(ValueError):
    """Raised when a hosted URL is not authorized to receive Arkheia API keys."""


def allow_unsafe_hosted_url_from_env() -> bool:
    """Return True only for an explicit unsafe-hosted-URL opt-in."""
    return os.environ.get(ALLOW_UNSAFE_HOSTED_URL_ENV, "").strip().lower() in _TRUE_VALUES


def authorize_hosted_base_url(
    hosted_url: Optional[str],
    *,
    allow_unsafe: Optional[bool] = None,
) -> HostedAuthorityDecision:
    """
    Validate and normalize a hosted API base URL before key-bearing egress.

    Default policy is deliberately narrow: HTTPS to the production Arkheia
    authority, plus local/private self-hosted authorities. Public custom
    authorities are supported only when the caller, or the environment,
    explicitly opts into unsafe hosted URLs.
    """
    raw = (hosted_url or DEFAULT_HOSTED_API_URL).strip()
    if not raw:
        raw = DEFAULT_HOSTED_API_URL

    parsed = urlsplit(raw)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"} or not host:
        raise HostedAuthorityError("hosted URL must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise HostedAuthorityError("hosted URL must not contain userinfo")
    if parsed.query or parsed.fragment:
        raise HostedAuthorityError("hosted URL must not contain query or fragment")

    try:
        port = parsed.port
    except ValueError as exc:
        raise HostedAuthorityError("hosted URL contains an invalid port") from exc

    normalized_netloc = host
    if port is not None and port != _default_port(scheme):
        normalized_netloc = f"{normalized_netloc}:{port}"
    path = parsed.path.rstrip("/")
    normalized_base = urlunsplit((scheme, normalized_netloc, path, "", ""))
    origin = urlunsplit((scheme, normalized_netloc, "", "", ""))

    opted_in = allow_unsafe_hosted_url_from_env() if allow_unsafe is None else allow_unsafe
    needs_self_hosted_check = not opted_in and origin != DEFAULT_HOSTED_API_URL
    self_hosted = _is_self_hosted_host(host) if needs_self_hosted_check else False
    needs_loopback_check = not opted_in and scheme != "https"
    loopback = _is_loopback_host(host) if needs_loopback_check else False
    if not opted_in and origin != DEFAULT_HOSTED_API_URL and not self_hosted:
        raise HostedAuthorityError(
            "hosted URL is not the approved Arkheia production authority; "
            f"set {ALLOW_UNSAFE_HOSTED_URL_ENV}=1 only for trusted custom endpoints"
        )
    if not opted_in and scheme != "https" and not loopback:
        raise HostedAuthorityError("hosted URL must use HTTPS unless it is loopback-local")

    return HostedAuthorityDecision(
        base_url=normalized_base,
        origin=origin,
        allow_unsafe=bool(opted_in),
        self_hosted=self_hosted,
    )


def _default_port(scheme: str) -> int:
    return 80 if scheme == "http" else 443


def _is_self_hosted_host(host: str) -> bool:
    addresses = _resolve_host_addresses(host)
    return bool(addresses) and all(_is_self_hosted_address(addr) for addr in addresses)


def _resolve_host_addresses(host: str) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    if host == "localhost" or host.endswith(".localhost"):
        return (ipaddress.ip_address("127.0.0.1"),)
    try:
        return (ipaddress.ip_address(host),)
    except ValueError:
        pass

    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return ()

    for _family, _socktype, _proto, _canonname, sockaddr in infos:
        if not sockaddr:
            continue
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue
    return tuple(addresses)


def _is_self_hosted_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return any(addr in network for network in _SELF_HOSTED_NETWORKS)


def _is_loopback_host(host: str) -> bool:
    addresses = _resolve_host_addresses(host)
    return bool(addresses) and all(_is_loopback_address(addr) for addr in addresses)


def _is_loopback_address(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_loopback


def hosted_key_egress_client(*, timeout: float) -> Any:
    """
    Return the only httpx client production hosted-key egress should use.

    ``trust_env=False`` prevents HTTP(S)_PROXY and ALL_PROXY from receiving
    ``X-Arkheia-Key`` on key-bearing hosted requests.
    """
    import httpx

    return httpx.AsyncClient(timeout=timeout, trust_env=False)
