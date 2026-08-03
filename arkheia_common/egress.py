"""Shared outbound HTTP client factories for production egress."""
from __future__ import annotations

from typing import Any

import httpx


def _without_environment_proxy(kwargs: dict[str, Any]) -> dict[str, Any]:
    """
    Force outbound clients to ignore ambient proxy and CA environment settings.

    Credentialed calls pass API keys, bearer tokens, or signed headers. They must
    not inherit HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, SSL_CERT_FILE, or related
    process-level transport settings from the shell that launched this service.
    """
    options = dict(kwargs)
    if "trust_env" in options and options["trust_env"] is not False:
        raise ValueError("Arkheia egress clients do not allow trust_env=True")
    options["trust_env"] = False
    return options


def egress_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """Return an async httpx client with ambient environment trust disabled."""
    return httpx.AsyncClient(**_without_environment_proxy(kwargs))


def egress_client(**kwargs: Any) -> httpx.Client:
    """Return a sync httpx client with ambient environment trust disabled."""
    return httpx.Client(**_without_environment_proxy(kwargs))
