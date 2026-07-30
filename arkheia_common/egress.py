"""Shared outbound HTTP client factories for production egress."""
from __future__ import annotations

from typing import Any

import httpx


def egress_async_client(**kwargs: Any) -> httpx.AsyncClient:
    """
    Return an ``httpx.AsyncClient`` for outbound production egress.

    ``trust_env=False`` prevents ambient HTTP(S)_PROXY / ALL_PROXY environment
    variables from silently interposing on credentialed provider and Arkheia
    service calls.
    """
    if "trust_env" in kwargs and kwargs["trust_env"] is not False:
        raise ValueError("egress_async_client does not allow trust_env=True")
    kwargs["trust_env"] = False
    return httpx.AsyncClient(**kwargs)
