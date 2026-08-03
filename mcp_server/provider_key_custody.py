"""Provider API-key custody boundary.

This module is the only production code allowed to read provider secret
environment variables directly. It captures those secrets at import time and
removes them from ambient ``os.environ`` so unrelated process code cannot copy
or forward them later. Provider transports call `provider_api_key()` so the
custody floor has a single module to audit and future secret-manager wiring has
one place to replace.
"""
from __future__ import annotations

import os
from collections.abc import Mapping

_PROVIDER_ENV_BY_PROVIDER = {
    "xai": "XAI_API_KEY",
    "google": "GOOGLE_API_KEY",
    "together": "TOGETHER_API_KEY",
}

_PROVIDER_API_KEYS = {
    "xai": os.environ.pop("XAI_API_KEY", ""),
    "google": os.environ.pop("GOOGLE_API_KEY", ""),
    "together": os.environ.pop("TOGETHER_API_KEY", ""),
}


def _provider_env_name(provider: str) -> str:
    try:
        return _PROVIDER_ENV_BY_PROVIDER[provider]
    except KeyError:
        raise ValueError(f"unknown provider: {provider}") from None


def provider_api_key(provider: str, environ: Mapping[str, str] | None = None) -> str:
    env_name = _provider_env_name(provider)
    if environ is not None:
        return environ.get(env_name, "")
    return _PROVIDER_API_KEYS[provider]
