"""Provider API-key custody boundary.

This module is the only production code allowed to read provider secret
environment variables directly. Provider transports call `provider_api_key()` so
the custody floor has a single module to audit and future secret-manager wiring
has one place to replace.
"""
from __future__ import annotations

import os
from collections.abc import Mapping


def provider_api_key(provider: str, environ: Mapping[str, str] | None = None) -> str:
    if environ is None:
        if provider == "xai":
            return os.environ.get("XAI_API_KEY", "")
        if provider == "google":
            return os.environ.get("GOOGLE_API_KEY", "")
        if provider == "together":
            return os.environ.get("TOGETHER_API_KEY", "")
        raise ValueError(f"unknown provider: {provider}")

    source = environ
    if provider == "xai":
        return source.get("XAI_API_KEY", "")
    if provider == "google":
        return source.get("GOOGLE_API_KEY", "")
    if provider == "together":
        return source.get("TOGETHER_API_KEY", "")
    raise ValueError(f"unknown provider: {provider}")
