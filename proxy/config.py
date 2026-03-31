"""
Arkheia Enterprise Proxy -- configuration.

Structural config loads from arkheia-proxy.yaml (no secrets).
The only secret (ARKHEIA_API_KEY) is read from OS environment only.
No secrets are ever written to any file.
"""
import os
import logging
from pathlib import Path
from typing import Optional

import yaml
from pydantic import SecretStr
from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# YAML config loader
# ---------------------------------------------------------------------------

def _load_yaml(config_path: Optional[str] = None) -> dict:
    """Load YAML config file. Returns empty dict if not found (use defaults)."""
    if config_path:
        candidates = [Path(config_path)]
    else:
        candidates = [
            Path(os.environ.get("ARKHEIA_CONFIG", "")),
            Path(__file__).parent / "arkheia-proxy.yaml",
            Path.cwd() / "arkheia-proxy.yaml",
            Path("/etc/arkheia/arkheia-proxy.yaml"),
        ]
    for path in candidates:
        if path and str(path) and path.is_file():
            with open(path) as f:
                data = yaml.safe_load(f)
            logger.info("Loaded config from: %s", path)
            return data or {}
    logger.warning("No arkheia-proxy.yaml found -- using built-in defaults")
    return {}


_yaml = _load_yaml()


# ---------------------------------------------------------------------------
# Settings sections (plain objects, not Pydantic -- no secrets here)
# ---------------------------------------------------------------------------

class _ProxySettings:
    host: str = os.environ.get(
        "ARKHEIA_PROXY_HOST",
        _yaml.get("proxy", {}).get("host", "0.0.0.0"),  # nosec B104 — intentional bind-all for container/service use
    )
    port: int = int(os.environ.get(
        "ARKHEIA_PROXY_PORT",
        _yaml.get("proxy", {}).get("port", 8098),  # 8098 = Enterprise Proxy (8099 = Local Proxy)
    ))
    log_level: str = _yaml.get("proxy", {}).get("log_level", "INFO")


class _DetectionSettings:
    # Allow env var override for local dev (point at existing proxy profiles)
    profile_dir: str = os.environ.get(
        "ARKHEIA_PROFILES_DIR",
        _yaml.get("detection", {}).get(
            "profile_dir",
            str(Path(__file__).parent.parent / "profiles"),
        ),
    )
    high_risk_action: str = _yaml.get("detection", {}).get("high_risk_action", "warn")
    unknown_action: str = _yaml.get("detection", {}).get("unknown_action", "pass")
    upstream_url: str = os.environ.get(
        "ARKHEIA_UPSTREAM_URL",
        _yaml.get("detection", {}).get("upstream_url", ""),
    )
    interception_enabled: bool = str(
        os.environ.get(
            "ARKHEIA_INTERCEPTION_ENABLED",
            str(_yaml.get("detection", {}).get("interception_enabled", False)),
        )
    ).lower() in ("true", "1", "yes")


class _RegistrySettings:
    url: str = _yaml.get("registry", {}).get("url", "https://registry.arkheia.ai")
    pull_on_startup: bool = _yaml.get("registry", {}).get("pull_on_startup", False)
    pull_interval_hours: int = _yaml.get("registry", {}).get("pull_interval_hours", 24)
    pin_major_version: Optional[int] = _yaml.get("registry", {}).get("pin_major_version")


class _AuditSettings:
    log_path: str = os.environ.get(
        "ARKHEIA_AUDIT_LOG",
        _yaml.get("audit", {}).get(
            "log_path",
            str(Path(__file__).parent.parent / "audit.jsonl"),
        ),
    )
    retention_days: int = _yaml.get("audit", {}).get("retention_days", 365)
    include_prompt_hash: bool = _yaml.get("audit", {}).get("include_prompt_hash", True)


class _MCPSettings:
    enabled: bool = _yaml.get("mcp_server", {}).get("enabled", True)
    port: int = _yaml.get("mcp_server", {}).get("port", 8100)
    proxy_url: str = os.environ.get(
        "ARKHEIA_PROXY_URL",
        _yaml.get("mcp_server", {}).get("proxy_url", "http://localhost:8098"),
    )


# ---------------------------------------------------------------------------
# Secrets (Pydantic BaseSettings -- reads from OS env only)
# ---------------------------------------------------------------------------

class _Secrets(BaseSettings):
    arkheia_api_key: SecretStr = SecretStr("")

    model_config = {
        "env_file": None,   # never load from .env file
        "env_prefix": "",
    }


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

class Settings:
    proxy = _ProxySettings()
    detection = _DetectionSettings()
    registry = _RegistrySettings()
    audit = _AuditSettings()
    mcp = _MCPSettings()
    _secrets = _Secrets()

    @property
    def arkheia_api_key(self) -> SecretStr:
        return self._secrets.arkheia_api_key


settings = Settings()
