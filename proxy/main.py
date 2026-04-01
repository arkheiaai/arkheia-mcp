"""
Arkheia Enterprise Proxy -- FastAPI entry point.

Instantiates and wires all components:
  - ProfileRouter (loads profiles at startup)
  - DetectionEngine (wraps feature extraction)
  - AuditWriter (async JSONL log)
  - RegistryClient (profile registry pull, if API key set)
  - Endpoints: /detect/verify, /audit/log, /admin/*
"""

# Load .env BEFORE any proxy.* imports so env vars are available.
import os
import sys
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv(usecwd=True), override=True)

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI

from proxy.config import settings
from proxy.router.profile_router import ProfileRouter
from proxy.detection.engine import DetectionEngine
from proxy.audit.writer import AuditWriter
from proxy.registry.client import RegistryClient
from proxy.registry.validator import ProfileValidator
from proxy.endpoints.detect import router as detect_router
from proxy.endpoints.admin import router as admin_router
from proxy.endpoints.audit import router as audit_router
from proxy.endpoints.passthrough import router as passthrough_router
from proxy.endpoints.auth_routes import router as auth_router

logging.basicConfig(
    level=getattr(logging, settings.proxy.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ----------------------------------------------------------------
    # STARTUP
    # ----------------------------------------------------------------
    # Validate JWT_SECRET at startup (fails fast with clear error, not at import time)
    from proxy.auth import _get_jwt_secret
    _get_jwt_secret()  # raises RuntimeError with clear message if missing/short

    logger.info("Arkheia Enterprise Proxy starting up")

    # 1. Profile router -- loads all YAML profiles
    profiles_dir = Path(settings.detection.profile_dir)
    if not profiles_dir.is_dir():
        logger.error(
            "[FATAL] ARKHEIA_PROFILES_DIR does not exist: %s. "
            "Set ARKHEIA_PROFILES_DIR in .env or NSSM AppEnvironmentExtra.",
            profiles_dir,
        )
        raise RuntimeError(f"Cannot start: required directory/config missing")
    profile_router = ProfileRouter(settings.detection.profile_dir)
    logger.info("Loaded %d profiles from %s",
                profile_router.loaded_count, settings.detection.profile_dir)
    if profile_router.loaded_count == 0:
        require_license = os.getenv("ARKHEIA_REQUIRE_LICENSE", "false").lower() in (
            "true", "1", "yes"
        )
        if require_license:
            logger.error(
                "[FATAL] Zero valid licensed profiles loaded from %s. "
                "All surfaces may be expired or unsigned. "
                "Renew your Arkheia license and restart.",
                settings.detection.profile_dir,
            )
            raise RuntimeError(f"Cannot start: required directory/config missing")
        logger.warning(
            "[WARN] Zero profiles loaded from %s — all detections will return UNKNOWN. "
            "Drop .yaml profile files into that directory and restart.",
            settings.detection.profile_dir,
        )

    # 1b. Dynamic key loading for encrypted profiles
    enc_files = list(profiles_dir.glob("*.yaml.enc"))
    if enc_files and not profile_router._decryption_key:
        api_key = os.getenv("ARKHEIA_API_KEY", "")
        if api_key:
            try:
                from proxy.crypto.profile_crypto import DynamicKeyLoader
                loader = DynamicKeyLoader(
                    hosted_url=os.getenv(
                        "ARKHEIA_HOSTED_URL",
                        "https://arkheia-proxy-production.up.railway.app",
                    ),
                    api_key=api_key,
                )
                key = await loader.fetch_key()
                if key:
                    profile_router.set_decryption_key(key)
                    logger.info(
                        "Decryption key loaded — %d encrypted profiles available",
                        profile_router.loaded_count,
                    )
                else:
                    logger.warning(
                        "Could not fetch decryption key — encrypted profiles unavailable"
                    )
            except Exception as exc:
                logger.warning(
                    "DynamicKeyLoader failed (continuing without encrypted profiles): %s",
                    exc,
                )
        else:
            logger.warning(
                "Encrypted profiles found but no ARKHEIA_API_KEY — "
                "set key or provide decryption_key"
            )

    # 2. Detection engine
    engine = DetectionEngine(profile_router)

    # 3. Audit writer
    audit_writer = AuditWriter(
        log_path=settings.audit.log_path,
        retention_days=settings.audit.retention_days,
    )
    await audit_writer.start()

    # 4. Registry client (only if API key configured)
    registry_client = RegistryClient(
        base_url=settings.registry.url,
        api_key=settings.arkheia_api_key,
        profile_dir=settings.detection.profile_dir,
        router=profile_router,
        validator=ProfileValidator(),
    )

    # Store on app state -- endpoints access via request.app.state
    app.state.profile_router = profile_router
    app.state.engine = engine
    app.state.audit_writer = audit_writer
    app.state.registry_client = registry_client
    app.state.settings = settings

    # 5. Registry pull on startup (if configured and key present)
    key_value = settings.arkheia_api_key.get_secret_value()
    if settings.registry.pull_on_startup and key_value:
        logger.info("Pulling profile updates from registry on startup...")
        try:
            result = await registry_client.pull()
            logger.info("Startup registry pull: %s", result)
        except Exception as e:
            logger.warning("Startup registry pull failed (continuing): %s", e)

    # 6. Start scheduled pull background task
    if key_value and settings.registry.pull_interval_hours > 0:
        await registry_client.start_scheduled_pull(settings.registry.pull_interval_hours)

    logger.info("Arkheia Enterprise Proxy ready on %s:%d",
                settings.proxy.host, settings.proxy.port)

    yield

    # ----------------------------------------------------------------
    # SHUTDOWN
    # ----------------------------------------------------------------
    logger.info("Arkheia Enterprise Proxy shutting down")
    await registry_client.stop()
    await audit_writer.stop()
    logger.info("Shutdown complete")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Arkheia Enterprise Proxy",
        description=(
            "Fabrication detection for enterprise AI pipelines. "
            "POST /detect/verify to score any (prompt, response, model_id) triple."
        ),
        version="1.1.0",
        lifespan=lifespan,
        # Never expose stack traces in production responses
        docs_url="/docs" if os.environ.get("ARKHEIA_ENV") != "production" else None,
        redoc_url=None,
    )

    app.include_router(auth_router)
    app.include_router(detect_router)
    app.include_router(audit_router)
    app.include_router(admin_router)
    app.include_router(passthrough_router)

    if settings.detection.interception_enabled:
        from proxy.middleware.interception import AIInterceptionMiddleware
        app.add_middleware(AIInterceptionMiddleware)
        logger.info(
            "AI interception middleware enabled (upstream: %s)",
            settings.detection.upstream_url,
        )

    @app.get("/")
    async def root():
        return {
            "service": "arkheia-enterprise-proxy",
            "version": "1.1.0",
            "status": "ok",
            "scope": (
                "Arkheia Enterprise Proxy intercepts API-driven AI traffic. "
                "Browser-native AI usage (ChatGPT web, Claude.ai, Copilot) requires "
                "a complementary network DLP or endpoint agent -- outside scope of "
                "current release."
            ),
        }

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "proxy.main:app",
        host=settings.proxy.host,
        port=settings.proxy.port,
        reload=False,
        log_level=settings.proxy.log_level.lower(),
    )
