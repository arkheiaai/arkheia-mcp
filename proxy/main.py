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

    # 1c. Binary integrity self-check for the compiled detection modules.
    #
    # proxy/license/integrity.py documents itself as "At startup, verifies that
    # compiled detection modules (.so/.pyd) have not been tampered with" — but
    # verify_integrity() had ZERO production call sites, so no startup ever
    # verified anything and the advertised tamper-evidence was inert. This is the
    # live call site. It mirrors the verify_chain() self-check below.
    #
    # scripts/build_release.py writes an `integrity_manifest.json` into each
    # compiled-module directory, so the dirs to check are discovered by looking
    # for that manifest rather than by duplicating COMPILED_MODULES here (which
    # would silently drift when the build's module list changes).
    #
    # FAIL-OPEN / FAIL-CLOSED SPLIT (Codex finding 4, ruled 2026-07-26).
    # This block used to catch every exception, TamperDetected included, and
    # continue — so a tampered detection engine produced "error log plus service
    # ready". Those are two different states and must not be collapsed:
    #
    #   ABSENT / UNVERIFIABLE  = absence of evidence. A source checkout has no
    #       manifest; a module might be unreadable. FAIL OPEN: log, continue, and
    #       publish the unverified state on app.state.integrity so /admin/health
    #       shows it. Silence would be the real defect (DONE.md floor invariant
    #       9(d): an outcome that produced no observation is not a success).
    #
    #   TamperDetected         = EVIDENCE. Hash mismatch, a manifest module missing
    #       from disk, or a manifest that exists and cannot be parsed. DO NOT
    #       START. A tampered detection engine that reports LOW is worse than no
    #       detection at all, because it is trusted: every downstream verdict,
    #       audit record and governance receipt would carry that engine's
    #       authority. Halting is a deliberate availability trade — see the
    #       failure mode named in the PR body.
    integrity_reports = []
    try:
        from proxy.license.integrity import TamperDetected, verify_all

        integrity_reports = verify_all()
    except TamperDetected as exc:
        logger.critical(
            "[FATAL] BINARY INTEGRITY TAMPER DETECTED — refusing to start: %s. "
            "This is a POSITIVE finding, not a failed check: a compiled detection "
            "module does not match its build-time hash (or its manifest is "
            "unreadable). A tampered detection engine would be TRUSTED, so the "
            "proxy must not serve traffic. Restore the verified artifact from the "
            "release build, or remove the integrity manifest only if you are "
            "deliberately running unverified from source.",
            exc,
        )
        app.state.integrity = {
            "status": "TAMPERED",
            "verified": False,
            "startup_blocked": True,
            "detail": str(exc),
        }
        raise
    except Exception as exc:  # fail-open: an UNVERIFIABLE environment may boot
        logger.error(
            "Binary integrity self-check could not be completed: %s. Continuing "
            "(fail-open) because this is an absence of evidence, not a tamper "
            "finding — but the modules are NOT verified and that is published on "
            "/admin/health.",
            exc,
        )
        app.state.integrity = {
            "status": "UNVERIFIABLE",
            "verified": False,
            "startup_blocked": False,
            "detail": f"{type(exc).__name__}: {exc}",
        }
    else:
        verified = all(r.verified for r in integrity_reports)
        app.state.integrity = {
            "status": "VERIFIED" if verified else integrity_reports[0].status,
            "verified": verified,
            "startup_blocked": False,
            "directories": [r.module_dir for r in integrity_reports],
            "modules_checked": sum(r.modules_checked for r in integrity_reports),
            "detail": "; ".join(r.detail for r in integrity_reports),
        }
        if verified:
            logger.info(
                "Binary integrity VERIFIED: %d module(s) across %d director%s (%s)",
                app.state.integrity["modules_checked"],
                len(integrity_reports),
                "y" if len(integrity_reports) == 1 else "ies",
                "; ".join(r.module_dir for r in integrity_reports),
            )
        else:
            # WARNING, not INFO: "not verified" must not read like a pass. It is
            # the normal state for a source deployment, which is why it does not
            # block startup — but it is published, not swallowed.
            logger.warning(
                "Binary integrity NOT VERIFIED (%s) — continuing fail-open: %s",
                app.state.integrity["status"],
                app.state.integrity["detail"],
            )

    # 2. Detection engine
    engine = DetectionEngine(profile_router)

    # 3. Audit writer
    audit_writer = AuditWriter(
        log_path=settings.audit.log_path,
        retention_days=settings.audit.retention_days,
    )
    await audit_writer.start()

    # Startup tamper-evidence self-check: walk the audit log's hash chain and
    # surface any break. This wires AuditWriter.verify_chain() to a live call
    # site so the tamper-evident chain is actually validated on boot rather than
    # only ever computed on write. Fail-open — an integrity check must never
    # block startup (consistent with the audit pipeline's non-blocking design).
    #
    # POSTURE ON A DETECTED BREAK (Codex adversarial review of PR #37,
    # 2026-07-27) — LOUDLY DEGRADED, not fail-closed. Startup used to detect the
    # break, log one WARNING, and continue with every downstream surface still
    # reporting "ok": we noticed and did nothing, which is the worst of both
    # worlds. The two candidate postures:
    #
    #   FAIL CLOSED (refuse to start) is right for BINARY INTEGRITY above,
    #     because a tampered detection engine is TRUSTED — it produces false
    #     LOW verdicts that every downstream receipt inherits. Wrong here: the
    #     audit LOG is downstream evidence, not an input to any live verdict,
    #     and the log is append-only and world-appendable by anything sharing
    #     the volume. Refusing to boot on a corrupt chain would hand an attacker
    #     a ONE-APPEND denial of the entire detection service — write `null`
    #     into the log, the proxy never starts again, and there is no detection
    #     at all. That trades silent audit loss for total loss.
    #
    #   LOUDLY DEGRADED (chosen): start, keep recording (a corrupt chain is
    #     exactly when you most want new records landing), and make the state
    #     impossible to mistake for healthy — app.state.audit_chain,
    #     /admin/health reporting top-level "degraded" instead of "ok", and
    #     AuditWriter re-emitting the signal from its writer loop for as long as
    #     the condition persists rather than once at boot.
    #
    # "fail-open, but NEVER fail-silent": fail-open is the availability call,
    # and the persistent operator-visible signal is the half that is not
    # optional.
    try:
        chain = audit_writer.verify_chain()
        if not chain.get("ok", True):
            audit_writer.mark_chain_degraded(
                "CHAIN_VERIFY_FAILED",
                f"startup verify_chain(): {len(chain.get('breaks', []))} break(s), "
                f"{len(chain.get('gaps', []))} sequence gap(s), "
                f"{chain.get('verified', 0)} record(s) verified"
                + (f" ({chain['error']})" if chain.get("error") else ""),
            )
            # "ok": False now covers three distinct causes (2026-07-27): a
            # genuine broken link (breaks non-empty), content that could not
            # be verified at all — e.g. every line unparseable, or the walk
            # raised (chain["error"] set, breaks empty) — or a sequence gap
            # (gaps non-empty, breaks empty: a record was numbered but never
            # written, see AuditWriter.verify_chain's docstring). All three
            # are surfaced here rather than any of them silently reading as
            # "0 breaks == fine".
            logger.warning(
                "Audit hash-chain integrity check FAILED on startup: "
                "%d record(s) verified, %d break(s), %d sequence gap(s) detected%s "
                "— possible tampering or a lost audit record",
                chain.get("verified", 0), len(chain.get("breaks", [])),
                len(chain.get("gaps", [])),
                f" ({chain['error']})" if chain.get("error") else "",
            )
        else:
            logger.info(
                "Audit hash-chain integrity OK on startup (%d record(s) verified)",
                chain.get("verified", 0),
            )
    except Exception as exc:  # fail-open: never block startup on the self-check
        # Not "skipped" as if that were benign: the check that exists to prove
        # the chain is intact did not run, so the chain is UNVERIFIED and that
        # must be visible, not swallowed.
        logger.error("Audit hash-chain startup self-check could not run: %s", exc)
        audit_writer.mark_chain_degraded(
            "CHAIN_UNVERIFIED",
            f"the startup chain self-check could not run: {type(exc).__name__}: {exc}",
        )

    # Published continuously, not just logged once at boot: /admin/health reads
    # this on every request and downgrades its top-level status when ok is False.
    app.state.audit_chain = audit_writer.chain_status()

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
