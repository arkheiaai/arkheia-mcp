"""
Arkheia Enterprise Proxy -- FastAPI entry point.

Instantiates and wires all components:
  - ProfileRouter (loads profiles at startup)
  - DetectionEngine (wraps feature extraction)
  - AuditWriter (async JSONL log)
  - RegistryClient (profile registry pull, if API key set)
  - Endpoints: /detect/verify, /audit/log, /admin/*
"""

import os
import sys

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

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


def _preconfigured_profile_key() -> Optional[bytes]:
    """
    A profile-decryption key this installation pins at deploy time, if any.

    Returns ``None`` today: no configuration surface supplies one, and inventing
    an env var that carries raw key material is not a change to make in passing.
    The seam is real rather than decorative — ``ProfileRouter(decryption_key=...)``
    is a supported construction and an enterprise install may pin one — and it has
    to be consulted HERE, before the router is built, because the router's first
    ``load_all()`` is the thing whose verdict the key changes.

    It replaces the previous ``if profile_router._decryption_key:`` test, which
    was equally unreachable from this lifespan (nothing ever passed a key to the
    router) and, worse, could only be evaluated AFTER the load it was meant to
    inform.
    """
    return None


async def _resolve_profile_key(
    audit_writer,
    profiles_dir: Path,
    preconfigured_key: Optional[bytes] = None,
) -> tuple[Optional[bytes], str]:
    """
    Decide which key this process will trust, receipt that decision, and return
    the key — **before any profile is loaded**.

    Returns ``(key_or_None, receipt_status)``. The status is ``"enqueued"`` or
    ``"unavailable"``, never ``"recorded"``: ``AuditWriter`` is fire-and-forget
    and cannot acknowledge that anything landed.

    WHY THE ORDER IS THE FIX
    -----------------------
    This ran at step 1b, *after* ``ProfileRouter`` was constructed at step 1. The
    router's ``__init__`` calls ``load_all()``, which — finding encrypted profiles
    and no key — journalled ``skipped_no_key``: *these surfaces went dark*. The
    very next statement fetched the key and every one of those surfaces
    authenticated. A real boot wrote::

        skipped_no_key  ->  fetched_from_hosted  ->  authenticated

    (Codex, PR #34.) That is auditable and it is false: it records surfaces going
    dark for a startup that never served them dark. It is the inverse of the
    failure this flow has been chasing — the rail received a too-ALARMING value
    rather than a too-reassuring one — and it is the same defect underneath, since
    in both cases the record does not describe what happened. A false alarm erodes
    an audit trail exactly as much as a false all-clear.

    The fix is ORDERING, never suppression. The key decision is conclusive before
    the router exists, so the router loads once, holding whatever key this process
    is going to have. ``skipped_no_key`` is now journalled if and only if key
    loading genuinely came back empty — and a keyless startup still says so.
    ``proxy/tests/test_f20_lifespan_ordering.py`` holds both halves: the boot that
    must NOT report dark surfaces, and the boot that must.

    Extracted from the lifespan body so the decision has one testable entry point
    rather than living inside a 100-line startup coroutine that only a running app
    can exercise. ``audit_writer`` is a PARAMETER, which is the whole point: the
    writer is built before this is called and there is no arrangement of this
    function in which it is not.
    """
    from proxy.audit.decision_journal import (
        KEY_LOAD_KEY_PRECONFIGURED,
        KEY_LOAD_LOADER_ERROR,
        KEY_LOAD_NO_API_KEY,
        KEY_LOAD_NO_ENCRYPTED_PROFILES,
        KEY_SOURCE_NONE,
        KEY_SOURCE_PRECONFIGURED,
        REVOCATION_NOT_APPLICABLE,
        build_key_load_record,
        emit,
    )

    enc_files = list(profiles_dir.glob("*.yaml.enc"))
    hosted_url = os.getenv(
        "ARKHEIA_HOSTED_URL",
        "https://arkheia-proxy-production.up.railway.app",
    )

    if not enc_files:
        return preconfigured_key, await emit(audit_writer, build_key_load_record(
            outcome=KEY_LOAD_NO_ENCRYPTED_PROFILES,
            key_source=KEY_SOURCE_NONE,
            revocation_state=REVOCATION_NOT_APPLICABLE,
            encrypted_profile_count=0,
        ))

    if preconfigured_key:
        return preconfigured_key, await emit(audit_writer, build_key_load_record(
            outcome=KEY_LOAD_KEY_PRECONFIGURED,
            key_source=KEY_SOURCE_PRECONFIGURED,
            revocation_state=REVOCATION_NOT_APPLICABLE,
            key=preconfigured_key,
            encrypted_profile_count=len(enc_files),
        ))

    api_key = os.getenv("ARKHEIA_API_KEY", "")
    if not api_key:
        logger.warning(
            "Encrypted profiles found but no ARKHEIA_API_KEY — "
            "set key or provide decryption_key"
        )
        return None, await emit(audit_writer, build_key_load_record(
            outcome=KEY_LOAD_NO_API_KEY,
            key_source=KEY_SOURCE_NONE,
            revocation_state=REVOCATION_NOT_APPLICABLE,
            hosted_url=hosted_url,
            encrypted_profile_count=len(enc_files),
        ))

    try:
        from proxy.crypto.profile_crypto import DynamicKeyLoader
        loader = DynamicKeyLoader(
            hosted_url=hosted_url,
            api_key=api_key,
            # The rail, at construction. fetch_key() is async, so unlike the
            # router's synchronous load_all() it receipts its decision AT the
            # moment it is taken — receipt_deferred_ms is ~0 for this record and
            # the field proves it rather than the comment.
            audit_writer=audit_writer,
        )
        key = await loader.fetch_key()
        if not key:
            logger.warning(
                "Could not fetch decryption key — encrypted profiles unavailable"
            )
        # fetch_key() has already written its own record naming the source and
        # the revocation state; re-emitting here would double-count the decision.
        # Report the status IT got, rather than asserting one.
        return key, loader.last_receipt_status
    except Exception as exc:
        logger.warning(
            "DynamicKeyLoader failed (continuing without encrypted profiles): %s",
            exc,
        )
        return None, await emit(audit_writer, build_key_load_record(
            outcome=KEY_LOAD_LOADER_ERROR,
            key_source=KEY_SOURCE_NONE,
            revocation_state=REVOCATION_NOT_APPLICABLE,
            hosted_url=hosted_url,
            encrypted_profile_count=len(enc_files),
            error_type=type(exc).__name__,
        ))


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ----------------------------------------------------------------
    # STARTUP
    # ----------------------------------------------------------------
    # Validate JWT_SECRET at startup (fails fast with clear error, not at import time)
    from proxy.auth import _get_jwt_secret
    _get_jwt_secret()  # raises RuntimeError with clear message if missing/short

    # Validate the governance push address at BOOT, not at push time. A trailing
    # slash in DETECTION_ADAPTER_URL used to compose `//v1/events/proxy`, which the
    # receiver 404s with an empty body on a fire-and-forget path -- every push lost,
    # silently. The value cannot become valid later, so refusing here (while an
    # operator is watching) is the only moment the feedback is cheap. Silent when
    # the rail is unconfigured, so a clean local/demo boot is unaffected.
    from proxy.detection_adapter import validate_config_or_raise
    validate_config_or_raise()  # raises RuntimeError naming the setting and value

    logger.info("Arkheia Enterprise Proxy starting up")

    # ----------------------------------------------------------------
    # 0. Audit writer -- FIRST, because everything below it DECIDES.
    #
    # This used to be step 3. That ordering was the root cause of F20's
    # receipted axis failing: the profile router (step 1) decides whether each
    # encrypted profile authenticated, and the key loader (step 1b) decides
    # which key to trust and from where — both of them before any writer
    # existed to record them. A missing call site is a bug; a missing writer is
    # a structure that makes the call site impossible.
    #
    # Nothing below the writer's own construction is needed to build it: it
    # takes a path and a retention window from settings, and its background
    # drain task only needs the running loop. So the fix is genuinely just to
    # move it, not to add a second rail.
    #
    # Enforced by tests/test_f20_profile_key_floor.py::INV-1, which fails the
    # build if a future edit puts a decision site above the writer again.
    # ----------------------------------------------------------------
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
    # It runs HERE, before the first record of this boot is enqueued, so a break
    # it reports is a break inherited from a previous run rather than one this
    # process might have introduced.
    try:
        chain = audit_writer.verify_chain()
        if not chain.get("ok", True):
            # "ok": False now covers two distinct causes (2026-07-27): a genuine
            # broken link (breaks non-empty), or content that could not be
            # verified at all — e.g. every line unparseable, or the walk raised
            # (chain["error"] set, breaks empty). Both are surfaced here rather
            # than the second one silently reading as "0 breaks == fine".
            logger.warning(
                "Audit hash-chain integrity check FAILED on startup: "
                "%d record(s) verified, %d break(s) detected%s — possible tampering",
                chain.get("verified", 0), len(chain.get("breaks", [])),
                f" ({chain['error']})" if chain.get("error") else "",
            )
        else:
            logger.info(
                "Audit hash-chain integrity OK on startup (%d record(s) verified)",
                chain.get("verified", 0),
            )
    except Exception as exc:  # fail-open: never block startup on the self-check
        logger.warning("Audit hash-chain startup self-check skipped: %s", exc)

    profiles_dir = Path(settings.detection.profile_dir)
    if not profiles_dir.is_dir():
        logger.error(
            "[FATAL] ARKHEIA_PROFILES_DIR does not exist: %s. "
            "Set ARKHEIA_PROFILES_DIR in .env or NSSM AppEnvironmentExtra.",
            profiles_dir,
        )
        raise RuntimeError(f"Cannot start: required directory/config missing")

    # ----------------------------------------------------------------
    # 1. Which key will this process trust? — BEFORE the router, because the
    #    router's first (and now only) load_all() decides whether each encrypted
    #    profile authenticated, and that verdict depends on holding the key.
    #
    #    Every branch is a decision about which key to trust and every branch
    #    leaves a row, including the two that are not failures. "This deployment
    #    has no encrypted profiles and never fetched a key" is the branch that
    #    fires in production today (0 of 60 profiles are encrypted), and a
    #    governance plane that only hears about the exotic branches cannot tell a
    #    dormant control from a working one.
    #
    #    Ordering matters for a second reason, and it is the one Codex found:
    #    when the router ran first it journalled skipped_no_key — "these surfaces
    #    went dark" — for a startup that then fetched the key and authenticated
    #    every surface. See _resolve_profile_key's docstring.
    # ----------------------------------------------------------------
    decryption_key, _key_receipt_status = await _resolve_profile_key(
        audit_writer, profiles_dir, preconfigured_key=_preconfigured_profile_key(),
    )

    # 2. Profile router -- loads all YAML profiles, ONCE, holding the key the
    #    step above concluded on.
    profile_router = ProfileRouter(
        settings.detection.profile_dir,
        decryption_key=decryption_key,
        # The rail, at construction. load_all() runs inside __init__ and is
        # synchronous, so each per-profile authentication decision is journalled
        # with its true decided_at and drained below; every record carries
        # receipt_deferred_ms so the gap between deciding and enqueueing is a
        # number a reader can see, not a claim they have to take on trust.
        audit_writer=audit_writer,
    )
    await profile_router.flush_decision_journal()
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

    # 3. Binary integrity self-check for the compiled detection modules.
    #
    # proxy/license/integrity.py documents itself as "At startup, verifies that
    # compiled detection modules (.so/.pyd) have not been tampered with" — but
    # verify_integrity() had ZERO production call sites, so no startup ever
    # verified anything and the advertised tamper-evidence was inert. This is the
    # live call site. It mirrors the verify_chain() self-check above (step 0).
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

    # 4. Detection engine
    engine = DetectionEngine(profile_router)

    # 5. Registry client (only if API key configured)
    registry_client = RegistryClient(
        base_url=settings.registry.url,
        api_key=settings.arkheia_api_key,
        profile_dir=settings.detection.profile_dir,
        router=profile_router,
        validator=ProfileValidator(),
        audit_writer=audit_writer,
    )

    # Store on app state -- endpoints access via request.app.state
    app.state.profile_router = profile_router
    app.state.engine = engine
    app.state.audit_writer = audit_writer
    app.state.registry_client = registry_client
    app.state.settings = settings

    # 6. Registry pull on startup (if configured and key present)
    key_value = settings.arkheia_api_key.get_secret_value()
    if settings.registry.pull_on_startup and key_value:
        logger.info("Pulling profile updates from registry on startup...")
        try:
            result = await registry_client.pull()
            logger.info("Startup registry pull: %s", result)
        except Exception as e:
            logger.warning("Startup registry pull failed (continuing): %s", e)

    # 7. Start scheduled pull background task
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
