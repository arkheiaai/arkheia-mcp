"""
The AUTHORITATIVE screening-coverage check for fleet defaults — run against the REAL
ProfileRouter, the real profiles/ directory and the real DetectionEngine.

Runs in the REQUIRED `unit-tests` context (.github/workflows/unit-tests.yml, job `unit`).

WHY IT LIVES HERE AND NOT IN THE FLOOR TIER. The floor job installs pytest and nothing else,
so `tests/test_fleet_default_screening_floor.py` cannot import yaml and therefore cannot ask
ProfileRouter to resolve anything; it can only see EXACT profile ids and is deliberately
conservative. Re-implementing the router's prefix/family/version rules there would create a
second, drifting resolver — the defect DONE.md v1.13 clause 4 forbids. So the two tiers split
the job:

    floor tier  (no deps)  registry contract + exact-id presence, conservative, always runs
    unit tier   (this)     the REAL resolver's answer, authoritative

They share ONE derivation of "what is a fleet default", imported from the floor module below,
so they can never disagree about the population — only about resolution, which is exactly
what the parity test here pins.

INV-1  Every derived fleet default resolves through the REAL router, or is registered as
       knowingly-unprofiled with an unexpired waiver.
INV-2  The floor's conservative answer and the real router's answer AGREE for the registered
       id, so the waiver is not covering a resolution the router would actually have made.
INV-3  DIFFERENTIAL derivation: the ast walk and an independent `inspect`-based walk over the
       live tool signatures produce the SAME default set. Two mechanisms, one answer.
INV-4  "Has a profile" is NOT "is screened", pinned by measurement — because that distinction
       is the reason a profiled fallback would not have fixed the grok gap.
"""

from __future__ import annotations

import importlib.util
import inspect
import pathlib

import pytest

from mcp_server import server as server_module
from mcp_server.screening import is_screened
from mcp_server.tools import providers
from proxy.detection.engine import DetectionEngine
from proxy.router.profile_router import ProfileRouter

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE_DIR = str(REPO_ROOT / "profiles")

PROSE = (
    "The capital of France is Paris, a city on the river Seine with a population of "
    "roughly two million people inside the city limits. "
) * 6


def _load_floor_module():
    """
    Import the floor module BY PATH. It is a test module in a directory that is not a
    package, and the point of importing it is to reuse its derivation rather than write a
    second one.
    """
    path = REPO_ROOT / "tests" / "test_fleet_default_screening_floor.py"
    spec = importlib.util.spec_from_file_location("_fleet_default_floor", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


floor = _load_floor_module()


@pytest.fixture(scope="module")
def router() -> ProfileRouter:
    r = ProfileRouter(PROFILE_DIR)
    # POSITIVE CONTROL for every assertion in this file.
    assert r.loaded_count > 40, f"only {r.loaded_count} profiles loaded from {PROFILE_DIR}"
    return r


# ---------------------------------------------------------------------------
# INV-1 — the authoritative resolve-or-registered check
# ---------------------------------------------------------------------------

def test_every_fleet_default_resolves_or_is_registered(router):
    defaults = floor.derive_fleet_defaults()
    registered = {str(e.get("model_id", "")).lower() for e in floor.load_registry()}

    assert len(defaults) >= 4, (
        f"derived only {len(defaults)} fleet defaults: {sorted(defaults)} — the shared "
        "derivation is not finding what it must check"
    )

    unscreenable = {
        model_id: sites
        for model_id, sites in defaults.items()
        if router.get(model_id) is None and model_id.lower() not in registered
    }

    assert not unscreenable, (
        "these fleet defaults do not resolve to ANY profile through the real router and are "
        "not registered as knowingly-unprofiled — traffic on them is UNSCREENED:\n  "
        + "\n  ".join(f"{m!r} at {', '.join(s)}" for m, s in sorted(unscreenable.items()))
    )


def test_the_registered_default_really_is_unresolvable_by_the_real_router(router):
    """
    The waiver must describe reality. If a registered id starts resolving, the waiver is
    hiding real coverage and must be deleted — so this fails rather than passing quietly.
    """
    registered = [str(e.get("model_id", "")) for e in floor.load_registry()]
    assert registered, "no registered knowingly-unprofiled defaults — nothing to check"

    for model_id in registered:
        assert router.get(model_id) is None, (
            f"{model_id!r} is registered as knowingly-unprofiled but the real router now "
            "resolves it — delete the registry entry so the coverage becomes visible"
        )


# ---------------------------------------------------------------------------
# INV-2 — floor and real router agree
# ---------------------------------------------------------------------------

def test_the_floor_and_the_real_router_agree_on_every_fleet_default(router):
    """
    The floor is allowed to be MORE conservative than the router (it cannot see fuzzy
    resolution), but it must never be LESS: a default the floor calls profiled while the
    router returns None would be a green floor over an unscreened path. Asserts that
    direction, per default, naming the units.
    """
    defaults = floor.derive_fleet_defaults()
    exact = floor.exact_profile_ids()

    checked = 0
    for model_id in sorted(defaults):
        floor_says_profiled = model_id.lower() in exact
        router_resolves = router.get(model_id) is not None
        checked += 1
        if floor_says_profiled:
            assert router_resolves, (
                f"{model_id!r}: the floor reads an exact profile for it but the real router "
                "resolves NOTHING — the floor would go green over an unscreened default"
            )

    assert checked >= 4, f"compared only {checked} defaults"


# ---------------------------------------------------------------------------
# INV-3 — two independent derivations, one answer
# ---------------------------------------------------------------------------

def test_the_ast_derivation_matches_an_independent_signature_walk():
    """
    DIFFERENTIAL (DONE.md v1.13 clause 3). The floor derives defaults by parsing source; this
    derives them by introspecting the LIVE objects. A drift between the two means the floor is
    checking something other than what the process actually runs.
    """
    from_ast = set(floor.derive_fleet_defaults())

    from_inspect: set[str] = set()
    for module in (server_module, providers):
        for name, fn in vars(module).items():
            if not callable(fn) or not (name.startswith("run_") or name.startswith("call_")):
                continue
            try:
                param = inspect.signature(fn).parameters.get("model")
            except (TypeError, ValueError):  # pragma: no cover - non-introspectable callable
                continue
            if param is None or param.default is inspect.Parameter.empty:
                continue
            if isinstance(param.default, str) and param.default:
                from_inspect.add(param.default)

    assert from_inspect, "the signature walk found no model defaults — it is broken"
    assert from_ast == from_inspect, (
        "the source-parsing derivation and the live-signature derivation disagree:\n"
        f"  only in ast:     {sorted(from_ast - from_inspect)}\n"
        f"  only in inspect: {sorted(from_inspect - from_ast)}"
    )


# ---------------------------------------------------------------------------
# INV-4 — having a profile is not the same as being screened
# ---------------------------------------------------------------------------

class TestHavingAProfileIsNotBeingScreened:
    """
    This distinction decided the default-posture ruling. A "profiled" fallback for grok would
    NOT have restored screening on this path, because the cross-domain-validated grok profiles
    need logprob features that /detect/verify cannot supply. Pinned by measurement so the
    reasoning cannot quietly stop being true.
    """

    @pytest.fixture
    def engine(self) -> DetectionEngine:
        return DetectionEngine(ProfileRouter(PROFILE_DIR))

    @pytest.mark.asyncio
    async def test_gemini_default_has_a_profile_yet_returns_unknown_on_this_path(self, engine):
        result = await engine.verify("q", PROSE, "gemini-2.5-flash")
        assert result.risk_level == "UNKNOWN"
        assert result.error == "no_computable_features"
        # ... and the caller is told, by the same mechanism that covers the grok case.
        assert is_screened(
            {"risk_level": result.risk_level, "error": result.error}
        ) is False

    @pytest.mark.asyncio
    async def test_a_profiled_grok_id_also_returns_unknown_on_this_path(self, engine):
        """
        The measurement behind 'do not fall back to a profiled grok id'. If this ever starts
        returning a real band, the ruling should be revisited — and this test failing is how
        that gets noticed.
        """
        result = await engine.verify("q", PROSE, "grok-4-1-fast-non-reasoning")
        assert result.risk_level == "UNKNOWN"
        assert result.error == "no_computable_features"

    @pytest.mark.asyncio
    async def test_the_local_defaults_ARE_genuinely_screened(self, engine):
        """
        DIFFERENTIAL CONTROL. Two of the four fleet defaults really are screened on this path,
        so the tests above are measuring a property of those model ids and not a broken engine.
        """
        for model_id in ("phi4:14b", "moonshotai/Kimi-K2.5"):
            result = await engine.verify("q", PROSE, model_id)
            assert result.risk_level == "LOW", f"{model_id} -> {result.risk_level}"
            assert result.error is None
            assert result.features_triggered, f"{model_id} fired no features"
