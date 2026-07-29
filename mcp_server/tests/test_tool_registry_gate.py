"""
Tests for the tool-registry allow/deny gate — the published product's policy gate.

Before this file the gate had ZERO tests anywhere in the repo:
``git grep -n 'tool_registry\\|PolicyViolation\\|ToolPolicy' -- '*test*'`` on
origin/master returned no hits. ``ToolPolicy.permissions`` / ``network_egress`` /
``requires_human_confirm`` were enforced nowhere any test observed.

Collected by the REQUIRED status context ``unit-tests``
(``.github/workflows/unit-tests.yml``, job ``unit``, which runs
``pytest proxy/tests mcp_server/tests registry_server/tests tests``).

PASSING CRITERIA
  1.  check() on an unregistered name raises PolicyViolation — the deny decision.
  2.  The deny reason and .tool_name are pinned POSITIVELY, per deny branch, so
      the three branches cannot be confused for one another.
  3.  check() on every registered name returns that name's policy.
  4.  Every REGISTRY key equals its policy's `name` field.
  5.  An empty permission set is default-deny (was: read nowhere).
  6.  requires_human_confirm blocks without approval, allows with (was: read
      nowhere — setting it blocked nothing).
  7.  ADVERTISED-IDENTIFIER, TWO TRANSPORTS: every tool name the server publishes
      is exercised VERBATIM end-to-end under two transports whose name-resolution
      behaviour differs — direct in-process call of the decorated coroutine, and
      FastMCP `call_tool(name, args)` string dispatch. Asserting a name equals an
      expected string is not a test of the name.
  8.  Parity between the advertised set and REGISTRY, both directions, naming the
      offending units.
  9.  assert_registry_covers() fails closed on either-direction drift AND on an
      empty advertised set.
  10. The refusal contract is pinned per tool: 5 tools propagate PolicyViolation,
      4 return an error dict. Pinned because it is an inconsistency, not because
      it is right — see the PR body.
  11. PRIVILEGE ESCALATION: the ToolPolicy check() hands a caller cannot be used
      to alter what the gate decides next — neither by assigning a field nor by
      mutating one in place.
  12. LATE REGISTRATION: the public REGISTRY name is a read-only view, so a
      policy cannot be added or widened after the startup coverage self-check.
  13. ALIAS EVASION: no alternative spelling of an allowed tool name resolves.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import FrozenInstanceError, fields, replace
from enum import Enum

import pytest

from mcp_server import server as srv
from mcp_server import receipts
from mcp_server.tool_registry import (
    REGISTRY,
    Permission,
    _REGISTRY,
    PolicyViolation,
    RegistryCoverageError,
    ToolPolicy,
    assert_registry_covers,
    check,
    check_receipted,
    decide,
)

# The nine tools this server is expected to expose. Hard-coded on purpose: a set
# derived from REGISTRY would agree with REGISTRY however wrong REGISTRY became.
EXPECTED_TOOLS = {
    "arkheia_verify",
    "arkheia_audit_log",
    "run_grok",
    "run_gemini",
    "run_together",
    "run_ollama",
    "memory_store",
    "memory_retrieve",
    "memory_relate",
}

# Tools whose body lets PolicyViolation propagate to the orchestrator, vs those
# that catch it and return an error dict. See CRITERION 10.
RAISING_TOOLS = {
    "arkheia_verify",
    "arkheia_audit_log",
    "memory_store",
    "memory_retrieve",
    "memory_relate",
}
DICT_RETURNING_TOOLS = {"run_grok", "run_gemini", "run_together", "run_ollama"}


@pytest.fixture(autouse=True)
def _isolate_memory_db_and_receipts(tmp_path, monkeypatch):
    """mcp_server/tools/memory.py defaults MEMORY_DB_PATH to the hard-coded
    Windows path 'C:/arkheia-mcp/data/memory.db', which on POSIX creates a literal
    './C:' directory under the CWD. Point it at tmp_path so this suite never
    writes outside its sandbox. (The hard-coded default is a separate defect,
    named in the PR body — it belongs to the memory flow, not the gate.)"""
    monkeypatch.setenv("MEMORY_DB_PATH", str(tmp_path / "memory.db"))
    monkeypatch.setenv(
        "ARKHEIA_TOOL_GATE_RECEIPT_LOG",
        str(tmp_path / "tool-gate-receipts.jsonl"),
    )


@pytest.fixture
def registry_sandbox():
    """Mutate the allowlist inside a test without leaking into other tests.

    Reaches for the PRIVATE backing dict deliberately: the public ``REGISTRY``
    name is a read-only view (CRITERION 12), so installing a synthetic policy is
    now an explicit act rather than something any holder of the public name can
    do. Yields the writable dict; ``REGISTRY`` observes the same entries because
    the view is live."""
    original = dict(_REGISTRY)
    try:
        yield _REGISTRY
    finally:
        _REGISTRY.clear()
        _REGISTRY.update(original)


# ---------------------------------------------------------------------------
# 1 + 2 — the deny decision, and its reason, pinned positively
# ---------------------------------------------------------------------------

class TestDefaultDeny:

    def test_unregistered_tool_is_denied(self):
        """CRITERION 1: an unregistered name raises PolicyViolation."""
        with pytest.raises(PolicyViolation) as exc:
            check("exfiltrate_secrets")
        # Pin the identity of the refusal, not merely that *something* raised.
        assert exc.value.tool_name == "exfiltrate_secrets"

    def test_deny_reason_names_the_default_deny_rule(self):
        """CRITERION 2: the operator-facing reason states WHY, and lists the
        allowlist. The rendered wording is a decision site, not decoration."""
        with pytest.raises(PolicyViolation) as exc:
            check("exfiltrate_secrets")
        reason = exc.value.reason
        assert "not in allowlist" in reason
        assert "default deny" in reason
        # The refusal must be actionable: it has to say what IS allowed.
        for name in sorted(EXPECTED_TOOLS):
            assert name in reason, f"deny reason does not list allowed tool {name!r}"

    def test_deny_message_is_prefixed_and_carries_the_tool_name(self):
        with pytest.raises(PolicyViolation) as exc:
            check("exfiltrate_secrets")
        assert str(exc.value) == (
            f"Policy violation for 'exfiltrate_secrets': {exc.value.reason}"
        )

    @pytest.mark.parametrize(
        "bad_name",
        [
            "",                    # empty string
            "ARKHEIA_VERIFY",      # wrong case — the allowlist is case-sensitive
            "arkheia_verify ",     # trailing space
            " arkheia_verify",     # leading space
            "arkheia_verify\n",    # trailing newline
            "arkheia-verify",      # hyphen for underscore
            "mcp_server.arkheia_verify",
            "arkheia_verify;run_grok",
        ],
    )
    def test_near_miss_names_are_denied(self, bad_name):
        """A gate that accepts near-misses of an allowed name is not an allowlist.
        Every one of these is NOT in REGISTRY, so every one must be refused."""
        assert bad_name not in REGISTRY  # guard: the input really is a near-miss
        with pytest.raises(PolicyViolation):
            check(bad_name)


# ---------------------------------------------------------------------------
# 3 + 4 — the allow decision
# ---------------------------------------------------------------------------

class TestAllowDecision:

    @pytest.mark.parametrize("tool_name", sorted(EXPECTED_TOOLS))
    def test_registered_tool_is_allowed_and_returns_its_own_policy(self, tool_name):
        """CRITERION 3/4: check() returns a ToolPolicy, and it is the policy FOR
        THAT TOOL — not merely some ToolPolicy."""
        policy = check(tool_name)
        assert isinstance(policy, ToolPolicy)
        assert policy.name == tool_name
        assert policy is REGISTRY[tool_name]

    def test_registry_keys_match_their_policy_names(self):
        """A key/name mismatch would make check(key) hand back a policy describing
        a different tool — the wrong permissions, silently."""
        mismatched = sorted(
            f"{k}->{v.name}" for k, v in REGISTRY.items() if k != v.name
        )
        assert not mismatched, f"REGISTRY key != ToolPolicy.name for: {mismatched}"

    def test_every_expected_tool_has_at_least_one_permission(self):
        """Pinned positively per tool: an empty permission set is now a deny, so a
        shipped tool with none would be dead on arrival."""
        empty = sorted(k for k, v in REGISTRY.items() if not v.permissions)
        assert not empty, f"shipped tools with an empty permission set: {empty}"

    def test_permission_values_are_from_the_declared_enum(self):
        bad = sorted(
            f"{k}:{p!r}"
            for k, v in REGISTRY.items()
            for p in v.permissions
            if not isinstance(p, Permission)
        )
        assert not bad, f"non-Permission values in REGISTRY: {bad}"

    def test_expected_permission_grants_are_pinned_exactly(self):
        """Positively pinned, per tool. A permissive `assert permissions` would
        pass against any wrong-but-non-empty grant and no mutation could reveal
        it — e.g. silently granting DEPLOY to a read-only tool."""
        expected = {
            "arkheia_verify": {Permission.READ},
            "arkheia_audit_log": {Permission.READ},
            "run_grok": {Permission.READ, Permission.EXECUTE},
            "run_gemini": {Permission.READ, Permission.EXECUTE},
            "run_together": {Permission.READ, Permission.EXECUTE},
            "run_ollama": {Permission.READ, Permission.EXECUTE},
            "memory_store": {Permission.READ, Permission.WRITE},
            "memory_retrieve": {Permission.READ},
            "memory_relate": {Permission.READ, Permission.WRITE},
        }
        assert set(expected) == EXPECTED_TOOLS
        actual = {k: set(v.permissions) for k, v in REGISTRY.items()}
        assert actual == expected

        # No shipped tool may hold DEPLOY — the most dangerous grant in the enum.
        deploying = sorted(k for k, v in actual.items() if Permission.DEPLOY in v)
        assert not deploying, f"tools granted DEPLOY: {deploying}"

    def test_expected_egress_posture_is_pinned_exactly(self):
        """network_egress is NOT enforced (named in the floor's KNOWN_UNENFORCED).
        Pinning the declared values still has value: it is the evidence a reviewer
        reads, and a silent flip of a local-only tool to egress-permitted should
        be visible even while the field is inert."""
        expected_no_egress = {
            "arkheia_audit_log",
            "run_ollama",
            "memory_store",
            "memory_retrieve",
            "memory_relate",
        }
        actual_no_egress = {k for k, v in REGISTRY.items() if not v.network_egress}
        assert actual_no_egress == expected_no_egress

    def test_no_shipped_tool_requires_human_confirm(self):
        """Pins the fact that the newly-live requires_human_confirm branch is not
        reached by any shipped tool today. Honest bucket: the mechanism is
        enforced and tested; whether a tool should declare it is a product
        decision, named in the PR body."""
        confirm_required = sorted(
            k for k, v in REGISTRY.items() if v.requires_human_confirm
        )
        assert confirm_required == []


# ---------------------------------------------------------------------------
# 11 — the policy handed to a caller cannot be used to alter the registry
# ---------------------------------------------------------------------------

class TestReturnedPolicyCannotWidenTheRegistry:
    """CRITERION 11 — PRIVILEGE ESCALATION THROUGH THE VALUE THE GATE HANDS BACK.

    ``check()`` returns the REGISTRY's own ``ToolPolicy`` instance (pinned by
    ``test_registered_tool_is_allowed_and_returns_its_own_policy``: ``policy is
    REGISTRY[tool_name]``). Sharing the instance is only safe if the instance is
    immutable. Before this branch ``ToolPolicy`` was a plain, non-frozen
    ``@dataclass`` whose ``permissions`` field was a ``list``, so every caller of
    the gate held a writable handle on the gate's own decision data::

        p = check("memory_store")          # egress-denied, READ+WRITE
        p.network_egress = True            # writes THROUGH to REGISTRY
        p.permissions.append(Permission.DEPLOY)
        p.requires_human_confirm = False
        check("memory_store")              # now egress-permitted + DEPLOY, for
                                           # every caller, for the life of the
                                           # process

    Blast radius: any code path that receives a policy — i.e. every gated tool
    body, since ``check()`` is documented as "the FIRST statement in every MCP
    tool body" — could silently widen its own permissions AND everyone else's.
    The widening is process-wide and permanent: nothing re-reads the declared
    allowlist after import, and ``assert_registry_covers()`` only compares NAMES
    at startup, so a mutated policy passes the startup self-check unchanged.

    The property these tests establish: a ToolPolicy obtained from the gate
    CANNOT be used to alter what the gate subsequently decides. Each test drives
    the escalation end to end and asserts the SECOND ``check()`` still returns
    the restrictive declared value — a determinate value, not "unchanged".
    """

    def test_scalar_field_write_through_a_returned_policy_cannot_widen_egress(self):
        """The reproducer verbatim. memory_store is declared local-only."""
        handed_out = check("memory_store")
        assert handed_out.network_egress is False  # baseline: the declared value

        try:
            handed_out.network_egress = True
        except FrozenInstanceError:
            pass  # the write was refused — that is one correct outcome

        # The decision the gate makes NEXT is what actually matters.
        assert check("memory_store").network_egress is False, (
            "a caller widened the registry's egress posture through the policy "
            "object the gate handed it — process-wide and permanent"
        )

    def test_mutable_field_write_through_a_returned_policy_cannot_grant_deploy(self):
        """`frozen=True` alone does NOT protect a mutable FIELD: a list inside a
        frozen dataclass is still mutable in place. `permissions` is the field
        `check()` itself reads, so widening it widens the gate's own decision."""
        handed_out = check("memory_retrieve")
        assert set(handed_out.permissions) == {Permission.READ}

        try:
            handed_out.permissions.append(Permission.DEPLOY)
        except AttributeError:
            pass  # tuple has no .append — the field is immutable

        assert set(check("memory_retrieve").permissions) == {Permission.READ}, (
            "a caller granted itself DEPLOY — the most dangerous grant in the "
            "enum — by appending to the permission list it was handed"
        )

    def test_permissions_cannot_be_emptied_through_a_returned_policy(self):
        """The denial-of-service direction of the same hole: clearing the list
        turns a live tool into a permanent default-deny for the whole process,
        because an empty permission set is a deny branch."""
        handed_out = check("arkheia_verify")
        assert set(handed_out.permissions) == {Permission.READ}

        try:
            handed_out.permissions.clear()
        except AttributeError:
            pass

        assert set(check("arkheia_verify").permissions) == {Permission.READ}

    def test_confirm_requirement_cannot_be_cleared_through_a_returned_policy(
        self, registry_sandbox
    ):
        """The human-approval control is the one an attacker most wants gone.
        Register a confirm-required policy, obtain it via an APPROVED call, then
        try to clear the flag through the returned object."""
        registry_sandbox["deploy_to_prod"] = ToolPolicy(
            name="deploy_to_prod",
            permissions=[Permission.DEPLOY],
            requires_human_confirm=True,
        )
        handed_out = check("deploy_to_prod", human_confirmed=True)
        assert handed_out.requires_human_confirm is True

        try:
            handed_out.requires_human_confirm = False
        except FrozenInstanceError:
            pass

        # Without approval it must STILL be denied.
        with pytest.raises(PolicyViolation) as exc:
            check("deploy_to_prod")
        assert "human confirmation" in exc.value.reason

    def test_name_cannot_be_repointed_through_a_returned_policy(self):
        """Repointing `name` makes check(key) hand back a policy describing a
        different tool — the exact confusion
        test_registry_keys_match_their_policy_names exists to forbid."""
        handed_out = check("memory_retrieve")
        assert handed_out.name == "memory_retrieve"

        try:
            handed_out.name = "run_grok"
        except FrozenInstanceError:
            pass

        assert check("memory_retrieve").name == "memory_retrieve"
        mismatched = sorted(f"{k}->{v.name}" for k, v in REGISTRY.items() if k != v.name)
        assert mismatched == []

    # -- the mechanism, pinned determinately ---------------------------------

    @pytest.mark.parametrize(
        "field,new_value",
        [
            ("name", "run_grok"),
            ("permissions", [Permission.DEPLOY]),
            ("description", "x"),
            ("network_egress", True),
            ("requires_human_confirm", False),
        ],
    )
    def test_every_policy_field_refuses_assignment(self, field, new_value):
        """EVERY field, not just the interesting ones: the class is frozen, so
        the guarantee does not depend on which field a future control uses."""
        handed_out = check("memory_store")
        with pytest.raises(FrozenInstanceError):
            setattr(handed_out, field, new_value)

    def test_every_policy_field_holds_an_immutable_type(self):
        """`frozen=True` protects the BINDING, not the object bound. Enumerated
        over the real dataclass fields so a future mutable field (a list of
        allowed hosts, a dict of rate limits) cannot be added silently."""
        immutable_types = (str, bool, int, float, tuple, frozenset, type(None), Enum)
        policy = check("memory_store")
        offenders = sorted(
            f"{f.name}:{type(getattr(policy, f.name)).__name__}"
            for f in fields(policy)
            if not isinstance(getattr(policy, f.name), immutable_types)
        )
        assert offenders == [], (
            f"ToolPolicy field(s) hold a mutable object: {offenders}. A frozen "
            f"dataclass still lets a caller mutate such a field IN PLACE."
        )
        # Work-done assertion: an empty field list would vacuously pass above.
        assert len(fields(policy)) == 5

    def test_the_immutability_holds_for_every_shipped_policy(self):
        """Per tool, not on one sample — a single entry constructed differently
        would be the one that is still writable."""
        widened = []
        for name in sorted(EXPECTED_TOOLS):
            declared = check(name).network_egress
            try:
                check(name).network_egress = not declared
            except FrozenInstanceError:
                pass
            if check(name).network_egress is not declared:
                widened.append(name)
        assert widened == [], f"policies mutable through the gate: {widened}"

    def test_replace_produces_an_independent_policy(self):
        """The sanctioned way to derive a variant. It must NOT write back into
        the registry entry it was derived from."""
        original = check("memory_store")
        derived = replace(original, network_egress=True)
        assert derived.network_egress is True
        assert derived is not original
        assert check("memory_store").network_egress is False
        assert set(derived.permissions) == {Permission.READ, Permission.WRITE}


# ---------------------------------------------------------------------------
# 12 — the registry container itself is not writable through the public name
# ---------------------------------------------------------------------------

class TestRegistryContainerIsReadOnly:
    """LATE REGISTRATION. ``assert_registry_covers()`` is a STARTUP check; it
    compares names once, at import time, and is never consulted again. So any
    module that could write to the public ``REGISTRY`` name could add or replace
    a policy after the self-check had already passed, and nothing would notice.

    That does not make a NEW tool dispatchable — FastMCP's decorator registry is
    the effective allowlist (INV-2) — but replacing an EXISTING entry with a
    widened one is a real escalation, and it is exactly the shape the returned-
    policy hole had. The public name is therefore a read-only view. In-process
    Python has no hard boundary (``_REGISTRY`` is reachable by anyone who reaches
    for it deliberately, which is how the test sandbox works), so what this pins
    is that widening the live allowlist can no longer happen by ACCIDENT or as an
    implicit capability of merely importing the gate.
    """

    def test_registry_rejects_late_registration_of_a_new_policy(self):
        with pytest.raises(TypeError):
            REGISTRY["late_backdoor"] = ToolPolicy(
                name="late_backdoor", permissions=[Permission.DEPLOY]
            )
        assert "late_backdoor" not in REGISTRY
        with pytest.raises(PolicyViolation) as exc:
            check("late_backdoor")
        assert "not in allowlist" in exc.value.reason

    def test_registry_rejects_replacing_an_existing_policy(self):
        with pytest.raises(TypeError):
            REGISTRY["memory_store"] = ToolPolicy(
                name="memory_store",
                permissions=[Permission.DEPLOY],
                network_egress=True,
            )
        assert set(check("memory_store").permissions) == {
            Permission.READ, Permission.WRITE,
        }
        assert check("memory_store").network_egress is False

    def test_registry_rejects_deletion(self):
        with pytest.raises(TypeError):
            del REGISTRY["arkheia_verify"]
        assert check("arkheia_verify").name == "arkheia_verify"

    def test_registry_rejects_bulk_mutation(self):
        for op in ("clear", "update", "pop", "popitem", "setdefault"):
            assert not hasattr(REGISTRY, op), (
                f"REGISTRY exposes the mutating method {op!r} — the public name "
                f"must be a read-only view"
            )
        assert sorted(REGISTRY) == sorted(EXPECTED_TOOLS)


# ---------------------------------------------------------------------------
# 13 — alias evasion: no spelling of an allowed name other than the exact one
# ---------------------------------------------------------------------------

class TestAliasEvasion:
    """The allowlist is an exact string match on a dict key. These pin that no
    alternative SPELLING of an allowed name resolves — case, unicode
    normalisation forms, homoglyphs, separators, whitespace, zero-width
    characters, prefixes. Each input is asserted to be a genuine near-miss
    (absent from REGISTRY) and then required to be refused with the default-deny
    reason, so a future normalisation step cannot quietly make one of them land.
    """

    EVASIONS = [
        # case
        "MEMORY_STORE", "Memory_Store", "memory_Store",
        # separators
        "memory-store", "memory.store", "memory store", "memorystore",
        "memory__store", "memory/store",
        # whitespace / control
        " memory_store", "memory_store ", "\tmemory_store", "memory_store\n",
        "memory_store\r", "memory_store\x00", "memory\u00a0store",  # NBSP
        # zero-width and bidi
        "memory​store", "memory_store​", "‮memory_store",
        # unicode normalisation: NFKC of these folds to "memory_store"
        "ﬁmemory_store", "memory＿store", "ｍemory_store",
        "memory_ｓtore", "𝗆emory_store",
        # homoglyphs (Cyrillic о / е)
        "memоry_store", "mеmory_store",
        # prefix / namespace
        "mcp__memory_store", "mcp_server.memory_store", "arkheia:memory_store",
        "/memory_store", "memory_store()",
        # combining marks that normalise away under NFD/NFC round-trips
        "memory_stóre",
    ]

    @pytest.mark.parametrize("alias", EVASIONS)
    def test_alias_spelling_of_an_allowed_tool_is_denied(self, alias):
        assert alias not in REGISTRY, f"{alias!r} is not a near-miss — it IS a key"
        with pytest.raises(PolicyViolation) as exc:
            check(alias)
        assert exc.value.tool_name == alias
        assert "not in allowlist" in exc.value.reason
        assert "default deny" in exc.value.reason

    def test_the_evasion_corpus_is_not_empty_and_targets_a_real_tool(self):
        """Work-done assertion: an empty corpus would make the sweep vacuous."""
        assert len(self.EVASIONS) == 32
        assert "memory_store" in REGISTRY

    def test_the_exact_spelling_still_resolves(self):
        """Positive control: the evasion sweep must not be passing because
        check() denies everything."""
        assert check("memory_store").name == "memory_store"


# ---------------------------------------------------------------------------
# 5 + 6 — the two controls that were read nowhere before this branch
# ---------------------------------------------------------------------------

class TestPolicyControlsAreEnforced:

    def test_empty_permission_set_is_denied(self, registry_sandbox):
        """CRITERION 5. Before this branch `permissions` was read zero times, so a
        policy granting nothing allowed exactly as much as one granting DEPLOY."""
        registry_sandbox["neutered"] = ToolPolicy(name="neutered", permissions=[])
        with pytest.raises(PolicyViolation) as exc:
            check("neutered")
        assert exc.value.tool_name == "neutered"
        assert "empty permission set" in exc.value.reason
        # Distinguish this branch from the not-registered branch: the tool IS
        # registered, so the reason must NOT claim it is absent from the allowlist.
        assert "not in allowlist" not in exc.value.reason

    def test_requires_human_confirm_denies_without_approval(self, registry_sandbox):
        """CRITERION 6. Documented as 'True = block until explicit approval'; it
        blocked nothing because it was read nowhere."""
        registry_sandbox["deploy_to_prod"] = ToolPolicy(
            name="deploy_to_prod",
            permissions=[Permission.DEPLOY],
            requires_human_confirm=True,
        )
        with pytest.raises(PolicyViolation) as exc:
            check("deploy_to_prod")
        assert exc.value.tool_name == "deploy_to_prod"
        assert "human confirmation" in exc.value.reason
        assert "not in allowlist" not in exc.value.reason
        assert "empty permission set" not in exc.value.reason

    def test_requires_human_confirm_allows_with_approval(self, registry_sandbox):
        registry_sandbox["deploy_to_prod"] = ToolPolicy(
            name="deploy_to_prod",
            permissions=[Permission.DEPLOY],
            requires_human_confirm=True,
        )
        policy = check("deploy_to_prod", human_confirmed=True)
        assert policy.name == "deploy_to_prod"

    def test_approval_does_not_override_the_allowlist(self, registry_sandbox):
        """human_confirmed must not become a skeleton key: an approval for a tool
        that is not registered at all is still a deny."""
        with pytest.raises(PolicyViolation) as exc:
            check("never_registered", human_confirmed=True)
        assert "not in allowlist" in exc.value.reason

    def test_approval_does_not_override_an_empty_permission_set(self, registry_sandbox):
        registry_sandbox["neutered"] = ToolPolicy(name="neutered", permissions=[])
        with pytest.raises(PolicyViolation) as exc:
            check("neutered", human_confirmed=True)
        assert "empty permission set" in exc.value.reason

    def test_human_confirmed_is_keyword_only(self):
        """Positional confirmation is how an approval gets passed by accident."""
        sig = inspect.signature(check)
        param = sig.parameters["human_confirmed"]
        assert param.kind is inspect.Parameter.KEYWORD_ONLY
        assert param.default is False, "the approval must default to absent"

    def test_confirm_default_is_deny_for_every_shipped_tool_if_flagged(
        self, registry_sandbox
    ):
        """The control must hold for every shipped policy, not just a synthetic
        one: flip the flag on each real policy and observe the deny."""
        for name in sorted(EXPECTED_TOOLS):
            registry_sandbox[name] = replace(
                REGISTRY[name], requires_human_confirm=True
            )
            with pytest.raises(PolicyViolation) as exc:
                check(name)
            assert "human confirmation" in exc.value.reason, name
            assert check(name, human_confirmed=True).name == name


# ---------------------------------------------------------------------------
# 7 — advertised identifiers, exercised VERBATIM under two transports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestAdvertisedToolNamesTwoTransports:
    """DONE.md: 'a test for an advertised identifier must exercise it verbatim,
    end-to-end ... under at least two transports whose decode behaviour differs.'

    Tool names ARE advertised identifiers — published to every orchestrator via
    ``tools/list`` and then supplied back as strings to ``tools/call``.

    Transport A: direct in-process call of the decorated coroutine. The Python
                 attribute name resolves at import time; no string is decoded.
    Transport B: ``FastMCP.call_tool(name, arguments)``, which looks the name up
                 as a STRING in the framework's tool table and validates
                 arguments through a generated pydantic model.

    They differ exactly where it matters: transport A cannot see a name-table
    mismatch and transport B cannot see a gate call that was never wired, so a
    single transport would agree with a broken server.
    """

    async def test_advertised_set_is_exactly_the_expected_set(self):
        advertised = {t.name for t in await srv.mcp.list_tools()}
        assert advertised, "list_tools() returned nothing — an empty check must fail"
        missing = sorted(EXPECTED_TOOLS - advertised)
        extra = sorted(advertised - EXPECTED_TOOLS)
        assert not missing, f"expected tools NOT advertised: {missing}"
        assert not extra, (
            f"tools advertised that this test does not know about: {extra}. Every "
            f"advertised name is reachable by any orchestrator, so an unreviewed "
            f"one is an ungoverned surface."
        )

    async def test_every_advertised_name_verbatim_passes_the_gate(self):
        """Transport A, using the VERBATIM advertised string (not a literal
        retyped here) as the argument to the gate."""
        advertised = [t.name for t in await srv.mcp.list_tools()]
        assert len(advertised) == 9, f"expected 9 advertised tools, got {len(advertised)}"
        for name in advertised:
            policy = check(name)
            assert policy.name == name

    async def test_every_advertised_name_verbatim_dispatches(self, monkeypatch):
        """Transport B: FastMCP resolves the VERBATIM advertised string. A tool
        that dispatches proves the name in the advertisement and the name in the
        dispatch table are the same string — which comparing them as strings
        cannot prove, and which is precisely the bug class DONE.md clause 10 was
        earned on in this repo.

        Provider and proxy calls are stubbed so the assertion under test is name
        resolution, not network reachability: an unreachable provider would fail
        first and make this assertion pass against a broken name table.
        """
        async def _fake_verify(**kwargs):
            return {"risk_level": "LOW", "confidence": 0.9, "detection_id": "t"}

        async def _fake_audit(**kwargs):
            return {"events": [], "summary": {}}

        async def _fake_provider(prompt, model):
            return {"response": "stub", "model": model, "prompt_hash": "0" * 64}

        monkeypatch.setattr(srv.proxy, "verify", _fake_verify)
        monkeypatch.setattr(srv.proxy, "get_audit_log", _fake_audit)
        for fn in ("call_grok", "call_gemini", "call_ollama", "call_together"):
            monkeypatch.setattr(srv, fn, _fake_provider)

        args_for = {
            "arkheia_verify": {"prompt": "p", "response": "r", "model": "m"},
            "arkheia_audit_log": {"limit": 1},
            "run_grok": {"prompt": "p"},
            "run_gemini": {"prompt": "p"},
            "run_together": {"prompt": "p"},
            "run_ollama": {"prompt": "p"},
            "memory_store": {
                "name": "E", "entity_type": "t", "observations": ["o"],
            },
            "memory_retrieve": {"query": "E"},
            "memory_relate": {
                "from_entity": "E", "relation_type": "r", "to_entity": "E",
            },
        }

        advertised = [t.name for t in await srv.mcp.list_tools()]
        assert set(args_for) == set(advertised), (
            f"argument fixtures drifted from the advertised set: "
            f"only-in-fixtures={sorted(set(args_for) - set(advertised))}, "
            f"only-advertised={sorted(set(advertised) - set(args_for))}"
        )

        dispatched = []
        for name in advertised:
            result = await srv.mcp.call_tool(name, args_for[name])
            assert result is not None, name
            dispatched.append(name)

        # Work-done assertion: a loop that dispatched nothing must not pass.
        assert sorted(dispatched) == sorted(EXPECTED_TOOLS), (
            f"dispatched {len(dispatched)} of {len(EXPECTED_TOOLS)}: "
            f"not dispatched = {sorted(EXPECTED_TOOLS - set(dispatched))}"
        )

    async def test_a_name_not_advertised_is_refused_by_both_transports(self):
        """The negative under both transports. Transport B refuses via FastMCP's
        own tool table — which is the evidence that REGISTRY is a SHADOW allowlist:
        the framework refuses before check() is ever consulted."""
        advertised = {t.name for t in await srv.mcp.list_tools()}
        rogue = "exfiltrate_secrets"
        assert rogue not in advertised

        with pytest.raises(PolicyViolation):
            check(rogue)

        with pytest.raises(Exception) as exc:
            await srv.mcp.call_tool(rogue, {})
        assert rogue in str(exc.value)


# ---------------------------------------------------------------------------
# 8 + 9 — registry coverage, fail closed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRegistryCoverageAdvertised:

    async def test_advertised_tools_and_registry_are_in_parity(self):
        advertised = {t.name for t in await srv.mcp.list_tools()}
        assert sorted(advertised) == sorted(REGISTRY), (
            f"advertised-but-ungoverned={sorted(advertised - set(REGISTRY))}, "
            f"registry-but-not-advertised={sorted(set(REGISTRY) - advertised)}"
        )


class TestRegistryCoverage:
    """Deliberately SYNCHRONOUS: startup_policy_selfcheck() owns its own event
    loop via anyio.run (it runs before the server's loop exists), so it cannot be
    called from inside a running loop."""

    def test_startup_selfcheck_passes_on_the_real_server(self):
        srv.startup_policy_selfcheck()  # must not raise

    def test_startup_selfcheck_ACTUALLY_checks(self, registry_sandbox):
        """The companion above is a PERMISSIVE assertion: 'does not raise' passes
        just as happily against a self-check whose body was deleted. Mutation M28
        (replacing `assert_registry_covers(advertised)` with `pass`) survived the
        entire suite until this test existed.

        So drive it the other way: make the real server's advertised set diverge
        from REGISTRY and require the self-check to REFUSE. Now the mutation is
        killed, because a self-check that no longer checks cannot refuse.
        """
        del registry_sandbox["memory_relate"]
        with pytest.raises(RegistryCoverageError) as exc:
            srv.startup_policy_selfcheck()
        assert "memory_relate" in exc.value.reason
        assert "ungoverned" in exc.value.reason
        assert "refusing to start" in exc.value.reason

    def test_coverage_fails_on_an_advertised_tool_with_no_policy(self):
        with pytest.raises(RegistryCoverageError) as exc:
            assert_registry_covers(sorted(EXPECTED_TOOLS) + ["rogue_exfiltrate"])
        assert "rogue_exfiltrate" in exc.value.reason
        assert "ungoverned" in exc.value.reason

    def test_coverage_fails_on_dead_policy(self):
        with pytest.raises(RegistryCoverageError) as exc:
            assert_registry_covers(sorted(EXPECTED_TOOLS - {"memory_relate"}))
        assert "memory_relate" in exc.value.reason
        assert "dead policy" in exc.value.reason

    def test_coverage_fails_on_an_empty_advertised_set(self):
        """DONE.md clause 9: a check that measured nothing must not report clean."""
        with pytest.raises(RegistryCoverageError) as exc:
            assert_registry_covers([])
        assert "never actually checked" in exc.value.reason

    def test_coverage_error_is_a_policy_violation(self):
        """So an existing `except PolicyViolation` handler cannot let a coverage
        failure through as an unrelated crash."""
        assert issubclass(RegistryCoverageError, PolicyViolation)


# ---------------------------------------------------------------------------
# Receipted gate — allow and deny decisions leave attributable evidence
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestReceiptedGate:

    async def test_allowed_dispatch_decision_is_written_to_the_audit_rail(
        self, tmp_path
    ):
        log_path = tmp_path / "gate.jsonl"
        decision = await decide(
            "memory_retrieve",
            call_site="unit",
            argument_keys=["query", "limit"],
            log_path=log_path,
        )

        assert decision.allowed is True
        assert decision.policy is REGISTRY["memory_retrieve"]
        assert decision.receipt_status == receipts.STATUS_RECORDED
        assert decision.receipt_id

        row = receipts.find_receipt(log_path, decision.receipt_id)
        assert row is not None
        assert row["event_type"] == "mcp.tool_gate"
        assert row["tool"] == "memory_retrieve"
        assert row["decision"] == receipts.DECISION_ALLOWED
        assert row["control"] == "tool_registry_gate"
        assert row["call_site"] == "unit"
        assert row["permissions_applied"] == ["read"]
        assert row["argument_keys"] == ["limit", "query"]
        assert row["deny_code"] is None
        assert row["seq"] == 1
        assert row["prev_hash"] == "0" * 64
        assert row["this_hash"]

    async def test_concurrent_dispatch_decisions_consume_unique_sequence_numbers(
        self, tmp_path
    ):
        log_path = tmp_path / "gate.jsonl"

        decisions = await asyncio.gather(
            *[
                decide(
                    "memory_retrieve",
                    call_site=f"unit-{idx}",
                    argument_keys=["query"],
                    log_path=log_path,
                )
                for idx in range(20)
            ]
        )

        assert all(d.receipt_status == receipts.STATUS_RECORDED for d in decisions)
        rows = receipts.read_rows(log_path)
        assert len(rows) == 20
        assert [row["seq"] for row in rows] == list(range(1, 21))
        assert len({row["receipt_id"] for row in rows}) == 20
        assert len({row["this_hash"] for row in rows}) == 20
        prev_hash = "0" * 64
        for row in rows:
            assert row["prev_hash"] == prev_hash
            prev_hash = row["this_hash"]

    async def test_denied_dispatch_decision_is_written_before_refusal_reaches_caller(
        self, tmp_path
    ):
        log_path = tmp_path / "gate.jsonl"

        with pytest.raises(PolicyViolation) as exc:
            await check_receipted("exfiltrate_secrets", log_path=log_path)

        assert exc.value.tool_name == "exfiltrate_secrets"
        assert exc.value.code == "not_registered"
        assert exc.value.receipt_status == receipts.STATUS_RECORDED
        assert exc.value.receipt_id in str(exc.value)

        row = receipts.find_receipt(log_path, exc.value.receipt_id)
        assert row is not None
        assert row["decision"] == receipts.DECISION_DENIED
        assert row["tool"] == "exfiltrate_secrets"
        assert row["deny_code"] == "not_registered"
        assert "default deny" in row["deny_reason"]
        assert row["permissions_applied"] is None

    async def test_dispatch_chokepoint_receipts_an_unknown_name(self, tmp_path, monkeypatch):
        log_path = tmp_path / "dispatch.jsonl"
        monkeypatch.setenv("ARKHEIA_TOOL_GATE_RECEIPT_LOG", str(log_path))

        with pytest.raises(PolicyViolation) as exc:
            await srv.mcp.call_tool("exfiltrate_secrets", {})

        assert exc.value.receipt_status == receipts.STATUS_RECORDED
        row = receipts.find_receipt(log_path, exc.value.receipt_id)
        assert row is not None
        assert row["call_site"] == "dispatch"
        assert row["decision"] == receipts.DECISION_DENIED
        assert row["tool"] == "exfiltrate_secrets"

    async def test_argument_values_do_not_enter_the_policy_receipt(self, tmp_path):
        log_path = tmp_path / "gate.jsonl"
        secret = "sk-ant-VERYSECRETTOOLARGUMENTVALUE1234567890"

        decision = await decide(
            "memory_store",
            argument_keys=["name", "observations"],
            log_path=log_path,
        )

        assert decision.receipt_status == receipts.STATUS_RECORDED
        assert secret.encode() not in log_path.read_bytes()
        row = receipts.find_receipt(log_path, decision.receipt_id)
        assert row is not None
        assert row["argument_keys"] == ["name", "observations"]
        assert "argument_values" not in row

    async def test_emit_reports_unrecorded_when_readback_cannot_find_receipt(
        self, tmp_path, monkeypatch
    ):
        log_path = tmp_path / "gate.jsonl"
        receipt_id = receipts.new_receipt_id()
        record = receipts.build_record(
            receipt_id=receipt_id,
            tool="memory_retrieve",
            decision=receipts.DECISION_ALLOWED,
            event_type="mcp.tool_gate",
            control="tool_registry_gate",
            call_site="unit",
        )
        real_find_receipt = receipts.find_receipt
        readback_calls = []

        def missing_readback(path, candidate):
            readback_calls.append((path, candidate))
            return None

        monkeypatch.setattr(receipts, "find_receipt", missing_readback)

        assert await receipts.emit(log_path, record) is False
        assert readback_calls == [(log_path, receipt_id)]
        assert real_find_receipt(log_path, receipt_id) is not None

    async def test_receipt_failure_does_not_change_the_gate_decision(self, tmp_path):
        denied = await decide("exfiltrate_secrets", log_path="relative.jsonl")
        assert denied.allowed is False
        assert denied.violation is not None
        assert denied.receipt_status == receipts.STATUS_UNRECORDED
        assert denied.violation.receipt_status == receipts.STATUS_UNRECORDED

        allowed = await decide("memory_retrieve", log_path="relative.jsonl")
        assert allowed.allowed is True
        assert allowed.policy is REGISTRY["memory_retrieve"]
        assert allowed.receipt_status == receipts.STATUS_UNRECORDED


# ---------------------------------------------------------------------------
# 10 — the refusal contract, pinned per tool
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
class TestRefusalContract:
    """The gate refuses in TWO different shapes depending on the tool, which is an
    inconsistency this branch pins rather than changes (changing it alters the MCP
    wire contract for four tools — named in the PR body as a decision for David).

    Five tools let PolicyViolation propagate: the orchestrator sees a protocol
    error. Four catch it and return ``{"error": ..., "risk_level": "UNKNOWN"}``:
    the orchestrator sees a SUCCESS carrying a *detection* verdict, so a
    governance refusal is rendered as detection uncertainty.
    """

    async def test_raising_and_dict_returning_sets_cover_every_tool(self):
        assert RAISING_TOOLS | DICT_RETURNING_TOOLS == EXPECTED_TOOLS
        assert not (RAISING_TOOLS & DICT_RETURNING_TOOLS)

    @pytest.mark.parametrize("tool_name", sorted(RAISING_TOOLS))
    async def test_deregistered_tool_propagates_policy_violation(
        self, tool_name, registry_sandbox
    ):
        del registry_sandbox[tool_name]
        fn = getattr(srv, tool_name)
        with pytest.raises(PolicyViolation) as exc:
            await fn(**self._args(tool_name))
        assert exc.value.tool_name == tool_name

    @pytest.mark.parametrize("tool_name", sorted(DICT_RETURNING_TOOLS))
    async def test_deregistered_provider_tool_returns_an_error_dict(
        self, tool_name, registry_sandbox
    ):
        del registry_sandbox[tool_name]
        fn = getattr(srv, tool_name)
        result = await fn(prompt="p")
        assert isinstance(result, dict)
        # Pin the rendered wording an operator reads. This is a POLICY refusal
        # being reported as an UNKNOWN detection risk — pinned so the conflation
        # is visible in the suite rather than only in the source.
        assert result["risk_level"] == "UNKNOWN"
        assert "Policy violation for" in result["error"]
        assert tool_name in result["error"]
        assert "not in allowlist" in result["error"]
        # And it must NOT look like a successful screening.
        assert "arkheia" not in result
        assert "response" not in result

    @staticmethod
    def _args(tool_name: str) -> dict:
        return {
            "arkheia_verify": {"prompt": "p", "response": "r", "model": "m"},
            "arkheia_audit_log": {"limit": 1},
            "memory_store": {
                "name": "E", "entity_type": "t", "observations": ["o"],
            },
            "memory_retrieve": {"query": "E"},
            "memory_relate": {
                "from_entity": "E", "relation_type": "r", "to_entity": "E",
            },
        }[tool_name]

    @pytest.mark.parametrize("tool_name", sorted(RAISING_TOOLS))
    async def test_gate_refuses_BEFORE_any_side_effect(
        self, tool_name, registry_sandbox, monkeypatch
    ):
        """The gate must be the first thing that happens. If the tool body did its
        work and then checked, the refusal would be cosmetic."""
        called = []

        async def _tripwire(*a, **k):
            called.append(1)
            return {}

        for attr in (
            "store_entity", "retrieve_entities", "store_relation",
        ):
            monkeypatch.setattr(srv, attr, _tripwire)
        monkeypatch.setattr(srv.proxy, "verify", _tripwire)
        monkeypatch.setattr(srv.proxy, "get_audit_log", _tripwire)

        del registry_sandbox[tool_name]
        with pytest.raises(PolicyViolation):
            await getattr(srv, tool_name)(**self._args(tool_name))
        assert called == [], (
            f"{tool_name} performed its side effect despite the policy denial"
        )

    @pytest.mark.parametrize("tool_name", sorted(DICT_RETURNING_TOOLS))
    async def test_provider_gate_refuses_before_calling_the_provider(
        self, tool_name, registry_sandbox, monkeypatch
    ):
        called = []

        async def _tripwire(*a, **k):
            called.append(1)
            return {"response": "leaked", "model": "m", "prompt_hash": "0"}

        for fn in ("call_grok", "call_gemini", "call_ollama", "call_together"):
            monkeypatch.setattr(srv, fn, _tripwire)
        monkeypatch.setattr(srv.proxy, "verify", _tripwire)

        del registry_sandbox[tool_name]
        result = await getattr(srv, tool_name)(prompt="p")
        assert result.get("risk_level") == "UNKNOWN"
        assert called == [], (
            f"{tool_name} called its provider despite the policy denial — the "
            f"refusal would be cosmetic and the prompt would already have left "
            f"the process"
        )
