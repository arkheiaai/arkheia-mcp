"""
Tool registry and policy gate.

Defines which tools the MCP Trust Server is allowed to expose.
Default deny: any tool not in REGISTRY cannot be called.

Policy rules are evaluated synchronously before the tool body executes.
A PolicyViolation exception bubbles up as a structured MCP error — the
orchestrator sees a refusal, not a crash.

THE DECISION IS RECEIPTED (added 2026-07-26)
--------------------------------------------
This gate makes an allow/deny decision about tool execution on behalf of an
orchestrator, which is a governed decision, and until now it left no record of
any kind. The deny side was the serious half: a blocked tool call produced an
exception message on the wire and nothing else, so afterwards there was no way
to distinguish "the agent was refused 400 times" from "the agent never asked".
A refusal nobody can see later cannot be investigated and cannot be contested.

So every decision this gate reaches now writes one row through
``mcp_server.receipts`` -> ``proxy.audit.writer.AuditWriter`` — the SAME rail the
proxy uses for detection events, the registry uses for auth decisions and the
memory tools use for graph mutations. JSONL, secrets redaction, tamper-evident
hash chain (seq / prev_hash / this_hash). One rail, not a second one.

``check()`` stays exactly what it was: pure, synchronous, no I/O, the decision
itself. ``check_receipted()`` is the async wrapper that makes the same decision
and records it, and it is what the dispatch chokepoint calls — see
``mcp_server.server.GatedFastMCP``.

FAILURE POSTURE — fail-open on the RECEIPT, never on the DECISION
-----------------------------------------------------------------
A receipt that cannot be written must never turn a deny into an allow, and must
never turn a deny into a crash either (the standing ruling: a receipt failure
must not block the halt). It must also never be silent: an unwritten receipt is
logged at error level and surfaced to the caller as
``receipt_status="unrecorded"``.

The known trap, seen on a sibling flow in this repo and deliberately NOT
reproduced here: wrapping the whole receipt path in ``except Exception: log``
makes the fail-open posture correct and simultaneously destroys the
caller-boundary guarantee, because a typo'd decision then yields a log line and
no row at all. Here a decision that cannot be represented as a record is written
as ``DECISION_UNREPRESENTABLE`` carrying the offending value, so it lands in the
stream instead of disappearing; and the decision strings are module constants
whose call sites are pinned statically by ``tests/test_tool_gate_floor.py``
INV-6, so the unrepresentable branch is unreachable by construction rather than
merely unlikely.

Hook for enterprise upgrade:
  - Load REGISTRY from a signed YAML / remote policy store
  - Add caller-identity checks (which session, which agent)
  - Add per-tool rate limits
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType

from mcp_server import receipts

logger = logging.getLogger(__name__)


class Permission(str, Enum):
    READ    = "read"      # query / retrieve
    EXECUTE = "execute"   # call a model or tool
    WRITE   = "write"     # mutate persistent state
    DEPLOY  = "deploy"    # push to production systems


@dataclass(frozen=True)
class ToolPolicy:
    """
    One tool's policy. FROZEN, and ``permissions`` is a TUPLE, on purpose.

    ``check()`` hands the caller the live policy object out of the registry. While
    this was a mutable dataclass holding a mutable list, any caller could widen
    the policy for every subsequent decision in the process —
    ``check("arkheia_verify").permissions.append(Permission.DEPLOY)`` mutated the
    registry's own object, and ``policy.requires_human_confirm = False`` turned a
    confirm-gated tool into an open one. Neither needed a second reference to the
    registry: the object the gate returns on the ALLOW path was enough.
    """
    name: str
    permissions: tuple[Permission, ...]
    description: str = ""
    network_egress: bool = True        # False = local-only (no outbound HTTP)
    requires_human_confirm: bool = False  # True = block until explicit approval


# ---------------------------------------------------------------------------
# The allowlist
#
# ``_POLICIES`` is the dict; ``REGISTRY`` is a read-only view of it. Assigning
# ``REGISTRY["anything"] = ToolPolicy(...)`` raises TypeError, so a policy cannot
# be injected for an ungoverned tool through the public name every other module
# imports. This is not a process boundary — code that deliberately reaches for the
# private ``_POLICIES`` can still edit it, and code in this process could rebind
# ``check`` itself — but it removes the accidental and the incidental case, and it
# means the enterprise "load REGISTRY from a signed store" hook has exactly one
# write site to guard. What compensates for the rest: the boot-time coverage
# self-check, the dispatch gate consulting the registry on EVERY call rather than
# caching a decision, and the receipt recording the permissions actually applied.
# ---------------------------------------------------------------------------

_POLICIES: dict[str, ToolPolicy] = {
    # ── Detection & audit (read-only) ────────────────────────────────────────
    "arkheia_verify": ToolPolicy(
        name="arkheia_verify",
        permissions=(Permission.READ,),
        network_egress=True,
        description="Screen an AI response for fabrication risk",
    ),
    "arkheia_audit_log": ToolPolicy(
        name="arkheia_audit_log",
        permissions=(Permission.READ,),
        network_egress=False,
        description="Retrieve structured audit evidence",
    ),
    # ── External inference (execute + egress) ────────────────────────────────
    "run_grok": ToolPolicy(
        name="run_grok",
        permissions=(Permission.READ, Permission.EXECUTE),
        network_egress=True,
        description="Call xAI Grok API and screen response through Arkheia",
    ),
    "run_gemini": ToolPolicy(
        name="run_gemini",
        permissions=(Permission.READ, Permission.EXECUTE),
        network_egress=True,
        description="Call Google Gemini API and screen response through Arkheia",
    ),
    "run_together": ToolPolicy(
        name="run_together",
        permissions=(Permission.READ, Permission.EXECUTE),
        network_egress=True,
        description="Call Together AI API (Kimi K2.5 etc.) and screen response through Arkheia",
    ),
    # ── Local inference (execute, no egress) ─────────────────────────────────
    "run_ollama": ToolPolicy(
        name="run_ollama",
        permissions=(Permission.READ, Permission.EXECUTE),
        network_egress=False,
        description="Call local Ollama model and screen response through Arkheia",
    ),
    # ── Memory (local SQLite knowledge graph, no egress) ─────────────────────
    "memory_store": ToolPolicy(
        name="memory_store",
        permissions=(Permission.READ, Permission.WRITE),
        network_egress=False,
        description="Store an entity and observations in the persistent knowledge graph",
    ),
    "memory_retrieve": ToolPolicy(
        name="memory_retrieve",
        permissions=(Permission.READ,),
        network_egress=False,
        description="Retrieve entities and their observations from the knowledge graph",
    ),
    "memory_relate": ToolPolicy(
        name="memory_relate",
        permissions=(Permission.READ, Permission.WRITE),
        network_egress=False,
        description="Store a named relationship between two entities in the knowledge graph",
    ),
}

#: Read-only view of ``_POLICIES``. Every other module imports THIS name.
REGISTRY: Mapping[str, ToolPolicy] = MappingProxyType(_POLICIES)


# ---------------------------------------------------------------------------
# Policy gate
# ---------------------------------------------------------------------------

#: Machine-readable deny codes. The prose ``reason`` is for a human reading the
#: refusal; the code is what a query counts, so "we denied 400 calls" can be
#: broken down into "all four hundred were the same unknown tool name" versus
#: "someone is probing nine different names". Prose is not a taxonomy.
DENY_NOT_REGISTERED = "not_registered"
DENY_EMPTY_PERMISSIONS = "empty_permission_set"
DENY_HUMAN_CONFIRM_REQUIRED = "human_confirm_required"
DENY_MALFORMED_TOOL_NAME = "malformed_tool_name"

DENY_CODES = (
    DENY_NOT_REGISTERED,
    DENY_EMPTY_PERMISSIONS,
    DENY_HUMAN_CONFIRM_REQUIRED,
    DENY_MALFORMED_TOOL_NAME,
)


class PolicyViolation(Exception):
    """
    Raised when a tool call violates the allowlist or a policy rule.

    Carries the evidence a refused caller needs, per the legibility-and-recourse
    criterion: WHICH branch denied (``code``), WHY in plain words (``reason``),
    WHAT WOULD CLEAR IT (``remedy``), and the id of the row that recorded the
    refusal (``receipt_id`` / ``receipt_status``) so the caller can quote it. A
    bare "policy violation" with the reason swallowed is indistinguishable from a
    crash, and in a governance product it is indistinguishable from fabrication.
    """

    def __init__(
        self,
        tool_name: str,
        reason: str,
        *,
        code: str | None = None,
        remedy: str | None = None,
    ):
        self.tool_name = tool_name
        self.reason = reason
        self.code = code
        self.remedy = remedy
        #: Set by ``check_receipted`` after the refusal has been recorded. ``None``
        #: means this refusal came from the pure ``check()`` and was NOT receipted
        #: — deliberately not defaulted to a plausible-looking value, because "no
        #: receipt" and "a receipt I did not look up" must not read the same.
        self.receipt_id: str | None = None
        self.receipt_status: str | None = None
        super().__init__(f"Policy violation for '{tool_name}': {reason}")


class RegistryCoverageError(PolicyViolation):
    """
    Raised at startup when the set of tools ADVERTISED to orchestrators is not
    identical to the set of tools covered by REGISTRY.

    This exists because REGISTRY is a *shadow* allowlist: the effective allowlist
    is the MCP framework's own decorator registry, which is what decides which
    names are advertised via ``tools/list`` and which names ``call_tool`` will
    dispatch. A tool present in the framework but absent from REGISTRY is
    reachable by every orchestrator with no policy covering it. Refusing to start
    is the fail-closed answer: an ungoverned tool must never be advertised.
    """


def check(tool_name: str, *, human_confirmed: bool = False) -> ToolPolicy:
    """
    Evaluate the policy for tool_name and return it if the call is allowed.

    Args:
        tool_name:       The tool being invoked.
        human_confirmed: True only if this call site carries an explicit human
                         approval for a tool whose policy sets
                         ``requires_human_confirm``. Defaults to False, so a
                         confirm-required tool is denied unless the approval is
                         passed deliberately (fail closed).

    Returns:
        The ToolPolicy, if every policy rule allows the call.

    Raises:
        PolicyViolation, with a distinct reason per deny branch:
          * malformed name            -> default deny (not a str => not a key)
          * not registered            -> default deny
          * empty permission set      -> default deny (grants nothing => allows nothing)
          * requires_human_confirm    -> deny until an approval is supplied

    This is the PURE decision: synchronous, no I/O, and it writes NO RECEIPT.
    Production dispatch must go through ``check_receipted()``; a tool body calling
    this directly is defence in depth behind that gate, and the two are proved to
    reach the identical verdict by the differential test in
    ``mcp_server/tests/test_tool_gate_adversarial.py``.
    """
    # A non-string name is not merely unregistered, it is not even a possible key.
    # `{}.get(["x"])` raises TypeError: unhashable type, which is NOT a
    # PolicyViolation, so the refusal would arrive at the orchestrator as an
    # internal error and — worse — could not be receipted as a deny by any caller
    # that only knows to catch PolicyViolation. Fail CLOSED, in the gate's own
    # vocabulary, so a malformed name is a recorded denial like any other.
    if not isinstance(tool_name, str):
        raise PolicyViolation(
            tool_name if isinstance(tool_name, str) else repr(tool_name),
            f"tool name is {type(tool_name).__name__}, not str — default deny. A "
            f"tool name arrives from an orchestrator as a JSON string; anything "
            f"else is malformed input, not an unknown tool.",
            code=DENY_MALFORMED_TOOL_NAME,
            remedy="Send the tool name as a JSON string exactly as published by tools/list.",
        )

    policy = REGISTRY.get(tool_name)
    if policy is None:
        raise PolicyViolation(
            tool_name,
            f"not in allowlist — default deny. "
            f"Known tools: {sorted(REGISTRY.keys())}",
            code=DENY_NOT_REGISTERED,
            remedy=(
                "Call one of the advertised tools, or add a ToolPolicy for this "
                "name to the registry and re-deploy — the gate will not invent one."
            ),
        )

    # A policy that grants no permission must not authorise a call. Previously
    # `permissions` was declared on every entry and read nowhere, so an entry with
    # `permissions=()` allowed exactly as much as one granting DEPLOY.
    if not policy.permissions:
        raise PolicyViolation(
            tool_name,
            "registered with an empty permission set — default deny. A policy "
            "that grants nothing cannot authorise a call.",
            code=DENY_EMPTY_PERMISSIONS,
            remedy=(
                "Grant the tool the least permission it needs in its ToolPolicy "
                "(read / execute / write / deploy) and re-deploy."
            ),
        )

    # `requires_human_confirm` is documented as "block until explicit approval".
    # Before this it was read nowhere, so setting it blocked nothing at all.
    if policy.requires_human_confirm and not human_confirmed:
        raise PolicyViolation(
            tool_name,
            "requires explicit human confirmation — denied because no approval "
            "was supplied. An approving call site must pass human_confirmed=True.",
            code=DENY_HUMAN_CONFIRM_REQUIRED,
            remedy=(
                "Obtain the human approval this tool requires; the approving call "
                "site then re-issues the call with human_confirmed=True."
            ),
        )

    return policy


# ---------------------------------------------------------------------------
# The receipted gate — the decision, recorded
# ---------------------------------------------------------------------------

#: Every gate decision lands in ONE stream, whichever of the nine tools it was
#: about, because the subject of the record is the CONTROL. `tool` carries which
#: tool it was about.
GATE_EVENT_TYPE = "mcp.tool_gate"

#: Where the receipts go. Absolute and per-user by default, mirroring the memory
#: flow's ruling: a package-relative default lands inside a shared, world-readable
#: `node_modules` under the npm install, and evidence about who was refused what
#: must be at least as protected as the thing it describes.
RECEIPT_LOG_ENV = "ARKHEIA_TOOL_GATE_RECEIPT_LOG"
DEFAULT_RECEIPT_LOG = "~/.arkheia/mcp/tool-gate-receipts.jsonl"

_DIR_MODE = 0o700
_FILE_MODE = 0o600


def receipt_log_path() -> Path:
    """
    Resolve the receipt log. ALWAYS absolute, `~` expanded.

    A relative path is refused rather than silently resolved against the process
    CWD, which for a stdio MCP server is whatever directory the orchestrator
    happened to be started in — so the same install would scatter evidence across
    the filesystem and no one could answer "where is the log?".
    """
    raw = os.environ.get(RECEIPT_LOG_ENV) or DEFAULT_RECEIPT_LOG
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise ValueError(
            f"{RECEIPT_LOG_ENV} must be an absolute path (or start with '~'); got "
            f"{raw!r}. A relative receipt path resolves against the orchestrator's "
            f"CWD, which scatters the evidence."
        )
    return path


def _prepare_receipt_dir(path: Path) -> None:
    """Create the parent 0700 and pre-create the file 0600 before the writer opens it.

    ``AuditWriter.start()`` does ``mkdir(parents=True, exist_ok=True)`` and opens the
    file with no mode argument, so both would otherwise inherit the umask (0755 /
    0644 as measured on this machine). Doing it here means there is no window in
    which the log is world-readable.
    """
    parent = path.parent
    try:
        # Created by us => we set the mode. NOT `exist_ok=True`: an already-existing
        # directory belongs to whoever made it, and chmod'ing it to 0700 because a
        # log happens to live there would be this code silently re-permissioning an
        # operator's directory (point ARKHEIA_TOOL_GATE_RECEIPT_LOG at /tmp/x.jsonl
        # and the naive version chmods /tmp). We own the FILE; the operator owns the
        # DIRECTORY.
        parent.mkdir(parents=True, mode=_DIR_MODE)
    except FileExistsError:
        pass
    if not path.exists():
        # O_CREAT|O_EXCL so a symlink planted at this path is not followed.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, _FILE_MODE)
        os.close(fd)
    elif path.stat().st_mode & 0o777 != _FILE_MODE:
        os.chmod(path, _FILE_MODE)


async def _emit_gate_receipt(
    *,
    tool_name: object,
    decision: str,
    policy: ToolPolicy | None,
    human_confirmed: bool,
    violation: PolicyViolation | None,
    call_site: str,
    argument_keys: Iterable[str] | None,
    log_path: str | Path | None,
) -> tuple[str, str]:
    """
    Write the one row for one gate decision. Returns ``(receipt_id, status)``.

    NEVER RAISES — the decision has already been made and must stand. NEVER SILENT
    — every failure path logs at error level naming the receipt id, and the status
    it returns is surfaced to the caller.

    NOTE the deliberate shape, which is the point of this function. The whole path
    is guarded, so the decision cannot be blocked by a receipt fault; but a
    ``build_record`` rejection does NOT collapse into a log line and no row. It is
    re-emitted as ``DECISION_UNREPRESENTABLE`` carrying the offending value, so the
    fault lands IN the evidence stream where a query for gate decisions will find
    it. Fail-open on the receipt, and still no silent hole.
    """
    receipt_id = receipts.new_receipt_id()
    resolved: Path | None = None

    try:
        resolved = Path(log_path) if log_path is not None else receipt_log_path()
        _prepare_receipt_dir(resolved)
    except Exception as exc:
        logger.error(
            "tool-gate receipt path FAILED (%s): tool=%r decision=%s receipt_id=%s "
            "— this decision is UNRECORDED",
            exc, tool_name, decision, receipt_id, exc_info=True,
        )
        return receipt_id, receipts.STATUS_UNRECORDED

    fields = {
        "control": "tool_registry_gate",
        "call_site": call_site,
        "deny_code": None if violation is None else violation.code,
        "deny_reason": None if violation is None else violation.reason,
        "remedy": None if violation is None else violation.remedy,
        # The policy that was APPLIED, not the policy as declared in source. If the
        # registry is ever loaded from a remote store, or mutated in-process, the
        # receipt is the only artefact that says which grant the decision used.
        "permissions_applied": (
            None if policy is None else sorted(p.value for p in policy.permissions)
        ),
        "network_egress_declared": None if policy is None else policy.network_egress,
        "requires_human_confirm": None if policy is None else policy.requires_human_confirm,
        "human_confirmed": human_confirmed,
        # Argument NAMES and count only — never values. Arguments carry prompts and
        # observation text; a policy receipt is not a place to copy them, and the
        # audit rail's redactor would silently rewrite them if it did.
        "argument_keys": None if argument_keys is None else sorted(argument_keys),
    }

    tool_label = tool_name if isinstance(tool_name, str) else repr(tool_name)

    try:
        record = receipts.build_record(
            receipt_id=receipt_id,
            tool=tool_label,
            decision=decision,
            event_type=GATE_EVENT_TYPE,
            **fields,
        )
    except Exception as exc:
        logger.error(
            "tool-gate receipt could not be BUILT for decision=%r (%s): tool=%r "
            "receipt_id=%s — recording it as %s so it is not lost",
            decision, exc, tool_name, receipt_id, receipts.DECISION_UNREPRESENTABLE,
        )
        try:
            record = receipts.build_record(
                receipt_id=receipt_id,
                tool=tool_label,
                decision=receipts.DECISION_UNREPRESENTABLE,
                event_type=GATE_EVENT_TYPE,
                unrepresentable_decision=repr(decision),
                receipt_fault=f"{type(exc).__name__}: {exc}",
                **fields,
            )
        except Exception as exc2:  # pragma: no cover — defensive last resort
            logger.error(
                "tool-gate receipt FALLBACK also failed (%s): tool=%r decision=%r "
                "receipt_id=%s — this decision is UNRECORDED",
                exc2, tool_name, decision, receipt_id,
            )
            return receipt_id, receipts.STATUS_UNRECORDED

    try:
        ok = await receipts.emit(resolved, record)
    except Exception as exc:  # pragma: no cover — receipts.emit is itself guarded
        logger.error(
            "tool-gate receipt FAILED to write (%s): tool=%r decision=%s "
            "receipt_id=%s — this decision is UNRECORDED",
            exc, tool_name, decision, receipt_id, exc_info=True,
        )
        ok = False

    return receipt_id, (
        receipts.STATUS_RECORDED if ok else receipts.STATUS_UNRECORDED
    )


async def check_receipted(
    tool_name: str,
    *,
    human_confirmed: bool = False,
    call_site: str = "dispatch",
    argument_keys: Iterable[str] | None = None,
    log_path: str | Path | None = None,
) -> ToolPolicy:
    """
    Make the gate's allow/deny decision AND record it. The production entry point.

    Identical verdict to ``check()`` — same inputs, same branches, same exception —
    plus one durable row per decision on the shared audit rail, and the receipt id
    attached to the refusal so a denied caller can quote it.

    Returns:
        The ToolPolicy, on allow.

    Raises:
        PolicyViolation, on deny, with ``receipt_id`` and ``receipt_status`` set.
        The receipt is written BEFORE the refusal is re-raised, so there is no
        ordering in which the caller learns of a denial the log has not seen.
    """
    violation: PolicyViolation | None = None
    policy: ToolPolicy | None = None
    try:
        policy = check(tool_name, human_confirmed=human_confirmed)
        decision = receipts.DECISION_ALLOWED
    except PolicyViolation as exc:
        violation = exc
        decision = receipts.DECISION_DENIED

    receipt_id, status = await _emit_gate_receipt(
        tool_name=tool_name,
        decision=decision,
        policy=policy,
        human_confirmed=human_confirmed,
        violation=violation,
        call_site=call_site,
        argument_keys=argument_keys,
        log_path=log_path,
    )

    if violation is not None:
        violation.receipt_id = receipt_id
        violation.receipt_status = status
        raise violation

    assert policy is not None  # allow branch: check() returned a policy
    return policy


def assert_registry_covers(advertised: Iterable[str]) -> None:
    """
    Fail closed unless every advertised tool has a policy and every policy covers
    an advertised tool.

    Args:
        advertised: The tool names the server actually exposes to orchestrators.

    Raises:
        RegistryCoverageError naming the specific offending tools on each side.
        The units are named rather than counted: a bare "2 tools differ" would
        hide *which* tool is ungoverned, which is the only actionable fact.
    """
    advertised_set = set(advertised)
    registry_set = set(REGISTRY)

    if not advertised_set:
        raise RegistryCoverageError(
            "<startup>",
            "no tools were advertised, so registry coverage was never actually "
            "checked. An empty check must fail, not pass.",
        )

    ungoverned = sorted(advertised_set - registry_set)
    dead_policy = sorted(registry_set - advertised_set)

    if ungoverned or dead_policy:
        raise RegistryCoverageError(
            "<startup>",
            f"registry coverage mismatch — refusing to start. "
            f"advertised but NOT in REGISTRY (ungoverned, reachable by any "
            f"orchestrator): {ungoverned}; "
            f"in REGISTRY but NOT advertised (dead policy, misleading evidence): "
            f"{dead_policy}.",
        )
