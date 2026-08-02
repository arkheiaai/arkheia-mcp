#!/usr/bin/env python3
"""
Mutation campaign for F11 — passthrough provider forwarding + SSRF path/header guard.

WHAT THIS ANSWERS
-----------------
The suites are green. That is a statement about the code, not about the suites.
This plants a fault the suites are *supposed* to catch and checks that they do.

FILES IT PLANTS FAULTS IN
-------------------------
    proxy/endpoints/passthrough.py          (the only one)

THE TIER MUST COVER EVERY FILE IT MUTATES. It does:

    proxy/tests/test_passthrough.py             (pre-existing)
    proxy/tests/test_passthrough_adversarial.py
    proxy/tests/test_passthrough_receipts.py
    proxy/tests/test_passthrough_wire.py
    tests/test_passthrough_ssrf_floor.py

BUCKETS — three, and only three
-------------------------------
Every trial is totalled against the baseline and lands in exactly one bucket.
"Not observed" is never folded into "killed":

  KILLED            the tier RAN and at least one test FAILED.
  KILLED_COLLECTION the tier could not import the mutated module at all. CI would
                    go red, so it is not a survivor — but no test OBSERVED the
                    behaviour, so it is reported separately and never summed into
                    KILLED.
  SURVIVED          the tier ran fully green against the fault.
  NOT_OBSERVED      the mutant could not be applied (pattern absent or ambiguous),
                    or the runner timed out. Nothing was learned. Reported by name.

An equivalent survivor is a defect in the MUTANT, not evidence about the suite:
withdraw it, replace it, and say so.

THE COUNTERFACTUAL
------------------
Each mutant is also run against the PRE-EXISTING suite alone
(``proxy/tests/test_passthrough.py``, unmodified from origin/master), so the
report can say what this branch's tests actually added rather than asserting it.

USAGE
-----
    .venv/bin/python tools/mutate_f11_passthrough.py            # full campaign
    .venv/bin/python tools/mutate_f11_passthrough.py --only M01
    .venv/bin/python tools/mutate_f11_passthrough.py --json out.json
"""
from __future__ import annotations

import argparse
import atexit
import json
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGET = REPO / "proxy" / "endpoints" / "passthrough.py"

#: CRASH-SAFE RESTORE — earned 2026-07-27, in this file, tonight.
#:
#: The campaign was killed by a watchdog partway through trial M02. `finally:`
#: does not run when the process is terminated, so the PLANTED MUTANT was left
#: in the working tree: `passthrough.py` sat there with its OpenAI allowlist
#: end-anchor weakened from `\Z` to `$`, one `git add` away from being committed
#: as a security regression that reads like a typo. It was caught by inspecting
#: the diff, which is not a control.
#:
#: So the original is written to a sidecar BEFORE the first fault is planted,
#: and three things restore from it: a SIGTERM/SIGINT handler, an atexit hook,
#: and — for SIGKILL, where no handler can run — the NEXT invocation, which
#: refuses to start while a sidecar exists and puts the file back first. The
#: sidecar is removed only on a clean finish, so its presence always means "a
#: run died holding a mutant".
BACKUP = TARGET.with_suffix(".py.mutation-original")

NEW_TIER = [
    "proxy/tests/test_passthrough.py",
    "proxy/tests/test_passthrough_adversarial.py",
    "proxy/tests/test_passthrough_receipts.py",
    "proxy/tests/test_passthrough_wire.py",
    "proxy/tests/test_passthrough_credential_wire.py",
    "tests/test_passthrough_ssrf_floor.py",
]
PREEXISTING_TIER = ["proxy/tests/test_passthrough.py"]

TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class Mutant:
    mid: str
    what: str
    old: str
    new: str
    #: Which control this fault removes. Grouping only; never affects a verdict.
    area: str
    #: Further (old, new) pairs applied in the same trial. Used where two checks
    #: are deliberately redundant, so removing either alone is unobservable and a
    #: single-edit mutant would be equivalent.
    extra: tuple = ()


MUTANTS: list[Mutant] = [
    # -- path allowlist -----------------------------------------------------
    Mutant("M01", "restore the exact pre-fix `audio/.*` arm",
           r"|audio/(speech|transcriptions|translations)|moderations)\Z",
           r"|audio/.*|moderations)\Z", "allowlist"),
    Mutant("M02", "OpenAI allowlist end-anchor \\Z -> $",
           r'|audio/(speech|transcriptions|translations)|moderations)\Z"',
           r'|audio/(speech|transcriptions|translations)|moderations)$"', "allowlist"),
    Mutant("M03", "OpenAI allowlist start-anchor \\A -> ^",
           r'r"\A(chat/completions|completions',
           r'r"^(chat/completions|completions', "allowlist"),
    Mutant("M04", "Gemini allowlist end-anchor \\Z -> $",
           r'r"\Amodels(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?\Z"',
           r'r"\Amodels(/[a-zA-Z0-9._-]+(:[a-zA-Z]+)?)?$"', "allowlist"),
    Mutant("M05", "Anthropic allowlist end-anchor \\Z -> $",
           'r"\\A(messages|models)\\Z"', 'r"\\A(messages|models)$"', "allowlist"),
    # M06 WITHDRAWN — equivalent. `fullmatch` -> `match` is a no-op while every
    # pattern is \A..\Z anchored, so the mutant changes no observable behaviour
    # and a survival would say nothing about the suite. The anchoring itself is
    # what M02/M03 attack and floor INV-2 enforces. Replaced by M06R.
    Mutant("M06R", "every route screens against the OpenAI allowlist "
                   "(one shared regex widens three surfaces at once)",
           "    if not provider.path_re.fullmatch(path):",
           "    if not _OPENAI_PATH_RE.fullmatch(path):", "allowlist"),
    # M07 WITHDRAWN — equivalent by REDUNDANCY, which is a fact about the code
    # rather than the suite: the '..' marker and the raw-path segment check
    # overlap completely for every reachable input, so deleting either alone is
    # unobservable. Deliberate belt-and-braces; both are kept. M07R deletes BOTH.
    Mutant("M07R", "delete BOTH the '..' marker and the raw-path segment check",
           '_TRAVERSAL_MARKERS = ("..", "\\\\", "%2e"',
           '_TRAVERSAL_MARKERS = ("\\\\", "%2e"', "allowlist",
           extra=((
               '    if any(segment in (".", "..") for segment in path.split("/")):\n'
               "        return DENY_PATH_TRAVERSAL\n", ""),)),
    Mutant("M08", "drop percent-encoded dots from the traversal markers",
           '"%2e", "%2E", ', '', "allowlist"),
    Mutant("M09", "drop percent-encoded slashes from the traversal markers",
           '"%2f", "%2F", ', '', "allowlist"),
    # M10 WITHDRAWN — equivalent by REDUNDANCY: the backslash marker on the raw
    # path and the backslash check on the RESOLVED path overlap for every
    # reachable input. M10R deletes both.
    Mutant("M10R", "delete BOTH backslash checks (raw path and resolved path)",
           '_TRAVERSAL_MARKERS = ("..", "\\\\", ',
           '_TRAVERSAL_MARKERS = ("..", ', "allowlist",
           extra=((
               '    if "\\\\" in resolved_path:\n'
               "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", ""),)),
    Mutant("M11", "delete the '.'/'..' segment check on the raw path",
           '    if any(segment in (".", "..") for segment in path.split("/")):\n'
           '        return DENY_PATH_TRAVERSAL\n', '', "allowlist"),
    Mutant("M12", "delete the control-character check",
           "    if any(ch for ch in path if ord(ch) < 0x20 or ord(ch) == 0x7F):\n"
           "        return DENY_PATH_ILLEGAL_CHARACTER\n", "", "allowlist"),

    # -- resolved-URL post-condition ---------------------------------------
    Mutant("M13", "post-condition no longer compares the host",
           "    if parsed.host != provider.expected_host:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M14", "post-condition no longer compares the scheme",
           "    if parsed.scheme != provider.expected_scheme:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M15", "post-condition no longer compares the port",
           "    if parsed.port != provider.expected_port:\n"
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M16", "post-condition allows a smuggled query/fragment",
           "    if parsed.query or parsed.fragment:", "    if False:", "postcondition"),
    Mutant("M17", "post-condition no longer rejects decoded dot segments",
           '    if any(segment in (".", "..") for segment in resolved_path.split("/")):\n'
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M18", "post-condition no longer rejects a decoded backslash",
           '    if "\\\\" in resolved_path:\n'
           "        return None, DENY_UPSTREAM_TARGET_ESCAPED\n", "", "postcondition"),
    Mutant("M19", "prefix test loses its trailing separator (prefix confusion)",
           'if not (resolved_path == base_path or resolved_path.startswith(base_path + "/")):',
           "if not (resolved_path == base_path or resolved_path.startswith(base_path)):",
           "postcondition"),
    Mutant("M20", "post-condition short-circuits: always resolve",
           "    candidate = f\"{provider.base}/{path}\"\n",
           "    candidate = f\"{provider.base}/{path}\"\n    return candidate, None\n",
           "postcondition"),

    # -- gate ordering and credentials -------------------------------------
    # M21/M22/M23R REPOINTED TWICE (2026-07-27 rounds 2 and 3). Round 2 moved
    # them off `_duplicate_credential_headers`; round 3 moved them again when the
    # count went per-DESTINATION across channels and the per-header helper was
    # absorbed into `_credential_presentations`. The FAULTS they express are
    # unchanged; only the anchors moved. Left un-repointed they would score
    # NOT_OBSERVED, which is a measurement of nothing, not a pass.
    Mutant("M21", "gate no longer refuses more than one credential",
           "    if len(_credential_presentations(request)) > 1:\n"
           "        return DENY_MULTIPLE_CREDENTIALS\n", "", "credentials"),
    Mutant("M22", "the multiplicity limit needs three credentials, not two",
           "    if len(_credential_presentations(request)) > 1:",
           "    if len(_credential_presentations(request)) > 2:", "credentials"),
    Mutant("M23R", "nothing is recognised as a credential on any channel",
           "            if name in channel.vocabulary:",
           "            if name in frozenset():", "credentials"),
    Mutant("M24", "cookie added to the shared forward allowlist",
           '_SAFE_TRANSPORT_HEADERS = frozenset({\n    "content-type",\n',
           '_SAFE_TRANSPORT_HEADERS = frozenset({\n    "cookie",\n    "content-type",\n',
           "credentials"),
    Mutant("M25", "gate screens the path but ignores the verdict",
           "    deny = _screen_path(provider, path)\n    if deny:\n        return None, deny\n",
           "    deny = _screen_path(provider, path)\n", "credentials"),

    # -- response framing and hop-by-hop -----------------------------------
    Mutant("M26", "content-length no longer stripped (the framing desync)",
           '    "content-length",\n', "", "framing"),
    Mutant("M27", "proxy-authenticate no longer stripped",
           '    "proxy-authenticate",\n', "", "framing"),
    Mutant("M28", "upgrade no longer stripped",
           '    "upgrade",\n', "", "framing"),
    Mutant("M29", "content-encoding no longer stripped",
           '    "content-encoding",\n', "", "framing"),
    Mutant("M30", "Connection-nominated headers no longer honoured",
           "    connection_value = upstream_headers.get(\"connection\")\n"
           "    if connection_value:",
           "    connection_value = upstream_headers.get(\"connection\")\n"
           "    if False:", "framing"),
    # M31/M32 REPOINTED (2026-08-02, master merge). The client is now built by
    # `arkheia_common.egress.egress_async_client`, which forwards **kwargs to
    # httpx.AsyncClient after pinning trust_env=False. The FAULTS are unchanged —
    # only the spelling of the construction moved. Left un-repointed they would
    # score NOT_OBSERVED, which is a measurement of nothing, not a pass.
    Mutant("M31", "redirects are followed",
           "egress_async_client(timeout=60.0, follow_redirects=False)",
           "egress_async_client(timeout=60.0, follow_redirects=True)", "framing"),
    Mutant("M32", "redirect policy falls back to the library default",
           "egress_async_client(timeout=60.0, follow_redirects=False)",
           "egress_async_client(timeout=60.0)", "framing"),
    # M32B is NEW and belongs to the merge: the second egress control the merged
    # call site carries. `egress_async_client` refuses trust_env=True outright,
    # so the removable form of the fault is a bare httpx client — the exact
    # regression "just use httpx here" would reintroduce, letting an ambient
    # HTTP(S)_PROXY interpose on a call carrying the caller's provider key.
    Mutant("M32B", "outbound client stops pinning trust_env (ambient proxy can interpose)",
           "egress_async_client(timeout=60.0, follow_redirects=False)",
           "httpx.AsyncClient(timeout=60.0, follow_redirects=False)", "framing"),

    # -- receipts -----------------------------------------------------------
    Mutant("M33", "refusal receipt is never written",
           "    try:\n        await audit.write(record)\n",
           "    try:\n        pass\n", "receipts"),
    Mutant("M34", "refusal is filed as a pass",
           '"action_taken": "refuse",\n        "source": "passthrough",\n'
           '        "error": None,',
           '"action_taken": "pass",\n        "source": "passthrough",\n'
           '        "error": None,', "receipts"),
    Mutant("M35", "refusal is filed at a screened risk level",
           '"risk_level": REFUSAL_RISK_LEVEL,', '"risk_level": "LOW",', "receipts"),
    Mutant("M36", "the deny code is dropped from the record",
           '"deny_code": deny_code,\n        "attempted_path"',
           '"deny_code": None,\n        "attempted_path"', "receipts"),
    Mutant("M37", "header VALUES are recorded instead of key names",
           '"request_header_names": sorted(set(_header_names(request))),',
           '"request_header_names": sorted({v.decode("latin-1") '
           'for _k, v in request.headers.raw}),', "receipts"),
    Mutant("M38", "the attempted path is no longer length-capped",
           '"attempted_path": attempted_path[:_MAX_RECORDED_PATH],',
           '"attempted_path": attempted_path,', "receipts"),
    Mutant("M39", "the refusal receipt is skipped entirely by _refuse",
           "    receipt_id, receipt_status = await _receipt_refusal(\n"
           "        request, provider, deny_code, attempted_path\n    )",
           '    receipt_id, receipt_status = str(uuid.uuid4()), "enqueued"',
           "receipts"),
    Mutant("M40", "the record's id field no longer matches the id handed out",
           '"detection_id": receipt_id,\n        "timestamp": datetime.now',
           '"detection_id": str(uuid.uuid4()),\n        "timestamp": datetime.now',
           "receipts"),
    Mutant("M41", "a refusal returns 200",
           "        status_code=400,\n        media_type=\"application/json\",\n"
           "        headers={\"X-Arkheia-Risk\": REFUSAL_RISK_LEVEL},",
           "        status_code=200,\n        media_type=\"application/json\",\n"
           "        headers={\"X-Arkheia-Risk\": REFUSAL_RISK_LEVEL},", "receipts"),
    Mutant("M42", "the refusal stops telling the caller what would clear it",
           '        body["allowed"] = list(provider.allowed)',
           '        body["allowed"] = []', "receipts"),

    # -- the credential boundary (2026-07-27, cross-provider disclosure) -----
    # Each of these is a way back to the defect Codex reproduced: one vendor's
    # credential delivered to another vendor on the accepted path.
    Mutant("M43", "restore the exact pre-fix shape: ONE shared allowlist "
                  "holding both credential headers, applied to every provider",
           "    allowed = (\n"
           "        _SAFE_TRANSPORT_HEADERS\n"
           "        | provider.credential_headers\n"
           "        | provider.extra_headers\n"
           "    )\n",
           "    allowed = _SAFE_TRANSPORT_HEADERS | _CREDENTIAL_HEADERS | frozenset({\n"
           '        "anthropic-version", "anthropic-beta"})\n',
           "credential-boundary"),
    Mutant("M44", "the gate stops screening credentials entirely",
           "    deny = _screen_credentials(request, provider)\n"
           "    if deny:\n        return None, deny\n", "", "credential-boundary"),
    Mutant("M45", "a foreign credential is dropped silently instead of refused "
                  "(the alternative ruling, planted as a fault)",
           "    if _foreign_credentials(request, provider):\n"
           "        return DENY_FOREIGN_CREDENTIAL\n\n", "", "credential-boundary"),
    Mutant("M46", "every provider accepts every credential the screen knows",
           "        if name not in getattr(provider, channel.provider_field):",
           "        if name not in channel.vocabulary:", "credential-boundary"),
    # M47 REPOINTED (round 3) to the ROUND-2 REGRESSION ITSELF: the count taken
    # over the header channel alone. That is the defect Codex reproduced, so
    # this mutant is the campaign's memory of it — a survival here means the
    # suite has forgotten the finding it was written for.
    Mutant("M47", "the count is taken over the HEADER channel alone "
                  "(the exact round-2 regression)",
           "    if len(_credential_presentations(request)) > 1:",
           '    if len([p for p in _credential_presentations(request) '
           'if p[0] == "header"]) > 1:', "credential-boundary"),
    # Deliberately redundant with the gate screen, so a single-edit mutant would
    # be equivalent: the filter and the screen must BOTH be removed for the
    # credential to reach the wire.
    Mutant("M48", "delete BOTH credential-header controls: the per-destination "
                  "forward filter and the gate's foreign screen",
           "    allowed = (\n"
           "        _SAFE_TRANSPORT_HEADERS\n"
           "        | provider.credential_headers\n"
           "        | provider.extra_headers\n"
           "    )\n",
           "    allowed = _SAFE_TRANSPORT_HEADERS | _CREDENTIAL_HEADERS | frozenset({\n"
           '        "anthropic-version", "anthropic-beta"})\n',
           "credential-boundary",
           extra=((
               "    if _foreign_credentials(request, provider):\n"
               "        return DENY_FOREIGN_CREDENTIAL\n\n", ""),)),
    Mutant("M49", "delete BOTH credential-PARAMETER controls: the per-destination "
                  "param filter and the gate's foreign screen for the query channel",
           "        if key.lower() not in _CREDENTIAL_QUERY_PARAMS\n"
           "        or key.lower() in provider.credential_query_params\n",
           "        if True\n",
           "credential-boundary",
           extra=((
               "    for channel_name, name in _credential_presentations(request):\n",
               "    for channel_name, name in [p for p in "
               '_credential_presentations(request) if p[0] != "query"]:\n'),)),
    Mutant("M50", "no query parameter is recognised as credential-bearing",
           '_CREDENTIAL_QUERY_PARAMS = frozenset({\n'
           '    "key", "api_key", "apikey", "access_token", "auth_token", "token",\n})',
           "_CREDENTIAL_QUERY_PARAMS = frozenset()", "credential-boundary"),
    Mutant("M51", "the anthropic credential set widens to every known credential",
           '    credential_headers=frozenset({"x-api-key", "authorization"}),',
           "    credential_headers=_CREDENTIAL_HEADERS,", "credential-boundary"),
    Mutant("M52", "the grok credential set widens to every known credential",
           '    # xAI is OpenAI-compatible: `Authorization: Bearer <xai key>`, and nothing\n'
           "    # else. It has no x-api-key surface at all.\n"
           '    credential_headers=frozenset({"authorization"}),',
           "    credential_headers=_CREDENTIAL_HEADERS,", "credential-boundary"),
    Mutant("M53", "provider-specific headers travel to every destination again",
           "        | provider.extra_headers\n",
           '        | frozenset({"anthropic-version", "anthropic-beta"})\n',
           "credential-boundary"),
    Mutant("M54", "the refusal stops naming the credential this provider uses",
           '        body["credential_headers"] = sorted(provider.credential_headers)',
           '        body["credential_headers"] = []', "credential-boundary"),
    # -- credential MULTIPLICITY per destination (2026-07-27, round 3) ------
    # Codex proved the round-2 screen counted HEADERS, so a bearer plus a
    # `?key=` both reached Google and `?key=FIRST&key=SECOND` collapsed to the
    # last value. Each mutant below is a way back to one of those.
    Mutant("M56", "the count is per DISTINCT credential, not per occurrence "
                  "(?key=FIRST&key=SECOND reads as one)",
           "    if len(_credential_presentations(request)) > 1:",
           "    if len(set(_credential_presentations(request))) > 1:",
           "multiplicity"),
    # Deleting the query channel row ALONE trips the import-time coverage guard,
    # so the fault would never be OBSERVED by a test. The guard is disabled in
    # the same trial, which is the point: this measures whether the suites see
    # the query channel go dark, not whether the guard exists (M62 measures
    # that).
    Mutant("M57", "the credential channel table loses its query row "
                  "(and the coverage guard that would have caught it)",
           '    CredentialChannel(\n'
           '        "query", _CREDENTIAL_QUERY_PARAMS, "credential_query_params",\n'
           "        _query_param_names, lambda name: f\"?{name}\",\n"
           "    ),\n",
           "", "multiplicity",
           extra=(("if _DECLARED_CREDENTIAL_FIELDS != _CHANNELLED_CREDENTIAL_FIELDS:",
                   "if False:"),)),
    Mutant("M58", "the query channel is read through a collapsing accessor, so "
                  "a repeated credential parameter is invisible to the count",
           "    return [key.lower() for key, _ in request.query_params.multi_items()]",
           "    return [key.lower() for key in request.query_params.keys()]",
           "multiplicity"),
    Mutant("M59", "the header channel is read through a collapsing accessor, so "
                  "a repeated credential header is invisible to the count",
           '    return [raw_key.decode("latin-1").lower() '
           "for raw_key, _ in request.headers.raw]",
           '    return [key.lower() for key in request.headers.keys()]',
           "multiplicity"),
    Mutant("M60", "the forwarded query string collapses repeats again",
           "        (key, value) for key, value in request.query_params.multi_items()",
           "        (key, value) for key, value in request.query_params.items()",
           "multiplicity"),
    Mutant("M61", "the forwarded headers collapse repeats again "
                  "(the dict comprehension that kept the LAST)",
           "    return [\n"
           '        (raw_key.decode("latin-1"), raw_value.decode("latin-1"))\n'
           "        for raw_key, raw_value in request.headers.raw\n"
           '        if raw_key.decode("latin-1").lower() in allowed\n'
           "    ]",
           "    return {k: v for k, v in request.headers.items() "
           "if k.lower() in allowed}",
           "multiplicity"),
    Mutant("M62", "a fifth credential channel is declared on Provider with no "
                  "channel row to read it",
           "    credential_headers: frozenset = frozenset()",
           "    credential_headers: frozenset = frozenset()\n"
           "    credential_cookies: frozenset = frozenset()",
           "multiplicity"),
    # The redundancy-aware twin of M62: with the import guard removed, the
    # STATIC floor invariant and the derived provider-table test are what must
    # catch it. If only the guard catches it, the property holds solely on a
    # branch that imports this module.
    Mutant("M63", "the same uncounted channel, with the import-time coverage "
                  "guard removed too",
           "    credential_headers: frozenset = frozenset()",
           "    credential_headers: frozenset = frozenset()\n"
           "    credential_cookies: frozenset = frozenset()",
           "multiplicity",
           extra=(("if _DECLARED_CREDENTIAL_FIELDS != _CHANNELLED_CREDENTIAL_FIELDS:",
                   "if False:"),)),
    Mutant("M64", "Gemini stops accepting its own query key "
                  "(a boundary that refuses a working path is not a boundary)",
           '    credential_query_params=frozenset({"key"}),',
           "    credential_query_params=frozenset(),", "multiplicity"),
    Mutant("M65", "the refusal stops naming the query parameter this provider "
                  "uses, so the caller is not told the way out",
           '        body["credential_query_params"] = sorted(provider.credential_query_params)',
           '        body["credential_query_params"] = []', "multiplicity"),
    Mutant("M55", "the credential refusal is reported as a path problem",
           "        \"error\": (\n"
           '            "invalid_credential_header"\n'
           "            if deny_code in _CREDENTIAL_DENY_CODES\n"
           '            else "invalid_path"\n'
           "        ),",
           '        "error": "invalid_path",', "credential-boundary"),
]


# ---------------------------------------------------------------------------

@dataclass
class Trial:
    mid: str
    what: str
    area: str
    bucket: str
    detail: str = ""
    failing_tests: list[str] = field(default_factory=list)
    preexisting_bucket: str = ""
    seconds: float = 0.0


def run_pytest(paths: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", *paths, "-q", "-p", "no:cacheprovider",
         "--timeout=60", "--no-header", "-x" if False else "--tb=no"],
        cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
        env=None,
    )
    return proc.returncode, proc.stdout + proc.stderr


def classify(returncode: int, output: str) -> tuple[str, list[str]]:
    failures = [ln.split(" ")[1] for ln in output.splitlines()
                if ln.startswith("FAILED ") and len(ln.split(" ")) > 1]
    if "ERROR collecting" in output or "INTERNALERROR" in output:
        return "KILLED_COLLECTION", failures
    if returncode == 0:
        return "SURVIVED", []
    if returncode == 5:
        return "NOT_OBSERVED", []
    return ("KILLED", failures) if failures else ("KILLED_COLLECTION", failures)


def _recover_from_a_killed_run() -> None:
    """
    Put the target back if a previous run died holding a planted mutant.

    A sidecar that still exists means the previous process never reached its
    clean finish. Restoring is unconditional and LOUD: a silent recovery would
    hide the fact that a mutated file was sitting in the tree.
    """
    if not BACKUP.exists():
        return
    saved = BACKUP.read_text(encoding="utf-8")
    current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
    print("!" * 78)
    print("A PREVIOUS RUN DIED HOLDING A PLANTED MUTANT.")
    print(f"  target differs from the saved original: {saved != current}")
    print(f"  restoring {TARGET.relative_to(REPO)} from {BACKUP.name}")
    print("!" * 78)
    TARGET.write_text(saved, encoding="utf-8")
    BACKUP.unlink()


def _arm_restore(original: str) -> None:
    """Restore on a clean exit, on SIGTERM/SIGINT, and (via BACKUP) on SIGKILL."""
    BACKUP.write_text(original, encoding="utf-8")

    def restore() -> None:
        if TARGET.read_text(encoding="utf-8") != original:
            TARGET.write_text(original, encoding="utf-8")

    atexit.register(restore)

    def _on_signal(signum, _frame):
        restore()
        BACKUP.unlink(missing_ok=True)
        # 128+signum is the shell's convention for "died on this signal"; the
        # campaign must never exit 0 after being cut short.
        sys.exit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _on_signal)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", nargs="*", default=None)
    parser.add_argument("--json", default=None)
    args = parser.parse_args()

    _recover_from_a_killed_run()
    original = TARGET.read_text(encoding="utf-8")
    _arm_restore(original)

    print("=" * 78)
    print("BASELINE — the tier must be green before any fault is planted")
    print("=" * 78)
    rc, out = run_pytest(NEW_TIER)
    if rc != 0:
        print(out[-4000:])
        print("BASELINE IS NOT GREEN — aborting. Nothing below would mean anything.")
        return 2
    baseline_line = [ln for ln in out.splitlines() if " passed" in ln][-1]
    print(f"  new tier          : {baseline_line.strip()}")

    rc0, out0 = run_pytest(PREEXISTING_TIER)
    assert rc0 == 0, out0[-2000:]
    print(f"  pre-existing tier : "
          f"{[ln for ln in out0.splitlines() if ' passed' in ln][-1].strip()}")
    print()

    selected = [m for m in MUTANTS if not args.only or m.mid in args.only]
    trials: list[Trial] = []

    try:
        for mutant in selected:
            started = time.monotonic()
            pairs = ((mutant.old, mutant.new),) + tuple(mutant.extra)
            counts = [original.count(old) for old, _ in pairs]
            if any(c != 1 for c in counts):
                trials.append(Trial(
                    mutant.mid, mutant.what, mutant.area, "NOT_OBSERVED",
                    detail=f"anchors matched {counts}, each must match exactly 1 — "
                           f"the fault was never planted, so nothing was learned",
                ))
                print(f"  {mutant.mid}  NOT_OBSERVED  (anchors {counts})  {mutant.what}")
                continue

            mutated = original
            for old, new in pairs:
                mutated = mutated.replace(old, new)
            assert mutated != original
            TARGET.write_text(mutated, encoding="utf-8")
            try:
                rc, out = run_pytest(NEW_TIER)
                bucket, failures = classify(rc, out)
                rc_old, out_old = run_pytest(PREEXISTING_TIER)
                pre_bucket, _ = classify(rc_old, out_old)
            except subprocess.TimeoutExpired:
                bucket, failures, pre_bucket = "NOT_OBSERVED", [], "NOT_OBSERVED"
                out = "runner timed out"
            finally:
                TARGET.write_text(original, encoding="utf-8")

            trials.append(Trial(
                mutant.mid, mutant.what, mutant.area, bucket,
                detail="" if bucket != "SURVIVED" else "tier fully green against the fault",
                failing_tests=failures[:6],
                preexisting_bucket=pre_bucket,
                seconds=round(time.monotonic() - started, 1),
            ))
            marker = {"KILLED": "kill", "SURVIVED": "SURVIVED **",
                      "KILLED_COLLECTION": "kill(collect)",
                      "NOT_OBSERVED": "NOT_OBSERVED"}[bucket]
            print(f"  {mutant.mid}  {marker:<14} old-tier={pre_bucket:<18} {mutant.what}")
    finally:
        TARGET.write_text(original, encoding="utf-8")

    # Post-campaign baseline: prove the target was restored byte-for-byte, then
    # drop the sidecar — its presence is the signal that a run died holding a
    # mutant, so it is removed only here, on the clean path.
    assert TARGET.read_text(encoding="utf-8") == original, "target not restored"
    BACKUP.unlink(missing_ok=True)
    rc, out = run_pytest(NEW_TIER)
    restored_green = rc == 0

    totals = {b: sum(1 for t in trials if t.bucket == b)
              for b in ("KILLED", "KILLED_COLLECTION", "SURVIVED", "NOT_OBSERVED")}
    scored = totals["KILLED"] + totals["KILLED_COLLECTION"] + totals["SURVIVED"]

    print()
    print("=" * 78)
    print("TOTALS — every trial accounted for, against the baseline")
    print("=" * 78)
    print(f"  planted           : {len(selected)}")
    print(f"  KILLED            : {totals['KILLED']}")
    print(f"  KILLED_COLLECTION : {totals['KILLED_COLLECTION']}   "
          f"(CI red, but no test observed the behaviour — NOT summed into KILLED)")
    print(f"  SURVIVED          : {totals['SURVIVED']}")
    print(f"  NOT_OBSERVED      : {totals['NOT_OBSERVED']}")
    print(f"  scored            : {scored} of {len(selected)}")
    print(f"  baseline restored green : {restored_green}")

    not_observed = [t for t in trials if t.bucket == "NOT_OBSERVED"]
    if not_observed:
        print("\n  NOT OBSERVED — named, never summarised:")
        for t in not_observed:
            print(f"    {t.mid}  {t.what}\n        {t.detail}")

    survivors = [t for t in trials if t.bucket == "SURVIVED"]
    if survivors:
        print("\n  ** SURVIVORS — each is either a hole in the suite or a defect "
              "in the mutant:")
        for t in survivors:
            print(f"    {t.mid}  {t.what}")

    print("\n  COUNTERFACTUAL — same faults against the PRE-EXISTING suite alone:")
    counter = {}
    for t in trials:
        counter[t.preexisting_bucket] = counter.get(t.preexisting_bucket, 0) + 1
    for bucket, n in sorted(counter.items()):
        print(f"    {bucket or '(not run)':<18} {n}")
    would_have_survived = [t.mid for t in trials
                           if t.preexisting_bucket == "SURVIVED"]
    print(f"    mutants the pre-existing suite would NOT have caught: "
          f"{len(would_have_survived)} — {', '.join(would_have_survived)}")

    verdict = (
        "CLEAN" if (totals["SURVIVED"] == 0 and totals["NOT_OBSERVED"] == 0
                    and scored == len(selected) and restored_green and selected)
        else "INCOMPLETE"
    )
    print(f"\n  VERDICT: {verdict}")

    if args.json:
        Path(args.json).write_text(json.dumps({
            "verdict": verdict,
            "interpreter": sys.version,
            "mutated_files": [str(TARGET.relative_to(REPO))],
            "tier": NEW_TIER,
            "preexisting_tier": PREEXISTING_TIER,
            "totals": {**totals, "planted": len(selected), "scored": scored},
            "baseline_restored_green": restored_green,
            "not_observed": [t.mid for t in not_observed],
            "survivors": [t.mid for t in survivors],
            "counterfactual_survived_preexisting": would_have_survived,
            "trials": [vars(t) for t in trials],
        }, indent=2), encoding="utf-8")
        print(f"  wrote {args.json}")

    return 0 if verdict == "CLEAN" else 1


if __name__ == "__main__":
    sys.exit(main())
