#!/usr/bin/env python3
"""Adversarial mutation campaign against the F5 memory knowledge-graph test suite.

Ported from arkheia-proxy `tools/mutate_f8_signal_emission.py` (PR #59) rather than
reinvented: same three-bucket accounting, same KILLED-BY-OTHER vacuity signal, same
name-the-units reporting. Only the target suites and the mutant table are new.

NOT A CI GATE. Nothing runs this automatically, so by the DONE.md standard ("present-but-
undiscovered checks are decoration") it gates nothing today. It is committed because it makes
the non-vacuity claim REPRODUCIBLE instead of asserted in a commit message, and because the
next agent to touch `_db_path`, the permission modes, `_like_escape` or the relate contract can
re-run it in well under a minute to find out whether their change is actually covered.

    python tools/mutate_f5_memory_graph.py

Last full run (2026-07-26, branch sweep/mcp-memory-knowledge-graph): baseline 50 passed / 0 failed;
36 mutants, 36 KILLED by their own expected assertion, 0 KILLED-BY-OTHER, 0 SURVIVED, 0 NOT-OBSERVED.
(Previous run: baseline 40 passed, 27 mutants. The 9 added mutants M26-M34 cover the two Codex
findings on PR #19 — the one-sided `limit` bound and the name-as-identity relation key.)

TWO OF THE HARNESS'S OWN DEFECTS, found by running it — quoted because a kill rate means nothing
without them. The first pass reported 2 SURVIVED and both were the instrument, not the coverage:
M20 was a mutant that changed no behaviour (it added a no-op line instead of actually moving the
write before the refusal), and M22 was never loaded at all (see _purge_bytecode). A later pass
reported 3 NOT-OBSERVED after `_get_conn` was refactored and three anchors stopped matching — that
one is the discipline working as intended: the anchors were stale, the mutants never applied, and
the harness said so instead of counting three unexamined guards as clean. It happened a THIRD time
when store_relation's inline `missing = [...]` block became `_resolve_endpoint`: M17-M20 all went
NOT-OBSERVED at once. Had the harness folded NOT-OBSERVED into KILLED, that refactor would have
silently retired four guards on the dangling-edge contract while still reporting a 100% kill rate.

THREE BUCKETS ONLY, and the third is never folded into the others:
    KILLED        — the mutant was applied AND the run observed >=1 assertion failure.
    SURVIVED      — the mutant was applied AND the run observed a full green suite.
    NOT-OBSERVED  — the run observed NOTHING it was meant to observe: the mutation did not
                    apply (anchor missing or ambiguous), pytest errored at collection or
                    internally, no tests were collected, or the run timed out. A timeout is
                    NOT a kill.
A mutant killed only by tests OTHER than its expected killers is reported as KILLED-BY-OTHER.
That is the vacuity signal: the assertion written for this defect did not fire and something
upstream refused first.

WHAT THIS CAMPAIGN HAS NO MUTANT FOR (not-observed, therefore NOT clean):
  1. CONCURRENCY. Two servers writing the same sqlite file simultaneously. Now that the path
     is a single shared absolute default, concurrent writers are MORE likely than before, and
     nothing here opens two connections at once. No WAL pragma, no busy_timeout, no test.
  2. [RESOLVED 2026-07-26 — no longer an exclusion] The name-keyed relations schema. This entry
     used to read "out of scope for this unit; no mutant, and the defect is recorded in the PR
     body instead." Codex found it on PR #19 and it is now fixed: `relations` carries
     from_entity_id/to_entity_id, retrieve joins on identity, ambiguous endpoints are refused,
     and legacy rows are migrated where their names resolve uniquely. Covered by M30-M34.
     Kept visible rather than deleted, because "recorded in the PR body instead" is exactly how
     a known defect becomes permanent — the note is the audit trail for why it did not.
  3. Migration of graphs already written to the old relative location. Nothing detects or
     merges a `<cwd>/C:/arkheia-mcp/data/memory.db` left by the defective build.
  4. The `check()` tool gate in front of these three tools. That belongs to flow F1 and is
     covered by its own suite; nothing here mutates it.
  5. Everything above the sqlite file: the OS enforcement of 0600 is asserted as a mode bit,
     not proved by attempting a read as another uid.
"""

import re
import subprocess
import sys
from pathlib import Path

WT = Path(__file__).resolve().parent.parent
PY = sys.executable
TARGETS = [
    "mcp_server/tests/test_memory_knowledge_graph.py",
    "mcp_server/tests/test_mcp_tools.py",
]
TIMEOUT_S = 240

MEM = "mcp_server/tools/memory.py"
SRV = "mcp_server/server.py"

# (id, file, anchor, replacement, what-it-breaks, [expected killer test-name substrings])
MUTANTS = [
    # ---- INV-1: the graph must not fork with the working directory -------------
    ("M1-restore-the-windows-relative-default", MEM,
     'DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"',
     'DEFAULT_DB_PATH = "C:/arkheia-mcp/data/memory.db"',
     "the exact defect from origin/master returns: every process resolves the graph against "
     "its own cwd and silently gets a private, empty one",
     ["test_default_path_is_absolute_and_under_the_users_home",
      "test_two_working_directories_share_one_graph",
      "test_two_processes_in_different_cwds_see_one_graph"]),

    ("M2-plausible-relative-default", MEM,
     'DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"',
     'DEFAULT_DB_PATH = "data/memory.db"',
     "a tidier-looking relative default with the same forking behaviour — proves the guard is "
     "about ABSOLUTENESS and not about the literal string 'C:'",
     ["test_default_path_is_absolute_and_under_the_users_home",
      "test_two_working_directories_share_one_graph"]),

    ("M3-absolute-but-outside-home", MEM,
     'DEFAULT_DB_PATH = "~/.arkheia/mcp/memory.db"',
     'DEFAULT_DB_PATH = "/tmp/arkheia-mcp/memory.db"',
     "absolute (so cwd-independent) but in a world-writable shared location — the failure mode "
     "the npm PYTHON_DIR install had. An is_absolute()-only assertion would miss this.",
     ["test_default_path_is_absolute_and_under_the_users_home",
      "test_two_processes_in_different_cwds_see_one_graph"]),

    ("M4-relative-refusal-deleted", MEM,
     '    if not path.is_absolute():\n        raise ValueError(',
     '    if False:\n        raise ValueError(',
     "an explicitly relative MEMORY_DB_PATH is silently accepted again",
     ["test_relative_memory_db_path_is_refused_loudly",
      "test_the_exact_master_default_would_now_be_refused"]),

    ("M5-refusal-message-drops-the-offending-value", MEM,
     'f"MEMORY_DB_PATH must be an absolute path (or start with \'~\'); got {raw!r}. "',
     '"MEMORY_DB_PATH is invalid. "',
     "the error no longer says WHICH path was rejected or that absoluteness is the rule, so an "
     "operator cannot act on it",
     ["test_relative_memory_db_path_is_refused_loudly"]),

    ("M6-expanduser-dropped", MEM,
     '    path = Path(raw).expanduser()',
     '    path = Path(raw)',
     "'~/.arkheia/mcp/memory.db' is never expanded, so the default becomes a literal relative "
     "'~' directory — the same cwd fork wearing a different name",
     ["test_default_path_is_absolute_and_under_the_users_home",
      "test_two_working_directories_share_one_graph",
      "test_two_processes_in_different_cwds_see_one_graph"]),

    # ---- INV-2: the OS boundary is the control, so it must actually be set -----
    ("M7-file-mode-world-readable", MEM,
     '_FILE_MODE = 0o600',
     '_FILE_MODE = 0o644',
     "the DB file is world-readable again — the exact mode measured on master",
     ["test_new_db_and_directory_are_owner_only",
      "test_a_pre_existing_world_readable_db_is_tightened"]),

    ("M8-dir-mode-world-readable", MEM,
     '_DIR_MODE = 0o700',
     '_DIR_MODE = 0o755',
     "the containing directory is world-readable and world-traversable again",
     ["test_new_db_and_directory_are_owner_only",
      "test_a_pre_existing_world_readable_db_is_tightened"]),

    ("M9-modes-set-only-on-create", MEM,
     '    _enforce_mode(parent, _DIR_MODE)',
     '    pass  # directory mode no longer re-asserted',
     "the directory mode is re-asserted no longer, so mkdir's umask-masked mode stands and an "
     "install that already ran under the defective code stays world-readable forever",
     ["test_a_pre_existing_world_readable_db_is_tightened"]),

    ("M10-file-chmod-dropped", MEM,
     '    _enforce_mode(Path(path), _FILE_MODE)',
     '    pass  # file mode never set',
     "the DB file keeps whatever mode sqlite3 created it with (0644 under the default umask)",
     ["test_new_db_and_directory_are_owner_only",
      "test_a_pre_existing_world_readable_db_is_tightened"]),

    ("M11a-mode-failure-swallowed-silently", MEM,
     '    except OSError as exc:\n        logger.warning(',
     '    except OSError as exc:\n        return\n        logger.warning(',
     "a chmod that cannot be applied is swallowed, so the operator believes in a boundary that "
     "was never set — the 'guard wired but switched off' defect, and invisible because the store "
     "keeps working perfectly",
     ["test_an_unenforceable_mode_is_reported_not_swallowed"]),

    ("M11b-mode-failure-logged-at-debug", MEM,
     '        logger.warning(\n            "memory: could not set mode %o on %s (%s).',
     '        logger.debug(\n            "memory: could not set mode %o on %s (%s).',
     "the warning is demoted to DEBUG, so it is emitted but never seen at default log level — "
     "present-but-undiscovered, which is decoration",
     ["test_an_unenforceable_mode_is_reported_not_swallowed"]),

    # ---- INV-3: search strings are matched literally ---------------------------
    ("M11-escape-is-a-no-op", MEM,
     '    return value.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_")',
     '    return value',
     "LIKE metacharacters flow through again: query='%' dumps the whole graph",
     ["test_like_escape_covers_all_three_metacharacters",
      "test_percent_query_does_not_return_the_whole_graph",
      "test_underscore_matches_only_a_literal_underscore"]),

    ("M12-escape-misses-underscore", MEM,
     '    return value.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_")',
     '    return value.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%")',
     "only '%' is escaped — the commoner real-world case ('auth_middleware') still over-matches",
     ["test_like_escape_covers_all_three_metacharacters",
      "test_underscore_matches_only_a_literal_underscore"]),

    ("M13-escape-misses-percent", MEM,
     '    return value.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_")',
     '    return value.replace("\\\\", "\\\\\\\\").replace("_", "\\\\_")',
     "only '_' is escaped — a wildcard query still returns the entire graph",
     ["test_like_escape_covers_all_three_metacharacters",
      "test_percent_query_does_not_return_the_whole_graph"]),

    ("M14-escape-char-escaped-last", MEM,
     '    return value.replace("\\\\", "\\\\\\\\").replace("%", "\\\\%").replace("_", "\\\\_")',
     '    return value.replace("%", "\\\\%").replace("_", "\\\\_").replace("\\\\", "\\\\\\\\")',
     "the backslash is doubled AFTER the metacharacters are escaped, so the escapes are "
     "themselves escaped and stop working — the classic ordering bug",
     ["test_like_escape_covers_all_three_metacharacters"]),

    ("M15-escape-clause-dropped-untyped-branch", MEM,
     '"SELECT * FROM entities WHERE name LIKE ? ESCAPE \'\\\\\'",',
     '"SELECT * FROM entities WHERE name LIKE ?",',
     "the no-entity_type SQL branch loses its ESCAPE clause, so the backslashes _like_escape "
     "inserts are matched as literal characters and nothing is found",
     ["test_percent_query_does_not_return_the_whole_graph",
      "test_underscore_matches_only_a_literal_underscore"]),

    ("M16-escape-clause-dropped-typed-branch", MEM,
     '"SELECT * FROM entities WHERE name LIKE ? ESCAPE \'\\\\\' AND entity_type = ?",',
     '"SELECT * FROM entities WHERE name LIKE ? AND entity_type = ?",',
     "ONLY the entity_type branch loses its ESCAPE clause. This is the mutant that justifies "
     "test_escaping_survives_the_entity_type_filter_branch existing at all: without it, a "
     "one-branch fix would leave the other defective and the suite green.",
     ["test_escaping_survives_the_entity_type_filter_branch"]),

    # ---- INV-4: the relate contract is enforced --------------------------------
    # NB M17-M20 were re-anchored when store_relation's inline `missing = [...]` block was
    # replaced by _resolve_endpoint (the name-as-identity fix). The old anchors matched 0
    # times and the harness reported them NOT-OBSERVED rather than counting four unexamined
    # guards as clean — that is the instrument working, and re-anchoring is the response.
    ("M17-existence-check-deleted", MEM,
     '    if not ids:\n        qualifier =',
     '    if False:\n        qualifier =',
     "memory_relate accepts any endpoint again, so a typo stores a dangling edge that "
     "memory_retrieve reports back as a real relation",
     ["test_unknown_endpoint_raises_and_names_which_one",
      "test_a_refused_relation_leaves_no_row_behind"]),

    ("M18-only-from-entity-checked", MEM,
     '        to_id = _resolve_endpoint(conn, "to_entity", to_entity, to_entity_type)',
     '        to_id = (_entity_ids_for_name(conn, to_entity, to_entity_type) or [None])[0]',
     "only the source endpoint is validated; a mistyped TARGET still dangles. Half-enforcement "
     "reads as enforcement in any test that only tries a bad from_entity.",
     ["test_unknown_endpoint_raises_and_names_which_one"]),

    ("M19-error-does-not-name-the-side", MEM,
     'f"memory_relate: no such entity \u2014 {label}={name!r}{qualifier}. "',
     '"memory_relate: no such entity. "',
     "the refusal no longer says which endpoint was wrong, so the agent cannot tell which of "
     "the two names it mistyped",
     ["test_unknown_endpoint_raises_and_names_which_one"]),

    ("M20-insert-then-raise", MEM,
     '        from_id = _resolve_endpoint(conn, "from_entity", from_entity, from_entity_type)\n'
     '        to_id = _resolve_endpoint(conn, "to_entity", to_entity, to_entity_type)\n',
     '        conn.execute(\n'
     '            "INSERT INTO relations (rel_id, from_entity, relation_type, to_entity,'
     ' created_at) VALUES (?, ?, ?, ?, ?)",\n'
     '            (str(uuid.uuid4()), from_entity, relation_type, to_entity, "mutant"),\n'
     '        )\n'
     '        conn.commit()\n'
     '        from_id = _resolve_endpoint(conn, "from_entity", from_entity, from_entity_type)\n'
     '        to_id = _resolve_endpoint(conn, "to_entity", to_entity, to_entity_type)\n',
     "the row is written and THEN the refusal is raised — the endpoint check becomes cosmetic "
     "while every pytest.raises assertion still passes. Proves the row-count assertion, not the "
     "raises, is what makes the refusal real.",
     ["test_a_refused_relation_leaves_no_row_behind"]),

    # ---- INV-5: the documented limit cap ---------------------------------------
    # NB the cap moved from server.py's wrapper into memory._validate_limit when the
    # one-sided-bound defect was fixed, so this anchors on its new home. Anchoring on the
    # old `limit = min(limit, 50)` in SRV would now silently NOT-OBSERVE.
    ("M21-upper-cap-removed", MEM,
     '    return min(limit, MAX_RETRIEVE_LIMIT)',
     '    return limit',
     "the documented 'max 50' cap is gone. THIS IS THE MUTANT THE SUPERSEDED PERMISSIVE "
     "ASSERTION COULD NOT SEE: `assert 'entities' in result` holds either way.",
     ["test_server_wrapper_caps_limit_at_fifty", "test_retrieve_limit_capped_at_50"]),

    ("M22-total-counts-only-the-page", MEM,
     '        total = len(rows)\n        rows = rows[:limit]',
     '        rows = rows[:limit]\n        total = len(rows)',
     "`total` reports the truncated page instead of all matches, so a caller can never tell "
     "there is more to fetch",
     ["test_limit_truncates_entities_but_total_reports_all_matches",
      "test_server_wrapper_caps_limit_at_fifty", "test_retrieve_limit_capped_at_50"]),

    ("M23-dedup-removed", MEM,
     '            if content not in existing:',
     '            if True:',
     "observation dedup is gone — re-storing the same fact grows the graph without bound",
     ["test_store_entity_deduplication"]),

    # ---- The scrub-vs-access-control decision, attacked from both sides --------
    ("M24-content-silently-truncated-on-write", MEM,
     '                    (str(uuid.uuid4()), entity_id, content, now),',
     '                    (str(uuid.uuid4()), entity_id, content[:20], now),',
     "a silent lossy rewrite on the write path — the failure shape a redaction pass would have. "
     "Proves the verbatim round-trip assertion is a real check and not a restatement.",
     ["test_content_round_trips_byte_identical"]),

    ("M25-redactor-imported-into-memory", MEM,
     'from pathlib import Path\n\nlogger = logging.getLogger',
     'from pathlib import Path\nfrom proxy.audit.redactor import redact  # noqa: F401\n\n'
     'logger = logging.getLogger',
     "the ACCESS-CONTROL ruling is quietly reversed by importing the audit redactor. The pin "
     "exists so that decision cannot drift without a test going red and the ledger being revisited.",
     ["test_no_redactor_is_imported_by_the_memory_module"]),

    # ---- INV-6: the limit is bounded on BOTH sides (Codex finding A) -----------
    ("M26-lower-bound-deleted", MEM,
     '    if limit < 1:\n        raise ValueError(',
     '    if False:\n        raise ValueError(',
     "restores the exact one-sided bound Codex found: limit=-1 reaches rows[:-1] and returns "
     "59 of 60 rows against a documented cap of 50",
     ["test_negative_limit_does_not_return_more_than_the_cap",
      "test_zero_limit_is_refused_rather_than_silently_emptying",
      "test_the_lower_level_function_also_refuses_a_negative_limit"]),

    ("M27-negative-silently-coerced-instead-of-refused", MEM,
     '    if limit < 1:\n        raise ValueError(',
     '    if limit < 1:\n        limit = 1\n    if False:\n        raise ValueError(',
     "the cap is no longer bypassed, but an invalid limit is silently COERCED to 1 instead of "
     "refused. Distinguishes 'clamped' from 'rejected explicitly' — a bare count assertion "
     "(<= 50) would pass against this.",
     ["test_negative_limit_does_not_return_more_than_the_cap",
      "test_zero_limit_is_refused_rather_than_silently_emptying"]),

    ("M28-bool-slips-through-as-int", MEM,
     '    if isinstance(limit, bool) or not isinstance(limit, int):',
     '    if not isinstance(limit, int):',
     "bool is an int subclass, so limit=True is accepted as limit=1 — a caller's mistyped flag "
     "silently returns exactly one row",
     ["test_non_integer_limit_is_refused_not_coerced"]),

    ("M29-validation-not-called-by-the-lower-level-function", MEM,
     '    limit = _validate_limit(limit)',
     '    pass  # validation skipped',
     "the bound exists but retrieve_entities never invokes it, so every import site other than "
     "the server wrapper is unguarded again",
     ["test_negative_limit_does_not_return_more_than_the_cap",
      "test_the_lower_level_function_also_refuses_a_negative_limit",
      "test_server_wrapper_caps_limit_at_fifty"]),

    # ---- INV-7: relations keyed by identity, not by name (Codex finding B) -----
    ("M30-retrieve-joins-on-name-again", MEM,
     '                "SELECT relation_type, to_entity FROM relations WHERE from_entity_id = ? ORDER BY created_at",\n'
     '                (eid,),',
     '                "SELECT relation_type, to_entity FROM relations WHERE from_entity = ? ORDER BY created_at",\n'
     '                (row["name"],),',
     "the exact defect Codex found: the read path re-joins on the display NAME, so one stored "
     "edge is reported as a fact about every entity sharing that name",
     ["test_relation_attaches_to_only_the_named_entity_not_its_namesake",
      "test_same_name_different_type_each_keeps_its_own_edges",
      "test_a_dangling_edge_planted_directly_is_no_longer_reported"]),

    ("M31-ambiguous-endpoint-silently-resolved-to-the-first", MEM,
     '    if len(ids) > 1:',
     '    if False:',
     "an ambiguous name is silently resolved to whichever row sqlite returned first, instead of "
     "being refused — the edge becomes a confident fact about a guessed entity",
     ["test_ambiguous_endpoint_is_refused_rather_than_guessed"]),

    ("M32-ids-not-written-to-the-relations-row", MEM,
     '            (rel_id, from_entity, relation_type, to_entity, now, from_id, to_id),',
     '            (rel_id, from_entity, relation_type, to_entity, now, None, None),',
     "endpoints resolve and ambiguity is still refused, but the identities are never persisted, "
     "so every edge is NULL-keyed and attached to nobody. A read-path-only assertion would miss it.",
     ["test_relations_are_stored_against_entity_ids_on_disk",
      "test_relation_attaches_to_only_the_named_entity_not_its_namesake",
      "test_same_name_different_type_each_keeps_its_own_edges"]),

    ("M33-migration-guesses-ambiguous-legacy-edges", MEM,
     '        if len(from_ids) == 1 and len(to_ids) == 1:',
     '        if len(from_ids) >= 1 and len(to_ids) >= 1:',
     "the migration back-fills an AMBIGUOUS legacy edge by taking the first candidate, "
     "manufacturing a confident identity the original row never recorded",
     ["test_an_ambiguous_legacy_edge_is_retained_but_attached_to_nobody"]),

    ("M34-migration-drops-what-it-cannot-resolve", MEM,
     '        else:\n            unresolved += 1',
     '        else:\n            unresolved += 1\n            conn.execute("DELETE FROM relations WHERE rel_id = ?", (row["rel_id"],))',
     "unresolvable legacy edges are silently DELETED instead of retained — data loss dressed up "
     "as a clean migration",
     ["test_an_ambiguous_legacy_edge_is_retained_but_attached_to_nobody"]),
]


def _purge_bytecode() -> None:
    """
    Delete every __pycache__ under the worktree before a run.

    THIS HARNESS FOUND ONE OF ITS OWN DEFECTS HERE — the same class the three-bucket
    discipline exists to catch, so it is documented rather than quietly patched.
    M22 swaps two adjacent lines, which leaves the source file BYTE-IDENTICAL IN LENGTH.
    CPython invalidates a cached .pyc on (mtime, size), and mtime is stored at 1-second
    resolution, so a same-size rewrite landing in the same wall-clock second as the
    previous run's .pyc is served from stale bytecode: the mutant is never loaded, the
    suite is green, and the harness reports SURVIVED. That is a NOT-OBSERVED outcome
    wearing the SURVIVED bucket's clothes — precisely the conflation floor ledger entry
    9(d) forbids, and it is timing-dependent, so it would have been intermittent and
    blamed on flakiness. Verified by hand: run the same mutation a second later and it
    kills three tests.
    Two independent defences, because either alone is a single point of failure:
    bytecode writing is disabled in the child env, AND every cache is purged here.
    """
    for cache in WT.rglob("__pycache__"):
        if ".venv" in cache.parts or ".git" in cache.parts:
            continue
        for f in cache.glob("*.pyc"):
            f.unlink(missing_ok=True)


def run_suite() -> tuple[str, list[str], int, str]:
    """-> (bucket, failed_test_names, exit_code, note). bucket in {failed, green, not-observed}."""
    _purge_bytecode()
    cmd = [PY, "-m", "pytest", *TARGETS, "-q", "-p", "no:cacheprovider", "--tb=no", "-rf"]
    try:
        p = subprocess.run(
            cmd, cwd=WT, capture_output=True, text=True, timeout=TIMEOUT_S,
            env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                 "PYTHONDONTWRITEBYTECODE": "1",
                 "JWT_SECRET": "test-secret-for-pytest-not-for-production-use!!"},
        )
    except subprocess.TimeoutExpired:
        return "not-observed", [], -1, f"pytest exceeded {TIMEOUT_S}s — nothing was observed"
    out = p.stdout + p.stderr
    # exit 0 all-pass | 1 tests failed | 2 interrupted | 3 internal | 4 usage | 5 no tests collected
    if p.returncode in (2, 3, 4, 5):
        return "not-observed", [], p.returncode, (
            f"pytest exit {p.returncode} (collection/internal/usage error, or zero tests collected)")
    if re.search(r"^ERROR\s", out, re.M):
        return "not-observed", [], p.returncode, "pytest reported a collection ERROR"
    m = re.search(r"(\d+) passed", out)
    n_passed = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) failed", out)
    n_failed = int(m.group(1)) if m else 0
    if n_passed == 0 and n_failed == 0:
        return "not-observed", [], p.returncode, "no test outcomes reported at all"
    failed = sorted({ln.split("::")[-1].split(" ")[0].split("[")[0]
                     for ln in out.splitlines() if ln.startswith("FAILED ")})
    if n_failed > 0:
        return "failed", failed, p.returncode, f"{n_failed} failed / {n_passed} passed"
    return "green", [], p.returncode, f"{n_passed} passed, 0 failed"


def main() -> int:
    results = []

    print("=== BASELINE (no mutation) ===")
    bucket, failed, rc, note = run_suite()
    print(f"  {bucket}: {note}")
    if bucket != "green":
        print("  ABORT: the campaign observes nothing if the unmutated suite is not green.")
        print(f"  failed: {failed}")
        return 1
    baseline_note = note

    for mid, rel, anchor, repl, breaks, expected in MUTANTS:
        path = WT / rel
        original = path.read_text(encoding="utf-8")
        n = original.count(anchor)
        if n != 1:
            results.append((mid, "NOT-OBSERVED", breaks, [], expected,
                            f"mutation anchor found {n} times (need exactly 1) — mutant never applied"))
            print(f"  {mid}: NOT-OBSERVED (anchor x{n})")
            continue
        try:
            mutated = original.replace(anchor, repl)
            path.write_text(mutated, encoding="utf-8")
            # Read back from disk before observing anything. A mutant that did not land
            # is NOT-OBSERVED, never SURVIVED — a green suite over unmutated source is
            # the harness lying to itself, and it is the failure mode that actually
            # occurred here (see _purge_bytecode).
            if path.read_text(encoding="utf-8") != mutated:
                bucket, failed, rc, note = (
                    "not-observed", [], -1, "mutated source did not survive read-back")
            else:
                bucket, failed, rc, note = run_suite()
        finally:
            path.write_text(original, encoding="utf-8")
            _purge_bytecode()

        if bucket == "not-observed":
            results.append((mid, "NOT-OBSERVED", breaks, failed, expected, note))
        elif bucket == "green":
            results.append((mid, "SURVIVED", breaks, [], expected, note))
        else:
            hit = [f for f in failed if any(e in f for e in expected)]
            status = "KILLED" if hit else "KILLED-BY-OTHER"
            results.append((mid, status, breaks, failed, expected, note))
        print(f"  {mid}: {results[-1][1]} — {note}")

    # ---- report: name the units behind every non-KILLED outcome ----
    print("\n" + "=" * 78)
    print("MUTATION CAMPAIGN — F5 memory knowledge graph")
    print(f"baseline: {baseline_note}")
    print("=" * 78)
    for label in ("KILLED", "KILLED-BY-OTHER", "SURVIVED", "NOT-OBSERVED"):
        rows = [r for r in results if r[1] == label]
        print(f"\n{label}: {len(rows)} of {len(results)} mutants")
        for mid, _st, breaks, failed, expected, note in rows:
            print(f"  - {mid}")
            print(f"      breaks : {breaks}")
            if label == "KILLED":
                caught = [f for f in failed if any(e in f for e in expected)]
                print(f"      caught by (expected): {', '.join(caught)}")
                other = [f for f in failed if f not in caught]
                if other:
                    print(f"      also failed: {', '.join(other[:6])}{' …' if len(other) > 6 else ''}")
            else:
                print(f"      expected killer(s) : {', '.join(expected)}")
                print(f"      actually failed    : {', '.join(failed) if failed else '(nothing)'}")
                print(f"      note               : {note}")
    unresolved = [r for r in results if r[1] != "KILLED"]
    print("\n" + "=" * 78)
    if unresolved:
        print(f"UNRESOLVED — {len(unresolved)} mutant(s) NOT killed by their own assertion, named:")
        for mid, st, *_ in unresolved:
            print(f"  {st}: {mid}")
    else:
        print(f"All {len(results)} mutants KILLED by their own expected assertion.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
