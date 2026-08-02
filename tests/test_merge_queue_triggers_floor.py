"""Floor: if a workflow gates pull requests, it must also gate merge groups.

EARNED, 2026-07-30. `master` carries `strict: true` — branches must be up to date before merging — so
with ~40 open PRs every merge voids every other one and the green count cannot advance. The fix is a
GitHub merge queue. But a queue dispatches CI on the **`merge_group`** event, against a
`gh-readonly-queue/master/**` branch, and every workflow here filters `push:` to `branches: [master]`.

So a REQUIRED status context whose workflow has no `merge_group` trigger **never posts on a queued PR.**
It does not go red — it sits at "Expected — waiting" until GitHub's status-check timeout evicts the PR
from the queue. That failure mode is silent in the direction that matters: a queue that merges nothing
looks like a queue that is merely slow.

The invariant is deliberately stated as "gates PRs ⇒ gates merge groups" rather than against a pinned
list of required contexts. Branch-protection membership is not readable from the repository, so pinning
it here would be a literal that drifts the moment protection changes — and a workflow that is not
required loses nothing by also running in the queue. This way a NEW workflow added later is covered
automatically, which a pinned list could not do.
"""

import pathlib
import re

_WORKFLOWS = pathlib.Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _on_block(text):
    """The body of the top-level `on:` mapping, or '' if the workflow has none."""
    match = re.search(r"^on:(.*?)(?=^\S)", text, re.DOTALL | re.MULTILINE)
    return match.group(1) if match else ""


def _events(on_block):
    """Top-level event names declared under `on:` (indent-2 keys)."""
    return set(re.findall(r"^  ([A-Za-z_]+):", on_block, re.MULTILINE))


def _workflow_files():
    assert _WORKFLOWS.is_dir(), f"missing {_WORKFLOWS}"
    files = sorted(_WORKFLOWS.glob("*.yml")) + sorted(_WORKFLOWS.glob("*.yaml"))
    assert files, f"no workflow files found under {_WORKFLOWS}"
    return files


def test_every_pull_request_gating_workflow_also_gates_merge_groups():
    offenders = {}
    for path in _workflow_files():
        events = _events(_on_block(path.read_text(encoding="utf-8")))
        if "pull_request" in events and "merge_group" not in events:
            offenders[path.name] = sorted(events)

    assert not offenders, (
        "workflow(s) run on `pull_request` but not on `merge_group`: "
        f"{offenders}. `master` is strict:true, so merging at any scale needs a merge queue — and a "
        "queue dispatches CI on `merge_group`, not `pull_request`. If any status context these "
        "workflows produce is REQUIRED, a queued PR would never receive it: it waits at "
        '"Expected \u2014 waiting" until GitHub\'s status-check timeout evicts it, rather than failing '
        "visibly. Add `merge_group:` (with the same `branches:` filter as `pull_request`) to each."
    )


def test_the_merge_group_filter_targets_the_same_branches_as_pull_request():
    """A `merge_group` trigger filtered to the wrong branch is the same defect, wearing a fix.

    The `merge_group` event's `branches:` filter matches the **base** branch of the queued PR, not the
    `gh-readonly-queue/**` ref the queue actually builds. So the correct filter is identical to the one
    on `pull_request`. Getting this wrong reproduces the silent wait exactly, which is why it is pinned
    rather than left to review.
    """
    def branches(on_block, event):
        block = re.search(
            rf"^  {event}:(.*?)(?=^  [A-Za-z_]+:|\Z)", on_block, re.DOTALL | re.MULTILINE
        )
        if not block:
            return None
        listed = re.search(r"^    branches:\s*\[([^\]]*)\]", block.group(1), re.MULTILINE)
        if listed:
            return {b.strip().strip("'\"") for b in listed.group(1).split(",") if b.strip()}
        seq = re.search(
            r"^    branches:\s*$\n((?:\s{6,}-\s*\S+\s*$\n?)+)", block.group(1), re.MULTILINE
        )
        if seq:
            return {
                m.group(1).strip("'\"")
                for m in re.finditer(r"^\s+-\s*(\S+)\s*$", seq.group(1), re.MULTILINE)
            }
        return set()

    mismatched = {}
    for path in _workflow_files():
        on_block = _on_block(path.read_text(encoding="utf-8"))
        events = _events(on_block)
        if not {"pull_request", "merge_group"} <= events:
            continue
        pr_branches = branches(on_block, "pull_request")
        mg_branches = branches(on_block, "merge_group")
        if pr_branches != mg_branches:
            mismatched[path.name] = {"pull_request": sorted(pr_branches or []),
                                     "merge_group": sorted(mg_branches or [])}

    assert not mismatched, (
        "the `merge_group` branches filter does not match the `pull_request` one: "
        f"{mismatched}. `merge_group.branches` matches the BASE branch of the queued PR, so it must "
        "list the same branches `pull_request` does; otherwise the workflow silently never runs in the "
        "queue and the required context waits forever instead of failing."
    )
