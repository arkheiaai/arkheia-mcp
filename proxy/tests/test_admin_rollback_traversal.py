"""Path-traversal hardening for the proxy admin rollback WRITE path (F23 sibling).

`POST /admin/profiles/{model_id}/rollback` (proxy/endpoints/admin.py) builds
``<profile_dir>/<model_id>.yaml`` straight from an authenticated-but-untrusted
``model_id`` and then ``path.write_bytes(...)``. Without validation a crafted
``model_id`` ("../pwned", an absolute path) escapes the profiles root and WRITES
a file OUTSIDE it (also a file-existence oracle + reload trigger) — the WRITE-side
twin of the storage read traversal (registry_server/storage.py).

These tests call the handler directly (bypassing Starlette's ``[^/]+`` route
matcher, which would 404 slash-bearing URLs before the handler and mask the
storage-layer bug — see registry_server test notes), so they GENUINELY exercise
the write path and are RED on the unpatched handler.

MERGE NOTE (master): the handler this now drives is master's hardened rollback —
it emits a governance receipt for every outcome, validates BOTH the live and the
backup profile before swapping, and restores the live file if the reload fails.
Two adaptations follow from that and NOTHING else was relaxed: the auth
dependency is bound as ``admin_email`` (not ``_``), and the planted profiles are
real, schema-valid profile bodies so the validator does not reject them before
the path guard's behaviour can be observed. Every security assertion below (no
out-of-root write, no reload, fail-closed status) is unchanged.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest

from proxy.endpoints.admin import rollback_profile


def _profile_bytes(model_id: str, version: str) -> bytes:
    """A schema-valid profile body (master's rollback validates live AND backup)."""
    return (
        f'model: "{model_id}"\n'
        f'version: "{version}"\n'
        "detection:\n"
        "  features: {}\n"
    ).encode("utf-8")


class _FakeRouter:
    def __init__(self):
        self.reload_called = False

    async def reload(self):
        self.reload_called = True


def _make_request(profile_dir: str, router: _FakeRouter):
    """Minimal object exposing the two app.state attributes the handler reads."""
    state = SimpleNamespace(
        settings=SimpleNamespace(detection=SimpleNamespace(profile_dir=str(profile_dir))),
        profile_router=router,
        audit_writer=None,  # receipts fail soft; rollback must not depend on the rail
    )
    return SimpleNamespace(app=SimpleNamespace(state=state))


@pytest.fixture()
def rollback_env(tmp_path):
    """A profiles root plus an OUT-OF-ROOT location whose *.yaml.bak is planted
    so the *vulnerable* write path would reach ``write_bytes`` and land the file
    outside the root. Returns (profile_dir, outside_dir)."""
    root = tmp_path / "profiles"
    root.mkdir()
    (root / "claude-opus-4-8.yaml").write_bytes(_profile_bytes("claude-opus-4-8", "1.0"))
    outside = tmp_path / "outside"
    outside.mkdir()
    return root, outside


def _escaping_cases(root: Path, outside: Path):
    """(model_id, escaped_target_path) pairs that resolve OUTSIDE ``root``."""
    cases = [
        # relative parent traversal: <root>/../pwned.yaml == <tmp>/pwned.yaml
        ("../pwned", (root.parent / "pwned.yaml")),
        # nested traversal that climbs back out of the root
        ("foo/../../pwned2", (root.parent / "pwned2.yaml")),
        # absolute path: Path(root) / "/abs/....yaml" discards root entirely
        (str(outside / "abs"), (outside / "abs.yaml")),
    ]
    return cases


@pytest.mark.asyncio
@pytest.mark.parametrize("idx", range(3))
async def test_rollback_traversal_never_writes_outside_root(rollback_env, idx):
    """A traversing model_id must NOT write outside the profiles root, must NOT
    reload the router, and must be rejected fail-closed (HTTP 400)."""
    root, outside = rollback_env
    model_id, escaped_target = _escaping_cases(root, outside)[idx]

    # Plant the .bak at the ESCAPED location so the unpatched write would succeed.
    bak = Path(str(escaped_target) + ".bak")
    bak.write_bytes(b"model: pwned\nversion: '9.9'\n")
    assert not escaped_target.exists()  # canary not yet written

    router = _FakeRouter()
    request = _make_request(str(root), router)
    result = await rollback_profile(
        model_id=model_id, request=request, admin_email="admin@example.com"
    )

    # SECURITY: no file was written outside the profiles root.
    assert not escaped_target.exists(), (
        f"traversal WROTE outside root: {escaped_target}"
    )
    # No side effects: the router must not have been reloaded.
    assert router.reload_called is False
    # Fail-closed: rejected with HTTP 400 (a JSONResponse, not a 200 dict).
    status = getattr(result, "status_code", 200)
    assert status == 400, f"expected 400 rejection, got {status!r} / {result!r}"


@pytest.mark.asyncio
async def test_rollback_legit_still_works(rollback_env):
    """A legitimate model_id with an in-root .bak still rolls back (happy path
    preserved by the hardening)."""
    root, _outside = rollback_env
    current = root / "claude-opus-4-8.yaml"
    bak = Path(str(current) + ".bak")
    backup_bytes = _profile_bytes("claude-opus-4-8", "0.9")
    bak.write_bytes(backup_bytes)

    router = _FakeRouter()
    request = _make_request(str(root), router)
    result = await rollback_profile(
        model_id="claude-opus-4-8", request=request, admin_email="admin@example.com"
    )

    assert current.read_bytes() == backup_bytes
    assert router.reload_called is True
    # Success returns the plain ok dict (implicit 200), not an error response.
    assert isinstance(result, dict) and result.get("status") == "ok"


@pytest.mark.asyncio
async def test_rollback_missing_backup_is_rejected(rollback_env):
    """A safe model_id with no .bak is rejected fail-closed (HTTP 404), no
    write, no reload."""
    root, _outside = rollback_env
    router = _FakeRouter()
    request = _make_request(str(root), router)
    result = await rollback_profile(
        model_id="no-such-model", request=request, admin_email="admin@example.com"
    )
    assert router.reload_called is False
    assert getattr(result, "status_code", 200) == 404
