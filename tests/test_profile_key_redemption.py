"""
F20 — the key is REDEEMED, not merely shaped: hosted key vs release ciphertext.

Run to ground 2026-07-26 against ``sweep/mcp-encrypted-profile-decryption`` @ 301a29d,
and against ``arkheia-proxy`` ``app/routers/profile_key.py`` @ b785107 (unchanged on
``origin/main`` and on ``origin/sweep/proxy-profile-key``).

WHY THIS FILE EXISTS — the hole the existing F20 suite could not see
-------------------------------------------------------------------
``tests/test_encrypted_profile_tamper.py`` proves a great deal about AES-256-GCM in
this repo, and a mutation harness killed 18 of 19 mutants against it. None of that
was ever able to observe the defect below, because **every test on this side mocked
the transport** (``respx.post(KEY_URL).mock(...)``) and handed the loader a key the
test had generated itself — that is, it asserted the loader's behaviour given a
correctly-formed key, and the proxy side asserted the key's *shape*. Neither side
ever redeemed a real hosted key against real release ciphertext, so the two halves
of one derivation contract were each tested against themselves.

THE CONTRADICTION, three files, one env var (``ARKHEIA_PROFILE_MASTER_KEY``)
----------------------------------------------------------------------------
* **ENCRYPTION** — arkheia-mcp ``scripts/build_release.py::resolve_profile_key``:
  ``master_key = base64.b64decode(ENV)``, required to be exactly 32 bytes.
  ``encrypt_profile`` then uses ``derive_key(master_key, name)``.
* **DISTRIBUTION** — arkheia-proxy ``app/routers/profile_key.py``:
  ``key_bytes = hashlib.sha256(ENV.encode("utf-8")).digest()``, issued base64.
* **CLIENT** — this repo ``proxy/crypto/profile_crypto.py::DynamicKeyLoader``:
  base64-decodes whatever the endpoint issued, requires 32 bytes, and passes it to
  ``derive_key`` as the master key.

So the build encrypts under ``sha256(b64decode(ENV) + name)`` and a hosted install
decrypts under ``sha256(sha256(ENV) + name)``. They cannot agree, and the failure
mode is ``InvalidTag`` on every encrypted profile.

WHICH SIDE IS CORRECT: the BUILD side (``b64decode``)
-----------------------------------------------------
Not a judgement call — three independent producers/consumers in this repo already
pin the base64-of-32-raw-bytes format, and the proxy is the lone outlier:
  1. ``scripts/build_release.py`` ``--profile-key`` help: *"Base64-encoded 32-byte
     profile master key. Defaults to ARKHEIA_PROFILE_MASTER_KEY."*
  2. ``scripts/encrypt_profiles.py`` module docstring, which gives the generator
     verbatim: ``base64.b64encode(secrets.token_bytes(32))``.
  3. ``DynamicKeyLoader._fetch_from_hosted`` refuses anything that is not exactly
     32 bytes after ``b64decode(..., validate=True)``.
The proxy's derivation also contradicts its OWN comment two lines above it ("Use
the raw bytes of the master key, padded/truncated to 32 bytes" — it hashes
instead), which is what a divergence introduced in isolation looks like. Under the
correct contract the endpoint's response body is the env value itself, validated:
``b64encode(b64decode(ENV)) == ENV``.

**This file does not fix the derivation.** That fix is sequenced with a security
exposure on the proxy side and is the operator's call. What this file does is make
the break *measurable*: the redemption tests below are marked
``xfail(strict=True)``, so they record the break honestly today AND turn the suite
RED the moment the derivation is corrected, forcing the marker off rather than
letting a fixed contract sit behind a stale "known break".

TEST RIG DISCIPLINE
-------------------
* **Nothing is mocked.** ``fetch_key`` is the real method, over real httpx, against
  a real socket served by a real ``http.server`` — because a transport mock is
  precisely what hid this defect (DONE.md floor invariant 10: an advertised
  identifier must be redeemed as a caller would redeem it, end to end).
* **The ciphertext is release ciphertext** — produced by the real
  ``scripts/build_release.py::step_encrypt_profiles``, which is the code that
  deletes the plaintext, and read back by the real ``ProfileRouter``.
* **Every xfail has a passing control on the same rig** (DONE.md v1.15 clause 5): a
  correctly-issued key decrypts, and a fabricated key does not. Without both, a red
  run cannot distinguish "the derivation disagrees" from "the harness is broken".
* **No key value is ever printed or asserted verbatim.** Keys are freshly random
  per test; only ``key_fingerprint`` (non-reversing) appears in any message.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Iterator

import pytest
import yaml

from proxy.crypto.profile_crypto import (
    DynamicKeyLoader,
    key_fingerprint,
)
from proxy.router.profile_router import ProfileRouter, ProfileLoadReport
from proxy.tests._receipt_probe import ReceiptProbe
from scripts.build_release import resolve_profile_key, step_encrypt_profiles

REPO_ROOT = Path(__file__).resolve().parent.parent

# The profile that gets encrypted and redeemed. `model` is required by
# ProfileRouter._extract_model_id, so a successful load is observable as a
# dispatchable model id and not merely as "no exception".
PROFILE_NAME = "f20-redemption-probe"
PROFILE_MODEL_ID = "f20-redemption-probe"
PROFILE_YAML = yaml.dump(
    {
        "model": PROFILE_MODEL_ID,
        "version": "1.0",
        "features": {"burstiness": {"mean": 0.5, "std": 0.1}},
    },
    sort_keys=True,
).encode("utf-8")


# ---------------------------------------------------------------------------
# The two derivations, pinned side by side.
# ---------------------------------------------------------------------------

#: The arkheia-proxy derivation, transcribed VERBATIM from
#: ``app/routers/profile_key.py`` @ b785107977ecc6db7853d16049a1710fa5a6e564,
#: lines 46-53. Kept as source text so the drift guard below can assert the pin
#: still matches the sibling repo rather than trusting this comment.
PINNED_HOSTED_DERIVATION_SOURCE = (
    '    # Derive a 32-byte key from the master key\n'
    '    # Use the raw bytes of the master key, padded/truncated to 32 bytes\n'
    '    raw = master_key.encode("utf-8")\n'
    '    # SHA-256 gives exactly 32 bytes deterministically\n'
    '    import hashlib\n'
    '    key_bytes = hashlib.sha256(raw).digest()\n'
    '\n'
    '    profile_key_b64 = base64.b64encode(key_bytes).decode("ascii")\n'
)
PINNED_HOSTED_DERIVATION_REPO = "arkheia-proxy"
PINNED_HOSTED_DERIVATION_PATH = "app/routers/profile_key.py"
PINNED_HOSTED_DERIVATION_COMMIT = "b785107977ecc6db7853d16049a1710fa5a6e564"


def hosted_issued_key_b64(env_value: str) -> str:
    """
    What ``POST /v1/profile-key`` issues today, for a given env value.

    A transcription of ``PINNED_HOSTED_DERIVATION_SOURCE`` and nothing else; the
    drift guard keeps the transcription honest.
    """
    raw = env_value.encode("utf-8")
    key_bytes = hashlib.sha256(raw).digest()
    return base64.b64encode(key_bytes).decode("ascii")


def correctly_issued_key_b64(env_value: str) -> str:
    """
    What the endpoint would issue under the format the build side documents.

    Deliberately routed through the REAL build-side resolver rather than a second
    ``b64decode``, so this control cannot drift away from the encryption path
    (DONE.md v1.13 clause 4: no second source of truth).
    """
    return base64.b64encode(resolve_profile_key(env_value)).decode("ascii")


def _fresh_env_value() -> str:
    """A well-formed ``ARKHEIA_PROFILE_MASTER_KEY``: base64 of 32 random bytes."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


# ---------------------------------------------------------------------------
# A REAL hosted endpoint. Not respx, not a monkeypatched client: a socket.
# ---------------------------------------------------------------------------


class _ProfileKeyHandler(BaseHTTPRequestHandler):
    """The narrowest possible stand-in for ``POST /v1/profile-key``."""

    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802  (stdlib naming)
        if self.path != "/v1/profile-key":
            self.send_error(404)
            return
        # The real endpoint is behind `verify_api_key`; refusing an unauthenticated
        # POST keeps the rig from passing for a client that forgot the header.
        if not self.headers.get("X-Arkheia-Key"):
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(
            {
                "profile_key": self.server.issue_key(),  # type: ignore[attr-defined]
                "expires_at": "2099-01-01T00:00:00+00:00",
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # pragma: no cover - silence the server
        pass


@contextmanager
def hosted_endpoint(issue_key: Callable[[], str]) -> Iterator[str]:
    """Serve ``POST /v1/profile-key`` on a real loopback socket. Yields the base URL."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ProfileKeyHandler)
    server.issue_key = issue_key  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _isolated_loader(hosted_url: str, tmp_path: Path) -> DynamicKeyLoader:
    """A real ``DynamicKeyLoader`` whose cache lives in tmp, never ``~/.arkheia``."""
    loader = DynamicKeyLoader(hosted_url, "ak_live_test")
    loader.CACHE_DIR = tmp_path / ".arkheia"
    loader.CACHE_FILE = loader.CACHE_DIR / "profile_key.cache"
    return loader


# ---------------------------------------------------------------------------
# Real release ciphertext, via the real release step.
# ---------------------------------------------------------------------------


def _release_profile_dir(tmp_path: Path, env_value: str) -> Path:
    """
    Run the REAL release encryption step and return the resulting profile dir.

    ``step_encrypt_profiles`` is the function the release orchestrator calls: it
    writes ``<name>.yaml.enc`` and unlinks the plaintext. Using it (rather than
    calling ``encrypt_profile`` directly) means this rig cannot pass against a
    build pipeline whose key handling has drifted from its crypto helper.
    """
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / f"{PROFILE_NAME}.yaml").write_bytes(PROFILE_YAML)

    master_key = resolve_profile_key(env_value)
    count = step_encrypt_profiles(master_key, profile_dir)

    assert count == 1, f"release step encrypted {count} profiles, expected 1"
    assert (profile_dir / f"{PROFILE_NAME}.yaml.enc").exists()
    assert not (profile_dir / f"{PROFILE_NAME}.yaml").exists(), (
        "the release step must delete the plaintext; if it did not, a later "
        "assertion could be satisfied by the plaintext path and never touch AES-GCM"
    )
    return profile_dir


async def _redeem_and_load(
    tmp_path: Path, env_value: str, issue_key: Callable[[], str]
) -> tuple[ProfileLoadReport, ProfileRouter, bytes]:
    """
    The whole customer path, end to end, nothing mocked.

    build the ciphertext -> serve the endpoint -> ``fetch_key()`` over real HTTP ->
    hand the key to a real ``ProfileRouter`` -> report what actually decrypted.
    """
    profile_dir = _release_profile_dir(tmp_path, env_value)
    with hosted_endpoint(issue_key) as hosted_url:
        loader = _isolated_loader(hosted_url, tmp_path)
        key = await loader.fetch_key()
        assert loader.last_source == "hosted", (
            f"the loader did not reach the live endpoint (source={loader.last_source!r}); "
            "the rig is broken, so no verdict below is meaningful"
        )
    assert key is not None
    router = ProfileRouter(str(profile_dir))
    report = router.set_decryption_key(key)
    return report, router, key


def _assert_redeemed(report: ProfileLoadReport, router_ids: list[str]) -> None:
    """The success condition: the encrypted profile is DISPATCHABLE, not merely present."""
    assert report.encrypted_present == 1
    assert report.encrypted_attempted == 1
    assert report.encrypted_failed == [], (
        f"AES-GCM authentication failed for {report.encrypted_failed}: the key the "
        f"hosted endpoint issued does not open the ciphertext the release build wrote"
    )
    assert report.encrypted_decrypted == 1
    assert report.clean is True
    assert PROFILE_MODEL_ID in router_ids


# ---------------------------------------------------------------------------
# 1. Which side is correct — the differential, on the env value alone.
# ---------------------------------------------------------------------------


def test_the_build_side_master_key_is_the_base64_decoded_env_value():
    """
    Pin the format the build side actually implements. Control row for the table:
    this passes, so the differential below discriminates rather than merely forbids.
    """
    env_value = _fresh_env_value()
    master_key = resolve_profile_key(env_value)
    assert master_key == base64.b64decode(env_value)
    assert len(master_key) == 32
    # And the documented generator produces exactly this shape.
    assert base64.b64encode(master_key).decode("ascii") == env_value


@pytest.mark.parametrize("bad_env", ["", "not base64!!", base64.b64encode(b"short").decode()])
def test_the_build_side_refuses_an_env_value_that_is_not_a_32_byte_base64_key(bad_env):
    """The build side's contract is enforced, not merely documented."""
    with pytest.raises(ValueError):
        resolve_profile_key(bad_env)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BREAK, not a flake. arkheia-proxy app/routers/profile_key.py issues "
        "b64encode(sha256(ENV)) while arkheia-mcp scripts/build_release.py encrypts "
        "under b64decode(ENV). The build side is correct (three producers pin "
        "base64-of-32-raw-bytes; the proxy is the lone outlier and contradicts its own "
        "comment). Fix is sequenced with a proxy-side security exposure and is the "
        "operator's call. When it lands this XPASSes and the strict marker turns the "
        "suite RED — remove the marker then, do not re-add it."
    ),
)
def test_the_hosted_endpoint_issues_the_key_the_build_encrypted_with():
    """The one-line differential the two repos never ran against each other."""
    env_value = _fresh_env_value()
    issued = base64.b64decode(hosted_issued_key_b64(env_value), validate=True)
    expected = resolve_profile_key(env_value)
    assert issued == expected, (
        "hosted-issued key fingerprint "
        f"{key_fingerprint(issued)} != build master key fingerprint "
        f"{key_fingerprint(expected)}"
    )


def test_pinned_hosted_derivation_matches_the_live_arkheia_proxy_source():
    """
    Keep the transcription above honest against the sibling repo.

    HONEST LIMITATION, stated rather than hidden: arkheia-mcp CI has no
    arkheia-proxy checkout, so in CI this SKIPS. A cross-repo derivation contract
    is not verifiable from inside one repo's CI — closing that needs either a
    shared contract module both repos import, or a job that checks out both. Until
    then this guard only fires for a developer or agent with both trees, and the
    ledger records the gap rather than counting a skip as coverage.
    """
    candidates = []
    env_override = os.environ.get("ARKHEIA_PROXY_REPO")
    if env_override:
        candidates.append(Path(env_override))
    # The sibling of a normal checkout, and the sibling of a `_wt/<name>` worktree
    # (this branch is developed in one, so a guard that only knew the first form
    # would silently skip in exactly the place it is meant to run).
    candidates.append(REPO_ROOT.parent / PINNED_HOSTED_DERIVATION_REPO)
    candidates.append(REPO_ROOT.parent.parent / PINNED_HOSTED_DERIVATION_REPO)

    for repo in candidates:
        source = repo / PINNED_HOSTED_DERIVATION_PATH
        if source.exists():
            text = source.read_text(encoding="utf-8")
            assert PINNED_HOSTED_DERIVATION_SOURCE in text, (
                f"{PINNED_HOSTED_DERIVATION_REPO}/{PINNED_HOSTED_DERIVATION_PATH} no "
                f"longer contains the derivation pinned in this file at commit "
                f"{PINNED_HOSTED_DERIVATION_COMMIT}. Re-pin "
                f"PINNED_HOSTED_DERIVATION_SOURCE and hosted_issued_key_b64 from the "
                f"current source, then re-check the xfail markers in this module: a "
                f"corrected derivation makes them XPASS."
            )
            return

    pytest.skip(
        "arkheia-proxy checkout not found (looked at $ARKHEIA_PROXY_REPO and "
        f"{REPO_ROOT.parent / PINNED_HOSTED_DERIVATION_REPO}); the cross-repo pin in "
        "this module is UNVERIFIED in this environment. This is a real coverage gap, "
        "not a pass."
    )


# ---------------------------------------------------------------------------
# 2. Redemption — a real key, over a real socket, against real ciphertext.
# ---------------------------------------------------------------------------


@pytest.mark.xfail(
    strict=True,
    reason=(
        "KNOWN BREAK, not a flake. Redeeming a key from the hosted endpoint as it is "
        "implemented today yields InvalidTag on every release-encrypted profile "
        "(b64encode(sha256(ENV)) issued vs b64decode(ENV) encrypted). This is the test "
        "whose absence let the break ship: every other key test in this repo mocks the "
        "transport. When the derivation is corrected this XPASSes and the strict marker "
        "turns the suite RED — remove the marker then, do not re-add it."
    ),
)
async def test_redeeming_the_hosted_key_decrypts_release_ciphertext(tmp_path):
    env_value = _fresh_env_value()
    report, router, _ = await _redeem_and_load(
        tmp_path, env_value, lambda: hosted_issued_key_b64(env_value)
    )
    _assert_redeemed(report, router.profile_ids)
    assert router.get(PROFILE_MODEL_ID) is not None


async def test_control_redeeming_a_correctly_issued_key_decrypts_release_ciphertext(tmp_path):
    """
    POSITIVE CONTROL for the xfail above, on the identical rig.

    Same release step, same socket, same real ``fetch_key``, same ``ProfileRouter``
    — only the endpoint's derivation differs. It passes, so the red above is the
    derivation disagreeing and not the harness failing to work at all.
    """
    env_value = _fresh_env_value()
    report, router, key = await _redeem_and_load(
        tmp_path, env_value, lambda: correctly_issued_key_b64(env_value)
    )
    assert key_fingerprint(key) == key_fingerprint(resolve_profile_key(env_value))
    _assert_redeemed(report, router.profile_ids)
    assert router.get(PROFILE_MODEL_ID) is not None


async def test_control_a_fabricated_key_from_the_endpoint_does_not_decrypt(tmp_path):
    """
    NEGATIVE CONTROL: the rig's success condition can fail.

    A 32-byte key of the right SHAPE but the wrong VALUE — which is exactly what
    the shape assertions on the proxy side accept — is refused by AES-GCM and named
    in the load report. Without this, ``_assert_redeemed`` could be passing for
    reasons unrelated to the key.
    """
    env_value = _fresh_env_value()
    fabricated = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    report, router, key = await _redeem_and_load(tmp_path, env_value, lambda: fabricated)

    assert len(key) == 32  # the shape check the proxy side asserts passes...
    assert report.encrypted_decrypted == 0  # ...and the redemption does not
    assert report.encrypted_failed == [f"{PROFILE_NAME}.yaml.enc"]
    assert report.clean is False
    assert router.get(PROFILE_MODEL_ID) is None
    with pytest.raises(AssertionError):
        _assert_redeemed(report, router.profile_ids)


# ---------------------------------------------------------------------------
# 3. Receipted — does the decision leave a durable, attributable record?
# ---------------------------------------------------------------------------
#
# Two decisions are made on this path, both security-bearing:
#
#   * WHICH KEY was loaded, and from where — ``fetch_key`` chooses hosted, then a
#     locally cached key whose own docstring says it "may have been revoked", then
#     none. That is an authorisation decision taken on the customer's machine.
#   * WHETHER A PROFILE AUTHENTICATED — an AES-GCM ``InvalidTag`` is the strongest
#     tamper signal this component can produce.
#
# Today both leave only a ``logger`` line. The audit rail (``proxy/audit/writer.py``,
# hash-chained JSONL) is not merely unused here — in ``proxy/main.py`` it is
# constructed at step 3, AFTER the key load at step 1b, so at the moment these
# decisions are taken there is no writer in existence to receive them.
#
# The probe is the ONE shared probe (``proxy/tests/_receipt_probe.py``), parameterised
# on the id field a receipt for this flow would carry. No fourth copy.


def _audit_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the configured audit log at tmp — the place a real emitter would write."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("ARKHEIA_AUDIT_LOG", str(path))
    from proxy.config import settings

    monkeypatch.setattr(settings.audit, "log_path", str(path), raising=False)
    return path


async def test_control_the_receipt_probe_observes_a_record_that_is_written(tmp_path):
    """
    VACUITY GUARD for the two xfails below.

    The absence assertions are worth nothing unless the probe can see a record that
    IS written, through the production ``AuditWriter``, at the exact path used
    below. Proven here before any absence is claimed.
    """
    probe = ReceiptProbe(tmp_path / "audit.jsonl", id_field="profile_name")
    await probe.start()
    await probe.write({"profile_name": f"{PROFILE_NAME}.yaml.enc", "outcome": "probe"})
    await probe.stop()

    row = probe.require(f"{PROFILE_NAME}.yaml.enc")
    assert row["outcome"] == "probe"
    assert probe.find("no-such-profile") is None  # the lookup is not decorative
    assert probe.recompute_this_hash(row) == row["this_hash"]


@pytest.mark.xfail(
    strict=True,
    reason=(
        "receipted=FAIL. An AES-GCM authentication failure on an encrypted profile "
        "leaves NO durable record: proxy/router/profile_router.py logs it and drops the "
        "profile, and no emission site exists. Structurally, proxy/main.py builds the "
        "AuditWriter at step 3, after the profile key load at step 1b, so no writer "
        "exists when the decision is taken. When a receipt is wired this XPASSes and "
        "the strict marker turns the suite RED — remove the marker then."
    ),
)
async def test_an_authentication_failure_leaves_a_durable_receipt(tmp_path, monkeypatch):
    env_value = _fresh_env_value()
    profile_dir = _release_profile_dir(tmp_path, env_value)
    audit_path = _audit_path(tmp_path, monkeypatch)

    router = ProfileRouter(str(profile_dir))
    report = router.set_decryption_key(secrets.token_bytes(32))
    # Positive control on the DECISION: the failure really did happen.
    assert report.encrypted_failed == [f"{PROFILE_NAME}.yaml.enc"]

    probe = ReceiptProbe(audit_path, id_field="profile_name")
    row = probe.require(f"{PROFILE_NAME}.yaml.enc")
    assert row.get("event") in {"profile_authentication_failed", "profile_decrypt_failed"}


@pytest.mark.xfail(
    strict=True,
    reason=(
        "receipted=FAIL. DynamicKeyLoader.fetch_key chooses between hosted, a cached "
        "key it warns 'may have been revoked', and none — and records that choice only "
        "in self.last_source plus a log line. Nothing durable, nothing attributable, "
        "nothing an auditor can read back. When a receipt is wired this XPASSes and the "
        "strict marker turns the suite RED — remove the marker then."
    ),
)
async def test_the_key_source_decision_leaves_a_durable_receipt(tmp_path, monkeypatch):
    env_value = _fresh_env_value()
    audit_path = _audit_path(tmp_path, monkeypatch)

    with hosted_endpoint(lambda: correctly_issued_key_b64(env_value)) as hosted_url:
        loader = _isolated_loader(hosted_url, tmp_path)
        key = await loader.fetch_key()
    # Positive control on the DECISION: a key really was loaded, from the endpoint.
    assert key is not None
    assert loader.last_source == "hosted"

    # A receipt for this decision would be looked up by the fingerprint the loader
    # already computes for its log line — the only key identifier that is safe to
    # persist, and the one that answers "is the running key the build's key?".
    probe = ReceiptProbe(audit_path, id_field="profile_key_fingerprint")
    row = probe.require(key_fingerprint(key))
    assert row.get("key_source") == "hosted"
