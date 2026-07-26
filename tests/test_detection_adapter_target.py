"""
THE ADDRESS IS PART OF THE CONTRACT, AND THE OPERATOR SUPPLIES IT.

`tests/test_detection_adapter_push.py` ran the SIGNATURE and the BODY to ground
against the real receiver. Both are ours: they are computed in this repo and
cannot drift without a code change. The third element of the contract — the
ADDRESS — is the only one a human types into a deployment, and it was never
checked.

THE DEFECT
----------
`push_event` composed its target as ``f"{url}{ADAPTER_PATH}"``. With

    DETECTION_ADAPTER_URL=http://adapter:7070/

— a trailing slash, the commonest way anyone writes a base URL — that POSTs to
``//v1/events/proxy``. Verified in this file, not assumed:

  * `httpx` does NOT fold `//` (see `test_httpx_does_not_rescue_a_double_slash`);
  * the receiver's axum router is built with NO `NormalizePathLayer` (verified in
    `main.rs` and transcribed into `_receiver_oracle.ROUTES`), so `//v1/events/proxy`
    has an empty first segment and does not match `/v1/events/proxy`.

The result is a **404 with an empty body** on a **fire-and-forget** path. That is
strictly worse than the defect this branch was opened to fix: the 401 it replaced
at least named a reason. One character in one env var reverts the governance rail
to dark, and nothing in the signature, the schema or the receipt notices, because
every one of them is about a request that never arrived.

WHAT IS ASSERTED HERE
---------------------
Not "the composed string looks right" — that is a restatement of the sender. The
composed target is fed to the RECEIVER'S OWN ROUTER (`_receiver_oracle.route`,
transcribed from `main.rs`) and must reach the handler. A test that only compared
f-strings would have passed against a receiver that 404s.

Both halves of the fail-open contract are pinned here, because they are easy to
confuse and only one of them was ever true:

  * fail-OPEN  — a misconfigured or unreachable adapter never raises into the
                 caller and never blocks the governed decision;
  * never fail-SILENT — it is an ERROR naming the ATTEMPTED TARGET, and the
                 unrecoverable case (a URL that cannot be parsed) fails at
                 STARTUP rather than being discovered one lost push at a time.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest
import respx

from tests import _receiver_oracle as oracle

import proxy.detection_adapter as mod
from proxy.detection_adapter import ADAPTER_PATH, PushOutcome

KEY_ID = "mcp-v1"
SECRET = "test-secret-32-bytes-minimum-len"

PAYLOAD = {
    "detection_id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
    "model_id": "gpt-4o",
    "confidence": 0.81,
}


@pytest.fixture
def secret_configured(monkeypatch):
    """Everything except the URL, which each case sets for itself."""
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    monkeypatch.setenv("DETECTION_ADAPTER_KEY_ID", KEY_ID)


class Capture:
    def __init__(self, status: int = 200, body: str = "{}"):
        self.status = status
        self.body = body
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self.status, text=self.body)

    @property
    def only(self) -> httpx.Request:
        assert len(self.requests) == 1, (
            f"expected exactly 1 request at the transport boundary, saw {len(self.requests)}"
        )
        return self.requests[0]


async def _push(audit=None):
    return await mod.push_event("acme-corp", "gpt-4o", "mcp_detection", PAYLOAD, "LOW", audit)


# ══════════════════════════════════════════════════════════════════════════════
# A. The ground truth this rests on — asserted, not assumed
# ══════════════════════════════════════════════════════════════════════════════

def test_httpx_does_not_rescue_a_double_slash():
    """
    The reason a trailing slash is fatal rather than cosmetic. If httpx ever
    started folding `//`, the defect would be latent rather than live and this
    file would be over-claiming — so the premise is pinned, not trusted.
    """
    assert httpx.URL("http://adapter:7070/" + ADAPTER_PATH).path == "//v1/events/proxy"
    # control: without the trailing slash the same concatenation is correct, so
    # the assertion above is about the slash and not about httpx generally.
    assert httpx.URL("http://adapter:7070" + ADAPTER_PATH).path == ADAPTER_PATH


def test_the_receivers_router_refuses_a_double_slashed_path():
    """
    The oracle transcribes `main.rs`. Prove the misrouted path is a 404 there AND
    that the correct path is matched — a router oracle that refused everything
    would make every test in this file pass for the wrong reason.
    """
    assert oracle.route("POST", "//v1/events/proxy") == oracle.NOT_FOUND
    assert oracle.route("POST", "///v1/events/proxy") == oracle.NOT_FOUND
    assert oracle.route("POST", "/v1/events/proxy/") == oracle.NOT_FOUND
    # positive controls
    assert oracle.route("POST", ADAPTER_PATH) == oracle.ROUTE_MATCHED
    assert oracle.route("GET", ADAPTER_PATH) == oracle.METHOD_NOT_ALLOWED


# ══════════════════════════════════════════════════════════════════════════════
# B. Every realistic way an operator writes the base URL lands on the handler
# ══════════════════════════════════════════════════════════════════════════════

# (base URL as written in the deployment, receiver-visible path prefix stripped
# by any gateway in front of it). The prefix cases model a reverse proxy mounted
# at a sub-path, which is why the expected target keeps the prefix while the
# RECEIVER still sees `/v1/events/proxy`.
WELL_FORMED = [
    ("http://adapter:7070", "http://adapter:7070/v1/events/proxy", ""),
    ("http://adapter:7070/", "http://adapter:7070/v1/events/proxy", ""),
    ("http://adapter:7070///", "http://adapter:7070/v1/events/proxy", ""),
    ("  http://adapter:7070  ", "http://adapter:7070/v1/events/proxy", ""),
    ("\thttp://adapter:7070/\n", "http://adapter:7070/v1/events/proxy", ""),
    ("https://adapter.example.com", "https://adapter.example.com/v1/events/proxy", ""),
    ("https://adapter.example.com/", "https://adapter.example.com/v1/events/proxy", ""),
    ("http://gw.example/adapter", "http://gw.example/adapter/v1/events/proxy", "/adapter"),
    ("http://gw.example/adapter/", "http://gw.example/adapter/v1/events/proxy", "/adapter"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("base, expected_target, prefix", WELL_FORMED)
async def test_the_push_reaches_the_receivers_handler(
    secret_configured, monkeypatch, respx_mock, base, expected_target, prefix
):
    """
    THE red-first case. Against the pre-fix `f"{url}{ADAPTER_PATH}"` every base
    carrying a trailing slash posts to `//v1/events/proxy`, which the oracle
    router 404s — so this fails before the fix and passes after, for each of the
    realistic ways the value gets written.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", base)
    cap = Capture()
    respx_mock.route(method="POST").mock(side_effect=cap)

    outcome = await _push()
    assert outcome.status == PushOutcome.DELIVERED

    sent = cap.only
    assert str(sent.url) == expected_target, f"misroute from base {base!r}"

    # What the RECEIVER sees, after any gateway strips its own mount prefix.
    received_path = sent.url.path[len(prefix):]
    assert oracle.route("POST", received_path) == oracle.ROUTE_MATCHED, (
        f"base {base!r} composed {sent.url.path!r}, which the receiver's router "
        f"does not match — the push is lost as a 404 with an empty body"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("base, expected_target, prefix", WELL_FORMED)
async def test_the_signature_still_verifies_whatever_the_base_url_was(
    secret_configured, monkeypatch, respx_mock, base, expected_target, prefix
):
    """
    Normalising the address must not disturb the signature.

    The receiver signs over the path ITS OWN handler is mounted at — `handlers.rs`
    passes the literal "/v1/events/proxy" into `verify` — never over whatever
    absolute URL the sender happened to use. So `ADAPTER_PATH` is right in the
    signing string even when a gateway prefix is present in the base URL, and
    that is a property worth pinning rather than rediscovering.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", base)
    cap = Capture()
    respx_mock.route(method="POST").mock(side_effect=cap)
    await _push()

    req = cap.only
    oracle.verify(SECRET.encode(), KEY_ID, ADAPTER_PATH, req.content, dict(req.headers))


# ══════════════════════════════════════════════════════════════════════════════
# C. A base URL that cannot work is refused, loudly, and never sent
# ══════════════════════════════════════════════════════════════════════════════

MALFORMED = [
    ("adapter:7070", "no scheme — 'adapter' parses as the scheme, leaving no host"),
    ("adapter.example.com/v1", "bare hostname, no scheme"),
    ("not a url at all", "not a URL"),
    ("ftp://adapter:7070", "unsupported scheme"),
    ("http://", "scheme but no host"),
    ("//adapter:7070", "protocol-relative — no scheme to dial"),
    ("/v1/events/proxy", "a path, not a base URL"),
    # Refused rather than silently truncated. Appending a path to a URL that
    # already has a query or fragment cannot preserve both, and quietly dropping
    # half of what an operator wrote is the same silence this whole change is
    # about — they would see a working push to an address they did not specify.
    ("http://adapter:7070?tenant=acme", "a query string cannot survive a path append"),
    ("http://adapter:7070/#frag", "a fragment cannot survive a path append"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("base, why", MALFORMED)
async def test_a_malformed_base_url_is_reported_not_attempted(
    secret_configured, monkeypatch, respx_mock, caplog, base, why
):
    """
    A URL that cannot be dialled is a CONFIGURATION defect, not a delivery
    failure, and it is indistinguishable from "unconfigured" unless it gets its
    own outcome. `SKIPPED` means "nobody asked for this rail" and is silent by
    design; reusing it here would file an operator's typo under 'safe'.

    So: its own status, an ERROR naming the offending value, and zero bytes sent.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", base)
    route = respx_mock.route(method="POST").mock(side_effect=Capture())

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()  # fail-open: must not raise

    assert outcome.status == PushOutcome.MISCONFIGURED, why
    assert outcome.delivered is False
    assert route.call_count == 0, "a push was attempted at an undialable address"

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, f"expected exactly one ERROR, got {[r.message for r in errors]}"
    msg = errors[0].getMessage()
    assert mod.FAILURE_MARKER in msg
    assert "DETECTION_ADAPTER_URL" in msg, "the operator is not told WHICH setting is wrong"
    assert base.strip() in msg, "the operator is not shown the offending value"


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "   ", "\n\t"])
async def test_a_blank_url_is_unconfigured_not_misconfigured(
    secret_configured, monkeypatch, respx_mock, caplog, blank
):
    """
    The paired boundary: absent config stays SILENT-BUT-SAFE (`SKIPPED`), because
    an unconfigured deployment has not asked for this rail. Whitespace-only is
    absent, not malformed. Without this pair the previous test could be satisfied
    by shouting at every deployment that never enabled the push.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", blank)
    route = respx_mock.route(method="POST").mock(side_effect=Capture())

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()

    assert outcome.status == PushOutcome.SKIPPED
    assert route.call_count == 0
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR] == []


# ══════════════════════════════════════════════════════════════════════════════
# D. A misroute that DOES happen is loud, and names the target
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 405])
async def test_a_route_miss_is_an_error_naming_the_attempted_target(
    secret_configured, monkeypatch, respx_mock, caplog, status
):
    """
    The existing suite covered 401 and 503. A 404/405 is the misroute signature
    and it is the WORST case to diagnose, because axum answers it with an EMPTY
    BODY — so `resp.text` carries nothing and a log line without the target says
    only "something, somewhere, returned 404".

    The attempted target must therefore be in the message. This is the difference
    between an operator fixing an env var in a minute and a rail that is dark
    until someone reads the code.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    respx_mock.route(method="POST").mock(side_effect=Capture(status=status, body=""))

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()

    assert outcome.status == PushOutcome.REJECTED
    assert outcome.http_status == status

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, f"expected exactly one ERROR, got {[r.message for r in errors]}"
    msg = errors[0].getMessage()
    assert mod.FAILURE_MARKER in msg
    assert str(status) in msg
    assert "http://adapter:7070/v1/events/proxy" in msg, (
        "an empty-bodied route miss must at least name the address it was sent to"
    )
    assert "DETECTION_ADAPTER_URL" in msg, (
        "a route miss is a configuration fault; point at the setting to change"
    )
    assert "not mounted" in msg, "the cause must be NAMED, not left to inference"


@pytest.mark.asyncio
async def test_a_401_still_reads_as_a_credential_fault_not_a_route_fault(
    secret_configured, monkeypatch, respx_mock, caplog
):
    """
    Paired control for the test above. If every rejection were labelled a
    configuration/route fault, the 404 message would carry no information. A 401
    means the request ARRIVED and was refused — a different fix entirely.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070")
    body = json.dumps({"error": {"code": "UNKNOWN_KEY_ID"}})
    respx_mock.route(method="POST").mock(side_effect=Capture(status=401, body=body))

    with caplog.at_level(logging.ERROR, logger="proxy.detection_adapter"):
        outcome = await _push()

    assert outcome.status == PushOutcome.REJECTED
    msg = [r for r in caplog.records if r.levelno >= logging.ERROR][0].getMessage()
    assert "UNKNOWN_KEY_ID" in msg
    assert "http://adapter:7070/v1/events/proxy" in msg, "the target belongs on every failure"
    assert "not mounted" not in msg, "a 401 is not a route miss; do not misdiagnose it"


@pytest.mark.asyncio
async def test_the_receipt_records_the_target_actually_posted_to(
    secret_configured, monkeypatch, respx_mock
):
    """
    The receipt is the durable half of "never fail-silent". Recording the raw base
    URL would leave the forensic record unable to answer the only question a
    misroute raises: what address did this attempt use?
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "http://adapter:7070/")
    respx_mock.route(method="POST").mock(side_effect=Capture(status=404, body=""))

    written: list[dict] = []

    class Audit:
        async def write(self, record):
            written.append(record)

    outcome = await _push(audit=Audit())

    assert outcome.status == PushOutcome.REJECTED
    assert len(written) == 1
    assert written[0]["adapter_url"] == "http://adapter:7070/v1/events/proxy"
    assert written[0]["delivery_status"] == PushOutcome.REJECTED
    assert written[0]["http_status"] == 404


@pytest.mark.asyncio
async def test_a_misconfigured_url_is_receipted_too(secret_configured, monkeypatch):
    """
    A push that was never attempted still has to leave a durable trace, or the
    audit rail shows a gap that reads identically to "no detections happened".
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "not a url at all")
    written: list[dict] = []

    class Audit:
        async def write(self, record):
            written.append(record)

    outcome = await _push(audit=Audit())

    assert outcome.status == PushOutcome.MISCONFIGURED
    assert len(written) == 1
    assert written[0]["delivery_status"] == PushOutcome.MISCONFIGURED
    assert written[0]["http_status"] is None
    assert "not a url at all" in written[0]["error"]


# ══════════════════════════════════════════════════════════════════════════════
# E. Invalid configuration fails at STARTUP, not one lost push at a time
# ══════════════════════════════════════════════════════════════════════════════

def test_startup_refuses_a_malformed_url(monkeypatch):
    """
    Discovering a bad address at push time means every push until someone reads
    the logs is lost. The value cannot become valid later, so the honest moment
    to refuse is boot — before any traffic, where an operator is watching.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", "adapter:7070")
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)

    with pytest.raises(RuntimeError) as ei:
        mod.validate_config_or_raise()
    assert "DETECTION_ADAPTER_URL" in str(ei.value)
    assert "adapter:7070" in str(ei.value)


@pytest.mark.parametrize("base", [b for b, _, _ in WELL_FORMED])
def test_startup_accepts_every_well_formed_base_url(monkeypatch, base):
    """Paired control: the guard must not brick a correctly-configured boot."""
    monkeypatch.setenv("DETECTION_ADAPTER_URL", base)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", SECRET)
    mod.validate_config_or_raise()


def test_startup_is_silent_when_the_rail_is_simply_not_enabled(monkeypatch, caplog):
    """
    Demo/local parity (DONE.md Gate 2, startup-guard ↔ demo-env parity). The
    guard fires ONLY on a value an operator actually set and got wrong. With the
    rail unconfigured — which is what `.env.example` and docker-compose ship — it
    must not raise and must not shout, or the guard would brick every local boot
    and be switched off within a day.
    """
    monkeypatch.delenv("DETECTION_ADAPTER_URL", raising=False)
    monkeypatch.delenv("DETECTION_ADAPTER_HMAC_SECRET", raising=False)

    with caplog.at_level(logging.WARNING, logger="proxy.detection_adapter"):
        mod.validate_config_or_raise()
    assert [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING] == []


@pytest.mark.parametrize(
    "url, secret, missing",
    [
        ("http://adapter:7070", "", "DETECTION_ADAPTER_HMAC_SECRET"),
        ("", SECRET, "DETECTION_ADAPTER_URL"),
    ],
)
def test_a_half_configured_rail_is_surfaced_at_startup(monkeypatch, caplog, url, secret, missing):
    """
    Half-configured is the quietest way to be dark: `push_event` returns SKIPPED,
    which is the same answer it gives a deployment that never wanted the rail. An
    operator who set ONE of the two plainly wanted it, so say so at boot.

    Not fatal — an unsigned push is never sent, so the state is safe; it is only
    silent, and silence is the thing being fixed.
    """
    monkeypatch.setenv("DETECTION_ADAPTER_URL", url)
    monkeypatch.setenv("DETECTION_ADAPTER_HMAC_SECRET", secret)

    with caplog.at_level(logging.WARNING, logger="proxy.detection_adapter"):
        mod.validate_config_or_raise()  # must not raise

    msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(msgs) == 1, f"expected one half-configured warning, got {msgs}"
    assert missing in msgs[0]


def test_the_proxy_app_runs_the_guard_at_startup():
    """
    PRESENCE IS NOT EFFECT. A validator nothing calls protects nothing — the same
    shape as `verify_integrity` in this repo, which has zero production callers.
    So assert the wiring, structurally, in the module that owns startup.
    """
    import ast
    import inspect

    import proxy.main

    tree = ast.parse(inspect.getsource(proxy.main))
    called = {
        n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
    }
    assert "validate_config_or_raise" in called, (
        "proxy.main never calls the startup guard — a bad DETECTION_ADAPTER_URL "
        "would still be discovered one lost push at a time"
    )


# ══════════════════════════════════════════════════════════════════════════════
# F. The normaliser itself, as a unit
# ══════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("base, expected_target, _prefix", WELL_FORMED)
def test_adapter_target_is_the_single_composer(base, expected_target, _prefix):
    """
    One function composes the target, so there is exactly one place for this bug
    to live. Called directly here so a regression is a unit failure with a clear
    message, not an oblique 404 three layers away.
    """
    assert mod.adapter_target(base) == expected_target


@pytest.mark.parametrize("base, why", MALFORMED)
def test_adapter_target_refuses_malformed_bases(base, why):
    with pytest.raises(mod.AdapterConfigError) as ei:
        mod.adapter_target(base)
    assert base.strip() in str(ei.value), why


@pytest.mark.parametrize("blank", ["", "   ", None])
def test_adapter_target_reports_absent_config_as_empty(blank):
    """Absent is its own answer, distinct from both valid and malformed."""
    assert mod.adapter_target(blank) == ""


def test_no_composed_target_ever_carries_a_double_slash():
    """
    The property, stated once over every case in this file rather than case by
    case: whatever the operator wrote, the path handed to httpx contains no empty
    segment. Cheap, total, and the exact shape of the defect.
    """
    checked = 0
    for base, _expected, _prefix in WELL_FORMED:
        path = httpx.URL(mod.adapter_target(base)).path
        assert "//" not in path, f"base {base!r} composed {path!r}"
        assert path.endswith(ADAPTER_PATH), f"base {base!r} composed {path!r}"
        checked += 1
    assert checked == len(WELL_FORMED) >= 9, "measured nothing — the case table is empty"
