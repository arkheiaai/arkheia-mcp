"""
ADVERSARIAL axis for flow F22 — "Registry API-key auth (fail-closed)".

The flow's name carries its claim, so the question this file answers is not
"does auth work" but the harder one:

    can ANY route reach a protected registry operation without a valid key?

Method — three properties, each enforced by a different kind of test:

1. **The protected set is DISCOVERED, never enumerated.**
   ``protected_routes()`` walks ``app.routes`` at runtime and derives the
   protected set as *everything that is not on an explicit, named exempt
   list*. A route added tomorrow without ``Depends(require_auth)`` fails
   ``test_every_protected_route_refuses_*`` — the author does not have to
   remember to extend this file. That matters concretely: PR #13 adds a
   SECOND download route (``GET /profiles/download?model_id=``), and this
   file covers it on the merge result without being edited.

2. **Refusal is proven by REACHABILITY, not by presence.**
   ``Depends(require_auth)`` appearing in a route signature is not the same
   thing as ``require_auth`` running. Every assertion below is made against
   a live response from the real ASGI app. ``test_declared_dependency_is_the
   _one_that_runs`` closes the loop the other way: it swaps the dependency
   for a sentinel and proves the sentinel is what decides — so the declared
   symbol IS the deciding symbol, not a decorative twin.

3. **Every refusal is paired with a POSITIVE CONTROL.**
   ``assert resp.status_code != 200`` passes for a 500 caused by a bug, and
   ``pytest.raises(Exception)`` passes for the wrong exception. So every
   refusal here pins the EXACT status, the EXACT ``detail`` string and the
   EXACT ``WWW-Authenticate`` header, and every refusal case is asserted
   alongside an authorised call that must return 200 with real content
   through the same client. A gate that refuses everything is not
   fail-closed, it is broken, and only the positive control tells them apart.

Deliberately NOT asserted: that a whitespace-padded VALID key is accepted.
FastAPI's ``get_authorization_scheme_param`` applies ``.strip()`` to the
credential (fastapi/security/utils.py), so ``"Bearer  <key> "`` currently
authenticates. That is upstream behaviour in the permissive direction for an
ALREADY-VALID key; pinning it would make a dependency bump red for no
security reason. What IS pinned is the direction that matters:
``test_whitespace_shaping_never_admits_an_invalid_key`` — no amount of
whitespace shaping turns a key that is not configured into one that is.
"""

import hashlib
import re

import pytest
import yaml
from fastapi.testclient import TestClient

from registry_server.main import app

# A syntactically well-formed key that is never configured anywhere.
# Shape matches generate_key() output so the compare is exercised on a
# realistic input, not on "x".
VALID_KEY = "ak_live_" + "a1b2c3d4" * 4
WRONG_KEY = "ak_live_" + "9f9f9f9f" * 4
assert len(VALID_KEY) == len("ak_live_") + 32
assert VALID_KEY != WRONG_KEY

PROFILE_YAML = 'model: adversarial-model\nversion: "3.1"\nthresholds:\n  high: 0.9\n'

# ---------------------------------------------------------------------------
# The unauthenticated surface, stated explicitly.
#
# This list is the answer to "which registry operations are INTENTIONALLY
# open?". It is a security decision, so it lives here in one place and the
# discovering tests below treat everything else as protected. Adding a route
# to this list is a visible, reviewable act.
#
# `/docs`, `/redoc` and `/openapi.json` are FastAPI's built-ins. They are
# listed because they ARE open, not because that is endorsed — see the PR
# body: on a customer-facing registry they publish the full API schema to
# anonymous callers and should be env-gated off in production. That is a
# product decision, so this file pins the fact rather than changing it.
# ---------------------------------------------------------------------------
EXEMPT_PATHS = frozenset({
    "/",                      # service info — static, no profile data
    "/health",                # liveness — see PR body re: unauthenticated cost
    "/openapi.json",          # FastAPI built-in (schema)
    "/docs",                  # FastAPI built-in (Swagger UI)
    "/docs/oauth2-redirect",  # FastAPI built-in
    "/redoc",                 # FastAPI built-in (ReDoc)
})


def protected_routes() -> list[tuple[str, str]]:
    """
    DISCOVER the protected surface: every (method, path) on the live app that
    is not on the exempt list. Never a hand-written list — a new route is
    covered the moment it is registered.
    """
    out: list[tuple[str, str]] = []
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or not methods:
            continue
        if path in EXEMPT_PATHS:
            continue
        for method in sorted(methods):
            if method in ("HEAD", "OPTIONS"):
                continue
            out.append((method, path))
    return out


def concrete(path: str) -> str:
    """
    Substitute a real, resolvable id for EVERY path parameter, whatever
    converter it declares.

    Deliberately a regex over `{...}` rather than `.replace("{model_id}", ...)`:
    PR #13 re-declares the legacy download route as `{model_id:path}`, and a
    literal replace silently produced the un-substituted URL — which 404s, so
    every refusal assertion on that route would still have "passed" while
    testing a route that does not exist. A parametrised test that quietly
    stops exercising its subject is the failure mode this whole file exists
    to avoid, so the substitution asserts it consumed every placeholder.
    """
    concrete_path = re.sub(r"\{[^}]+\}", "adversarial-model", path)
    assert "{" not in concrete_path, f"unsubstituted path parameter in {path!r}"
    return concrete_path


def request_for(client: TestClient, method: str, path: str, **kw):
    """Issue `method` at a concrete form of `path`, with a query id if needed."""
    url = concrete(path)
    if path.endswith("/profiles/download"):
        kw.setdefault("params", {})["model_id"] = "adversarial-model"
    return client.request(method, url, **kw)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def profile_dir(tmp_path):
    (tmp_path / "adversarial-model.yaml").write_text(PROFILE_YAML, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def env(monkeypatch, profile_dir):
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")
    return monkeypatch


@pytest.fixture()
def provisioned(env):
    """Server provisioned with exactly one key."""
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def unprovisioned(env):
    """Server with ARKHEIA_REGISTRY_KEYS absent entirely."""
    env.delenv("ARKHEIA_REGISTRY_KEYS", raising=False)
    with TestClient(app) as c:
        yield c


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture()
def raw_asgi(env, profile_dir):
    """
    Call the ASGI app directly with EXACT header bytes.

    httpx normalises and validates what it will send (it strips surrounding
    whitespace, refuses non-ASCII, and collapses repeated headers), so an
    assertion made through the test client can be an assertion about httpx.
    This fixture removes the client from the loop entirely: the bytes in the
    scope are the bytes the server sees.

    Returns a callable -> (status_code, body_bytes).
    """
    import asyncio

    from registry_server.storage import ProfileStorage

    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)

    def call(auth_header: bytes | None = None,
             auth_headers: list[bytes] | None = None,
             path: str = "/profiles") -> tuple[int, bytes]:
        headers: list[tuple[bytes, bytes]] = [(b"host", b"testserver")]
        for value in (auth_headers if auth_headers is not None
                      else ([auth_header] if auth_header is not None else [])):
            headers.append((b"authorization", value))

        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1", "method": "GET", "scheme": "http",
            "path": path, "raw_path": path.encode(), "query_string": b"",
            "root_path": "", "headers": headers,
            "client": ("203.0.113.7", 4444), "server": ("testserver", 80), "state": {},
        }
        captured: dict = {"body": b""}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
            elif message["type"] == "http.response.body":
                captured["body"] += message.get("body", b"")

        async def drive():
            # lifespan is not run for a bare ASGI call, so storage is seeded
            # here exactly as the lifespan would.
            app.state.storage = ProfileStorage(
                profile_dir=str(profile_dir), base_url="http://testserver"
            )
            await app(scope, receive, send)

        asyncio.run(drive())
        return captured["status"], captured["body"]

    return call


# ---------------------------------------------------------------------------
# The positive control. Everything below leans on this: it proves the gate
# is not simply refusing everything, and it proves the fixtures actually
# serve real content.
# ---------------------------------------------------------------------------

def assert_authorised_call_succeeds(client: TestClient, method: str, path: str) -> None:
    """
    POSITIVE CONTROL. Pins a positively-computed expected value, not a
    permissive `!= 401`: a listing must contain the seeded model with its
    real sha256, and a download must return the exact seeded bytes.
    """
    resp = request_for(client, method, path, headers=auth(VALID_KEY))
    assert resp.status_code == 200, (
        f"positive control FAILED for {method} {path}: expected 200 with a valid "
        f"key, got {resp.status_code} {resp.text!r}. Every refusal assertion in "
        f"this file is meaningless if an authorised call cannot succeed."
    )
    if path == "/profiles":
        body = resp.json()
        ids = {p["model_id"] for p in body["profiles"]}
        assert ids == {"adversarial-model"}, ids
        assert body["count"] == 1
        expected = hashlib.sha256(PROFILE_YAML.encode()).hexdigest()
        assert body["profiles"][0]["checksum"] == expected
        assert body["profiles"][0]["version"] == "3.1"
    else:
        assert yaml.safe_load(resp.content) == {
            "model": "adversarial-model",
            "version": "3.1",
            "thresholds": {"high": 0.9},
        }


def assert_refused_401(resp, where: str) -> None:
    """
    Pin the EXACT refusal shape. Not `!= 200` — a 500 from a bug satisfies
    that. Not `in (401, 403)` — a status that drifts is a behaviour change
    reviewers should see.
    """
    assert resp.status_code == 401, f"{where}: expected 401, got {resp.status_code} {resp.text!r}"
    assert resp.json() == {"detail": "Invalid or missing API key"}, f"{where}: {resp.text!r}"
    assert resp.headers.get("www-authenticate") == "Bearer", f"{where}: {dict(resp.headers)}"


def assert_refused_503(resp, where: str) -> None:
    assert resp.status_code == 503, f"{where}: expected 503, got {resp.status_code} {resp.text!r}"
    assert resp.json() == {
        "detail": "Registry not provisioned -- ARKHEIA_REGISTRY_KEYS not set"
    }, f"{where}: {resp.text!r}"


# ---------------------------------------------------------------------------
# 1. Discovering coverage: EVERY protected route refuses EVERY bad credential
# ---------------------------------------------------------------------------

def test_the_protected_surface_is_non_empty():
    """
    Vacuity guard. If `protected_routes()` ever returned [], every
    parametrised test below would silently pass having checked nothing —
    the "measurement gate that measures nothing" defect.
    """
    routes = protected_routes()
    assert routes, "discovered ZERO protected routes; the adversarial matrix is vacuous"
    paths = {p for _, p in routes}
    assert "/profiles" in paths, paths
    assert any("download" in p for p in paths), paths


def test_every_registered_route_is_either_exempt_or_discovered():
    """
    The exempt list must describe the app, not diverge from it. A stale
    entry (a path that no longer exists) is as much a defect as a missing
    one: it makes the list look considered when it is not.
    """
    live = {getattr(r, "path", None) for r in app.routes} - {None}
    stale = EXEMPT_PATHS - live
    assert not stale, f"EXEMPT_PATHS names paths that no longer exist: {sorted(stale)}"


# The credential shapes an attacker actually has. Each must refuse on EVERY
# protected route.
BAD_CREDENTIALS = {
    "absent":            None,
    "empty-value":       "",
    "scheme-only":       "Bearer",
    "scheme-and-space":  "Bearer ",
    "whitespace-only":   "Bearer    ",
    "no-scheme":         VALID_KEY,
    "wrong-scheme":      f"Basic {VALID_KEY}",
    "wrong-key":         f"Bearer {WRONG_KEY}",
    "prefix-of-valid":   f"Bearer {VALID_KEY[:-1]}",
    "valid-plus-suffix": f"Bearer {VALID_KEY}x",
    "comma-joined":      f"Bearer {VALID_KEY},{VALID_KEY}",
    "empty-string-key":  "Bearer ''",
    "null-byte":         f"Bearer {VALID_KEY[:-1]}\x00",
}
# NOTE: non-ASCII credentials are NOT in this table because httpx refuses to
# encode them client-side (UnicodeEncodeError) — a limitation of the test
# client, not a property of the server. They are covered against the raw ASGI
# app in `test_hostile_credential_bytes_do_not_produce_a_crash_oracle` below,
# which is the stronger instrument anyway: it puts exact bytes on the wire.


@pytest.mark.parametrize("method,path", protected_routes(), ids=lambda v: str(v))
@pytest.mark.parametrize("shape", sorted(BAD_CREDENTIALS))
def test_every_protected_route_refuses_every_bad_credential(provisioned, method, path, shape):
    """
    The core fail-closed claim, as a full cross product: no bad-credential
    shape reaches any protected operation on any route.
    """
    value = BAD_CREDENTIALS[shape]
    headers = {} if value is None else {"Authorization": value}
    resp = request_for(provisioned, method, path, headers=headers)
    assert_refused_401(resp, f"{method} {path} [{shape}]")
    # And nothing leaked into the body on the way out.
    assert b"adversarial-model" not in resp.content
    assert b"checksum" not in resp.content
    # POSITIVE CONTROL, same client, same route.
    assert_authorised_call_succeeds(provisioned, method, path)


@pytest.mark.parametrize("method,path", protected_routes(), ids=lambda v: str(v))
def test_every_protected_route_refuses_when_unprovisioned(unprovisioned, method, path):
    """
    The named branch: with no keys configured the server refuses EVERYTHING,
    including a syntactically perfect key. Unprovisioned is reject-all, not
    allow-all — that inversion is the classic fail-open default.
    """
    assert_refused_503(
        request_for(unprovisioned, method, path, headers=auth(VALID_KEY)),
        f"{method} {path} [unprovisioned + well-formed key]",
    )
    assert_refused_503(
        request_for(unprovisioned, method, path),
        f"{method} {path} [unprovisioned + no key]",
    )


@pytest.mark.parametrize(
    "keys_value",
    ["", "   ", ",", ",,,", " , , ", "\t", "\n", " ,\t, \n "],
    ids=lambda v: repr(v),
)
def test_degenerate_key_config_is_unprovisioned_not_open(env, keys_value):
    """
    A key list that parses to zero usable keys must land in the 503
    reject-all branch, NOT in "the set is empty so `not in` is vacuously
    false". Also proves the degenerate value cannot be echoed back as a
    credential to authenticate with itself.
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", keys_value)
    with TestClient(app) as c:
        assert_refused_503(c.get("/profiles", headers=auth(keys_value)),
                           f"KEYS={keys_value!r} echoed as credential")
        assert_refused_503(c.get("/profiles", headers=auth(keys_value.strip())),
                           f"KEYS={keys_value!r} stripped, echoed as credential")
        assert_refused_503(c.get("/profiles"), f"KEYS={keys_value!r} no credential")


# ---------------------------------------------------------------------------
# 2. Precedence — can anything the CALLER sends influence the check?
#
# The concurrent /v1/detect finding was that caller-supplied fields reached a
# trusted-metadata path: the party being checked could influence the check.
# The equivalent question here: does anything the caller sends change WHETHER
# a key is required, WHICH key is expected, or HOW the compare is made?
# ---------------------------------------------------------------------------

CALLER_OVERRIDE_ATTEMPTS = {
    # The dependency's own parameter name, as a query parameter. FastAPI must
    # not treat a `Depends()` parameter as caller-suppliable.
    "query-api_key":        ({"api_key": VALID_KEY}, {}),
    "query-credentials":    ({"credentials": VALID_KEY}, {}),
    "query-authorization":  ({"authorization": f"Bearer {VALID_KEY}"}, {}),
    "query-token":          ({"token": VALID_KEY}, {}),
    # Alternate header names a permissive implementation might also read.
    "header-x-api-key":     ({}, {"X-API-Key": VALID_KEY}),
    "header-api-key":       ({}, {"Api-Key": VALID_KEY}),
    "header-x-auth-token":  ({}, {"X-Auth-Token": VALID_KEY}),
    "header-cookie":        ({}, {"Cookie": f"api_key={VALID_KEY}"}),
    # Trust-the-edge headers: claiming to be an internal/local caller.
    "header-forwarded":     ({}, {"X-Forwarded-For": "127.0.0.1"}),
    "header-real-ip":       ({}, {"X-Real-IP": "127.0.0.1"}),
    "header-internal":      ({}, {"X-Internal-Request": "true"}),
    # Debug / local-mode flags, as a header and as a query parameter.
    "header-debug":         ({}, {"X-Debug": "1", "X-Arkheia-Debug": "true"}),
    "query-debug":          ({"debug": "true", "dev": "1", "local": "1"}, {}),
    "query-skip-auth":      ({"skip_auth": "true", "no_auth": "1"}, {}),
    # Method override, in case a framework or middleware honours it.
    "header-method-override": ({}, {"X-HTTP-Method-Override": "OPTIONS"}),
}


@pytest.mark.parametrize("attempt", sorted(CALLER_OVERRIDE_ATTEMPTS))
def test_no_caller_supplied_input_can_override_the_gate(provisioned, attempt):
    """
    Nothing the caller controls — query parameter, alternate header, edge
    header, debug flag, method override — makes the key optional or supplies
    it out of band. The Authorization header is the ONLY channel.
    """
    params, headers = CALLER_OVERRIDE_ATTEMPTS[attempt]
    assert_refused_401(
        provisioned.get("/profiles", params=params, headers=headers),
        f"caller override [{attempt}]",
    )
    assert_authorised_call_succeeds(provisioned, "GET", "/profiles")


def test_no_environment_variable_shaped_flag_disables_the_gate(env, monkeypatch):
    """
    Precedence, config side: there must be no env var that turns the check
    off. Names below are the ones this fleet has actually shipped as
    guard-disabling defaults (see the proxy's ARKHEIA_REQUIRE_LICENSE, which
    defaults false). If a future refactor adds one, this goes red.
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    for name in (
        "ARKHEIA_REGISTRY_REQUIRE_AUTH", "ARKHEIA_REQUIRE_AUTH", "ARKHEIA_AUTH_DISABLED",
        "ARKHEIA_REGISTRY_AUTH", "ARKHEIA_DEV_MODE", "ARKHEIA_LOCAL_MODE",
        "ARKHEIA_DEBUG", "DEBUG", "DEV", "ENV", "ARKHEIA_ENV",
        "ARKHEIA_REGISTRY_ALLOW_ANONYMOUS", "ARKHEIA_SKIP_AUTH",
    ):
        monkeypatch.setenv(name, "true" if name not in ("ENV", "ARKHEIA_ENV") else "development")
    with TestClient(app) as c:
        assert_refused_401(c.get("/profiles"), "every disabling env var set at once")
        assert_refused_401(c.get("/profiles", headers=auth(WRONG_KEY)), "wrong key, all flags on")
        assert_authorised_call_succeeds(c, "GET", "/profiles")


def test_whitespace_shaping_never_admits_an_invalid_key(provisioned):
    """
    FastAPI strips the credential, and `_load_valid_keys` strips each
    configured key. Neither normalisation may turn a NON-configured value
    into an accepted one — that is the only direction that matters.
    """
    for shaped in (
        f"Bearer  {WRONG_KEY}", f"Bearer {WRONG_KEY} ", f"Bearer\t{WRONG_KEY}",
        f"Bearer  {VALID_KEY[:-1]} ", f"Bearer {VALID_KEY[:16]} {VALID_KEY[16:]}",
        f"Bearer  ", f"Bearer {' ' * 20}",
    ):
        assert_refused_401(
            provisioned.get("/profiles", headers={"Authorization": shaped}),
            f"whitespace shaping {shaped!r}",
        )
    assert_authorised_call_succeeds(provisioned, "GET", "/profiles")


# ---------------------------------------------------------------------------
# 3. Short-circuit — can the check be skipped before it runs?
#
# The tool-registry finding was that the DENY branch was unreachable from
# production dispatch because a framework error fired first. The equivalent:
# is there a request shape where FastAPI answers (422 / 404 / 405 / 500)
# BEFORE `require_auth` executes, on a protected route?
# ---------------------------------------------------------------------------

def test_route_level_validation_never_answers_before_auth(provisioned):
    """
    `/profiles?since=` is validated INSIDE the handler, so a malformed
    `since` must produce 401 without a key (auth first) and 422 with one
    (auth passed, then validation). Observing 422 without a key would mean
    the handler ran unauthenticated.
    """
    no_key = provisioned.get("/profiles", params={"since": "not-a-date"})
    assert_refused_401(no_key, "malformed `since`, no key")

    with_key = provisioned.get("/profiles", params={"since": "not-a-date"}, headers=auth(VALID_KEY))
    assert with_key.status_code == 422, with_key.text
    assert "Invalid `since` datetime format" in with_key.json()["detail"]


def test_missing_required_query_parameter_never_answers_before_auth(provisioned):
    """
    Same question for a parameter FastAPI itself validates. PR #13's
    `/profiles/download` declares `model_id` as a REQUIRED query parameter;
    omitting it is the natural way to make FastAPI's own validation fire.
    That must still be a 401 without a key. Skipped (not silently passed)
    while the route does not exist, so the reason is visible.
    """
    paths = {p for _, p in protected_routes()}
    target = next((p for p in paths if not ("{" in p) and p != "/profiles"), None)
    if target is None:
        pytest.skip(
            "no protected route with a framework-validated required parameter on "
            "this revision (PR #13 adds GET /profiles/download?model_id=); "
            "NOT-OBSERVED here, covered automatically once that route lands"
        )
    assert_refused_401(provisioned.get(target), f"{target} with required param omitted, no key")
    assert_refused_401(
        provisioned.get(target, params={"model_id": "../../etc/passwd"}),
        f"{target} with hostile param, no key",
    )


@pytest.mark.parametrize(
    "raw_path",
    [
        "/profiles/%2e%2e%2fetc%2fpasswd/download",
        "/profiles/..%2f..%2fsecret/download",
        "/profiles/adversarial-model/download/",
        "/PROFILES",
        "/profiles%20",
        "/profiles;x=1",
        "/./profiles",
    ],
)
def test_path_shaping_never_serves_content_unauthenticated(provisioned, raw_path):
    """
    Whatever routing decides — match, 404, or redirect — an unauthenticated
    request must never come back carrying profile content. Routing outcomes
    legitimately differ between these shapes, so the invariant asserted is
    the one that matters: no 200-with-content without a key.
    """
    resp = provisioned.get(raw_path, follow_redirects=False)
    assert resp.status_code in (301, 307, 401, 404), f"{raw_path} -> {resp.status_code} {resp.text[:200]!r}"
    assert b"checksum" not in resp.content, f"{raw_path} leaked listing content"
    assert b"thresholds" not in resp.content, f"{raw_path} leaked profile content"
    assert_authorised_call_succeeds(provisioned, "GET", "/profiles")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def test_unrouted_methods_refuse_without_executing_a_handler(provisioned, method):
    """
    A method with no registered handler must be a plain 405. A 200 or a 500
    here would mean something ran.
    """
    resp = provisioned.request(method, "/profiles")
    assert resp.status_code == 405, f"{method} /profiles -> {resp.status_code} {resp.text!r}"
    assert b"checksum" not in resp.content


def test_hostile_credential_bytes_do_not_produce_a_crash_oracle(raw_asgi):
    """
    A 500 on a malformed credential is an enumeration oracle in its own
    right: it tells the attacker their input reached further than a plain
    reject did. Every hostile shape must land on the SAME 401.

    Driven against the raw ASGI app because httpx refuses to put non-ASCII
    bytes in a header at all — going through the client here would test the
    client, not the server.
    """
    for label, raw in (
        ("64KB credential",   b"Bearer " + b"a" * 65536),
        ("latin1 high bytes", b"Bearer \xff\xfe\xfd" + VALID_KEY.encode()),
        ("cyrillic lookalike", "Bearer ak_live_".encode() + "а".encode("utf-8") * 32),
        ("utf8 4-byte",       b"Bearer ak_live_" + "\U0001F600".encode("utf-8") * 8),
        ("null-terminated",   b"Bearer " + VALID_KEY.encode() + b"\x00"),
        ("null-embedded",     b"Bearer ak_live_\x00" + b"a" * 31),
        ("format-string",     b"Bearer %s%s%s%n"),
        ("json",              b'Bearer {"key": "' + VALID_KEY.encode() + b'"}'),
        ("bare CR",           b"Bearer " + VALID_KEY.encode().replace(b"a", b"\r")),
    ):
        status_code, body = raw_asgi(auth_header=raw)
        assert status_code == 401, f"hostile credential [{label}]: {status_code} {body[:200]!r}"
        assert body == b'{"detail":"Invalid or missing API key"}', f"[{label}]: {body!r}"
    # POSITIVE CONTROL through the same raw instrument.
    ok_status, ok_body = raw_asgi(auth_header=f"Bearer {VALID_KEY}".encode())
    assert ok_status == 200 and b"adversarial-model" in ok_body, (ok_status, ok_body[:200])


def test_duplicate_authorization_headers_resolve_deterministically(raw_asgi):
    """
    Two ``Authorization`` headers on one request is the classic front-proxy
    desync: if the edge authorises on one and the app reads the other, the
    two disagree. Starlette's ``headers.get`` takes the FIRST, so that is
    what is pinned — a silent change to last-wins would make an edge that
    validates the last header a bypass.

    Note the shapes below give the attacker no privilege they did not
    already have (both orders still require a genuinely valid key
    somewhere), which is why this is a characterisation rather than a
    finding. It is pinned so it stays that way.
    """
    V = f"Bearer {VALID_KEY}".encode()
    B = f"Bearer {WRONG_KEY}".encode()

    first_wins, _ = raw_asgi(auth_headers=[V, B])
    assert first_wins == 200, "first header no longer decides"

    second_ignored, body = raw_asgi(auth_headers=[B, V])
    assert second_ignored == 401, (
        f"a SECOND Authorization header authenticated the request ({second_ignored}); "
        f"the app now reads last-wins, which desyncs it from any edge reading first-wins"
    )
    assert body == b'{"detail":"Invalid or missing API key"}'

    assert raw_asgi(auth_headers=[b"", V])[0] == 401
    assert raw_asgi(auth_headers=[V, b""])[0] == 200


# ---------------------------------------------------------------------------
# 4. Error differentiation — is the refusal an enumeration oracle?
# ---------------------------------------------------------------------------

def test_unknown_key_is_byte_identical_to_absent_key(provisioned):
    """
    If an unknown key answered differently from a missing one — different
    status, different message, different headers — the difference IS the
    oracle: it tells an attacker which of their guesses is a real key shape.
    Compared byte-for-byte, headers included.
    """
    absent = provisioned.get("/profiles")
    unknown = provisioned.get("/profiles", headers=auth(WRONG_KEY))
    near_miss = provisioned.get("/profiles", headers=auth(VALID_KEY[:-1] + "z"))

    for other, label in ((unknown, "unknown key"), (near_miss, "near-miss key")):
        assert other.status_code == absent.status_code, label
        assert other.content == absent.content, f"{label}: {other.content!r} vs {absent.content!r}"
        strip = lambda h: {k.lower(): v for k, v in h.items() if k.lower() not in ("date", "server")}
        assert strip(other.headers) == strip(absent.headers), label
    assert_authorised_call_succeeds(provisioned, "GET", "/profiles")


def test_refusal_does_not_echo_the_presented_credential(provisioned):
    """
    A refusal that quotes the credential back writes it into every log,
    proxy trace and error tracker between the caller and the server.
    """
    marker = "ak_live_" + "deadbeef" * 4
    resp = provisioned.get("/profiles", headers=auth(marker))
    assert_refused_401(resp, "credential echo")
    assert marker.encode() not in resp.content
    assert marker not in str(dict(resp.headers))


def test_refusal_does_not_disclose_how_many_keys_are_configured(env):
    """
    The refusal must be identical whether the server holds one key or many —
    otherwise the 401 body leaks the size of the key set.
    """
    probe = "ak_test_" + "e" * 32   # never a member of any set below
    bodies = set()
    for keys in (VALID_KEY, f"{VALID_KEY},{WRONG_KEY}", ",".join(f"ak_live_{i:032x}" for i in range(50))):
        env.setenv("ARKHEIA_REGISTRY_KEYS", keys)
        assert probe not in keys.split(",")
        with TestClient(app) as c:
            r = c.get("/profiles", headers=auth(probe))
            assert_refused_401(r, f"{len(keys.split(','))} keys configured")
            bodies.add(r.content)
    assert len(bodies) == 1, f"401 body varies with key-set size: {bodies}"


# ---------------------------------------------------------------------------
# 5. Scope / tenancy / revocation
# ---------------------------------------------------------------------------

def test_a_key_is_revoked_by_removing_it_from_the_configured_set(env, profile_dir):
    """
    `_load_valid_keys()` re-reads the environment on EVERY request, so
    revocation takes effect on the next request with no restart of the app
    object. Proven both ways: the key works, then it does not, then a
    different key does. (Deployment-level caveat in the PR body: changing a
    container's env still requires a restart of the CONTAINER.)
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    with TestClient(app) as c:
        assert c.get("/profiles", headers=auth(VALID_KEY)).status_code == 200

        env.setenv("ARKHEIA_REGISTRY_KEYS", WRONG_KEY)   # rotate
        assert_refused_401(c.get("/profiles", headers=auth(VALID_KEY)), "revoked key")
        assert c.get("/profiles", headers=auth(WRONG_KEY)).status_code == 200

        env.delenv("ARKHEIA_REGISTRY_KEYS")             # deprovision
        assert_refused_503(c.get("/profiles", headers=auth(WRONG_KEY)), "deprovisioned")


def test_every_configured_key_has_identical_unscoped_authority(env, profile_dir):
    """
    CHARACTERISATION, not endorsement. There is no scope, tenant or
    expiry dimension in ARKHEIA_REGISTRY_KEYS: every configured key can read
    every profile. This test states that fact so that introducing scoping
    turns it red rather than passing silently — and so the PR body's claim
    ("a leaked key is total") is anchored to executable evidence.
    """
    keys = [f"ak_live_{i:032x}" for i in range(4)]
    env.setenv("ARKHEIA_REGISTRY_KEYS", ",".join(keys))
    with TestClient(app) as c:
        seen = []
        for k in keys:
            r = c.get("/profiles", headers=auth(k))
            assert r.status_code == 200, k
            seen.append(r.json())
            d = c.get("/profiles/adversarial-model/download", headers=auth(k))
            assert d.status_code == 200 and b"adversarial-model" in d.content, k
        assert all(s == seen[0] for s in seen), "keys already differ in what they see"


# ---------------------------------------------------------------------------
# 6. Presence is not effect — prove the DECLARED dependency is the deciding one
# ---------------------------------------------------------------------------

def test_declared_dependency_is_the_one_that_runs(provisioned):
    """
    13 of 36 gates audited in this fleet today were declared but not
    reached. `Depends(require_auth)` in a signature proves nothing on its
    own, and a docstring naming the check is not the check.

    So: override `require_auth` with a sentinel that refuses unconditionally
    and confirm every protected route flips to the sentinel's answer, then
    remove the override and confirm they flip back. If the routes did not
    move, whatever guards them is not the symbol this flow is named after.
    """
    from registry_server.auth import require_auth as declared

    SENTINEL = 418

    async def sentinel():
        from fastapi import HTTPException
        raise HTTPException(status_code=SENTINEL, detail="sentinel")

    routes = protected_routes()
    assert routes

    # Baseline: the real gate accepts.
    for method, path in routes:
        assert_authorised_call_succeeds(provisioned, method, path)

    app.dependency_overrides[declared] = sentinel
    try:
        for method, path in routes:
            r = request_for(provisioned, method, path, headers=auth(VALID_KEY))
            assert r.status_code == SENTINEL, (
                f"{method} {path} did NOT route through require_auth: overriding it "
                f"changed nothing (got {r.status_code}). The declared dependency is "
                f"not the deciding one."
            )
            assert r.json() == {"detail": "sentinel"}
        # Control: an exempt route must be UNAFFECTED, proving the override is
        # scoped to the gate and not a global kill-switch that would make the
        # assertion above true for the wrong reason.
        assert provisioned.get("/health").status_code == 200
    finally:
        app.dependency_overrides.pop(declared, None)

    for method, path in routes:
        assert_authorised_call_succeeds(provisioned, method, path)


def test_auth_still_refuses_when_application_startup_never_ran(env, profile_dir):
    """
    Fail-closed under misconfiguration: if lifespan never ran, `app.state.
    storage` is absent and the handler cannot work. The gate must still
    refuse an unauthenticated caller with 401 rather than falling through to
    a 500 — a 500 would mean the handler was entered.
    """
    env.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    saved = getattr(app.state, "storage", None)
    try:
        if hasattr(app.state, "storage"):
            del app.state.storage
        # NOTE: no `with` — TestClient's context manager is what runs lifespan.
        c = TestClient(app)
        assert_refused_401(c.get("/profiles"), "no lifespan, no key")
        assert_refused_401(c.get("/profiles", headers=auth(WRONG_KEY)), "no lifespan, wrong key")
    finally:
        if saved is not None:
            app.state.storage = saved


# ---------------------------------------------------------------------------
# 7. Constant-time comparison — structural, not timed
#
# A wall-clock timing assertion is flaky in CI, so what is enforced here is
# the STRUCTURE that makes timing safety hold regardless of interpreter
# details: the compare goes through `secrets.compare_digest`, and the loop
# over configured keys does not short-circuit on the first match (an early
# `return True` leaks the matching key's POSITION in the set).
#
# Measured evidence for why this is hygiene rather than a live defect is in
# the PR body: the previous `not in set` compare showed no prefix-length
# gradient (0.8-3.7 ns, non-monotonic, within noise), because CPython hashes
# the candidate before comparing bytes. The fix removes the dependence on
# that implementation detail (and on hash randomisation being enabled).
# ---------------------------------------------------------------------------

def _key_is_valid_ast():
    """The AST of `_key_is_valid`'s EXECUTABLE body, docstring stripped.

    Text matching is not good enough here and this is not hypothetical: the
    first version of this test asserted `"secrets.compare_digest" in source`,
    and a mutation that replaced the whole body with `return candidate in
    valid_keys` SURVIVED — because the phrase was still there in the
    docstring. A comment satisfying an invariant is this repo's most
    frequently observed defect shape; the check has to look at code.
    """
    import ast
    import inspect

    from registry_server import auth as auth_mod

    tree = ast.parse(inspect.getsource(auth_mod))
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_key_is_valid"
    )
    body = list(fn.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str)):
        body = body[1:]          # drop the docstring
    assert body, "_key_is_valid has no executable body"
    return fn, body


def test_key_comparison_is_constant_time_by_construction():
    """
    A wall-clock timing assertion is flaky in CI, so what is enforced is the
    STRUCTURE that makes timing safety hold regardless of interpreter
    details. Both halves are checked against the AST, not the source text.
    """
    import ast

    _fn, body = _key_is_valid_ast()

    calls = [
        n for stmt in body for n in ast.walk(stmt)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute) and n.func.attr == "compare_digest"
        and isinstance(n.func.value, ast.Name) and n.func.value.id == "secrets"
    ]
    assert calls, (
        "_key_is_valid does not CALL secrets.compare_digest anywhere in its "
        "executable body (a mention in the docstring does not count). A plain "
        "equality or `in set` compare makes timing safety an implementation "
        "detail of CPython's hashing rather than a property of this code."
    )

    loops = [n for stmt in body for n in ast.walk(stmt) if isinstance(n, (ast.For, ast.While))]
    assert loops, "_key_is_valid no longer iterates the configured keys"
    for loop in loops:
        for node in ast.walk(loop):
            if isinstance(node, ast.Return) and not (
                isinstance(node.value, ast.Constant) and node.value.value is False
            ):
                raise AssertionError(
                    "_key_is_valid returns from inside the comparison loop; an early "
                    "return short-circuits on the first match and leaks the matching "
                    "key's position among the configured keys (measured: ~12ns)."
                )
        assert any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "compare_digest"
            for n in ast.walk(loop)
        ), "the loop over configured keys does not compare with compare_digest"


def test_key_comparison_decides_correctly_for_every_position(env, profile_dir):
    """
    The behavioural half of the above: a non-short-circuiting compare must
    still say YES for a key at ANY position in the set and NO for one that
    is absent. A constant-time compare that always returns False would pass
    the structural test alone.
    """
    keys = [f"ak_live_{i:032x}" for i in range(8)]
    env.setenv("ARKHEIA_REGISTRY_KEYS", ",".join(keys))
    with TestClient(app) as c:
        for i, k in enumerate(keys):
            assert c.get("/profiles", headers=auth(k)).status_code == 200, f"position {i}"
        assert_refused_401(c.get("/profiles", headers=auth("ak_live_" + "f" * 32)), "absent key")
        # Not a member, but shares all but the last character with keys[0].
        near_miss = keys[0][:-1] + "e"
        assert near_miss not in keys
        assert_refused_401(c.get("/profiles", headers=auth(near_miss)), "near-miss")


def test_key_validity_helper_rejects_degenerate_candidates():
    """Unit-level pinning of the compare helper itself, including the empty
    candidate — the value `credentials is None` would otherwise stand in for."""
    from registry_server.auth import _key_is_valid

    ks = {"ak_live_" + "a" * 32, "ak_live_" + "b" * 32}
    assert _key_is_valid("ak_live_" + "a" * 32, ks) is True
    assert _key_is_valid("ak_live_" + "b" * 32, ks) is True
    assert _key_is_valid("ak_live_" + "c" * 32, ks) is False
    assert _key_is_valid("", ks) is False
    assert _key_is_valid("ak_live_" + "a" * 31, ks) is False
    assert _key_is_valid("ak_live_" + "a" * 33, ks) is False
    assert _key_is_valid("ak_live_" + "a" * 32, set()) is False
    # Non-ASCII candidate must not raise inside compare_digest (it rejects
    # non-ASCII str), it must simply be invalid.
    assert _key_is_valid("ak_live_" + "а" * 32, ks) is False
    assert _key_is_valid("ak_live_\x00" + "a" * 31, ks) is False
