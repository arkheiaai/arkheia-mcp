"""
Adversarial floor for mcp.registry_public_metadata_surface.

F22 proves protected registry routes require an API key. This file covers the
separate product exemption: the anonymous registry surface may stay public, but
it must remain operational metadata only. The authenticated profile listing is
also pinned to a narrow allowlist so provider, license, trust, and detection
profile internals cannot drift into the list response unnoticed.
"""

import json
import re

import pytest
import yaml
from fastapi.testclient import TestClient

from registry_server.main import app
from registry_server.storage import PUBLIC_PROFILE_METADATA_KEYS


VALID_KEY = "ak_live_" + "feedface" * 4
MODEL_ID = "public-surface-model"
PRIVATE_MARKERS = (
    "anthropic-private-provider",
    "tenant-license-secret",
    "internal-trust-root",
    "private-model-family",
    "private-profile-author",
    "private-generator-version",
    "private-threshold-label",
)


PUBLIC_ANONYMOUS_GET_ROUTES = frozenset({
    "/",
    "/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
})


def _profile_yaml() -> str:
    return yaml.safe_dump(
        {
            "model": MODEL_ID,
            "version": "9.9",
            "api": {
                "provider": PRIVATE_MARKERS[0],
                "logprobs_available": True,
            },
            "license": {
                "customer_id": PRIVATE_MARKERS[1],
                "valid_until": "2099-01-01",
                "signature": "fake-signature",
            },
            "trust": {
                "root": PRIVATE_MARKERS[2],
                "reviewed_by": "private-reviewer",
            },
            "metadata": {
                "model_family": PRIVATE_MARKERS[3],
                "author": PRIVATE_MARKERS[4],
                "generator_version": PRIVATE_MARKERS[5],
                "license": {"tier": "enterprise"},
                "trust": {"root": "nested-private-root"},
            },
            "detection": {
                "features": {
                    PRIVATE_MARKERS[6]: {
                        "enabled": True,
                        "weight": 1.0,
                        "threshold_low": 0.1,
                        "threshold_medium": 0.5,
                    }
                }
            },
        },
        sort_keys=False,
    )


@pytest.fixture()
def profile_dir(tmp_path):
    (tmp_path / f"{MODEL_ID}.yaml").write_text(_profile_yaml(), encoding="utf-8")
    return tmp_path


@pytest.fixture()
def client(monkeypatch, profile_dir, tmp_path):
    monkeypatch.setenv("ARKHEIA_REGISTRY_KEYS", VALID_KEY)
    monkeypatch.setenv("ARKHEIA_REGISTRY_PROFILE_DIR", str(profile_dir))
    monkeypatch.setenv("ARKHEIA_REGISTRY_BASE_URL", "http://testserver")
    monkeypatch.setenv("ARKHEIA_REGISTRY_AUDIT_LOG", str(tmp_path / "receipts.jsonl"))

    with TestClient(app) as c:
        yield c


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {VALID_KEY}"}


def _public_body(resp) -> str:
    content_type = resp.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        return json.dumps(resp.json(), sort_keys=True)
    return resp.text


def _concrete(path: str) -> str:
    concrete = re.sub(r"\{[^}]+\}", MODEL_ID, path)
    assert "{" not in concrete, path
    return concrete


def test_authenticated_profile_listing_is_metadata_allowlisted(client, profile_dir):
    resp = client.get("/profiles", headers=_auth())
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["count"] == 1
    listed = body["profiles"][0]
    assert list(listed) == list(PUBLIC_PROFILE_METADATA_KEYS)

    serialized = json.dumps(listed, sort_keys=True)
    for marker in PRIVATE_MARKERS:
        assert marker not in serialized
    assert str(profile_dir) not in serialized
    for field in ("api", "provider", "source_path", "license", "trust", "metadata", "detection", "features"):
        assert field not in listed

    # Positive control: the raw authenticated download still contains the
    # private profile internals. The listing test is meaningful only if the
    # fixture really carried data that could have leaked.
    downloaded = client.get(f"/profiles/{MODEL_ID}/download", headers=_auth())
    assert downloaded.status_code == 200, downloaded.text
    downloaded_text = downloaded.text
    for marker in PRIVATE_MARKERS:
        assert marker in downloaded_text


def test_anonymous_get_surface_is_exactly_the_known_product_exemption(client):
    discovered = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None) or set()
        if path is None or "GET" not in methods:
            continue
        resp = client.get(_concrete(path), follow_redirects=False)
        if resp.status_code not in (401, 405):
            discovered.add(path)

    assert discovered == PUBLIC_ANONYMOUS_GET_ROUTES


@pytest.mark.parametrize("path", sorted(PUBLIC_ANONYMOUS_GET_ROUTES))
def test_anonymous_public_routes_do_not_emit_profile_metadata(client, path):
    resp = client.get(_concrete(path), follow_redirects=False)
    assert resp.status_code == 200, f"{path} -> {resp.status_code} {resp.text[:200]!r}"

    body = _public_body(resp)
    assert MODEL_ID not in body
    for marker in PRIVATE_MARKERS:
        assert marker not in body
    for field in ("checksum", "download_url", "provider", "license", "trust"):
        assert field not in body


def test_anonymous_health_shape_is_liveness_only(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "profiles_available": 1}
