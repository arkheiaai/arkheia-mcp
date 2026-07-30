from fastapi import FastAPI
from fastapi.testclient import TestClient

from proxy.auth import require_auth
from proxy.endpoints.admin import router as admin_router


class PullClient:
    def __init__(self, result: dict):
        self.result = result
        self.calls = 0

    async def pull(self) -> dict:
        self.calls += 1
        return self.result


def _client_for_pull(result: dict) -> tuple[TestClient, PullClient]:
    app = FastAPI()
    app.include_router(admin_router)
    app.dependency_overrides[require_auth] = lambda: "admin-test@example.com"
    pull_client = PullClient(result)
    app.state.registry_client = pull_client
    return TestClient(app, raise_server_exceptions=False), pull_client


def test_manual_registry_pull_reports_all_failed_summary():
    client, pull_client = _client_for_pull({
        "updated": [],
        "skipped": [],
        "errors": ["llama-3-70b: Checksum mismatch"],
    })

    resp = client.post("/admin/registry/pull")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "error"
    assert data["updated"] == []
    assert data["skipped"] == []
    assert data["errors"] == ["llama-3-70b: Checksum mismatch"]
    assert data["summary"]["errors"] == data["errors"]
    assert pull_client.calls == 1


def test_manual_registry_pull_reports_partial_summary():
    client, _pull_client = _client_for_pull({
        "updated": ["gpt-4o"],
        "skipped": [],
        "errors": ["llama-3-70b: download failed"],
    })

    resp = client.post("/admin/registry/pull")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "partial"
    assert data["updated"] == ["gpt-4o"]
    assert data["errors"] == ["llama-3-70b: download failed"]


def test_manual_registry_pull_reports_ok_noop_summary():
    client, _pull_client = _client_for_pull({
        "updated": [],
        "skipped": [],
        "errors": [],
    })

    resp = client.post("/admin/registry/pull")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["updated"] == []
    assert data["skipped"] == []
    assert data["errors"] == []
