"""The Python client reads a service answer fail-closed, builds fresh verdict fields, and exports
the audit log as a typed view. Everything goes through the public clients with mocked HTTP."""
from __future__ import annotations

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp_server.proxy_client import ProxyClient

MODEL = "gpt-4o"
CLEAN = {"assessed": True, "evidence_depth_limited": False, "confidence": 0.5, "detection_id": "d1"}
SHAPES = {
    "wrong model": {"model_id": "other-model"},
    "conflicting models": {"model_id": MODEL, "model": "other-model"},
    "explicit null identity": {"model_id": None},
    "explicit null coverage": {"model_supported": None},
    "numeric true coverage": {"model_supported": 1},
    "numeric false qualifier": {"profile_fingerprint_borrowed": 0},
    "string qualifier": {"profile_fingerprint_borrowed": "false"},
    "numeric one flag": {"assessed": 1},
    "limited": {"evidence_depth_limited": True},
    "numeric limited flag": {"evidence_depth_limited": 0},
    "reason beside assessed": {"not_assessed_reason": "x"},
    "candidate beside assessed": {"candidate_alert": "HIGH"},
    "marker beside assessed": {"risk_demoted_from": "HIGH"},
    "error beside assessed": {"error": "e"},
    "qualified result": {"gate_reason": "x"},
}


def _resp(body):
    r = MagicMock()
    r.json.return_value = body
    r.raise_for_status = MagicMock()
    return r


async def _local(body):
    c = ProxyClient("http://localhost:8098", api_key=None)
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_resp(body)):
        return await c.verify("p", "r", MODEL)


async def _hosted(body):
    c = ProxyClient("", hosted_url="https://hosted.example.test", api_key="ak_live_x")
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=_resp(body)):
        return await c.verify("p", "r", MODEL)


def _run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("path,field", [(_local, "risk_level"), (_hosted, "risk")])
def test_clean_answer_is_assessed(path, field):
    out = _run(path({**CLEAN, field: "LOW", "model_id": MODEL.upper()}))
    assert out["risk_level"] == "LOW" and out["assessed"] is True


@pytest.mark.parametrize("path,field", [(_local, "risk_level"), (_hosted, "risk")])
@pytest.mark.parametrize("name", sorted(SHAPES))
def test_contradictory_shapes_never_read_as_assessed(path, field, name):
    out = _run(path({**CLEAN, field: "LOW", **SHAPES[name]}))
    assert out["risk_level"] == "NOT_ASSESSED" and out["assessed"] is False, name
    assert "LOW" not in json.dumps(out)


def test_local_unassessed_never_keeps_an_invalid_candidate():
    for cand in ("LOW", "SURPRISE", {"x": "sentinel_value"}, ["sentinel_value"]):
        out = _run(_local({"risk_level": "LOW", "assessed": False, "not_assessed_reason": "r", "candidate_alert": cand}))
        assert out["risk_level"] == "NOT_ASSESSED" and "candidate_alert" not in out
        assert "sentinel_value" not in json.dumps(out)


def test_candidate_must_match_the_band():
    ok = _run(_local({"risk_level": "HIGH", "assessed": False, "not_assessed_reason": "r", "candidate_alert": "HIGH"}))
    assert ok["candidate_alert"] == "HIGH" and ok["not_assessed_reason"] == "not_assessed"
    bad = _run(_local({"risk_level": "HIGH", "assessed": False, "not_assessed_reason": "r", "candidate_alert": "MEDIUM"}))
    assert "candidate_alert" not in bad and bad["not_assessed_reason"] == "unknown"


def test_only_typed_fields_are_passed_on():
    body = {**CLEAN, "risk_level": "HIGH", "extra_field": ["f"], "nested": {"a": 1}, "detection_id": {"x": 1},
            "confidence": "high", "gate_action": "x" * 500}
    out = _run(_local(body))
    assert set(out) <= {"risk_level", "assessed", "not_assessed_reason", "candidate_alert", "confidence",
                        "detection_id", "gate_action", "source", "error"}
    assert "detection_id" not in out and out["confidence"] == 0.0 and "gate_action" not in out


def test_root_server_builds_fresh_fields():
    server = pytest.importorskip("server")
    body = {**CLEAN, "risk_level": "LOW", "candidate_alert": {"x": "sentinel_value"}, "extra": 1}
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.post = AsyncMock(return_value=_resp(body))
    with patch("httpx.AsyncClient", return_value=client):
        out = _run(server.arkheia_verify("p", "r", MODEL))
    assert out["risk_level"] == "NOT_ASSESSED" and "sentinel_value" not in json.dumps(out) and "extra" not in out


AUDIT = {"events": [
    {"source": "proxy", "risk_level": "HIGH", "assessed": True, "evidence_depth_limited": False, "detection_id": "d1",
     "timestamp": "2026-01-01T00:00:00Z", "model_id": "m", "this_hash": "h", "message": "x" * 500,
     "nested": {"a": {"b": 1}}, "extra_method": "m"},
    {"source": "governance_push", "event_type": "governance_detection_push", "risk_level": "LOW"},
    "not a row",
]}


def test_audit_view_is_a_typed_allowlist_with_hashes_over_the_export():
    c = ProxyClient("http://localhost:8098", api_key=None)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_resp(AUDIT)):
        out = _run(c.get_audit_log())
    first, receipt = out["events"]
    assert sorted(first) == ["assessed", "id", "model", "record_kind", "risk_level", "timestamp", "view_hash"]
    assert "risk_level" not in receipt and out["summary"]["INVALID_ROWS"] == 1
    rows = out["events"]
    expected = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert out["export_hash"] == expected


def test_root_server_audit_uses_the_same_view():
    server = pytest.importorskip("server")
    client = MagicMock()
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    client.get = AsyncMock(return_value=_resp(AUDIT))
    with patch("httpx.AsyncClient", return_value=client):
        out = _run(server.arkheia_audit_log())
    assert "export_hash" in out and "this_hash" not in json.dumps(out)


def test_metadata_is_validated_with_fixed_fallbacks():
    body = {**CLEAN, "risk_level": "HIGH", "confidence": {"x": "sentinel_value"}, "detection_id": {"x": "sentinel_value"},
            "gate_action": "sentinel_value"}
    out = _run(_local(body))
    assert out["confidence"] == 0.0 and "detection_id" not in out and "gate_action" not in out
    assert "sentinel_value" not in json.dumps(out)
    out = _run(_local({**CLEAN, "risk_level": "HIGH", "confidence": 7, "detection_id": "has space"}))
    assert out["confidence"] == 0.0 and "detection_id" not in out
    out = _run(_hosted({"risk": "LOW", "assessed": False, "not_assessed_reason": "r", "error": "sentinel_value text"}))
    assert out["error"] == "service_error" and "sentinel_value" not in json.dumps(out)


def test_audit_unknown_kind_does_not_hide_a_detection_and_bad_rows_are_isolated():
    body = {"events": [
        {"source": "proxy", "record_kind": "sentinel_value", "risk_level": "HIGH", "assessed": True,
         "evidence_depth_limited": False, "detection_id": "d1"},
        {"source": "proxy", "risk_level": ["x"], "assessed": False, "not_assessed_reason": "r",
         "candidate_alert": "HIGH", "risk_demoted_from": {"a": 1}},
        {"source": "proxy", "risk_level": "MEDIUM", "assessed": False, "not_assessed_reason": "r",
         "candidate_alert": "HIGH", "risk_demoted_from": ["x"]},
    ], "error": "sentinel_value"}
    c = ProxyClient("http://localhost:8098", api_key=None)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_resp(body)):
        out = _run(c.get_audit_log())
    assert out["events"][0]["record_kind"] == "detection" and out["events"][0]["risk_level"] == "HIGH"
    assert len(out["events"]) == 3 and out["summary"]["HIGH"] == 1
    assert "sentinel_value" not in json.dumps(out) and out["error"] == "audit_unavailable"


def test_hash_uses_ascii_escaped_canonical_json():
    body = {"events": [{"source": "proxy", "risk_level": "HIGH", "assessed": True, "evidence_depth_limited": False,
                        "detection_id": "local-café", "timestamp": 1700000000.0}]}
    c = ProxyClient("http://localhost:8098", api_key=None)
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=_resp(body)):
        out = _run(c.get_audit_log())
    assert out["events"][0]["timestamp"] == 1700000000 and out["hash_scheme"] == "sha256-canonical-json-v1"
