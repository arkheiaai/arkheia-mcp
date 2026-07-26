"""
Suite-wide isolation for the mcp_server tests.

The tool-registry gate writes a decision receipt for every dispatch, to an
absolute per-user path (``~/.arkheia/mcp/tool-gate-receipts.jsonl``). A test suite
that dispatched tools would therefore append to the developer's real evidence log
and, worse, a suite whose assertions read that log would be reading rows left by
previous runs. Both are redirected here, per test, so every test starts with an
empty log it owns.

This is autouse ON PURPOSE. An opt-in fixture is one forgotten decorator away
from a test writing to the real log, and the failure is silent.
"""
from __future__ import annotations

import pytest

from mcp_server import tool_registry


@pytest.fixture(autouse=True)
def gate_receipt_log(tmp_path, monkeypatch):
    """Redirect the gate's receipt log into this test's tmp_path. Yields the path."""
    path = tmp_path / "tool-gate-receipts.jsonl"
    monkeypatch.setenv(tool_registry.RECEIPT_LOG_ENV, str(path))
    return path
