"""
Arkheia MCP Server — repo-root entry point.

This module is a THIN RE-EXPORT of the single real server, ``mcp_server.server``.
It defines no tools of its own on purpose.

Why it is a shim (defect fixed 2026-07-26)
------------------------------------------
This file used to be a SECOND, independent ``FastMCP("arkheia-trust")`` that
redefined ``arkheia_verify`` and ``arkheia_audit_log``. It never imported
``mcp_server.tool_registry``, so:

  * it bypassed the tool-registry allow/deny gate entirely — its tools made no
    policy decision at all, while the product documents "default deny: any tool
    not in REGISTRY cannot be called";
  * it POSTed ``{"model": ...}`` to ``/detect/verify``, whose ``VerifyRequest``
    requires ``model_id`` — every call 422'd and, because it used
    ``raise_for_status()`` with no fail-safe, raised the error straight at the
    orchestrator instead of returning ``risk_level: UNKNOWN``;
  * it had no API key and no hosted fallback, so it could only ever reach a
    local proxy;
  * it did not cap ``limit`` on audit-log reads.

None of that was hypothetical: ``ARKHEIA_INSTALL.md`` documented this file as the
Windows entry point (``"args": ["C:/arkheia-mcp/server.py"]``), so the published
install instructions pointed operators at the ungated, non-functional server.
Re-exporting keeps that documented path working while making it identical to
``python -m mcp_server.server``: gated, fail-safe, and hosted-fallback capable.

``tests/test_tool_gate_floor.py`` INV-4 keeps this from regressing — any
production module that defines ``@mcp.tool`` functions without importing the gate
fails the required ``floor-invariants`` context.
"""

from mcp_server.server import mcp, startup_policy_selfcheck

__all__ = ["mcp", "startup_policy_selfcheck"]

if __name__ == "__main__":
    startup_policy_selfcheck()
    mcp.run()
