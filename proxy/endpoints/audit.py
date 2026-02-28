"""
GET /audit/log

Returns structured audit events for compliance review.
Used by the MCP Trust Server's arkheia_audit_log tool.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Query, Request

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/audit/log")
async def get_audit_log(
    request: Request,
    session_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
):
    """
    Retrieve detection events from the audit log.

    Args:
        session_id: Optional -- scope to a specific session
        limit:      Max events to return (1-500, default 50)

    Returns:
        events:  List of detection events, most recent first
        summary: Aggregate counts by risk level
    """
    audit = getattr(request.app.state, "audit_writer", None)
    if audit is None:
        return {
            "events": [],
            "summary": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0},
            "error": "audit_writer_unavailable",
        }

    return audit.read_recent(limit=limit, session_id=session_id)
