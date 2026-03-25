from __future__ import annotations

import json
import logging
from typing import Any
from uuid import UUID

from sqlalchemy import text

from core.database import get_engine

logger = logging.getLogger(__name__)


def log_audit_event(
    *,
    event_type: str,
    user_id: UUID | None = None,
    email: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    success: bool | None = None,
    message: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Persist a structured audit log event.

    This uses a standalone connection so audit logging does not interfere
    with request transactions.
    """
    try:
        payload = json.dumps(metadata) if metadata is not None else None
        with get_engine().begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO audit_logs (
                        event_type,
                        user_id,
                        email,
                        ip_address,
                        user_agent,
                        success,
                        message,
                        metadata
                    )
                    VALUES (
                        :event_type,
                        :user_id,
                        :email,
                        :ip_address,
                        :user_agent,
                        :success,
                        :message,
                        CAST(:metadata AS jsonb)
                    )
                    """
                ),
                {
                    "event_type": event_type,
                    "user_id": str(user_id) if user_id else None,
                    "email": email,
                    "ip_address": ip_address,
                    "user_agent": user_agent,
                    "success": success,
                    "message": message,
                    "metadata": payload,
                },
            )
    except Exception as exc:
        logger.warning("Failed to write audit log: %s", exc)
