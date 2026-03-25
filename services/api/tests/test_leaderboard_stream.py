"""Leaderboard websocket and stream behavior tests.

Validates snapshot caching, broadcasts, and database trigger presence.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlalchemy import text

from core.leaderboard_stream import LeaderboardStream


class _FakeWebSocket:
    """Minimal websocket stub for testing LeaderboardStream."""

    def __init__(self) -> None:
        """Initialize the fake websocket state."""
        self.accepted = False
        self.sent: list[dict[str, Any]] = []

    async def accept(self) -> None:
        """Mark the websocket as accepted."""
        self.accepted = True

    async def send_json(self, payload: dict) -> None:
        """Record payloads sent to the websocket."""
        self.sent.append(payload)


@pytest.mark.skip(reason="This branch uses SSE-based leaderboard, not the WebSocket LeaderboardStream router")
def test_leaderboard_ws_snapshot_is_sent_and_cached(client, monkeypatch):
    """First websocket connection should compute and cache the snapshot."""
    from routers import leaderboard as leaderboard_module

    calls = {"count": 0}

    def _fake_snapshot() -> dict:
        """Return a deterministic snapshot payload for testing."""
        calls["count"] += 1
        return {"type": "leaderboard_snapshot", "defense": {"items": []}, "attack": {"items": []}}

    stream = leaderboard_module._leaderboard_stream
    monkeypatch.setattr(stream, "_compute_snapshot", _fake_snapshot)
    stream._cache = None
    stream._version = 0

    with client.websocket_connect("/api/leaderboard/ws") as websocket:
        payload = websocket.receive_json()
        assert payload["type"] == "leaderboard_snapshot"
        assert payload["version"] == 1
        assert "generated_at" in payload

    with client.websocket_connect("/api/leaderboard/ws") as websocket:
        payload = websocket.receive_json()
        assert payload["type"] == "leaderboard_snapshot"
        assert payload["version"] == 1

    assert calls["count"] == 1


def test_leaderboard_stream_broadcasts_on_change():
    """Change notifications should broadcast updated snapshots."""
    calls = {"count": 0}

    def _fake_snapshot() -> dict:
        """Return a deterministic snapshot payload for testing."""
        calls["count"] += 1
        return {"type": "leaderboard_snapshot", "defense": {"items": []}, "attack": {"items": []}}

    stream = LeaderboardStream(
        database_url="postgresql://example",
        compute_snapshot=_fake_snapshot,
        debounce_seconds=0.0,
    )

    async def _run() -> None:
        """Run a small async flow to validate broadcast behavior."""
        websocket = _FakeWebSocket()
        await stream.connect(websocket)
        assert websocket.sent[0]["version"] == 1

        stream._loop = asyncio.get_running_loop()
        stream._on_change()
        await asyncio.sleep(0)

        assert len(websocket.sent) == 2
        assert websocket.sent[1]["version"] == 2

    asyncio.run(_run())
    assert calls["count"] == 2


def test_leaderboard_trigger_exists(db_session):
    """Database trigger for leaderboard notifications should exist."""
    row = db_session.execute(
        text(
            """
            SELECT 1
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            WHERE c.relname = 'evaluation_pair_scores'
              AND t.tgname = 'trg_leaderboard_scores_notify'
              AND NOT t.tgisinternal
            """
        )
    ).fetchone()
    assert row is not None
