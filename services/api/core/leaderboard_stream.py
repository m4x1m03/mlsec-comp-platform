"""Realtime leaderboard streaming via Postgres LISTEN/NOTIFY and websockets.

Maintains websocket connections, listens for leaderboard changes, debounces
updates, and broadcasts cached snapshots to connected clients.
"""

from __future__ import annotations

import asyncio
import logging
import os
import select
import threading
import time
from datetime import datetime, timezone
from typing import Callable

import psycopg2
from fastapi import WebSocket
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

logger = logging.getLogger(__name__)


class LeaderboardConnectionManager:
    """Track websocket connections and broadcast leaderboard payloads."""

    def __init__(self) -> None:
        """Initialize the connection registry."""
        self._connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept the websocket and register it for broadcasts."""
        await websocket.accept()
        self._connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a websocket from the active connection set."""
        self._connections.discard(websocket)

    def has_connections(self) -> bool:
        """Return True when at least one websocket is connected."""
        return bool(self._connections)

    async def send(self, websocket: WebSocket, payload: dict) -> None:
        """Send a payload to a single websocket."""
        await websocket.send_json(payload)

    async def broadcast(self, payload: dict) -> None:
        """Broadcast a payload to all active websockets."""
        dead: list[WebSocket] = []
        for websocket in list(self._connections):
            try:
                await websocket.send_json(payload)
            except Exception:
                dead.append(websocket)
        for websocket in dead:
            self.disconnect(websocket)


class LeaderboardListener:
    """Background LISTEN/NOTIFY listener with debounced callbacks."""

    def __init__(
        self,
        *,
        database_url: str,
        channel: str,
        debounce_seconds: float,
        on_debounced_event: Callable[[], None],
    ) -> None:
        """Configure the listener and its debounce callback."""
        self._database_url = database_url
        self._channel = channel
        self._debounce_seconds = debounce_seconds
        self._on_debounced_event = on_debounced_event
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the background listener thread if not already running."""
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Signal the listener to stop and wait briefly for shutdown."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def _run(self) -> None:
        """Run the listen loop with simple retry/backoff behavior."""
        while not self._stop_event.is_set():
            try:
                self._listen_loop()
            except Exception as exc:
                logger.warning("Leaderboard LISTEN failed, retrying: %s", exc)
                time.sleep(1.0)

    def _listen_loop(self) -> None:
        """Listen for NOTIFY events and invoke the debounced callback."""
        conn = psycopg2.connect(self._database_url)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        cursor.execute(f"LISTEN {self._channel};")

        pending = False
        last_notify = 0.0

        try:
            while not self._stop_event.is_set():
                # Poll for notifications with a short timeout.
                ready, _, _ = select.select([conn], [], [], 0.5)
                if ready:
                    conn.poll()
                    while conn.notifies:
                        conn.notifies.pop(0)
                        pending = True
                        last_notify = time.monotonic()

                # Debounce rapid notifications into a single callback.
                if pending and (time.monotonic() - last_notify) >= self._debounce_seconds:
                    pending = False
                    self._on_debounced_event()
        finally:
            try:
                cursor.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


class LeaderboardStream:
    """Coordinate snapshot caching, listeners, and websocket broadcasts."""

    def __init__(
        self,
        *,
        database_url: str,
        compute_snapshot: Callable[[], dict],
        channel: str = "leaderboard_changes",
        debounce_seconds: float = 1.5,
    ) -> None:
        """Initialize the stream state and dependencies."""
        self._database_url = database_url
        self._compute_snapshot = compute_snapshot
        self._channel = channel
        self._debounce_seconds = debounce_seconds
        self._manager = LeaderboardConnectionManager()
        self._listener: LeaderboardListener | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._cache: dict | None = None
        self._version = 0

    def start(self, *, loop: asyncio.AbstractEventLoop) -> None:
        """Start the Postgres listener and bind to the given event loop."""
        self._loop = loop
        self._listener = LeaderboardListener(
            database_url=self._database_url,
            channel=self._channel,
            debounce_seconds=self._debounce_seconds,
            on_debounced_event=self._on_change,
        )
        self._listener.start()
        logger.info("Leaderboard stream listener started")

    def stop(self) -> None:
        """Stop the Postgres listener if running."""
        if self._listener:
            self._listener.stop()
            self._listener = None
        logger.info("Leaderboard stream listener stopped")

    def _build_snapshot(self) -> dict:
        """Compute, version, and cache a fresh leaderboard snapshot."""
        snapshot = self._compute_snapshot()
        with self._lock:
            self._version += 1
            snapshot["version"] = self._version
            snapshot["generated_at"] = datetime.now(timezone.utc).isoformat()
            self._cache = snapshot
        return snapshot

    def _get_cached_snapshot(self) -> dict | None:
        """Return the cached snapshot if one exists."""
        with self._lock:
            return self._cache

    async def connect(self, websocket: WebSocket) -> None:
        """Register a websocket and send the current snapshot."""
        await self._manager.connect(websocket)
        cached = self._get_cached_snapshot()
        if cached is None:
            snapshot = await asyncio.to_thread(self._build_snapshot)
            await self._manager.send(websocket, snapshot)
        else:
            await self._manager.send(websocket, cached)

    def disconnect(self, websocket: WebSocket) -> None:
        """Unregister a websocket from broadcasts."""
        self._manager.disconnect(websocket)

    def _on_change(self) -> None:
        """Handle a debounced leaderboard change notification."""
        # If no loop is available, skip broadcasting.
        if self._loop is None:
            return

        # If there are no connections and no cache, avoid work.
        if not self._manager.has_connections() and self._get_cached_snapshot() is not None:
            return

        snapshot = self._build_snapshot()
        # If we're already on the target loop, schedule directly; otherwise
        # marshal the coroutine to the loop thread safely.
        try:
            running_loop = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        if running_loop is self._loop:
            self._loop.create_task(self._manager.broadcast(snapshot))
        else:
            asyncio.run_coroutine_threadsafe(self._manager.broadcast(snapshot), self._loop)


def should_enable_leaderboard_stream() -> bool:
    """Return True when realtime streaming should be enabled."""
    if os.getenv("DISABLE_LEADERBOARD_STREAM") == "1":
        return False
    if os.getenv("PYTEST_CURRENT_TEST") is not None:
        return False
    return True
