from __future__ import annotations

import asyncio

from core.leaderboard_stream import (
    LeaderboardConnectionManager,
    LeaderboardListener,
    LeaderboardStream,
    should_enable_leaderboard_stream,
)


class _GoodWebSocket:
    def __init__(self):
        self.sent = []

    async def send_json(self, payload):
        self.sent.append(payload)


class _BadWebSocket:
    async def send_json(self, _payload):
        raise RuntimeError("boom")


def test_connection_manager_broadcast_handles_dead():
    async def _run():
        manager = LeaderboardConnectionManager()
        good = _GoodWebSocket()
        bad = _BadWebSocket()
        manager._connections = {good, bad}

        await manager.broadcast({"type": "ping"})

        assert good.sent
        assert bad not in manager._connections

    asyncio.run(_run())


def test_listener_start_noop_when_thread_alive():
    listener = LeaderboardListener(
        database_url="postgresql://example",
        channel="leaderboard",
        debounce_seconds=0.0,
        on_debounced_event=lambda: None,
    )

    class _Thread:
        def is_alive(self):
            return True

    thread = _Thread()
    listener._thread = thread
    listener.start()
    assert listener._thread is thread


def test_listener_start_creates_thread(monkeypatch):
    listener = LeaderboardListener(
        database_url="postgresql://example",
        channel="leaderboard",
        debounce_seconds=0.0,
        on_debounced_event=lambda: None,
    )

    class _FakeThread:
        def __init__(self, target=None, daemon=None):
            self.target = target
            self.daemon = daemon
            self.started = False

        def is_alive(self):
            return False

        def start(self):
            self.started = True

    monkeypatch.setattr("core.leaderboard_stream.threading.Thread", _FakeThread)

    listener.start()
    assert isinstance(listener._thread, _FakeThread)
    assert listener._thread.started is True


def test_listener_stop_joins():
    listener = LeaderboardListener(
        database_url="postgresql://example",
        channel="leaderboard",
        debounce_seconds=0.0,
        on_debounced_event=lambda: None,
    )

    class _Thread:
        def __init__(self):
            self.joined = False

        def is_alive(self):
            return True

        def join(self, timeout=None):
            self.joined = True

    thread = _Thread()
    listener._thread = thread
    listener.stop()
    assert thread.joined is True


def test_listener_run_handles_exception(monkeypatch):
    listener = LeaderboardListener(
        database_url="postgresql://example",
        channel="leaderboard",
        debounce_seconds=0.0,
        on_debounced_event=lambda: None,
    )

    def _boom():
        listener._stop_event.set()
        raise RuntimeError("boom")

    monkeypatch.setattr(listener, "_listen_loop", _boom)
    called = {"sleep": False}
    monkeypatch.setattr("core.leaderboard_stream.time.sleep", lambda *_args: called.__setitem__("sleep", True))

    listener._run()
    assert called["sleep"] is True


def test_listener_listen_loop_debounces(monkeypatch):
    called = {"count": 0}

    def _on_event():
        called["count"] += 1
        listener._stop_event.set()

    listener = LeaderboardListener(
        database_url="postgresql://example",
        channel="leaderboard",
        debounce_seconds=0.0,
        on_debounced_event=_on_event,
    )

    class _FakeCursor:
        def __init__(self):
            self.closed = False
            self.executed = []

        def execute(self, stmt):
            self.executed.append(stmt)

        def close(self):
            self.closed = True

    class _FakeConn:
        def __init__(self):
            self.notifies = [object()]
            self.closed = False
            self.cursor_obj = _FakeCursor()

        def set_isolation_level(self, _level):
            pass

        def cursor(self):
            return self.cursor_obj

        def poll(self):
            pass

        def close(self):
            self.closed = True

    fake_conn = _FakeConn()

    monkeypatch.setattr("core.leaderboard_stream.psycopg2.connect", lambda _url: fake_conn)
    monkeypatch.setattr("core.leaderboard_stream.select.select", lambda *_args, **_kwargs: ([fake_conn], [], []))
    monkeypatch.setattr("core.leaderboard_stream.time.monotonic", lambda: 0.0)

    listener._listen_loop()

    assert called["count"] == 1
    assert fake_conn.cursor_obj.closed is True
    assert fake_conn.closed is True


def test_stream_start_stop_uses_listener(monkeypatch):
    started = {"value": False}
    stopped = {"value": False}

    class _FakeListener:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            started["value"] = True

        def stop(self):
            stopped["value"] = True

    monkeypatch.setattr("core.leaderboard_stream.LeaderboardListener", _FakeListener)

    stream = LeaderboardStream(
        database_url="postgresql://example",
        compute_snapshot=lambda: {"type": "leaderboard_snapshot"},
    )

    loop = asyncio.new_event_loop()
    try:
        stream.start(loop=loop)
        stream.stop()
    finally:
        loop.close()

    assert started["value"] is True
    assert stopped["value"] is True


def test_stream_on_change_no_loop_returns():
    calls = {"count": 0}

    def _snapshot():
        calls["count"] += 1
        return {"type": "leaderboard_snapshot"}

    stream = LeaderboardStream(
        database_url="postgresql://example",
        compute_snapshot=_snapshot,
    )

    stream._on_change()
    assert calls["count"] == 0


def test_stream_on_change_skips_when_cached_and_no_connections():
    calls = {"count": 0}

    def _snapshot():
        calls["count"] += 1
        return {"type": "leaderboard_snapshot"}

    stream = LeaderboardStream(
        database_url="postgresql://example",
        compute_snapshot=_snapshot,
    )
    stream._loop = asyncio.new_event_loop()
    stream._cache = {"type": "leaderboard_snapshot"}

    stream._on_change()

    assert calls["count"] == 0
    stream._loop.close()


def test_stream_on_change_threadsafe_path(monkeypatch):
    calls = {"threadsafe": False}

    def _snapshot():
        return {"type": "leaderboard_snapshot"}

    stream = LeaderboardStream(
        database_url="postgresql://example",
        compute_snapshot=_snapshot,
    )
    stream._loop = object()

    def _raise_running():
        raise RuntimeError("no loop")

    def _fake_threadsafe(coro, loop):
        calls["threadsafe"] = True
        coro.close()

    monkeypatch.setattr(asyncio, "get_running_loop", _raise_running)
    monkeypatch.setattr(asyncio, "run_coroutine_threadsafe", _fake_threadsafe)

    stream._on_change()

    assert calls["threadsafe"] is True


def test_should_enable_leaderboard_stream_env(monkeypatch):
    monkeypatch.setenv("DISABLE_LEADERBOARD_STREAM", "1")
    assert should_enable_leaderboard_stream() is False

    monkeypatch.delenv("DISABLE_LEADERBOARD_STREAM", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "test")
    assert should_enable_leaderboard_stream() is False

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    assert should_enable_leaderboard_stream() is True
