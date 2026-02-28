"""Fake implementations for testing without external dependencies."""

from __future__ import annotations

import time
from typing import Any, Optional


class FakeRedis:
    """
    Mock Redis client with dict-based storage.

    Implements subset of redis-py interface needed for WorkerRegistry tests.
    Stores data in memory using Python data structures.
    """

    def __init__(self):
        """Initialize in-memory storage."""
        self.data = {}  # key -> value (strings)
        self.hashes = {}  # key -> {field: value} (hashes)
        self.sets = {}  # key -> set() (sets)
        self.lists = {}  # key -> list() (lists)
        self.expiry = {}  # key -> expiration timestamp

    def hset(self, key: str, field: str = None, value: Any = None, mapping: dict = None) -> int:
        """Set hash field(s)."""
        if key not in self.hashes:
            self.hashes[key] = {}

        if mapping:
            # Multiple fields from mapping
            self.hashes[key].update({str(k): str(v)
                                    for k, v in mapping.items()})
            return len(mapping)
        elif field is not None:
            # Single field
            self.hashes[key][str(field)] = str(value)
            return 1
        return 0

    def hgetall(self, key: str) -> dict:
        """Get all fields and values from hash."""
        return self.hashes.get(key, {}).copy()

    def hget(self, key: str, field: str) -> Optional[str]:
        """Get single field from hash."""
        return self.hashes.get(key, {}).get(str(field))

    def sadd(self, key: str, *members) -> int:
        """Add member(s) to set."""
        if key not in self.sets:
            self.sets[key] = set()

        initial_size = len(self.sets[key])
        self.sets[key].update(str(m) for m in members)
        return len(self.sets[key]) - initial_size

    def smembers(self, key: str) -> set:
        """Get all members of set."""
        return self.sets.get(key, set()).copy()

    def srem(self, key: str, *members) -> int:
        """Remove member(s) from set."""
        if key not in self.sets:
            return 0

        initial_size = len(self.sets[key])
        self.sets[key].difference_update(str(m) for m in members)
        removed = initial_size - len(self.sets[key])

        if not self.sets[key]:
            del self.sets[key]

        return removed

    def rpush(self, key: str, *values) -> int:
        """Push value(s) to end of list."""
        if key not in self.lists:
            self.lists[key] = []

        self.lists[key].extend(str(v) for v in values)
        return len(self.lists[key])

    def blpop(self, keys, timeout: int) -> Optional[tuple]:
        """Pop value from beginning of list (blocking with timeout).

        Args:
            keys: List of keys or single key
            timeout: Timeout in seconds (not actually blocking in fake)

        Returns:
            (key, value) tuple if value exists, None otherwise
        """
        # Normalize keys to list
        if isinstance(keys, str):
            keys = [keys]

        # Check each key in order
        for key in keys:
            if key in self.lists and self.lists[key]:
                value = self.lists[key].pop(0)

                if not self.lists[key]:
                    del self.lists[key]

                return (key, value)

        return None

    def lpop(self, key: str) -> Optional[str]:
        """Pop value from beginning of list (non-blocking)."""
        if key in self.lists and self.lists[key]:
            value = self.lists[key].pop(0)

            if not self.lists[key]:
                del self.lists[key]

            return value

        return None

    def llen(self, key: str) -> int:
        """Get length of list."""
        return len(self.lists.get(key, []))

    def setnx(self, key: str, value: Any) -> bool:
        """Set key if not exists (atomic).

        Returns:
            True if key was set, False if key already existed
        """
        if key in self.data:
            return False

        self.data[key] = str(value)
        return True

    def set(self, key: str, value: Any) -> bool:
        """Set key to value."""
        self.data[key] = str(value)
        return True

    def get(self, key: str) -> Optional[str]:
        """Get value of key."""
        # Check expiry
        if key in self.expiry and self.expiry[key] < time.time():
            # Expired
            del self.data[key]
            del self.expiry[key]
            return None

        return self.data.get(key)

    def expire(self, key: str, seconds: int) -> bool:
        """Set expiration on key.

        Args:
            key: Key to expire
            seconds: TTL in seconds

        Returns:
            True if expiration was set, False if key doesn't exist
        """
        # Check if key exists in any data structure
        exists = (key in self.data or
                  key in self.hashes or
                  key in self.sets or
                  key in self.lists)

        if exists:
            self.expiry[key] = time.time() + seconds
            return True

        return False

    def delete(self, *keys) -> int:
        """Delete key(s).

        Returns:
            Number of keys deleted
        """
        deleted = 0

        for key in keys:
            if key in self.data:
                del self.data[key]
                deleted += 1
            if key in self.hashes:
                del self.hashes[key]
                deleted += 1
            if key in self.sets:
                del self.sets[key]
                deleted += 1
            if key in self.lists:
                del self.lists[key]
                deleted += 1
            if key in self.expiry:
                del self.expiry[key]

        return max(deleted, len(keys) if any(k in (self.data, self.hashes, self.sets, self.lists) for k in keys) else 0)

    def exists(self, *keys) -> int:
        """Check if key(s) exist.

        Returns:
            Number of keys that exist
        """
        count = 0
        for key in keys:
            if (key in self.data or
                key in self.hashes or
                key in self.sets or
                    key in self.lists):
                count += 1
        return count

    def keys(self, pattern: str = "*") -> list:
        """Get all keys matching pattern (simplified, only supports '*')."""
        all_keys = set()
        all_keys.update(self.data.keys())
        all_keys.update(self.hashes.keys())
        all_keys.update(self.sets.keys())
        all_keys.update(self.lists.keys())
        return list(all_keys)

    def flushall(self) -> bool:
        """Delete all keys from all databases."""
        self.data.clear()
        self.hashes.clear()
        self.sets.clear()
        self.lists.clear()
        self.expiry.clear()
        return True
