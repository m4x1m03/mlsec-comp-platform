import pytest
from pathlib import Path
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy import event, text
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

import os
os.environ["CELERY_BROKER_URL"] = "memory://"
os.environ["CELERY_DEFAULT_QUEUE"] = "mlsec"

from main import app
from core.database import Base, get_db
from core.celery_app import get_celery
from unittest.mock import MagicMock


TEST_DB_URL = os.getenv("DATABASE_URL", "postgresql://mlsec2:mlsec2_pw@localhost:5433/mlsec_test")

engine = create_engine(TEST_DB_URL)
TestingSessionLocal = sessionmaker(bind=engine)


# Create tables once per test session
@pytest.fixture(scope="session", autouse=True)
def setup_database():
    # Execute SQL schema file since project uses raw SQL, not ORM models
    schema_path = Path(__file__).parent.parent.parent.parent / \
        "services" / "postgres" / "init" / "database_schema.sql"

    with engine.connect() as conn:
        # Drop and recreate schema to ensure clean state
        conn.execute(text("""
            DROP SCHEMA IF EXISTS public CASCADE;
            CREATE SCHEMA public;
        """))
        conn.commit()

        # Load and execute schema
        with open(schema_path, "r") as f:
            schema_sql = f.read()
        conn.execute(text(schema_sql))
        conn.commit()

    yield

    # Drop all tables on teardown
    with engine.connect() as conn:
        conn.execute(text("""
            DROP SCHEMA IF EXISTS public CASCADE;
            CREATE SCHEMA public;
        """))
        conn.commit()


# Provide a new database session for each test
@pytest.fixture()
def db_session():

    connection = engine.connect()
    transaction = connection.begin()

    session = TestingSessionLocal(bind=connection)

    # Tests run inside a transaction that is rolled back at the end of the test.
    #
    # Our API endpoints legitimately call `db.commit()` (e.g., after inserting a
    # row into `jobs`). If we didn't do anything special, a commit inside the
    # endpoint would end the transaction that the test is relying on.
    #
    # The nested transaction (SAVEPOINT) pattern makes application-level commits
    # safe while still guaranteeing isolation via the outer rollback.
    session.begin_nested()

    @event.listens_for(session, "after_transaction_end")
    def _restart_savepoint(sess, trans):
        if trans.nested and not trans._parent.nested:
            sess.begin_nested()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


# Override FastAPI dependency since we want to use the test database session
@pytest.fixture()
def client(db_session):

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app, client=("127.0.0.1", 50000)) as c:
            yield c
    finally:
        app.dependency_overrides.pop(get_db, None)


@pytest.fixture(autouse=True)
def mock_celery(monkeypatch):
    """Mock Celery to prevent physical broker connections during tests."""
    mock_app = MagicMock()
    monkeypatch.setattr("core.celery_app.get_celery", lambda: mock_app)
    return mock_app


@pytest.fixture()
def fake_redis():
    """Provide fake Redis client for testing without external dependency."""

    class FakeRedis:
        """Minimal Redis mock for API tests."""

        def __init__(self):
            self.hashes = {}  # key -> {field: value}
            self.sets = {}  # key -> set()
            self.lists = {}  # key -> list()
            self.data = {}  # key -> value
            self.expiry = {}  # key -> expiration timestamp

        def hgetall(self, key):
            return self.hashes.get(key, {}).copy()

        def hset(self, key, field=None, value=None, mapping=None):
            if key not in self.hashes:
                self.hashes[key] = {}
            if mapping:
                self.hashes[key].update({str(k): str(v)
                                        for k, v in mapping.items()})
                return len(mapping)
            elif field is not None:
                self.hashes[key][str(field)] = str(value)
                return 1
            return 0

        def smembers(self, key):
            return self.sets.get(key, set()).copy()

        def sadd(self, key, *members):
            if key not in self.sets:
                self.sets[key] = set()
            initial_size = len(self.sets[key])
            self.sets[key].update(str(m) for m in members)
            return len(self.sets[key]) - initial_size

        def rpush(self, key, *values):
            if key not in self.lists:
                self.lists[key] = []
            self.lists[key].extend(str(v) for v in values)
            return len(self.lists[key])

        def setnx(self, key, value):
            if key in self.data:
                return False
            self.data[key] = str(value)
            return True

        def set(self, key, value):
            self.data[key] = str(value)
            return True

        def setex(self, key, seconds, value):
            import time
            self.data[key] = str(value)
            self.expiry[key] = time.time() + seconds
            return True

        def get(self, key):
            return self.data.get(key)

        def expire(self, key, seconds):
            import time
            exists = (key in self.data or key in self.hashes or
                      key in self.sets or key in self.lists)
            if exists:
                self.expiry[key] = time.time() + seconds
                return True
            return False

        def exists(self, *keys):
            count = 0
            for key in keys:
                if (key in self.data or key in self.hashes or
                        key in self.sets or key in self.lists):
                    count += 1
            return count

        def delete(self, *keys):
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
            return deleted

    return FakeRedis()
