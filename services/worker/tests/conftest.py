"""Pytest fixtures for worker tests."""

from __future__ import annotations
from fakes import FakeRedis
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, event, text
import pytest

import os

# Set required environment variables BEFORE any imports
# This ensures worker modules can be imported during test collection
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
os.environ.setdefault(
    "DATABASE_URL", "postgresql://postgres:password123@localhost:5433/mlsec_test")
os.environ.setdefault("MINIO_ENDPOINT", "minio:9000")
os.environ.setdefault("MINIO_ACCESS_KEY", "minioadmin")
os.environ.setdefault("MINIO_SECRET_KEY", "minioadmin")
os.environ.setdefault("CELERY_DEFAULT_QUEUE", "mlsec")


# Environment variables fixture (kept for compatibility)
@pytest.fixture(scope="session", autouse=True)
def set_env_vars():
    """Environment variables are already set at module level."""
    pass
    os.environ.setdefault("MINIO_ACCESS_KEY", "minioadmin")
    os.environ.setdefault("MINIO_SECRET_KEY", "minioadmin")
    os.environ.setdefault("MINIO_BUCKET", "mlsec-submissions")
    os.environ.setdefault("GATEWAY_URL", "http://mlsec-gateway:8080/")
    os.environ.setdefault("GATEWAY_SECRET", "test_secret")
    yield


# Test database configuration
TEST_DB_URL = "postgresql://postgres:password123@localhost:5433/mlsec_test"

engine = create_engine(TEST_DB_URL)
TestingSessionLocal = sessionmaker(bind=engine)


# Create tables once per test session
@pytest.fixture(scope="session", autouse=True)
def setup_database():
    """Create database tables once per test session."""
    # Import all models to register with Base
    # Note: Worker doesn't use SQLAlchemy models, uses raw SQL
    # Tables should already exist from schema.sql initialization
    yield


# Provide a new database session for each test
@pytest.fixture()
def db_session(monkeypatch):
    """
    Provide database session with transaction rollback for test isolation.

    Monkeypatches Engine.connect() and Engine.begin() to return the test
    connection, ensuring worker functions see test data.
    """
    from contextlib import contextmanager

    connection = engine.connect()
    transaction = connection.begin()

    session = TestingSessionLocal(bind=connection)

    # Patch Engine methods to return test connection
    from contextlib import contextmanager

    class MockConnection:
        """Wrapper that prevents closing the test connection."""

        def __init__(self, real_conn):
            self._conn = real_conn

        def __getattr__(self, name):
            return getattr(self._conn, name)

        def __enter__(self):
            return self._conn

        def __exit__(self, *args):
            # Don't close the connection
            pass

        def close(self):
            # Don't actually close
            pass

    @contextmanager
    def mock_begin(self):
        """Return test connection without committing/closing on exit."""
        yield connection
        # Don't commit or close - let the test fixture handle that

    def mock_connect(self):
        """Return wrapped test connection that won't close."""
        return MockConnection(connection)

    monkeypatch.setattr(type(engine), "begin", mock_begin)
    monkeypatch.setattr(type(engine), "connect", mock_connect)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture()
def fake_redis():
    """Provide fake Redis client for testing without external dependency."""
    return FakeRedis()


@pytest.fixture()
def config_dict():
    """Provide test configuration dictionary."""
    return {
        "worker": {
            "defense_job": {
                "mem_limit": "512m",
                "nano_cpus": 1000000000,
                "pids_limit": 100,
                "container_timeout": 30,
                "max_uncompressed_size_mb": 1000,
            },
            "evaluation": {
                "requests_timeout_seconds": 5,
            },
        },
        "minio": {
            "endpoint": "minio:9000",
            "access_key": "minioadmin",
            "secret_key": "minioadmin",
            "bucket": "mlsec-submissions",
            "attack_files_bucket": "attack-files",
            "secure": False,
        },
        "source": {
            "max_zip_size_mb": 512,
            "max_build_time_seconds": 300,
            "build_mem_limit": "1g",
            "temp_build_dir": "/tmp/builds",
        },
    }


@pytest.fixture()
def mock_minio_client(monkeypatch):
    """Provide fake MinIO client for testing file operations."""

    class FakeMinioResponse:
        """Fake MinIO get_object response."""

        def __init__(self, data: bytes):
            self.data = data

        def read(self):
            return self.data

        def close(self):
            pass

        def release_conn(self):
            pass

    class FakeMinioClient:
        """Fake MinIO client."""

        def __init__(self):
            self.storage = {}  # bucket -> {object_key -> bytes}

        def get_object(self, bucket: str, object_key: str):
            """Get object from bucket."""
            if bucket not in self.storage:
                raise Exception(f"Bucket {bucket} not found")
            if object_key not in self.storage[bucket]:
                raise Exception(
                    f"Object {object_key} not found in bucket {bucket}")

            return FakeMinioResponse(self.storage[bucket][object_key])

        def put_object(self, bucket: str, object_key: str, data, length: int):
            """Put object in bucket."""
            if bucket not in self.storage:
                self.storage[bucket] = {}

            if hasattr(data, 'read'):
                self.storage[bucket][object_key] = data.read()
            else:
                self.storage[bucket][object_key] = data

        def bucket_exists(self, bucket: str) -> bool:
            """Check if bucket exists."""
            return bucket in self.storage

        def make_bucket(self, bucket: str):
            """Create bucket."""
            if bucket not in self.storage:
                self.storage[bucket] = {}

    client = FakeMinioClient()
    # Pre-create default buckets
    client.make_bucket("mlsec-submissions")
    client.make_bucket("attack-files")

    return client


@pytest.fixture()
def test_helpers(db_session):
    """Provide helper functions for creating test data."""

    class TestHelpers:
        """Test data creation helpers."""

        def __init__(self):
            # Create a test user once for all tests
            import uuid
            self.test_user_id = str(uuid.uuid4())
            db_session.execute(
                text("""
                    INSERT INTO users (id, username, email)
                    VALUES (CAST(:id AS uuid), :username, :email)
                    ON CONFLICT (id) DO NOTHING
                """),
                {
                    "id": self.test_user_id,
                    "username": "test_user",
                    "email": "test@example.com"
                }
            )
            db_session.commit()

        @staticmethod
        def create_submission(
            submission_type: str,
            status: str = "submitted",
            is_functional: bool = None,
            user_id: str = None
        ) -> str:
            """Create test submission and return ID."""
            import uuid

            # Get test user ID from instance
            # Since this is a static method, we need to get it from the fixture
            # Actually, let's just create a user if not provided
            if user_id is None:
                user_id = str(uuid.uuid4())
                # Create user if needed
                db_session.execute(
                    text("""
                        INSERT INTO users (id, username, email)
                        VALUES (CAST(:id AS uuid), :username, :email)
                        ON CONFLICT (id) DO NOTHING
                    """),
                    {
                        "id": user_id,
                        "username": f"user_{user_id[:8]}",
                        "email": f"user_{user_id[:8]}@example.com"
                    }
                )
                db_session.commit()

            result = db_session.execute(
                text("""
                    INSERT INTO submissions 
                    (submission_type, status, is_functional, version, user_id)
                    VALUES (:type, :status, :functional, 'v1.0.0', CAST(:user_id AS uuid))
                    RETURNING id
                """),
                {
                    "type": submission_type,
                    "status": status,
                    "functional": is_functional,
                    "user_id": user_id
                }
            ).scalar()
            db_session.commit()
            return str(result)

        @staticmethod
        def create_defense(
            source_type: str,
            docker_image: str = None,
            git_repo: str = None,
            object_key: str = None,
            is_functional: bool = None,
            status: str = "ready"
        ) -> str:
            """Create defense submission with details."""
            # Create submission
            submission_id = TestHelpers.create_submission(
                submission_type="defense",
                status=status,
                is_functional=is_functional
            )

            # Create defense details
            db_session.execute(
                text("""
                    INSERT INTO defense_submission_details
                    (submission_id, source_type, docker_image, git_repo, object_key)
                    VALUES (CAST(:id AS uuid), :source_type, :docker, :git, :obj_key)
                """),
                {
                    "id": submission_id,
                    "source_type": source_type,
                    "docker": docker_image,
                    "git": git_repo,
                    "obj_key": object_key
                }
            )
            db_session.commit()
            return submission_id

        @staticmethod
        def create_attack(file_count: int = 3) -> str:
            """Create attack submission with files."""
            # Create submission
            submission_id = TestHelpers.create_submission(
                submission_type="attack",
                status="ready"
            )

            # Create attack files
            for i in range(file_count):
                db_session.execute(
                    text("""
                        INSERT INTO attack_files
                        (attack_submission_id, object_key, filename, sha256, is_malware)
                        VALUES (CAST(:attack_id AS uuid), :obj_key, :filename, :sha256, :is_malware)
                    """),
                    {
                        "attack_id": submission_id,
                        "obj_key": f"attacks/{submission_id}/file{i}.exe",
                        "filename": f"file{i}.exe",
                        "sha256": f"{'0' * 63}{i}",
                        "is_malware": i % 2 == 0
                    }
                )
            db_session.commit()
            return submission_id

        @staticmethod
        def create_evaluation_run(
            defense_id: str,
            attack_id: str,
            status: str = "queued"
        ) -> str:
            """Create evaluation_run record."""
            result = db_session.execute(
                text("""
                    INSERT INTO evaluation_runs
                    (defense_submission_id, attack_submission_id, status, scope)
                    VALUES (CAST(:def_id AS uuid), CAST(:atk_id AS uuid), :status, 'zip')
                    RETURNING id
                """),
                {
                    "def_id": defense_id,
                    "atk_id": attack_id,
                    "status": status
                }
            ).scalar()
            db_session.commit()
            return str(result)

        @staticmethod
        def create_job(
            job_type: str,
            status: str = "queued",
            defense_submission_id: str = None,
            attack_submission_id: str = None
        ) -> str:
            """Create job record."""
            import json

            payload = {}
            if defense_submission_id:
                payload["defense_submission_id"] = defense_submission_id
            if attack_submission_id:
                payload["attack_submission_id"] = attack_submission_id

            result = db_session.execute(
                text("""
                    INSERT INTO jobs
                    (job_type, status, payload)
                    VALUES (:type, :status, :payload::jsonb)
                    RETURNING id
                """),
                {
                    "type": job_type,
                    "status": status,
                    "payload": json.dumps(payload)
                }
            ).scalar()
            db_session.commit()
            return str(result)

    return TestHelpers()
