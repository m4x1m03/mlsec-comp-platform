import os

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, text # type: ignore
from sqlalchemy.orm import sessionmaker

from core.database import get_db
from main import app
from routers.submissions import DEV_USER_ID

TEST_DB_URL = os.getenv(
    "TEST_DB_URL",
    "postgresql://postgres:password123@localhost:5433/mlsec_test",
)

engine = create_engine(TEST_DB_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def _cleanup_user_rows(db_session) -> None:
    db_session.rollback()
    db_session.execute(
        text("DELETE FROM submissions WHERE user_id = :user_id"),
        {"user_id": str(DEV_USER_ID)},
    )
    db_session.execute(
        text("DELETE FROM users WHERE id = :user_id"),
        {"user_id": str(DEV_USER_ID)},
    )
    db_session.commit()


@pytest.fixture()
def submission_db_session():
    session = TestingSessionLocal()
    _cleanup_user_rows(session)
    try:
        yield session
    finally:
        try:
            _cleanup_user_rows(session)
        finally:
            session.close()


@pytest.fixture()
async def submission_client(submission_db_session):
    def override_get_db():
        yield submission_db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.mark.anyio # tells pytest to run this test in an async event loop
async def test_submission_creates_row_in_database(submission_client, submission_db_session):
    payload = {
        "submission_type": "defense",
        "version": "v1.0.0",
        "display_name": "simple-test",
    }

    response = await submission_client.post("/api/submissions", json=payload)
    assert response.status_code == 201

    submission_id = response.json()["id"]
    row = submission_db_session.execute(
        text("SELECT id FROM submissions WHERE id = :submission_id"),
        {"submission_id": submission_id},
    ).first()

    assert row is not None
