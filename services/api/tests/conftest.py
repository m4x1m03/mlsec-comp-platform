import pytest
from sqlalchemy import create_engine # type: ignore
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, get_db


TEST_DB_URL = "postgresql://postgres:password123@localhost:5433/mlsec_test"

engine = create_engine(TEST_DB_URL)
TestingSessionLocal = sessionmaker(bind=engine)


# Create tables once per test session
@pytest.fixture(scope="session", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# Provide a new database session for each test
@pytest.fixture()
def db_session():

    connection = engine.connect()
    transaction = connection.begin()

    session = TestingSessionLocal(bind=connection)

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

    with TestClient(app) as c:
        yield c
