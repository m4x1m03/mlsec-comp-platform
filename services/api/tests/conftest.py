import pytest
from sqlalchemy import create_engine # type: ignore
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from main import app
from core.database import Base, get_db


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

    with TestClient(app) as c:
        yield c
