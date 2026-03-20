"""Basic database connectivity tests.

Verifies inserts and simple queries against the test database.
"""

from sqlalchemy import text

def test_insert_and_query_user(db_session):
    """Verify inserts and queries against the test database."""
    print(db_session.get_bind().engine.url)


    db_session.execute(text("""
        INSERT INTO users (username, email, is_admin)
        VALUES ('test_user', 'test@email.com', false)
    """))

    result = db_session.execute(text("""
        SELECT * FROM users
        WHERE username = 'test_user'
    """))

    user = result.fetchone()

    print(user)

    assert user[1] == "test_user"

def test_select_users(db_session):
    """Verify we can execute a simple SELECT query."""

    result = db_session.execute(text("SELECT * FROM users"))

    rows = result.fetchall()

    assert rows is not None
