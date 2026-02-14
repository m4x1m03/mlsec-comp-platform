from sqlalchemy import text

# This test verifies that we can insert a user into the database and query it back.
def test_insert_and_query_user(db_session):
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

# This test verifies that we can connect to the test database and execute a simple query.
def test_select_users(db_session):

    result = db_session.execute(text("SELECT * FROM users"))

    rows = result.fetchall()

    assert rows is not None
