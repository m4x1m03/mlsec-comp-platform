from sqlalchemy import text


def test_insert_and_query_user(db_session):
    db_session.execute(text("""
        INSERT INTO users (username, email, is_admin)
        VALUES ('test_user', 'test@email.com', false)
    """))

    result = db_session.execute(text("""
        SELECT * FROM users
        WHERE username = 'test_user'
    """))

    user = result.fetchone()
    assert user[1] == "test_user"


def test_select_users(db_session):
    result = db_session.execute(text("SELECT * FROM users"))
    rows = result.fetchall()
    assert rows is not None


def test_template_tables_exist(db_session):
    """Verify all new schema tables are present."""
    new_tables = [
        "attack_template",
        "heurval_sample_sets",
        "heurval_samples",
        "heurval_results",
        "heurval_file_results",
    ]
    for table in new_tables:
        result = db_session.execute(
            text(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = :name"
            ),
            {"name": table},
        ).scalar()
        assert result == 1, f"Expected table '{table}' to exist in schema"


def test_template_file_reports_has_template_id(db_session):
    """Verify template_file_reports has the template_id and object_key columns."""
    for col in ("template_id", "object_key"):
        result = db_session.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'template_file_reports' AND column_name = :col"
            ),
            {"col": col},
        ).scalar()
        assert result == 1, f"Expected column '{col}' on template_file_reports"


def test_evaluation_file_results_has_evaded_reason(db_session):
    """Verify evaluation_file_results has the evaded_reason column."""
    result = db_session.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = 'evaluation_file_results' AND column_name = 'evaded_reason'"
        )
    ).scalar()
    assert result == 1, "Expected column 'evaded_reason' on evaluation_file_results"
