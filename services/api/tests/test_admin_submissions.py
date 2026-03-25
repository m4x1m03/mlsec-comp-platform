"""Tests for admin submission drill-down endpoints."""

from __future__ import annotations

import hashlib
import pytest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import text

from core.database import get_db
from main import app


def _create_user(db_session, *, is_admin: bool = False) -> tuple[str, str]:
    """Insert a user and return (user_id, email)."""
    suffix = uuid4().hex[:8]
    email = f"sub_test_{suffix}@example.com"
    row = db_session.execute(
        text("""
            INSERT INTO users (username, email, is_admin)
            VALUES (:username, :email, :is_admin)
            RETURNING id
        """),
        {"username": f"sub_test_{suffix}", "email": email, "is_admin": is_admin},
    ).fetchone()
    assert row is not None
    return str(row[0]), email


def _create_session_token(db_session, *, user_id: str) -> str:
    token = f"sub-test-token-{uuid4()}"
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    db_session.execute(
        text("""
            INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
            VALUES (:user_id, :token_hash, :expires_at, :last_seen_at)
        """),
        {
            "user_id": user_id,
            "token_hash": token_hash,
            "expires_at": now + timedelta(hours=2),
            "last_seen_at": now,
        },
    )
    return token


def _create_submission(db_session, *, user_id: str, submission_type: str) -> str:
    row = db_session.execute(
        text("""
            INSERT INTO submissions (user_id, submission_type, version, status)
            VALUES (:user_id, :submission_type, '1.0.0', 'validated')
            RETURNING id
        """),
        {"user_id": user_id, "submission_type": submission_type},
    ).fetchone()
    assert row is not None
    return str(row[0])


def _set_active_submission(db_session, *, user_id: str, submission_type: str, submission_id: str) -> None:
    db_session.execute(
        text("""
            INSERT INTO active_submissions (user_id, submission_type, submission_id, updated_at)
            VALUES (:user_id, :submission_type, :submission_id, NOW())
            ON CONFLICT (user_id, submission_type) DO UPDATE
                SET submission_id = EXCLUDED.submission_id, updated_at = EXCLUDED.updated_at
        """),
        {"user_id": user_id, "submission_type": submission_type, "submission_id": submission_id},
    )


def _create_evaluation_run(
    db_session,
    *,
    defense_id: str,
    attack_id: str,
    status: str = "done",
) -> str:
    row = db_session.execute(
        text("""
            INSERT INTO evaluation_runs (defense_submission_id, attack_submission_id, status)
            VALUES (:def_id, :atk_id, :status)
            RETURNING id
        """),
        {"def_id": defense_id, "atk_id": attack_id, "status": status},
    ).fetchone()
    assert row is not None
    return str(row[0])


def _create_pair_score(
    db_session,
    *,
    defense_id: str,
    attack_id: str,
    run_id: str,
    score: float,
) -> None:
    db_session.execute(
        text("""
            INSERT INTO evaluation_pair_scores
                (defense_submission_id, attack_submission_id, latest_evaluation_run_id, zip_score_avg, computed_at)
            VALUES (:def_id, :atk_id, :run_id, :score, NOW())
            ON CONFLICT (defense_submission_id, attack_submission_id) DO UPDATE
                SET latest_evaluation_run_id = EXCLUDED.latest_evaluation_run_id,
                    zip_score_avg = EXCLUDED.zip_score_avg,
                    computed_at = EXCLUDED.computed_at
        """),
        {"def_id": defense_id, "atk_id": attack_id, "run_id": run_id, "score": score},
    )


# ---------------------------------------------------------------------------
# GET /admin/submissions/users/{user_id}
# ---------------------------------------------------------------------------

def test_user_submissions_requires_admin(client, db_session):
    user_id, _ = _create_user(db_session, is_admin=False)
    token = _create_session_token(db_session, user_id=user_id)

    resp = client.get(
        f"/admin/submissions/users/{user_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 403


def test_user_submissions_requires_localhost(db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app, client=("198.51.100.42", 50000)) as remote_client:
            resp = remote_client.get(
                f"/admin/submissions/users/{admin_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert resp.status_code == 403


def test_user_submissions_unknown_user_returns_404(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    resp = client.get(
        f"/admin/submissions/users/{uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 404


def test_user_submissions_returns_defense_and_attack(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    target_id, _ = _create_user(db_session)

    def_id = _create_submission(db_session, user_id=target_id, submission_type="defense")
    atk_id = _create_submission(db_session, user_id=target_id, submission_type="attack")

    resp = client.get(
        f"/admin/submissions/users/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    data = resp.json()
    ids = {s["id"] for s in data["submissions"]}
    assert def_id in ids
    assert atk_id in ids


def test_user_submissions_is_active_flag(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    target_id, _ = _create_user(db_session)

    active_id   = _create_submission(db_session, user_id=target_id, submission_type="defense")
    inactive_id = _create_submission(db_session, user_id=target_id, submission_type="attack")
    _set_active_submission(db_session, user_id=target_id, submission_type="defense", submission_id=active_id)

    resp = client.get(
        f"/admin/submissions/users/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    by_id = {s["id"]: s for s in resp.json()["submissions"]}
    assert by_id[active_id]["is_active"] is True
    assert by_id[inactive_id]["is_active"] is False


# ---------------------------------------------------------------------------
# GET /admin/submissions/{submission_id}/evaluations
# ---------------------------------------------------------------------------

def test_submission_evaluations_requires_admin(client, db_session):
    user_id, _ = _create_user(db_session, is_admin=False)
    token = _create_session_token(db_session, user_id=user_id)
    sub_id = _create_submission(db_session, user_id=user_id, submission_type="defense")

    resp = client.get(
        f"/admin/submissions/{sub_id}/evaluations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 403


def test_submission_evaluations_unknown_submission_returns_404(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    resp = client.get(
        f"/admin/submissions/{uuid4()}/evaluations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 404


def test_submission_evaluations_defense_returns_attack_pairs(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    def_user_id, _ = _create_user(db_session)
    atk_user_id, _ = _create_user(db_session)

    def_id = _create_submission(db_session, user_id=def_user_id, submission_type="defense")
    atk_id = _create_submission(db_session, user_id=atk_user_id, submission_type="attack")
    _set_active_submission(db_session, user_id=atk_user_id, submission_type="attack", submission_id=atk_id)

    resp = client.get(
        f"/admin/submissions/{def_id}/evaluations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["submission_type"] == "defense"
    pair_ids = {p["other_submission_id"] for p in data["pairs"]}
    assert atk_id in pair_ids
    assert def_id not in pair_ids


def test_submission_evaluations_attack_returns_defense_pairs(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    def_user_id, _ = _create_user(db_session)
    atk_user_id, _ = _create_user(db_session)

    def_id = _create_submission(db_session, user_id=def_user_id, submission_type="defense")
    atk_id = _create_submission(db_session, user_id=atk_user_id, submission_type="attack")
    _set_active_submission(db_session, user_id=def_user_id, submission_type="defense", submission_id=def_id)

    resp = client.get(
        f"/admin/submissions/{atk_id}/evaluations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["submission_type"] == "attack"
    pair_ids = {p["other_submission_id"] for p in data["pairs"]}
    assert def_id in pair_ids


def test_submission_evaluations_includes_score_when_run_exists(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)

    def_user_id, _ = _create_user(db_session)
    atk_user_id, _ = _create_user(db_session)

    def_id = _create_submission(db_session, user_id=def_user_id, submission_type="defense")
    atk_id = _create_submission(db_session, user_id=atk_user_id, submission_type="attack")
    _set_active_submission(db_session, user_id=atk_user_id, submission_type="attack", submission_id=atk_id)

    run_id = _create_evaluation_run(db_session, defense_id=def_id, attack_id=atk_id, status="done")
    _create_pair_score(db_session, defense_id=def_id, attack_id=atk_id, run_id=run_id, score=0.75)

    resp = client.get(
        f"/admin/submissions/{def_id}/evaluations",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 200
    pairs = resp.json()["pairs"]
    pair = next(p for p in pairs if p["other_submission_id"] == atk_id)
    assert pair["score"] == pytest.approx(0.75, rel=1e-3)
    assert pair["evaluation_run_id"] == run_id
    assert pair["evaluation_status"] == "done"


# ---------------------------------------------------------------------------
# POST /admin/submissions/{submission_id}/activate
# ---------------------------------------------------------------------------

ORIGIN = "http://localhost:14321"


def _issue_action_token(client, *, access_token: str) -> str:
    resp = client.post(
        "/admin/actions/token",
        headers={"Authorization": f"Bearer {access_token}", "Origin": ORIGIN},
    )
    assert resp.status_code == 200
    return resp.json()["token"]


def test_activate_submission_requires_admin(client, db_session):
    user_id, _ = _create_user(db_session, is_admin=False)
    token = _create_session_token(db_session, user_id=user_id)
    sub_id = _create_submission(db_session, user_id=user_id, submission_type="defense")

    resp = client.post(
        f"/admin/submissions/{sub_id}/activate",
        headers={"Authorization": f"Bearer {token}", "Origin": ORIGIN, "X-Admin-Action": "fake"},
    )

    assert resp.status_code == 403


def test_activate_submission_requires_action_token(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    sub_id = _create_submission(db_session, user_id=admin_id, submission_type="defense")

    resp = client.post(
        f"/admin/submissions/{sub_id}/activate",
        headers={"Authorization": f"Bearer {token}", "Origin": ORIGIN},
    )

    assert resp.status_code == 403


def test_activate_submission_unknown_returns_404(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    action_token = _issue_action_token(client, access_token=token)

    resp = client.post(
        f"/admin/submissions/{uuid4()}/activate",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": ORIGIN,
            "X-Admin-Action": action_token,
        },
    )

    assert resp.status_code == 404


def test_activate_submission_sets_active_when_none_exists(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    target_id, _ = _create_user(db_session)
    sub_id = _create_submission(db_session, user_id=target_id, submission_type="defense")

    action_token = _issue_action_token(client, access_token=token)
    resp = client.post(
        f"/admin/submissions/{sub_id}/activate",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": ORIGIN,
            "X-Admin-Action": action_token,
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["submission_id"] == sub_id
    assert data["submission_type"] == "defense"
    assert data["previous_active_id"] is None

    subs_resp = client.get(
        f"/admin/submissions/users/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_id = {s["id"]: s for s in subs_resp.json()["submissions"]}
    assert by_id[sub_id]["is_active"] is True


def test_activate_submission_replaces_existing_active(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    target_id, _ = _create_user(db_session)

    old_id = _create_submission(db_session, user_id=target_id, submission_type="defense")
    new_id = _create_submission(db_session, user_id=target_id, submission_type="defense")
    _set_active_submission(db_session, user_id=target_id, submission_type="defense", submission_id=old_id)

    action_token = _issue_action_token(client, access_token=token)
    resp = client.post(
        f"/admin/submissions/{new_id}/activate",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": ORIGIN,
            "X-Admin-Action": action_token,
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["submission_id"] == new_id
    assert data["previous_active_id"] == old_id

    subs_resp = client.get(
        f"/admin/submissions/users/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_id = {s["id"]: s for s in subs_resp.json()["submissions"]}
    assert by_id[new_id]["is_active"] is True
    assert by_id[old_id]["is_active"] is False


def test_activate_submission_does_not_affect_other_type(client, db_session):
    admin_id, _ = _create_user(db_session, is_admin=True)
    token = _create_session_token(db_session, user_id=admin_id)
    target_id, _ = _create_user(db_session)

    def_id = _create_submission(db_session, user_id=target_id, submission_type="defense")
    atk_id = _create_submission(db_session, user_id=target_id, submission_type="attack")
    _set_active_submission(db_session, user_id=target_id, submission_type="attack", submission_id=atk_id)

    action_token = _issue_action_token(client, access_token=token)
    resp = client.post(
        f"/admin/submissions/{def_id}/activate",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": ORIGIN,
            "X-Admin-Action": action_token,
        },
    )

    assert resp.status_code == 200

    subs_resp = client.get(
        f"/admin/submissions/users/{target_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    by_id = {s["id"]: s for s in subs_resp.json()["submissions"]}
    assert by_id[def_id]["is_active"] is True
    assert by_id[atk_id]["is_active"] is True
