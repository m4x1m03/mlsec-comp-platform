import os
import uuid
import requests
from sqlalchemy import create_engine, text

# Configuration
API_URL = "http://localhost:8000"
DATABASE_URL = "postgresql://postgres:password123@localhost:5432/mlsec"

def setup_api_auth():
    """Seeds a user and returns a valid session token."""
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        # Create user
        user_id = str(uuid.uuid4())
        suffix = uuid.uuid4().hex[:6]
        conn.execute(
            text("INSERT INTO users (id, username, email) VALUES (:id, :u, :e)"),
            {"id": user_id, "u": f"api_tester_{suffix}", "e": f"api_{suffix}@test.com"}
        )
        
        # Create submission
        sub_id = str(uuid.uuid4())
        conn.execute(
            text("INSERT INTO submissions (id, user_id, submission_type, version, status) VALUES (:id, :u, 'defense', '1.0.0', 'submitted')"),
            {"id": sub_id, "u": user_id}
        )
        conn.execute(
            text("INSERT INTO defense_submission_details (submission_id, source_type, docker_image) VALUES (:id, 'docker', 'https://hub.docker.com/r/thompaar003/notconv')"),
            {"id": sub_id}
        )

        # Create session token
        token = f"test-token-{uuid4().hex}"
        token_hash = hashlib_sha256(token)
        conn.execute(
            text("""
                INSERT INTO user_sessions (user_id, token_hash, expires_at, last_seen_at)
                VALUES (:u, :h, now() + interval '1 hour', now())
            """),
            {"u": user_id, "h": token_hash}
        )
        
        return token, sub_id

def hashlib_sha256(data: str) -> str:
    import hashlib
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def test_queue_endpoint(token, sub_id):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "defense_submission_id": sub_id,
        "scope": "test",
        "include_behavior_different": False
    }
    
    print(f"Sending POST to {API_URL}/queue/defense...")
    response = requests.post(f"{API_URL}/queue/defense", json=payload, headers=headers)
    
    if response.status_code == 200:
        print("SUCCESS! API accepted the job.")
        print(f"Response: {response.json()}")
    else:
        print(f"FAILED (Status {response.status_code})")
        print(f"Error: {response.text}")

if __name__ == "__main__":
    import uuid
    from uuid import uuid4
    try:
        token, sub_id = setup_api_auth()
        test_queue_endpoint(token, sub_id)
    except Exception as e:
        print(f"Error: {e}")
