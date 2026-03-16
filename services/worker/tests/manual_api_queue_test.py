import os
import uuid
from uuid import uuid4
import requests
import pytest
from sqlalchemy import create_engine, text

# Configuration - Use test database
API_URL = "http://localhost:8000"
DATABASE_URL = "postgresql://postgres:password123@localhost:5432/mlsec"
SESSION_COOKIE_NAME = os.getenv("AUTH_SESSION_COOKIE_NAME", "mlsec_session")

@pytest.fixture(scope="function")
def api_auth_setup():
    """Register a user and create a defense submission in the database."""
    # Register a new user (no password needed - email-based auth)
    suffix = uuid4().hex[:8]
    username = f"test_user_{suffix}"
    email = f"test_{suffix}@example.com"
    
    register_payload = {
        "username": username,
        "email": email
    }
    
    response = requests.post(f"{API_URL}/auth/register", json=register_payload)
    assert response.status_code == 201, f"Registration failed: {response.status_code} {response.text}"
    
    auth_data = response.json()
    user_id = auth_data["user"]["id"]
    token = response.cookies.get(SESSION_COOKIE_NAME)
    assert token, f"Missing {SESSION_COOKIE_NAME} cookie in register response"
    
    # Create a defense submission in the database
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        # Create submission
        sub_id = str(uuid4())
        conn.execute(
            text("""
                INSERT INTO submissions (id, user_id, submission_type, version, status)
                VALUES (:id, :user_id, 'defense', '1.0.0', 'submitted')
            """),
            {"id": sub_id, "user_id": user_id}
        )
        
        # Create defense submission details
        conn.execute(
            text("""
                INSERT INTO defense_submission_details (submission_id, source_type, docker_image)
                VALUES (:id, 'docker', 'user/defense:latest')
            """),
            {"id": sub_id}
        )
    
    return token, sub_id

def test_queue_endpoint(api_auth_setup):
    """Integration test for queue endpoint - requires running API service with auth."""
    token, sub_id = api_auth_setup
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "defense_submission_id": sub_id,
        "scope": "test",
        "include_behavior_different": False
    }
    
    print(f"Sending POST to {API_URL}/queue/defense...")
    response = requests.post(f"{API_URL}/queue/defense", json=payload, headers=headers)
    
    # Assert the response is successful
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    # Parse and validate response JSON
    response_data = response.json()
    print(f"SUCCESS! API accepted the job. Response: {response_data}")
    
    # Validate response contains expected fields
    assert "job_id" in response_data or "message" in response_data, "Response missing expected fields"

if __name__ == "__main__":
    try:
        from sqlalchemy import create_engine, text
        
        # Register user through API (email-based auth, no password)
        suffix = uuid4().hex[:8]
        username = f"test_user_{suffix}"
        email = f"test_{suffix}@example.com"
        
        register_payload = {
            "username": username,
            "email": email
        }
        
        print(f"Registering user {username}...")
        response = requests.post(f"{API_URL}/auth/register", json=register_payload)
        if response.status_code != 201:
            print(f"Registration failed: {response.status_code} {response.text}")
            exit(1)
        
        auth_data = response.json()
        user_id = auth_data["user"]["id"]
        token = response.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            print(f"Missing {SESSION_COOKIE_NAME} cookie in register response")
            exit(1)
        print(f"User registered successfully. Token: {token[:20]}...")
        
        # Create a defense submission in database
        engine = create_engine(DATABASE_URL)
        with engine.begin() as conn:
            sub_id = str(uuid4())
            conn.execute(
                text("""
                    INSERT INTO submissions (id, user_id, submission_type, version, status)
                    VALUES (:id, :user_id, 'defense', '1.0.0', 'submitted')
                """),
                {"id": sub_id, "user_id": user_id}
            )
            
            conn.execute(
                text("""
                    INSERT INTO defense_submission_details (submission_id, source_type, docker_image)
                    VALUES (:id, 'docker', 'user/defense:latest')
                """),
                {"id": sub_id}
            )
        print(f"Created defense submission: {sub_id}")
        
        # Test queue endpoint
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
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
