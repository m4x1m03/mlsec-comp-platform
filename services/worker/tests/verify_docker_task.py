import os
import sys
import uuid
import time
import subprocess
from sqlalchemy import create_engine, text
from celery import Celery

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password123@localhost:5432/mlsec")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "amqp://mlsec:mlsec@localhost:5672//")
DOCKER_IMAGE = "https://hub.docker.com/r/thompaar003/notconv"
# https://hub.docker.com/r/thompaar003/notconv
# https://hub.docker.com/r/gamdm/tsdes-defender
# https://hub.docker.com/r/thompaar003/evil-defense

def setup_test_data():
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
        # Create test user if not exists
        user_id = str(uuid.uuid4())
        num = int(time.time())
        username = f"test_bot_{num}"
        conn.execute(
            text("INSERT INTO users (id, username, email) VALUES (:id, :u, :e) ON CONFLICT DO NOTHING"),
            {"id": user_id, "u": username, "e": f"{username}@test.com"}
        )
        
        user_id = conn.execute(text("SELECT id FROM users WHERE username=:u"), {"u": username}).scalar()
        
        # Create defense submission
        def_sub_id = str(uuid.uuid4())
        conn.execute(
            text("INSERT INTO submissions (id, user_id, submission_type, version, status) VALUES (:id, :u, 'defense', '1.0.0', 'submitted')"),
            {"id": def_sub_id, "u": user_id}
        )
        
        # Add defense details
        conn.execute(
            text("INSERT INTO defense_submission_details (submission_id, source_type, docker_image) VALUES (:id, 'docker', :img)"),
            {"id": def_sub_id, "img": DOCKER_IMAGE}
        )
        
        # Create attack submission 1
        atk_sub_1_id = str(uuid.uuid4())
        conn.execute(
            text("INSERT INTO submissions (id, user_id, submission_type, version, status) VALUES (:id, :u, 'attack', '1.0.0', 'ready')"),
            {"id": atk_sub_1_id, "u": user_id}
        )
        # Mark attack 1 as active
        conn.execute(
            text("INSERT INTO active_submissions (user_id, submission_type, submission_id) VALUES (:u, 'attack', :id) ON CONFLICT (user_id, submission_type) DO UPDATE SET submission_id = EXCLUDED.submission_id"),
            {"u": user_id, "id": atk_sub_1_id}
        )
        
        # Add a couple of files to attack 1
        with open("services/worker/tests/minimal.exe", "rb") as f:
            npp_bytes = f.read()

        file_ids = []
        for i in range(5):
            file_id = str(uuid.uuid4())
            conn.execute(
                text("INSERT INTO attack_files (id, attack_submission_id, object_key, filename, byte_size, sha256) VALUES (:id, :atk, :ok, :fn, :size, :hash)"),
                {"id": file_id, "atk": atk_sub_1_id, "ok": f"minimal_{i}", "fn": f"sample_{i}.exe", "size": len(npp_bytes), "hash": f"hash_{i}"}
            )
            file_ids.append(file_id)
        
        print(f"Created Test Defense Submission: {def_sub_id}")
        print(f"Created Test Attack Submission: {atk_sub_1_id} with 10 files seeded.")
        return def_sub_id, atk_sub_1_id, file_ids

def trigger_job(sub_id):
    app = Celery("mlsec-worker", broker=CELERY_BROKER_URL)
    job_id = str(uuid.uuid4())
    
    # Need job entry in DB for worker to update status
    engine = create_engine(DATABASE_URL)
    with engine.begin() as conn:
         conn.execute(
            text("INSERT INTO jobs (id, job_type, status) VALUES (:id, 'D', 'queued')"),
            {"id": job_id}
        )
    
    print(f"Enqueuing Job: {job_id}")
    app.send_task(
        "worker.tasks.run_defense_job",
        kwargs={
            "job_id": job_id,
            "defense_submission_id": sub_id
        },
        queue="mlsec"
    )
    print("Task sent to Celery!")
    return job_id

if __name__ == "__main__":
    print("--- Docker Task Verification Script ---")
    
    try:
        def_sub_id, atk_sub_id, file_ids = setup_test_data()
        
        file_ids_str = ",".join(file_ids)
        print("Starting mock WebSocket server on port 8765...")
        ws_process = subprocess.Popen([sys.executable, "services/worker/tests/temp_ws_server.py", atk_sub_id, file_ids_str])
        time.sleep(2) # Sleepy
        
        job_id = trigger_job(def_sub_id)
        print(f"\nSUCCESS: Task is now in the queue.")
        ws_process.wait()
    except KeyboardInterrupt:
        print("\nStopping mock WebSocket server...")
        ws_process.terminate()
    except Exception as e:
        print(f"ERROR: {e}")
        ws_process.terminate()
