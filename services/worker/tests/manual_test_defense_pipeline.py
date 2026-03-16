import os
import sys
import uuid
import time
import json
import io
from sqlalchemy import create_engine, text
from celery import Celery
from minio import Minio

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:password123@localhost:5432/mlsec")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "amqp://mlsec:mlsec@localhost:5672//")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
DOCKER_IMAGE = "https://hub.docker.com/r/thompaar003/notconv"
# https://hub.docker.com/r/thompaar003/notconv
# https://hub.docker.com/r/gamdm/tsdes-defender
# https://hub.docker.com/r/thompaar003/evil-defense

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "mlsec_minio_admin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "mlsec_minio_password_change_in_production")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "mlsec-submissions")

def setup_test_data():
    engine = create_engine(DATABASE_URL)
    
    # MinIO setup
    minio_client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=False
    )
    
    if not minio_client.bucket_exists(MINIO_BUCKET):
        minio_client.make_bucket(MINIO_BUCKET)
        print(f"Created MinIO bucket: {MINIO_BUCKET}")
    else:
        # Clear existing objects in the bucket
        objects = minio_client.list_objects(MINIO_BUCKET, recursive=True)
        for obj in objects:
            minio_client.remove_object(MINIO_BUCKET, obj.object_name)
        print(f"Cleared existing objects in MinIO bucket: {MINIO_BUCKET}")

    with engine.begin() as conn:
        # Clear old test data to avoid worker picking up orphaned records
        print("Clearing old test data from database...")
        conn.execute(text("TRUNCATE evaluation_file_results, evaluation_runs, attack_files, attack_submission_details, defense_submission_details, active_submissions, submissions, jobs CASCADE"))
        
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
            text("INSERT INTO submissions (id, user_id, submission_type, version, status, is_functional) VALUES (:id, :u, 'defense', '1.0.0', 'ready', TRUE)"),
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
        
        # Add attack details
        conn.execute(
            text("INSERT INTO attack_submission_details (submission_id, zip_object_key, file_count) VALUES (:id, 'test_attack.zip', 5)"),
            {"id": atk_sub_1_id}
        )
        
        # Add a couple of files to attack 1
        with open("services/worker/tests/minimal.exe", "rb") as f:
            npp_bytes = f.read()

        file_ids = []
        for i in range(5):
            file_id = str(uuid.uuid4())
            object_key = f"attacks/{atk_sub_1_id}/sample_{i}.exe"
            
            # Upload to MinIO
            minio_client.put_object(
                MINIO_BUCKET, 
                object_key, 
                io.BytesIO(npp_bytes), 
                len(npp_bytes)
            )
            
            conn.execute(
                text("INSERT INTO attack_files (id, attack_submission_id, object_key, filename, byte_size, sha256) VALUES (:id, :atk, :ok, :fn, :size, :hash)"),
                {"id": file_id, "atk": atk_sub_1_id, "ok": object_key, "fn": f"sample_{i}.exe", "size": len(npp_bytes), "hash": f"hash_{i}"}
            )
            file_ids.append(file_id)
        
        print(f"Created Test Defense Submission: {def_sub_id}")
        print(f"Created Test Attack Submission: {atk_sub_1_id} with 5 files seeded in MinIO.")
        return def_sub_id, atk_sub_1_id, file_ids

def trigger_job(sub_id):
    app = Celery("mlsec-worker", broker=CELERY_BROKER_URL)
    job_id = str(uuid.uuid4())
    
    # Need job entry in DB for worker to update status
    engine = create_engine(DATABASE_URL)
    payload = {"defense_submission_id": sub_id}
    
    with engine.begin() as conn:
         conn.execute(
            text("INSERT INTO jobs (id, job_type, status, payload) VALUES (:id, 'defense', 'queued', CAST(:payload AS jsonb))"),
            {"id": job_id, "payload": json.dumps(payload)}
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
        job_id = trigger_job(def_sub_id)
        print(f"\nSUCCESS: Task is now in the queue.")
        print(f"Monitor the worker logs for Job ID: {job_id}")
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

