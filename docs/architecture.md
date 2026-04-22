# Architecture

## 1. API

The API is a FastAPI application (Python 3.11) that handles all user-facing and admin operations. It runs behind Nginx and communicates with PostgreSQL, MinIO, Redis, and RabbitMQ.

### a. Authentication

- **Sessions**: Login produces a 48-byte cryptographically random token, SHA-256 hashed before storage in the `user_sessions` table. Tokens are sent as cookies or `Authorization: Bearer` headers. Sessions renew automatically when approaching expiration and can be revoked explicitly on logout.
- **Email MFA**: When `email.mfa_enabled` is set in `config.yaml`, login is a two-step process. After credentials are verified, a 6-digit code is stored in Redis with a configurable TTL and sent to the user's email. The session is only created after the code is validated.
- **Join code**: Registration can be gated behind a join code configured in `config.yaml`. When set, users must supply the correct code to create an account.
- **Admin action tokens**: Sensitive admin operations require a short-lived secondary token (default 15 minutes) in addition to a valid session.

### b. Database and Artifact Management

PostgreSQL stores all persistent state: users, sessions, submissions (defense and attack), jobs, evaluation runs, per-file results, pair scores, and audit logs. Key design points:

- Each user has at most one active submission per type, enforced by the `active_submissions` table.
- Submitted artifacts (defense ZIPs, attack ZIPs, attack templates) are stored in MinIO using paths of the form `defense/{user_id}/{submission_id}.zip`.
- The leaderboard is kept current via a Postgres `LISTEN/NOTIFY` trigger on `evaluation_pair_scores`. The API listens for these notifications and forwards updates to connected clients via Server-Sent Events (SSE) through Redis pub/sub.

### c. Worker Coordination

When a submission is queued for evaluation, the API inserts a row into the `jobs` table (status: `queued`) and dispatches a Celery task to RabbitMQ. Job types are `D` (defense) and `A` (attack). Workers consume these tasks asynchronously. The API can also read active worker state from Redis for admin monitoring.

---

## 2. Workers

Workers are Celery processes (Python 3.11) that consume jobs from RabbitMQ. They have access to the Docker socket so they can build and run competitor containers.

### a. Worker Flow

**Defense job:**
1. Register with Redis; set queue state to OPEN so attack jobs can route files here.
2. Build or pull the defense Docker image (ZIP and GitHub sources are built; Docker Hub sources are pulled).
3. Start the container with configured resource limits and create an isolated evaluation network via the gateway service.
4. Poll the container's GET endpoint until it responds (up to 30 seconds).
5. Run functional validation.
6. Run heuristic validation (if enabled in `config.yaml`).
7. Enter the evaluation broadcast loop: pop attack files from the Redis queue, POST each file concurrently to all active defense containers, and record results.
8. Close the queue after `max_empty_polls` consecutive empty polls; unregister from Redis; stop and remove the container, network, and image (subject to cleanup config).

**Attack job:**
1. Download the attack ZIP from MinIO.
2. Run functional validation.
3. Extract files and write records to the database.
4. Run heuristic (similarity) validation (if enabled).
5. For each validated defense: find an open worker and push the attack to its Redis queue. If no worker is open, create a new batch defense job for unserved defenses.
6. Mark the attack as evaluated.

### b. Concurrency

Two settings control parallelism:

- `WORKER_CONCURRENCY` in `.env` sets the number of Celery worker processes per container.
- `worker.num_workers` in `config.yaml` sets the number of worker containers Compose launches.

Within a single job, asyncio is used for concurrent image builds, container startups, and per-sample evaluation across multiple defenses in a batch. Redis coordinates shared state: the worker registry (`workers:active`), per-worker attack queues (`worker:{id}:attacks`), gateway port leases, and atomic duplicate-evaluation prevention via `SETNX`.

### c. Internal Attack Queues

Each active worker maintains a per-worker Redis list (`worker:{id}:attacks`) that acts as its internal attack queue. When an attack job is processed and a worker with an OPEN queue is found for a given defense, the attack ID is pushed directly onto that list. The worker's evaluation loop pops from this list with a blocking pop (1-second timeout), so it receives and evaluates new attacks continuously without requiring a new Celery job to be scheduled. Workers close their queue and exit the loop only after `max_empty_polls` consecutive timeouts with no new attacks.

This design means a single defense worker can evaluate many sequential attack submissions with no scheduling overhead between them, as long as it remains registered and OPEN in Redis.

### d. Batching

`run_batch_defense_job` accepts a list of defense submission IDs and processes them concurrently within a single worker. All defenses in the batch share one OPEN Redis queue and receive the same attack files at the same time. When an attack job finds no open workers for a defense, it creates a new batch job covering the unserved defenses.

### e. Defense

#### i. Functional Validation

Before a defense enters the competition it must pass functional checks:

- **Dockerfile safety**: file size must be within the configured limit (default 100 KB); unsafe instructions are rejected.
- **Image size**: the uncompressed image must be within the configured limit (default 1 GB).
- **Container readiness**: the container must respond to a GET request within 30 seconds of starting.
- **POST endpoint**: the endpoint must accept a binary payload and return JSON containing a `result` field with a value of `0` or `1`.

#### ii. Heuristic Validation

When enabled (`defense.validation.enabled` in `config.yaml`), the defense is tested against a pre-loaded sample set of malware and goodware files stored in the database. The worker sends each file to the container and records its response.

After all samples are processed, true positive rate (TPR) and false positive rate (FPR) are computed separately for malware and goodware. If any metric falls below its configured minimum threshold and `reject_failures` is `true`, the defense is rejected. Results are stored in `heurval_results` and `heurval_file_results`.

Container restarts during validation are tracked; exceeding `defense_max_restarts` fails the defense.

#### iii. Evaluation

During evaluation, attack files are popped from the worker's Redis queue with a blocking pop (1-second timeout). Each file is concurrently POSTed to all active defense containers in the batch using asyncio. Per-file results (model output, duration, evade reason) are written to `evaluation_file_results`. After all files for an attack are processed, pair scores are computed and a leaderboard update is published.

### f. Attack

#### i. Functional Validation

A submitted attack ZIP must pass the following checks before its files are extracted:

- The ZIP must be password-protected with the password `infected` (AES-256 or ZipCrypto).
- Total uncompressed size must be within the configured limit; compression ratio must not exceed 100x (ZIP bomb detection).
- After stripping the longest common path prefix, the file list must exactly match the admin-uploaded attack template's expected file set.

#### ii. Heuristic Validation (Similarity)

When enabled (`attack.check_similarity` in `config.yaml`), each extracted file is submitted to the configured sandbox backend. The resulting behavioral signals are compared against the corresponding file's template report using Jaccard similarity. The average similarity across all files must meet `attack.minimum_attack_similarity` (default 50%). If `attack.reject_dissimilar_attacks` is `true`, attacks that fall below the threshold are rejected.

---

## 3. Sandbox

The sandbox is responsible for analyzing attack files and producing behavioral reports used during heuristic validation.

### a. Behavioral Algorithm

Behavioral similarity between a submitted attack file and its corresponding template file is scored 0-100 using a weighted multi-section comparison. Behavioral signals are extracted and normalized into nine categories: threat (signatures, MITRE techniques, IDS alerts), network (IP traffic, HTTP conversations, TLS), registry (keys opened/set/deleted), file (files opened/written/deleted), process (commands executed, processes created), crypto algorithms, system API calls, modules loaded, and synchronization primitives (mutexes, services). Registry hives and Windows paths are normalized to canonical forms before comparison. Five sections (registry, file, process, modules, sync) use overlap coefficient; the remaining four use Jaccard similarity. Each section carries a fixed weight (threat 0.25, network 0.18, registry 0.14, file 0.12, process 0.10, crypto 0.08, system_api 0.06, modules 0.04, sync 0.03) and only sections with data in either report contribute to the final weighted average. If both reports share the same non-null `behash` from VirusTotal, a score of 100 is returned immediately without running the full comparison.

### b. VirusTotal

The VirusTotal backend submits files to the VirusTotal API v3 and retrieves behavioral sandbox reports. The file is uploaded via `POST /api/v3/files` and the resulting analysis ID is polled (`GET /api/v3/analyses/{id}`) at configurable intervals until the status transitions to `completed`. The SHA-256 is then used to fetch behavioral attributes from `GET /api/v3/files/{sha256}/behaviours`. The first report containing at least one populated signal field is selected and returned as a `SandboxReport`. Configure with `sandbox_backend: virustotal` in `config.yaml`; the API key is read from the `VIRUSTOTAL_API_KEY` environment variable in `.env`.

### c. CAPE

The CAPE backend submits files to a CAPEv2 instance and converts its JSON behavior report to the same attribute schema used by the behavioral similarity comparator. The file is submitted via `POST /apiv2/tasks/create/file/` with the configured `cape_sandbox_name` as the machine tag. The task is polled until status reaches `reported`, then the full report is fetched and mapped: file operations, registry keys, process commands, loaded modules (extracted from `LoadLibraryA/W` calls), system API calls, mutexes, and network traffic are each converted to the corresponding VirusTotal field names. Configure with `sandbox_backend: cape` and `cape_sandbox_name` in `config.yaml`; the instance URL and optional authentication token are read from `CAPE_URL` and `CAPE_TOKEN` in `.env`.

---

## 4. Admin

The admin panel is a restricted section of the frontend available only to users with the `is_admin` flag set in the database. All `/admin` API endpoints additionally enforce origin restrictions: by default they are only reachable from localhost. This can be extended via `ADMIN_ALLOWED_HOSTS`, `ADMIN_TRUSTED_PROXY_HOSTS`, and `ADMIN_ALLOWED_NETWORKS` in `.env` (see `.env-example` for format).

Sensitive write operations (closing submissions, disabling users, etc.) require a second factor: a short-lived action token issued by `POST /admin/actions/token` and consumed on use.

**Admin pages:**

- **Users** - List all registered accounts; disable or enable accounts; grant or revoke admin role; revoke active sessions.
- **Submissions** - Browse any user's submission history; view per-submission evaluation results; manually activate a submission on a user's behalf.
- **Competition** - Open or close the submission window immediately; schedule an automatic close time. Upload or remove the attack template ZIP (the reference file set that all attacks are validated against). Upload or remove the heuristic validation sample set (malware/goodware files used to pre-screen defenses).
- **Workers** - View currently registered Celery workers, their queue state (OPEN/CLOSED), and which defenses they are evaluating.
- **Logs** - Inspect recent job records, evaluation runs, and the audit log of admin actions.
- **Export** - Download evaluation scores (aggregate or per-defense) and behavioral analysis results as CSV.

**Creating the first admin account:**

Register a normal account through the UI, then promote it via the database:

```bash
docker exec -it postgres-db psql -U mlsec2 -d mlsec \
  -c "UPDATE users SET is_admin = TRUE WHERE email = 'your@email.com';"
```

Replace `mlsec2` with the value of `POSTGRES_USER` from your `.env` file if you changed it.
