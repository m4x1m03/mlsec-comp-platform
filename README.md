# MLSEC Competition Platform

An open-source platform for hosting Machine Learning Security Evasion Competitions in-house. MLSEC 2.0 offers a suite for competitors to upload security artifacts and watch them be evaluated in real time.

## Quickstart

1. Copy `.env-example` to `.env` and replace all placeholder values with real passwords and secrets.
2. Review `config.yaml` and adjust settings to match your deployment (submission cooldowns, join code, email delivery, worker count, sandbox backend, etc.).
3. If using a local sandbox backend, see [docs/sandbox.md](docs/sandbox.md) (WIP).
4. Run `make prod-up` to launch all services in production mode.
5. Register an account through the UI, then promote it to admin via the database:

```bash
docker exec -it postgres-db psql -U mlsec2 -d mlsec \
  -c "UPDATE users SET is_admin = TRUE WHERE email = 'your@email.com';"
```

Replace `mlsec2` with the value of `POSTGRES_USER` from your `.env` if you changed it. See [Admin](docs/architecture.md#4-admin) in the architecture docs for what admin accounts can do.

For local development, use `make up` instead.

## System Overview

The platform is a set of Docker containers orchestrated by Docker Compose. Configuration comes from two sources:

- `.env` - secrets and host-specific deployment values (credentials, keys, network settings)
- `config.yaml` - application behavior (cooldowns, resource limits, sandbox backend, email, etc.)

Nginx terminates TLS on ports 80/443 and routes requests to the API or frontend. The API dispatches evaluation jobs to Celery workers via RabbitMQ. Workers run competitor defense containers in an isolated Docker network and evaluate them against submitted attack files.

| Component | Technology | Purpose |
|---|---|---|
| Frontend | Astro 5 + React 19 + Tailwind CSS | Competitor-facing UI (submissions, leaderboard, rules) and admin dashboard |
| API | FastAPI (Python 3.11) + SQLAlchemy | Auth, submission management, job dispatch, leaderboard streaming |
| Database | PostgreSQL 18 | Users, sessions, submissions, jobs, evaluations, audit logs |
| Task Queue | Celery 5 + RabbitMQ 3 | Async defense and attack job processing |
| Worker | Celery worker (Python 3.11) | Builds defense images, runs evaluation, records results |
| Object Storage | MinIO (S3-compatible) | Defense and attack ZIP artifacts |
| Cache and Coordination | Redis 7 | Worker registry, attack distribution, leaderboard pub/sub, MFA codes |
| Reverse Proxy | Nginx | TLS termination and request routing |
| Network Isolation | Docker `defense_net` + gateway service | Isolates competitor container traffic during evaluation |

For a detailed description of how each component works, see [docs/architecture.md](docs/architecture.md).

## Attribution

Created as a Spring 2026 Computer Science Engineering Capstone project at Texas A&M University by:

- Aaron Thompson
- Graham Dungan
- Karl Farrar
- Maxim Mouget
