# Contributing to MLSEC 2.0

Thank you for your interest in contributing. This document covers how to set up a development environment, the conventions used in this project, and how to submit changes.

## Table of Contents

- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Coding Conventions](#coding-conventions)
- [Branching and Commits](#branching-and-commits)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Issues](#reporting-issues)
- [Security Concerns](#security-concerns)

---

## Project Structure

```
mlsec-comp-platform/
├── services/
│   ├── api/            # FastAPI application (auth, submissions, job dispatch, leaderboard)
│   │   ├── core/       # Business logic (auth, storage, queue, leaderboard)
│   │   ├── routers/    # API route handlers
│   │   ├── schemas/    # Pydantic request/response models
│   │   └── tests/      # Pytest test suite
│   ├── worker/         # Celery worker (defense evaluation, attack validation)
│   ├── frontend/       # Astro + React + Tailwind frontend
│   ├── gateway/        # Docker network isolation service
│   ├── nginx/          # Reverse proxy config (dev and prod)
│   ├── postgres/       # Database init scripts
│   └── sandbox/        # Sandbox backend integrations (VirusTotal, CAPE)
├── docs/               # Architecture and sandbox documentation
├── config.yaml         # Application behavior settings
├── docker-compose.yaml      # Development compose file
├── docker-compose.prod.yaml # Production compose file
└── Makefile            # Shorthand targets for common operations
```

See [docs/architecture.md](docs/architecture.md) for a detailed description of each component.

---

## Development Setup

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for running tests outside Docker)
- Node.js 20+ (for frontend work outside Docker)

### 1. Clone and configure

```bash
git clone <repo-url>
cd mlsec-comp-platform
cp .env-example .env
```

Edit `.env` and replace all placeholder values. Review `config.yaml` for application-level settings.

### 2. Start the platform

```bash
make up
```

This launches all services in development mode, with hot-reload enabled for the API and frontend. The number of Celery workers is read from `config.yaml` (`worker.num_workers`).

Other useful Make targets:

| Command | Description |
|---|---|
| `make up` | Start all services (dev mode) |
| `make down` | Stop all services |
| `make build` | Rebuild all images |
| `make logs` | Follow all container logs |
| `make ps` | Show running containers |
| `make prod-up` | Start in production mode |

### 3. Create an admin account

Register through the UI, then promote the account:

```bash
docker exec -it postgres-db psql -U mlsec2 -d mlsec \
  -c "UPDATE users SET is_admin = TRUE WHERE email = 'your@email.com';"
```

---

## Running Tests

The test suite covers the API service and uses pytest with a real PostgreSQL database (no mocks).

### Setup

```bash
cd services/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
```

### Run

```bash
pytest
```

Tests are organized by feature area and live in `services/api/tests/`. When adding a feature or fixing a bug, include tests that cover the changed behavior.

---

## Coding Conventions

### General

- Do not leave comments that reference implementation phases or internal planning.
- Write comments only when the reason behind something is not obvious from the code itself. Do not describe what the code does.

### Python (API and Worker)

- Follow PEP 8. Use `black` for formatting and `ruff` for linting where possible.
- Use type annotations for all function signatures.
- Do not add validation or error handling for conditions that cannot occur in practice.

### TypeScript / Astro (Frontend)

- Components live in `services/frontend/src/`. Prefer small, focused components.
- Use Tailwind utility classes for styling; avoid custom CSS unless Tailwind cannot achieve the result.

### Security-sensitive areas

Given that the platform executes competitor-submitted Docker containers and handles potentially malicious PE files, pay close attention to:

- Input validation at all API boundaries (file sizes, compression ratios, ZIP structure).
- Docker socket usage in the worker: do not expand worker permissions beyond what is already in place.
- Admin endpoint origin restrictions: changes to `ADMIN_ALLOWED_HOSTS` behavior require careful review.
- No secrets or credentials in source code; all secrets belong in `.env`.

---

## Branching and Commits

- Branch from `main` for all changes.
- Use descriptive branch names that reflect the change: `fix-attack-validation`, `add-cape-backend`, `refactor-leaderboard-sse`.
- Keep commits focused. A commit should represent one logical change.
- Write commit messages in the imperative mood and keep the subject line under 72 characters. Add a body if the motivation is not obvious.

```
Add ZIP bomb detection to attack validation

Total uncompressed size and compression ratio are now checked before
extraction. Submissions exceeding either limit are rejected with a
clear error message.
```

---

## Submitting a Pull Request

1. Open an issue first for any non-trivial change so the approach can be discussed before implementation.
2. Fork the repository and create a branch from `main`.
3. Make your changes, add or update tests, and ensure `pytest` passes.
4. Open a pull request against `main`. Fill in the PR description with:
   - What changed and why.
   - How to test the change.
   - Any configuration or migration steps required.
5. A maintainer will review the PR. Address feedback and push additional commits to the same branch.

---

## Reporting Issues

Open a GitHub Issue and include:

- A clear description of the problem or feature request.
- Steps to reproduce (for bugs).
- Relevant log output from `make logs`.
- Your `config.yaml` settings (omit any secrets from `.env`).

---

## Security Concerns

If you discover a security vulnerability, do not open a public issue. Contact the maintainers directly with a description of the issue and steps to reproduce it. We will respond as quickly as possible.

>>> Parts of this documentation was written with Claude Sonnet 4.6
