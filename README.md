# Machine Learning Security Evasion Competition Platform 2.0

An open-source platform for hosting Machine Learning Security Evasion Competitions in-house. MLSEC 2.0 offers a suite for competitors to upload security artifacts and watch them be evaluated in real time.

## Quickstart

1. Copy `.env-example` to `.env` and replace all placeholder values with real passwords and secrets.
2. Review `config.yaml` and adjust settings to match your deployment (submission cooldowns, join code, email delivery, worker count, sandbox backend, etc.).
3. If using a local sandbox backend, see [docs/sandbox.md](docs/sandbox.md).
4. Run `make prod-up` to launch all services in production mode.

For local development, use `make up` instead.

## Starting a Competition

### 1. Create an admin account

Register a normal account through the UI, then promote it to admin via the database:

```bash
docker exec -it postgres-db psql -U mlsec2 -d mlsec \
  -c "UPDATE users SET is_admin = TRUE WHERE email = 'your@email.com';"
```

Replace `mlsec2` with the value of `POSTGRES_USER` from your `.env` if you changed it. See [Admin](docs/architecture.md#4-admin) in the architecture docs for a full description of admin capabilities.

### 2. Verify your configuration

Before opening the competition, confirm that `config.yaml` and `.env` reflect the intended settings: submission cooldowns, resource limits for defense containers, sandbox backend, and whether a join code or email MFA is required for registration.

### 3. Submit a defense validation set

The defense validation set is used to pre-screen competitor defenses before they enter the leaderboard. It is a standard (non-password-protected) ZIP file containing two folders:

```
validation.zip
├── malware/
│   ├── sample_a.exe
│   └── sample_b.exe
└── goodware/
    ├── clean_a.exe
    └── clean_b.exe
```

Each folder holds representative binary samples of the respective class. When heuristic validation runs, these files are sent to the defense container and its true positive and false positive rates are measured against the configurable thresholds in `config.yaml` under `defense.validation`.

Upload the validation set from the **Competition** tab of the admin panel.

### 4. Submit an attack template

The attack template is a non-password protected ZIP file containing the sample binaries that competitors are expected to make evasive. It defines the exact file set that every submitted attack must match structurally.

```
template.zip
├── sample_a.exe
├── sample_b.exe
├── sample_c.exe
└── sample_d.exe
```

Files in the template can optionally be seeded for behavioral analysis. When seeded, the platform submits each file to the configured sandbox (VirusTotal API key or CAPE) and records its behavioral signals. These signals are later used to score how similar a competitor's attack is to the original template. Seeding requires an active sandbox; see `config.yaml` under `attack` and `docs/sandbox.md` for configuration details.

Upload the attack template from the **Competition** tab of the admin panel. Seeding begins automatically after upload if a sandbox is configured.

### 5. Open the competition

Once the defense validation set and attack template are uploaded and seeding is complete, open the competition from the **Competition** tab. You can open it immediately or schedule an automatic close time.


## Production SSL Configuration

The platform uses Nginx to terminate TLS on port 443. To deploy with SSL on your own domain:

1. **Start without SSL**: Ensure the `ssl` listener and certificate lines in [services/nginx/nginx.prod.conf](services/nginx/nginx.prod.conf) are commented out (this is the default). Launch the platform:
   ```bash
   make prod-up
   ```
   > To test the UI before SSL is active, you can temporarily comment out the "Redirect" block and uncomment the "Temporary HTTP" block in `nginx.prod.conf`. This will allow access via `http://yourdomain.com` without trying to force HTTPS.

2. **Obtain Certificates**: Use Certbot to obtain certificates from Let's Encrypt (temporarily stop the platform or use a different machine to free port 80):
   ```bash
   docker run -it --rm -p 80:80 -v /etc/letsencrypt:/etc/letsencrypt \
     certbot/certbot certonly --standalone -d yourdomain.com
   ```
3. **Enable SSL**: Uncomment the `ssl` parameters and certificate paths in `services/nginx/nginx.prod.conf`, replacing `yourdomain.com` with your actual domain.
4. **Restart**: Re-launch the platform to apply changes:
   ```bash
   make prod-up
   ```

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

## Future Work
The following list contains possible improvements that could be made to MLSEC 2.0.
- **MLSEC 2.0 Logo:** A unique logo to represent the MLSEC 2.0 platform.
- **Defense Plagiarism Checking:** Devise a system for checking plagiarized defense submissions.
- **Behavior Algorithm Configuration:** Create configuration for tweaking the settings of the attack behavior similarity algorithm.
- **Gateway Logging:** Security audit information and logging for the Gateway network management Docker.
- **Fail2Ban**: Protections against DoS, spam.
- **Automatic Load Balancing**: Automatic load balancing for high submission loads.

## Credits and Acknowledgements

### Developers

MLSEC 2.0 is a Spring 2026 Computer Science Engineering Capstone project at Texas A&M University. This project was sponsored by Dr. Marcus Botacin, and created by:

- Aaron Thompson
- Graham Dungan
- Karl Farrar
- Maxim Mouget

### Third-Party Resources Used

- Claude Sonnet 4.6 for generating parts of documentation and tests