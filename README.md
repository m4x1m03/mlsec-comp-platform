# mlsec-comp-platform
A platform for hosting an MLSEC-style adversarial malware competition.

# Services
This project uses a microservices-style architecture with Docker for hosting different components of the application.

## Frontend
The frontend can be launched either via Docker, npm, or VSCode.
### Docker
```
docker-compose up frontend
```
### npm
```
cd ./services/frontend/
npm install
npm run dev
```
### VSCode
Open the "Run and Debug" menu (Ctrl + Shift + D), select the "Development Server", run.

*Note: You may need to perform `cd ./services/frontend/` and `npm install` before running with VSCode*

## API
The API can be launched either via Docker or locally.

### Docker
```
docker-compose up api
```

### Local
```
cd ./services/api/
python -m venv .venv
```
Activate the venv, then install dependencies:
```
pip install -r requirements-dev.txt
```
Run the API:
```
uvicorn main:app --host 0.0.0.0 --port 8000
```

### Requirements
- `services/api/requirements.txt` contains runtime dependencies for the API service.
- `services/api/requirements-dev.txt` contains developer/test dependencies and includes `requirements.txt`.

## API Testing 
Place all test scripts into the tests folder
Make sure to keep test_----.py naming convention 
```
cd services/api/ 
pytest -v
```
or to allow printing 
```
pytest -s
```

## Postgres

### Starting Postgres db server 
```
docker-compose up postgres
```
### Accessing Postgres db 
```
docker exec -it postgres-db psql -U postgres -d mlsec
```
### Starting TEST Postgres db server 
```
docker-compose up postgres-test
```
### Accessing TEST Postgres db 
```
docker exec -it test-postgres-db psql -U postgres -d mlsec-test
```


## MinIO
WIP

## RabbitMQ
RabbitMQ is used as the Celery broker (queue) for jobs.

### Docker
Start RabbitMQ (and the API/worker if you want to run jobs):
```
docker compose -f docker-compose.yaml up -d rabbitmq api worker
```

### Management UI
- http://localhost:15672
- Username: `mlsec`
- Password: `mlsec`

### Ports
- `5672` (AMQP broker)
- `15672` (management UI)

## Celery
Celery workers consume jobs from RabbitMQ and execute task stubs.

### Docker
Start the worker:
```
docker compose -f docker-compose.yaml up -d --build worker
```

View worker logs:
```
docker logs -f mlsec-worker
```

### Enqueuing jobs
The API publishes Celery tasks when you call:
- `POST /queue/defense`
- `POST /queue/attack`

