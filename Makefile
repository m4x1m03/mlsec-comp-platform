.PHONY: up down build ps logs worker-count prod-up prod-down prod-build prod-ps prod-logs
 
# Compose files
DOCKER_COMPOSE_DEV = docker-compose.yaml
DOCKER_COMPOSE_PROD = docker-compose.prod.yaml

# Parse num_workers from config.yaml
NUM_WORKERS=$(shell awk '/worker:/ {found=1} found && /num_workers:/ {print $$2; exit}' config.yaml)

# Development targets
up:
	@echo "Starting development platform with $(NUM_WORKERS) workers..."
	docker compose -f $(DOCKER_COMPOSE_DEV) up --scale worker=$(NUM_WORKERS)

down:
	docker compose -f $(DOCKER_COMPOSE_DEV) down

build:
	docker compose -f $(DOCKER_COMPOSE_DEV) build

ps:
	docker compose -f $(DOCKER_COMPOSE_DEV) ps

logs:
	docker compose -f $(DOCKER_COMPOSE_DEV) logs -f

# Production targets
prod-up:
	@echo "Starting production platform with $(NUM_WORKERS) workers..."
	docker compose -f $(DOCKER_COMPOSE_PROD) up -d --scale worker=$(NUM_WORKERS)

prod-down:
	docker compose -f $(DOCKER_COMPOSE_PROD) down

prod-build:
	docker compose -f $(DOCKER_COMPOSE_PROD) build

prod-ps:
	docker compose -f $(DOCKER_COMPOSE_PROD) ps

prod-logs:
	docker compose -f $(DOCKER_COMPOSE_PROD) logs -f

worker-count:
	@echo $(NUM_WORKERS)
