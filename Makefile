.PHONY: up down build ps logs worker-count

# Parse num_workers from config.yaml
NUM_WORKERS=$(shell awk '/worker:/ {found=1} found && /num_workers:/ {print $$2; exit}' config.yaml)

up:
	@echo "Starting platform with $(NUM_WORKERS) workers..."
	docker compose up --scale worker=$(NUM_WORKERS)

down:
	docker compose down

build:
	docker compose build

ps:
	docker compose ps

logs:
	docker compose logs -f

worker-count:
	@echo $(NUM_WORKERS)
