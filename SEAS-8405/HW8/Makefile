# Pre-build security checks
check:
	@echo "Running code analysis with Bandit..."
	docker run --rm -v $(PWD):/app python:3.13-alpine sh -c "pip install bandit && bandit -r /app"
	@echo "Running dependency check with pip-audit..."
	docker run --rm -v $(PWD):/app python:3.13-alpine sh -c "pip install pip-audit && pip-audit -r /app/app/requirements.txt"

# Host security check
host-security:
	@echo "Running Docker Bench for Security..."
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker/docker-bench-security

# Build Docker image after security checks
dbuild: check
	docker build -t mywebapp .

# Run the container
run:
	docker run -p 6000:5000 mywebapp

# Scan the built image for vulnerabilities
scan:
	docker scout recommendations mywebapp:latest

# Docker Compose commands
build:
	docker compose build

start:
	docker compose up -d

stop:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker system prune -f

restart: stop start

# Required additions
.PHONY: up down reset logs

DOCKER_COMPOSE := $(shell command -v docker-compose > /dev/null && echo docker-compose || echo docker compose)

up:
	@echo "[*] Starting Lab 1 (Keycloak + Flask App)..."
	@bash setup.sh

down:
	@echo "[*] Stopping and removing all lab containers and volumes..."
	@$(DOCKER_COMPOSE) down -v

reset: down
	@echo "[*] Resetting lab environment..."
	@rm -rf keycloak_config
	@docker system prune -f
	@bash setup.sh

logs:
	@$(DOCKER_COMPOSE) logs -f
