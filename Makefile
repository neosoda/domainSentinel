.PHONY: build run test clean docker-build docker-up docker-down logs

# Build the Go binary
build:
	go build -ldflags="-s -w" -o bin/domainsentinel .

# Run locally (requires go 1.23)
run:
	go run .

# Run tests
test:
	go test -v ./...

test-unit:
	go test -v ./tests/unit/...

# Build Docker image
docker-build:
	docker build -t domainsentinel:latest -t domainsentinel:$(git rev-parse --short HEAD 2>/dev/null || echo "dev") .

# Start in background
docker-up:
	docker compose up -d

# Stop
docker-down:
	docker compose down

# View logs
logs:
	docker compose logs -f

# Shell into container
shell:
	docker compose exec domainsentinel /bin/sh

# Build DB browser (sqlite3 CLI)
db-shell:
	docker compose exec domainsentinel sqlite3 /data/domainsentinel.db

# Lint (requires golangci-lint)
lint:
	golangci-lint run ./...

# Run all tests with coverage
test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

.DEFAULT_GOAL := build
