.PHONY: build run test test-integration lint clean docker-up docker-down migrate-up migrate-down

# Variables
BINARY_NAME=orbit
BUILD_DIR=./cmd/orbit
MIGRATIONS_DIR=./internal/adapter/persistence/postgres/migrations
DATABASE_URL?=postgres://orbit:orbit@localhost:5432/orbit?sslmode=disable

# Build
build:
	@echo "Building $(BINARY_NAME)..."
	go build -ldflags="-w -s" -o bin/$(BINARY_NAME) $(BUILD_DIR)

# Run
run:
	@echo "Running $(BINARY_NAME)..."
	go run $(BUILD_DIR)

# Test
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-short:
	@echo "Running short tests..."
	go test -v -short ./...

# Integration tests against a real Postgres (set ORBIT_TEST_DATABASE_URL)
test-integration:
	@echo "Running integration tests..."
	go test -tags integration ./internal/adapter/persistence/...

# Lint
lint:
	@echo "Linting..."
	golangci-lint run ./...

# Format
fmt:
	@echo "Formatting..."
	gofmt -s -w .
	goimports -w .

# Clean
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out

# Docker
docker-up:
	@echo "Starting Docker services..."
	docker compose -f deploy/docker/docker-compose.yml up --build -d

docker-down:
	@echo "Stopping Docker services..."
	docker compose -f deploy/docker/docker-compose.yml down

docker-logs:
	docker compose -f deploy/docker/docker-compose.yml logs -f

# Migrations (requires golang-migrate CLI)
migrate-up:
	@echo "Running migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" up

migrate-down:
	@echo "Rolling back migrations..."
	migrate -path $(MIGRATIONS_DIR) -database "$(DATABASE_URL)" down 1

migrate-create:
	@echo "Creating migration..."
	@read -p "Migration name: " name; \
	migrate create -ext sql -dir $(MIGRATIONS_DIR) -seq $$name

# Dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# All
all: deps lint test build
