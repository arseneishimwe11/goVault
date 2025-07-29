.PHONY: proto build clean test docker lint deps

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
CLI_BINARY=vaultify
SERVER_BINARY=vaultify-server

# Build directory
BUILD_DIR=build

# Proto settings
PROTO_DIR=proto
PB_DIR=pkg/pb

all: deps proto build

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	@mkdir -p $(PB_DIR)
	protoc --proto_path=$(PROTO_DIR) \
		--go_out=$(PB_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PB_DIR) --go-grpc_opt=paths=source_relative \
		--grpc-gateway_out=$(PB_DIR) --grpc-gateway_opt=paths=source_relative \
		$(PROTO_DIR)/*.proto

# Build CLI and server
build: build-cli build-server

build-cli:
	@echo "Building CLI..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(CLI_BINARY) ./cmd/cli

build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(SERVER_BINARY) ./cmd/server

# Install CLI globally
install-cli:
	$(GOCMD) install ./cmd/cli

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(PB_DIR)

# Run tests
test:
	$(GOTEST) -v ./...

# Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Lint code
lint:
	golangci-lint run

# Format code
fmt:
	$(GOCMD) fmt ./...

# Run server locally
run-server:
	$(GOBUILD) -o $(BUILD_DIR)/$(SERVER_BINARY) ./cmd/server && \
	./$(BUILD_DIR)/$(SERVER_BINARY)

# Docker operations
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Development setup
dev-setup: deps proto
	@echo "Development environment ready!"

# Full rebuild
rebuild: clean deps proto build

# Help
help:
	@echo "Available commands:"
	@echo "  deps           - Install Go dependencies"
	@echo "  proto          - Generate protobuf files"
	@echo "  build          - Build CLI and server"
	@echo "  build-cli      - Build only CLI"
	@echo "  build-server   - Build only server"
	@echo "  install-cli    - Install CLI globally"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  lint           - Lint code"
	@echo "  fmt            - Format code"
	@echo "  run-server     - Build and run server"
	@echo "  docker-build   - Build Docker images"
	@echo "  docker-up      - Start Docker containers"
	@echo "  docker-down    - Stop Docker containers"
	@echo "  docker-logs    - View Docker logs"
	@echo "  dev-setup      - Set up development environment"
	@echo "  rebuild        - Clean and rebuild everything"
	@echo "  help           - Show this help"