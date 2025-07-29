#!/bin/bash

# Vaultify Development Setup Script
# This script sets up the development environment

set -e

echo "🔐 Setting up Vaultify development environment..."

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or later."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
REQUIRED_VERSION="1.21"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Go version $GO_VERSION is too old. Please install Go $REQUIRED_VERSION or later."
    exit 1
fi

echo "✅ Go $GO_VERSION found"

# Check Redis
if ! command -v redis-server &> /dev/null; then
    echo "⚠️  Redis is not installed. Please install Redis 6.0 or later."
    echo "   On macOS: brew install redis"
    echo "   On Ubuntu: sudo apt-get install redis-server"
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed. Please install Docker for containerized development."
fi

# Check Make
if ! command -v make &> /dev/null; then
    echo "❌ Make is not installed. Please install Make."
    exit 1
fi

echo "✅ Prerequisites check complete"

# Install Go dependencies
echo "📦 Installing Go dependencies..."
go mod download
go mod tidy

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "Quick start:"
echo "  1. Start Redis: redis-server"
echo "  2. Start Vaultify server: ./build/vaultify-server"
echo "  3. Send a secret: ./build/vaultify send 'my secret'"
echo "  4. Or use Docker: docker-compose up -d"
echo ""
