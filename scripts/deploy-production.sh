#!/bin/bash

# Vaultify Production Deployment Script
# This script helps deploy Vaultify securely in production

set -e

echo "🔐 Vaultify Production Deployment"
echo "=================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "❌ Don't run this script as root for security reasons"
    exit 1
fi

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is required but not installed"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is required but not installed"
    exit 1
fi

if ! command -v openssl &> /dev/null; then
    echo "❌ OpenSSL is required but not installed"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Create production environment file
echo "🔑 Generating secure configuration..."

if [ -f .env.production ]; then
    echo "⚠️  Production environment file already exists"
    read -p "Do you want to regenerate it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Using existing .env.production"
    else
        rm .env.production
    fi
fi

if [ ! -f .env.production ]; then
    cat > .env.production << EOL
# Vaultify Production Configuration
# Generated on $(date)

# Server Configuration
VAULTIFY_SERVER_GRPC_PORT=8080
VAULTIFY_SERVER_HTTP_PORT=8081
VAULTIFY_SERVER_HOST=0.0.0.0
VAULTIFY_SERVER_BASE_URL=https://your-domain.com

# Security Configuration
VAULTIFY_AUDIT_SECRET_KEY=$(openssl rand -base64 32)

# Redis Configuration
VAULTIFY_REDIS_ADDRESS=redis:6379
VAULTIFY_REDIS_PASSWORD=$(openssl rand -base64 24)
VAULTIFY_REDIS_DB=0

# Audit Configuration
VAULTIFY_AUDIT_LOG_FILE=/app/logs/audit.log

# Crypto Configuration
VAULTIFY_CRYPTO_DEFAULT_TTL=24h
VAULTIFY_CRYPTO_MAX_TTL=168h
VAULTIFY_CRYPTO_DEFAULT_MAX_READS=1
VAULTIFY_CRYPTO_MAX_MAX_READS=1000
EOL
    echo "✅ Generated secure .env.production file"
fi

# Create directories
echo "📁 Creating necessary directories..."
mkdir -p logs data docker/ssl

# Set secure permissions
chmod 700 logs data
chmod 600 .env.production

echo "✅ Directories created with secure permissions"

# SSL Certificate setup
echo "🔒 SSL Certificate setup..."
if [ ! -f docker/ssl/vaultify.crt ] || [ ! -f docker/ssl/vaultify.key ]; then
    echo "⚠️  SSL certificates not found"
    echo "Please ensure you have valid SSL certificates in:"
    echo "  - docker/ssl/vaultify.crt"
    echo "  - docker/ssl/vaultify.key"
    echo ""
    read -p "Do you want to generate self-signed certificates for testing? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        openssl req -x509 -newkey rsa:4096 -keyout docker/ssl/vaultify.key -out docker/ssl/vaultify.crt -days 365 -nodes \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
        echo "✅ Self-signed certificates generated (NOT for production use)"
    fi
fi

# Build and deploy
echo "🏗️  Building and deploying..."

# Build images
docker-compose --env-file .env.production build

# Deploy with production profile
docker-compose --env-file .env.production --profile production up -d

echo "⏳ Waiting for services to start..."
sleep 10

# Health check
echo "🏥 Running health checks..."
if curl -f -s http://localhost/health > /dev/null; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed - check logs with: docker-compose logs"
    exit 1
fi

echo ""
echo "🎉 Vaultify deployed successfully!"
echo ""
echo "Next steps:"
echo "1. Update VAULTIFY_SERVER_BASE_URL in .env.production with your actual domain"
echo "2. Replace self-signed certificates with valid ones"
echo "3. Configure your domain's DNS to point to this server"
echo "4. Set up monitoring and log aggregation"
echo "5. Configure backup for audit logs"
echo ""
echo "Useful commands:"
echo "  docker-compose logs -f           # View logs"
echo "  docker-compose ps               # Check status"
echo "  docker-compose down             # Stop services"
echo "  docker-compose up -d --scale   # Scale services"
echo ""
echo "Security reminders:"
echo "  - Keep .env.production secure and backed up"
echo "  - Monitor audit logs regularly"
echo "  - Keep Docker images updated"
echo "  - Set up proper firewall rules"
echo ""
