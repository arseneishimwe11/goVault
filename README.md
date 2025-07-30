# 🔐 GoVault Tool

**Secure, Encrypted Secret-Sharing CLI + API**

Vaultify is a high-quality, security-focused tool that allows users and teams to share secrets safely and ephemerally, with end-to-end encryption, audit logging, and tamper-proof guarantees.

## ✨ Features

- **🔒 End-to-End Encryption**: AES-256-GCM encryption performed client-side
- **🕐 Ephemeral Secrets**: Configurable TTL and read limits
- **🚫 Zero-Knowledge Server**: Server never sees plaintext secrets
- **📜 Tamper-Proof Audit Logs**: Hash-chained audit trail with integrity verification
- **🛡️ High Performance**: gRPC API with Redis storage
- **🐳 Docker Ready**: Complete containerized deployment
- **💻 CLI First**: Powerful command-line interface
- **🌐 Web Interface**: Optional web UI for browser-based sharing
- **🔍 Audit Trail**: Complete logging of all operations

## 🚀 Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/arseneishimwe11/goVault
cd goVault

# Start the services
docker-compose up -d

# Wait for services to be healthy
docker-compose ps

# Send a secret
docker-compose run --rm vaultify-cli send "my secret password" --ttl=1h

# Retrieve a secret
docker-compose run --rm vaultify-cli get <token>
```

### Manual Installation

```bash
# Install dependencies
make deps

# Build binaries
make build

# Start Redis (required)
redis-server

# Start Vaultify server
./build/vaultify-server

# Use CLI
./build/vaultify send "my secret" --ttl=24h
./build/vaultify get <token>
```

## 🛠️ Build Instructions

### Prerequisites

- Go 1.21+
- Redis 6.0+
- Protocol Buffers compiler
- Make

### Development Setup

```bash
# Install development dependencies
make dev-setup

# Generate protobuf files
make proto

# Build everything
make build

# Run tests
make test

# Run with coverage
make test-coverage

# Lint code
make lint
```

## 📖 Usage

### CLI Examples

```bash
# Send a secret with custom TTL
vaultify send "database password" --ttl=2h --max-reads=3

# Send from file
vaultify send --file=secret.txt --ttl=30m

# Send from stdin
echo "secret data" | vaultify send --ttl=1h

# Get a secret
vaultify get abc123def456

# Get secret metadata without retrieving
vaultify metadata abc123def456

# Check server health
vaultify health

# Show version
vaultify version
```

### Configuration

Vaultify can be configured via environment variables or config files:

```bash
# Server configuration
export VAULTIFY_SERVER_GRPC_PORT=8080
export VAULTIFY_SERVER_HTTP_PORT=8081
export VAULTIFY_REDIS_ADDRESS=localhost:6379
export VAULTIFY_AUDIT_LOG_FILE=./audit.log
export VAULTIFY_AUDIT_SECRET_KEY=your-secret-key

# Client configuration
export VAULTIFY_SERVER=localhost:8080
```

## 🔐 Security Model

### Zero-Knowledge Architecture

Vaultify implements a **zero-knowledge** security model:

1. **Client-Side Encryption**: All secrets are encrypted on the client before transmission
2. **Server Never Sees Plaintext**: The server only stores encrypted data
3. **Password-Based Key Derivation**: Encryption keys are derived from user passwords
4. **Perfect Forward Secrecy**: Each secret uses unique encryption parameters

### Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: SHA-256-based key stretching
- **Nonce**: 96-bit random nonce per encryption
- **Salt**: 128-bit random salt per password
- **Authentication**: Built-in authenticated encryption

### Audit Logging

- **Hash Chaining**: Each log entry contains hash of previous entry
- **Tamper Detection**: Cryptographic verification of log integrity
- **Comprehensive Logging**: All operations (store, retrieve, delete) are logged
- **Immutable Records**: Append-only audit trail

### Security Guarantees

- ✅ **Confidentiality**: Secrets encrypted with AES-256-GCM
- ✅ **Integrity**: Authenticated encryption prevents tampering
- ✅ **Availability**: Redis TTL ensures automatic cleanup
- ✅ **Non-repudiation**: Tamper-proof audit logs
- ✅ **Forward Secrecy**: Unique keys per secret
- ✅ **Zero Knowledge**: Server cannot decrypt secrets

## 🏗️ Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│     CLI     │    │  Web Client  │    │   gRPC      │
│   Client    │    │              │    │   Client    │
└──────┬──────┘    └──────┬───────┘    └──────┬──────┘
       │                  │                   │
       └──────────────────┼───────────────────┘
                          │
                ┌─────────▼──────────┐
                │   Vaultify Server  │
                │   (gRPC + HTTP)    │
                └─────────┬──────────┘
                          │
          ┌───────────────┼───────────────┐
          │               │               │
    ┌─────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │   Redis    │ │    Audit    │ │  Crypto     │
    │  Storage   │ │   Logger    │ │  Service    │
    └────────────┘ └─────────────┘ └─────────────┘
```

### Components

- **CLI Client**: Command-line interface for users
- **gRPC Server**: High-performance API server
- **HTTP Gateway**: REST API and web interface
- **Redis Storage**: Encrypted secret storage with TTL
- **Audit Logger**: Tamper-proof logging system
- **Crypto Service**: Encryption/decryption operations

## 🐳 Docker Deployment

### Development

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Production

```bash
# Use production profile with Nginx
docker-compose --profile production up -d

# Or use environment-specific compose file
docker-compose -f docker-compose.prod.yml up -d
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULTIFY_SERVER_GRPC_PORT` | `8080` | gRPC server port |
| `VAULTIFY_SERVER_HTTP_PORT` | `8081` | HTTP server port |
| `VAULTIFY_REDIS_ADDRESS` | `localhost:6379` | Redis connection |
| `VAULTIFY_AUDIT_LOG_FILE` | `./audit.log` | Audit log file path |
| `VAULTIFY_AUDIT_SECRET_KEY` | *(required)* | Audit signing key |

## 🔧 API Reference

### gRPC API

The gRPC API is defined in `proto/vaultify.proto`:

- `StoreSecret`: Store an encrypted secret
- `RetrieveSecret`: Retrieve and delete a secret
- `GetSecretMetadata`: Get metadata without retrieving
- `GetAuditLogs`: Retrieve audit logs

### REST API

HTTP endpoints are available via gRPC-Gateway:

```
POST   /v1/secrets              # Store secret
GET    /v1/secrets/{token}      # Retrieve secret
GET    /v1/secrets/{token}/metadata  # Get metadata
GET    /v1/audit/logs           # Get audit logs
GET    /health                  # Health check
```

## 🔒 Security Best Practices

### For Users

1. **Use Strong Passwords**: Choose complex, unique passwords for encryption
2. **Secure Transmission**: Use HTTPS/TLS for all communications
3. **Minimal TTL**: Set the shortest reasonable TTL for secrets
4. **Limit Reads**: Use `--max-reads=1` for one-time secrets
5. **Verify Metadata**: Check secret metadata before retrieval

### For Operators

1. **Environment Variables**: Store sensitive config in environment variables
2. **TLS Encryption**: Always use TLS in production
3. **Network Isolation**: Deploy in isolated network environments
4. **Regular Backups**: Backup audit logs (not secrets)
5. **Monitor Logs**: Actively monitor audit logs for anomalies
6. **Rotate Keys**: Regularly rotate audit signing keys

### Production Checklist

- [ ] Set strong `VAULTIFY_AUDIT_SECRET_KEY`
- [ ] Configure TLS certificates
- [ ] Set up Redis authentication
- [ ] Enable firewall rules
- [ ] Configure log rotation
- [ ] Set up monitoring and alerts
- [ ] Test disaster recovery procedures

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development

```bash
# Fork the repository
git clone https://github.com/yourusername/vaultify.git
cd vaultify

# Create a feature branch
git checkout -b feature/amazing-feature

# Make changes and test
make test
make lint

# Commit and push
git commit -m "Add amazing feature"
git push origin feature/amazing-feature

# Create a Pull Request
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: https://vaultify.io/docs
- **Issues**: https://github.com/vaultify/vaultify/issues
- **Discussions**: https://github.com/vaultify/vaultify/discussions
- **Security**: security@vaultify.io

## 🙏 Acknowledgments

- Inspired by Mozilla Send and 1Password secret sharing
- Built with security principles from Signal and age
- Thanks to the Go cryptography community

---

**⚠️ Security Notice**: While Vaultify implements strong security measures, always follow security best practices and consider your specific threat model when sharing sensitive information.