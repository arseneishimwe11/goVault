# 🔐 Security Guide

This document outlines the security model, best practices, and guidelines for deploying and using Vaultify securely.

## Security Architecture

### Zero-Knowledge Model

Vaultify implements a **zero-knowledge** architecture where:

1. **Client-Side Encryption**: All encryption happens in the client before data transmission
2. **Server Blindness**: The server never sees plaintext secrets
3. **Forward Secrecy**: Each secret uses unique encryption parameters
4. **Ephemeral Storage**: Secrets are automatically deleted after expiration or max reads

### Cryptographic Details

#### Encryption Algorithm
- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **Nonce Size**: 96 bits (12 bytes)
- **Salt Size**: 128 bits (16 bytes) for password-based encryption

#### Key Derivation
- **Method**: SHA-256-based key stretching (simplified PBKDF2)
- **Iterations**: Single round (can be enhanced with proper PBKDF2)
- **Salt**: Random 128-bit salt per password

#### Authenticated Encryption
- **Mode**: GCM provides both confidentiality and authenticity
- **Tag Size**: 128 bits (16 bytes)
- **Additional Data**: None (can be enhanced with metadata authentication)

### Audit Logging

#### Hash Chaining
- Each log entry contains the hash of the previous entry
- Creates an immutable chain that detects tampering
- Uses SHA-256 for hash computation

#### Log Integrity
- Every operation is logged with timestamp and client info
- Failed operations are also logged for security monitoring
- Log verification can detect any unauthorized modifications

## Deployment Security

### Production Checklist

#### Essential Security Measures

- [ ] **Set Strong Audit Key**: `VAULTIFY_AUDIT_SECRET_KEY` must be cryptographically random
- [ ] **Enable TLS**: Use valid TLS certificates for all communications
- [ ] **Redis Security**: Enable Redis authentication and disable dangerous commands
- [ ] **Network Isolation**: Deploy in isolated network with proper firewall rules
- [ ] **Log Monitoring**: Implement real-time monitoring of audit logs
- [ ] **Regular Updates**: Keep all dependencies and base images updated

#### Environment Variables

```bash
# Required - Set to a cryptographically random string
export VAULTIFY_AUDIT_SECRET_KEY="$(openssl rand -base64 32)"

# Redis Security
export VAULTIFY_REDIS_PASSWORD="$(openssl rand -base64 24)"

# TLS Configuration
export VAULTIFY_SERVER_TLS_CERT_FILE="/path/to/cert.pem"
export VAULTIFY_SERVER_TLS_KEY_FILE="/path/to/key.pem"

# Security Headers
export VAULTIFY_SERVER_SECURE_HEADERS=true
```

#### Docker Production Setup

```bash
# Generate secure environment file
cat > .env.production << EOF
VAULTIFY_AUDIT_SECRET_KEY=$(openssl rand -base64 32)
VAULTIFY_REDIS_PASSWORD=$(openssl rand -base64 24)
VAULTIFY_SERVER_BASE_URL=https://your-domain.com
EOF

# Deploy with production profile
docker-compose --profile production up -d
```

### Network Security

#### Firewall Rules
```bash
# Allow only necessary ports
ufw allow 80/tcp    # HTTP (redirect to HTTPS)
ufw allow 443/tcp   # HTTPS
ufw deny 6379/tcp   # Redis (internal only)
ufw deny 8080/tcp   # gRPC (behind proxy)
ufw deny 8081/tcp   # HTTP API (behind proxy)
```

#### TLS Configuration
- Use TLS 1.2 or higher
- Strong cipher suites only
- HSTS headers enabled
- Certificate pinning for mobile apps

### Application Security

#### Rate Limiting
- API endpoints: 10 requests/second per IP
- Web interface: 5 requests/second per IP
- Burst allowance: 20 requests

#### Input Validation
- Secret size limit: 1MB
- TTL limits: 1 minute to 7 days
- Max reads limit: 0 to 1000
- Token format validation

#### Error Handling
- Generic error messages to prevent information disclosure
- Detailed errors only in audit logs
- No stack traces in production responses

## Operational Security

### Monitoring and Alerting

#### Key Metrics to Monitor
- Failed authentication attempts
- Unusual access patterns
- Audit log integrity failures
- High error rates
- Resource exhaustion

#### Alert Conditions
```bash
# Failed retrievals spike (potential brute force)
failed_retrievals_per_minute > 50

# Audit log verification failures
audit_integrity_check == false

# High memory usage (potential DoS)
memory_usage > 80%

# TLS certificate expiration
tls_cert_expires_in_days < 30
```

### Backup and Recovery

#### What to Backup
- **Audit logs**: Critical for compliance and forensics
- **Configuration**: Environment variables and config files
- **TLS certificates**: For service continuity

#### What NOT to Backup
- **Redis data**: Secrets are ephemeral by design
- **Application logs**: May contain sensitive debugging info

#### Backup Strategy
```bash
# Daily audit log backup
tar -czf audit-$(date +%Y%m%d).tar.gz audit.log

# Encrypt backup
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
    --output audit-$(date +%Y%m%d).tar.gz.gpg \
    audit-$(date +%Y%m%d).tar.gz

# Secure deletion of unencrypted backup
shred -vfz -n 3 audit-$(date +%Y%m%d).tar.gz
```

### Incident Response

#### Security Incident Types
1. **Unauthorized Access**: Failed authentication patterns
2. **Data Breach**: Potential exposure of encrypted data
3. **Audit Tampering**: Log integrity verification failures
4. **Service Compromise**: Unusual system behavior

#### Response Procedures
1. **Immediate**: Isolate affected systems
2. **Assessment**: Determine scope and impact
3. **Containment**: Stop ongoing attacks
4. **Recovery**: Restore secure operations
5. **Lessons Learned**: Update security measures

## User Security Guidelines

### For End Users

#### Strong Passwords
- Use unique, complex passwords for each secret
- Consider using a password manager
- Minimum 12 characters with mixed case, numbers, symbols

#### Safe Sharing Practices
- Share tokens and passwords through separate channels
- Use shortest reasonable TTL
- Prefer single-read secrets (`--max-reads=1`)
- Verify recipient before sharing

#### Operational Security
- Use HTTPS-only connections
- Verify TLS certificate
- Clear browser cache after use
- Don't share secrets over unencrypted channels

### For Developers

#### API Integration
```go
// Example secure usage
client := vaultify.NewClient(vaultify.Config{
    ServerURL: "https://vaultify.company.com",
    TLSConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
})

secret, err := client.StoreSecret(ctx, &vaultify.StoreRequest{
    Secret:   sensitiveData,
    Password: userProvidedPassword, // Never hardcode
    TTL:      time.Hour,           // Minimal TTL
    MaxReads: 1,                   // Single use
})
```

#### Security Best Practices
- Always use TLS for API calls
- Implement proper error handling
- Log security events to SIEM
- Validate all inputs
- Use secure random number generation

## Compliance Considerations

### Data Protection
- **GDPR**: Secrets are automatically deleted after TTL
- **CCPA**: No persistent storage of user data
- **HIPAA**: Encryption at rest and in transit
- **SOX**: Comprehensive audit logging

### Audit Requirements
- All operations are logged with timestamps
- Log integrity is cryptographically verifiable
- Failed access attempts are recorded
- User attribution for all actions

### Data Residency
- Configure deployment region as required
- Use local Redis instances
- Ensure audit logs remain in jurisdiction
- Document data flows for compliance

## Threat Model

### Threats Mitigated
✅ **Eavesdropping**: End-to-end encryption prevents plaintext interception  
✅ **Server Compromise**: Zero-knowledge design limits impact  
✅ **Brute Force**: Rate limiting and strong encryption  
✅ **Data Persistence**: Automatic expiration and deletion  
✅ **Audit Tampering**: Hash-chained audit logs  

### Threats Requiring Additional Measures
⚠️ **Client Compromise**: Malware on user devices  
⚠️ **Social Engineering**: User education required  
⚠️ **Physical Security**: Secure deployment environment  
⚠️ **Supply Chain**: Verify all dependencies  

### Known Limitations
- Password-based encryption relies on user password strength
- Client-side JavaScript can be modified by browser extensions
- Audit logs are append-only but not distributed
- No built-in key escrow or recovery mechanism

## Security Updates

### Staying Current
- Subscribe to security advisories
- Monitor dependency vulnerabilities
- Regular security assessments
- Automated dependency updates

### Reporting Vulnerabilities
- Email: security@vaultify.io
- PGP Key: Available on security page
- Responsible disclosure: 90-day timeline
- Bug bounty program for critical findings

---

**Remember**: Security is a shared responsibility. This guide provides the foundation, but proper implementation and operation are crucial for maintaining security in production environments.