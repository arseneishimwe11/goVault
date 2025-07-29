package types

import (
	"time"
)

// Secret represents a stored secret with metadata
type Secret struct {
	Token         string            `json:"token" redis:"token"`
	EncryptedData string            `json:"encrypted_data" redis:"encrypted_data"`
	KeyHash       string            `json:"key_hash" redis:"key_hash"`
	MaxReads      int32             `json:"max_reads" redis:"max_reads"`
	CurrentReads  int32             `json:"current_reads" redis:"current_reads"`
	CreatedAt     time.Time         `json:"created_at" redis:"created_at"`
	ExpiresAt     time.Time         `json:"expires_at" redis:"expires_at"`
	Metadata      map[string]string `json:"metadata" redis:"metadata"`
	ClientInfo    string            `json:"client_info" redis:"client_info"`
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID            string    `json:"id"`
	Token         string    `json:"token"`
	Action        string    `json:"action"`
	ClientInfo    string    `json:"client_info"`
	Success       bool      `json:"success"`
	ErrorMessage  string    `json:"error_message"`
	Timestamp     time.Time `json:"timestamp"`
	PreviousHash  string    `json:"previous_hash"`
	EntryHash     string    `json:"entry_hash"`
}

// SecretMetadata represents metadata about a secret without the actual data
type SecretMetadata struct {
	Token          string            `json:"token"`
	Exists         bool              `json:"exists"`
	MaxReads       int32             `json:"max_reads"`
	ReadsRemaining int32             `json:"reads_remaining"`
	CreatedAt      time.Time         `json:"created_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Metadata       map[string]string `json:"metadata"`
}

// StoreSecretRequest represents a request to store a secret
type StoreSecretRequest struct {
	Secret    string            `json:"secret"`
	Password  string            `json:"password,omitempty"`
	TTL       time.Duration     `json:"ttl"`
	MaxReads  int32             `json:"max_reads"`
	Metadata  map[string]string `json:"metadata"`
}

// StoreSecretResponse represents a response after storing a secret
type StoreSecretResponse struct {
	Token     string    `json:"token"`
	ShareURL  string    `json:"share_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RetrieveSecretRequest represents a request to retrieve a secret
type RetrieveSecretRequest struct {
	Token    string `json:"token"`
	Password string `json:"password,omitempty"`
}

// RetrieveSecretResponse represents a response when retrieving a secret
type RetrieveSecretResponse struct {
	Secret         string            `json:"secret"`
	ReadsRemaining int32             `json:"reads_remaining"`
	CreatedAt      time.Time         `json:"created_at"`
	Metadata       map[string]string `json:"metadata"`
}

// Config represents the application configuration
type Config struct {
	Server ServerConfig `json:"server"`
	Redis  RedisConfig  `json:"redis"`
	Audit  AuditConfig  `json:"audit"`
	Crypto CryptoConfig `json:"crypto"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	GRPCPort    int    `json:"grpc_port"`
	HTTPPort    int    `json:"http_port"`
	Host        string `json:"host"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	BaseURL     string `json:"base_url"`
}

// RedisConfig represents Redis configuration
type RedisConfig struct {
	Address  string `json:"address"`
	Password string `json:"password"`
	DB       int    `json:"db"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	LogFile   string `json:"log_file"`
	SecretKey string `json:"secret_key"`
}

// CryptoConfig represents cryptographic configuration
type CryptoConfig struct {
	DefaultTTL      time.Duration `json:"default_ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	DefaultMaxReads int32         `json:"default_max_reads"`
	MaxMaxReads     int32         `json:"max_max_reads"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// HealthCheckResponse represents a health check response
type HealthCheckResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Services  map[string]string `json:"services"`
}

// Constants for audit actions
const (
	ActionStore    = "STORE"
	ActionRetrieve = "RETRIEVE"
	ActionDelete   = "DELETE"
	ActionMetadata = "METADATA"
	ActionHealth   = "HEALTH"
)

// Constants for error codes
const (
	ErrCodeInvalidToken     = "INVALID_TOKEN"
	ErrCodeSecretNotFound   = "SECRET_NOT_FOUND"
	ErrCodeSecretExpired    = "SECRET_EXPIRED"
	ErrCodeMaxReadsExceeded = "MAX_READS_EXCEEDED"
	ErrCodeInvalidRequest   = "INVALID_REQUEST"
	ErrCodeInternalError    = "INTERNAL_ERROR"
	ErrCodeEncryptionError  = "ENCRYPTION_ERROR"
	ErrCodeDecryptionError  = "DECRYPTION_ERROR"
)

// Constants for secret limits
const (
	MaxSecretSize = 1024 * 1024      // 1MB
	MaxTTL        = 7 * 24 * time.Hour // 7 days
	MinTTL        = 1 * time.Minute    // 1 minute
	MaxMaxReads   = 1000
)

// SecretExists checks if a secret exists and is not expired
func (s *Secret) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// CanRead checks if a secret can be read (not expired and has reads remaining)
func (s *Secret) CanRead() bool {
	if s.IsExpired() {
		return false
	}
	if s.MaxReads > 0 && s.CurrentReads >= s.MaxReads {
		return false
	}
	return true
}

// IncrementReads increments the read count for a secret
func (s *Secret) IncrementReads() {
	s.CurrentReads++
}

// ReadsRemaining returns the number of reads remaining for a secret
func (s *Secret) ReadsRemaining() int32 {
	if s.MaxReads == 0 {
		return -1 // Unlimited reads
	}
	remaining := s.MaxReads - s.CurrentReads
	if remaining < 0 {
		return 0
	}
	return remaining
}