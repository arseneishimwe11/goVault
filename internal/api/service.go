package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	//d"log"
	"time"

	"github.com/vaultify/vaultify/internal/audit"
	"github.com/vaultify/vaultify/internal/crypto"
	"github.com/vaultify/vaultify/internal/storage"
	"github.com/vaultify/vaultify/pkg/types"
)

// VaultifyServer implements the gRPC VaultifyService
type VaultifyServer struct {
	storage    *storage.RedisStorage
	crypto     *crypto.CryptoService
	audit      *audit.Logger
	config     *types.Config
}

// NewVaultifyServer creates a new VaultifyServer instance
func NewVaultifyServer(storage *storage.RedisStorage, crypto *crypto.CryptoService, audit *audit.Logger, config *types.Config) *VaultifyServer {
	return &VaultifyServer{
		storage: storage,
		crypto:  crypto,
		audit:   audit,
		config:  config,
	}
}

// StoreSecret stores an encrypted secret with metadata
func (s *VaultifyServer) StoreSecret(ctx context.Context, req *types.StoreSecretRequest) (*types.StoreSecretResponse, error) {
	clientInfo := s.getClientInfo(ctx)
	
	// Validate request
	if err := s.validateStoreRequest(req); err != nil {
		s.audit.LogAction("", types.ActionStore, clientInfo, false, err.Error())
		return nil, err
	}

	// Generate unique token
	token, err := s.generateToken()
	if err != nil {
		s.audit.LogAction("", types.ActionStore, clientInfo, false, "failed to generate token")
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Encrypt the secret
	var encryptedData string
	var keyHash string
	
	if req.Password != "" {
		// Use password-based encryption
		encData, err := s.crypto.Encrypt(req.Secret, req.Password)
		if err != nil {
			s.audit.LogAction(token, types.ActionStore, clientInfo, false, "encryption failed")
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
		
		// Encode the encrypted data structure as JSON then base64
		jsonData := fmt.Sprintf(`{"ciphertext":"%s","nonce":"%s","salt":"%s"}`, 
			encData.Ciphertext, encData.Nonce, encData.Salt)
		encryptedData = base64.StdEncoding.EncodeToString([]byte(jsonData))
		keyHash = s.crypto.HashPassword(req.Password)
	} else {
		// Use server-generated key
		key, err := s.crypto.GenerateKey()
		if err != nil {
			s.audit.LogAction(token, types.ActionStore, clientInfo, false, "key generation failed")
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
		
		// 
		encData, err := s.crypto.EncryptWithKey(req.Secret, key)
		if err != nil {
			s.audit.LogAction(token, types.ActionStore, clientInfo, false, "encryption failed")
			return nil, fmt.Errorf("encryption failed: %w", err)
		}
		
		// Encode the encrypted data structure as JSON then base64
		jsonData := fmt.Sprintf(`{"ciphertext":"%s","nonce":"%s","salt":""}`, 
			encData.Ciphertext, encData.Nonce)
		encryptedData = base64.StdEncoding.EncodeToString([]byte(jsonData))
		keyHash = s.crypto.HashKey(key)
	}

	// Create secret object
	now := time.Now().UTC()
	expiresAt := now.Add(req.TTL)
	
	secret := &types.Secret{
		Token:         token,
		EncryptedData: encryptedData,
		KeyHash:       keyHash,
		MaxReads:      req.MaxReads,
		CurrentReads:  0,
		CreatedAt:     now,
		ExpiresAt:     expiresAt,
		Metadata:      req.Metadata,
		ClientInfo:    clientInfo,
	}

	// Store in Redis
	if err := s.storage.StoreSecret(ctx, secret); err != nil {
		s.audit.LogAction(token, types.ActionStore, clientInfo, false, "storage failed")
		return nil, fmt.Errorf("storage failed: %w", err)
	}

	// Log successful storage
	s.audit.LogAction(token, types.ActionStore, clientInfo, true, "")

	// Generate share URL
	shareURL := fmt.Sprintf("%s/s/%s", s.config.Server.BaseURL, token)

	return &types.StoreSecretResponse{
		Token:     token,
		ShareURL:  shareURL,
		ExpiresAt: expiresAt,
	}, nil
}

// RetrieveSecret retrieves and deletes a secret by token
func (s *VaultifyServer) RetrieveSecret(ctx context.Context, req *types.RetrieveSecretRequest) (*types.RetrieveSecretResponse, error) {
	clientInfo := s.getClientInfo(ctx)

	// Validate request
	if req.Token == "" {
		s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "empty token")
		return nil, fmt.Errorf("token is required")
	}

	// Atomically read and update the secret
	secret, err := s.storage.AtomicReadAndUpdate(ctx, req.Token)
	if err != nil {
		var errorMsg string
		switch err.(type) {
		case *storage.SecretNotFoundError:
			errorMsg = "secret not found"
		case *storage.SecretExpiredError:
			errorMsg = "secret expired"
		case *storage.MaxReadsExceededError:
			errorMsg = "max reads exceeded"
		default:
			errorMsg = "storage error"
		}
		s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, errorMsg)
		return nil, err
	}

	// Decrypt the secret
	var decryptedSecret string
	
	// Decode the encrypted data
	encDataBytes, err := base64.StdEncoding.DecodeString(secret.EncryptedData)
	if err != nil {
		s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "invalid encrypted data")
		return nil, fmt.Errorf("invalid encrypted data: %w", err)
	}

	// Parse the encrypted data JSON
	var encData crypto.EncryptedData
	if err := json.Unmarshal(encDataBytes, &encData); err != nil {
		s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "invalid encrypted data format")
		return nil, fmt.Errorf("invalid encrypted data format: %w", err)
	}

	if req.Password != "" {
		// Verify password hash
		if s.crypto.HashPassword(req.Password) != secret.KeyHash {
			s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "invalid password")
			return nil, fmt.Errorf("invalid password")
		}
		
		// Decrypt with password
		decryptedSecret, err = s.crypto.Decrypt(&encData, req.Password)
		if err != nil {
			s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "decryption failed")
			return nil, fmt.Errorf("decryption failed: %w", err)
		}
	} else {
		s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, false, "password required")
		return nil, fmt.Errorf("password is required for this secret")
	}

	// Log successful retrieval
	s.audit.LogAction(req.Token, types.ActionRetrieve, clientInfo, true, "")

	return &types.RetrieveSecretResponse{
		Secret:         decryptedSecret,
		ReadsRemaining: secret.ReadsRemaining(),
		CreatedAt:      secret.CreatedAt,
		Metadata:       secret.Metadata,
	}, nil
}

// GetSecretMetadata gets metadata about a secret without retrieving it
func (s *VaultifyServer) GetSecretMetadata(ctx context.Context, token string) (*types.SecretMetadata, error) {
	clientInfo := s.getClientInfo(ctx)

	if token == "" {
		s.audit.LogAction(token, types.ActionMetadata, clientInfo, false, "empty token")
		return nil, fmt.Errorf("token is required")
	}

	metadata, err := s.storage.GetSecretMetadata(ctx, token)
	if err != nil {
		s.audit.LogAction(token, types.ActionMetadata, clientInfo, false, "metadata retrieval failed")
		return nil, err
	}

	s.audit.LogAction(token, types.ActionMetadata, clientInfo, true, "")
	return metadata, nil
}

// GetAuditLogs retrieves audit logs for verification
func (s *VaultifyServer) GetAuditLogs(ctx context.Context, token string, from, to *time.Time, limit int) ([]types.AuditEntry, string, error) {
	clientInfo := s.getClientInfo(ctx)

	logs, verificationHash, err := s.audit.GetLogs(token, from, to, limit)
	if err != nil {
		s.audit.LogAction("", "GET_AUDIT_LOGS", clientInfo, false, "audit log retrieval failed")
		return nil, "", err
	}

	s.audit.LogAction("", "GET_AUDIT_LOGS", clientInfo, true, "")
	return logs, verificationHash, nil
}

// HealthCheck checks the health of the service
func (s *VaultifyServer) HealthCheck(ctx context.Context) (*types.HealthCheckResponse, error) {
	services := make(map[string]string)

	// Check Redis
	if err := s.storage.HealthCheck(ctx); err != nil {
		services["redis"] = "unhealthy: " + err.Error()
	} else {
		services["redis"] = "healthy"
	}

	// Check audit logger
	if _, err := s.audit.VerifyIntegrity(); err != nil {
		services["audit"] = "unhealthy: " + err.Error()
	} else {
		services["audit"] = "healthy"
	}

	status := "healthy"
	for _, serviceStatus := range services {
		if serviceStatus != "healthy" {
			status = "unhealthy"
			break
		}
	}

	return &types.HealthCheckResponse{
		Status:    status,
		Version:   "1.0.0",
		Timestamp: time.Now().UTC(),
		Services:  services,
	}, nil
}

// Helper methods

func (s *VaultifyServer) validateStoreRequest(req *types.StoreSecretRequest) error {
	if req.Secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}
	
	if len(req.Secret) > types.MaxSecretSize {
		return fmt.Errorf("secret too large (max %d bytes)", types.MaxSecretSize)
	}
	
	if req.TTL < types.MinTTL {
		return fmt.Errorf("TTL too short (min %v)", types.MinTTL)
	}
	
	if req.TTL > types.MaxTTL {
		return fmt.Errorf("TTL too long (max %v)", types.MaxTTL)
	}
	
	if req.MaxReads < 0 {
		return fmt.Errorf("max reads cannot be negative")
	}
	
	if req.MaxReads > types.MaxMaxReads {
		return fmt.Errorf("max reads too high (max %d)", types.MaxMaxReads)
	}

	return nil
}

func (s *VaultifyServer) generateToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	// Encode as base64 URL-safe string
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (s *VaultifyServer) getClientInfo(ctx context.Context) string {
	// In a real implementation, extract client IP, user agent, etc. from context
	// For now, return a placeholder
	return "client-info-placeholder"
}