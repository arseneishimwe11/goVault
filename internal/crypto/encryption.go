package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the size of the AES-256 key in bytes
	KeySize = 32
	// NonceSize is the size of the GCM nonce in bytes
	NonceSize = 12
	// SaltSize is the size of the PBKDF2 salt in bytes
	SaltSize = 16
	// PBKDF2Iterations is the number of iterations for key derivation
	PBKDF2Iterations = 100000
)

// EncryptedData represents encrypted data with all necessary components
type EncryptedData struct {
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Salt       string `json:"salt"`
}

// CryptoService provides encryption and decryption operations
type CryptoService struct{}

// NewCryptoService creates a new CryptoService instance
func NewCryptoService() *CryptoService {
	return &CryptoService{}
}

// GenerateKey generates a random 256-bit key
func (c *CryptoService) GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

// DeriveKey derives a key from a password using simple key stretching
// In production, consider using a proper PBKDF2 implementation
func (c *CryptoService) DeriveKey(password string, salt []byte) []byte {
	// Simple key derivation for now - combine password and salt, then hash
	combined := append([]byte(password), salt...)
	hash := sha256.Sum256(combined)
	return hash[:]
}

// GenerateSalt generates a random salt for key derivation
func (c *CryptoService) GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a derived key
func (c *CryptoService) Encrypt(plaintext, password string) (*EncryptedData, error) {
	if plaintext == "" {
		return nil, errors.New("plaintext cannot be empty")
	}
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}

	// Generate salt for key derivation
	salt, err := c.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := c.DeriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Return encrypted data with all components
	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Salt:       base64.StdEncoding.EncodeToString(salt),
	}, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with a derived key
func (c *CryptoService) Decrypt(encData *EncryptedData, password string) (string, error) {
	if encData == nil {
		return "", errors.New("encrypted data cannot be nil")
	}
	if password == "" {
		return "", errors.New("password cannot be empty")
	}

	// Decode base64 components
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encData.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(encData.Salt)
	if err != nil {
		return "", fmt.Errorf("failed to decode salt: %w", err)
	}

	// Derive key from password and salt
	key := c.DeriveKey(password, salt)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// EncryptWithKey encrypts plaintext using a provided key (for internal use)
func (c *CryptoService) EncryptWithKey(plaintext string, key []byte) (*EncryptedData, error) {
	if plaintext == "" {
		return nil, errors.New("plaintext cannot be empty")
	}
	if len(key) != KeySize {
		return nil, errors.New("key must be 32 bytes")
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	// Return encrypted data (salt will be empty for key-based encryption)
	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Salt:       "",
	}, nil
}

// DecryptWithKey decrypts ciphertext using a provided key (for internal use)
func (c *CryptoService) DecryptWithKey(encData *EncryptedData, key []byte) (string, error) {
	if encData == nil {
		return "", errors.New("encrypted data cannot be nil")
	}
	if len(key) != KeySize {
		return "", errors.New("key must be 32 bytes")
	}

	// Decode base64 components
	ciphertext, err := base64.StdEncoding.DecodeString(encData.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	nonce, err := base64.StdEncoding.DecodeString(encData.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// HashKey creates a SHA-256 hash of a key for verification purposes
func (c *CryptoService) HashKey(key []byte) string {
	hash := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(hash[:])
}

// HashPassword creates a SHA-256 hash of a password for verification purposes
func (c *CryptoService) HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}