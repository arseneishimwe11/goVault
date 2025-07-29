package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vaultify/vaultify/pkg/types"
)

// RedisStorage implements secret storage using Redis
type RedisStorage struct {
	client *redis.Client
}

// NewRedisStorage creates a new Redis storage instance
func NewRedisStorage(config types.RedisConfig) (*RedisStorage, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.Address,
		Password: config.Password,
		DB:       config.DB,
	})

	// Test the connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStorage{
		client: rdb,
	}, nil
}

// StoreSecret stores a secret in Redis with TTL
func (r *RedisStorage) StoreSecret(ctx context.Context, secret *types.Secret) error {
	secretData, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	// Calculate TTL
	ttl := time.Until(secret.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("secret is already expired")
	}

	// Store in Redis with TTL
	if err := r.client.Set(ctx, r.secretKey(secret.Token), secretData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to store secret in Redis: %w", err)
	}

	return nil
}

// GetSecret retrieves a secret from Redis
func (r *RedisStorage) GetSecret(ctx context.Context, token string) (*types.Secret, error) {
	secretData, err := r.client.Get(ctx, r.secretKey(token)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, &SecretNotFoundError{Token: token}
		}
		return nil, fmt.Errorf("failed to get secret from Redis: %w", err)
	}

	var secret types.Secret
	if err := json.Unmarshal([]byte(secretData), &secret); err != nil {
		return nil, fmt.Errorf("failed to unmarshal secret: %w", err)
	}

	// Check if secret is expired
	if secret.IsExpired() {
		// Delete expired secret
		r.client.Del(ctx, r.secretKey(token))
		return nil, &SecretExpiredError{Token: token}
	}

	return &secret, nil
}

// UpdateSecret updates a secret in Redis (typically for incrementing read count)
func (r *RedisStorage) UpdateSecret(ctx context.Context, secret *types.Secret) error {
	secretData, err := json.Marshal(secret)
	if err != nil {
		return fmt.Errorf("failed to marshal secret: %w", err)
	}

	// Calculate remaining TTL
	ttl := time.Until(secret.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("secret is already expired")
	}

	// Update in Redis
	if err := r.client.Set(ctx, r.secretKey(secret.Token), secretData, ttl).Err(); err != nil {
		return fmt.Errorf("failed to update secret in Redis: %w", err)
	}

	return nil
}

// DeleteSecret deletes a secret from Redis
func (r *RedisStorage) DeleteSecret(ctx context.Context, token string) error {
	deleted, err := r.client.Del(ctx, r.secretKey(token)).Result()
	if err != nil {
		return fmt.Errorf("failed to delete secret from Redis: %w", err)
	}

	if deleted == 0 {
		return &SecretNotFoundError{Token: token}
	}

	return nil
}

// GetSecretMetadata retrieves metadata about a secret without the encrypted data
func (r *RedisStorage) GetSecretMetadata(ctx context.Context, token string) (*types.SecretMetadata, error) {
	secret, err := r.GetSecret(ctx, token)
	if err != nil {
		return &types.SecretMetadata{
			Token:  token,
			Exists: false,
		}, err
	}

	return &types.SecretMetadata{
		Token:          secret.Token,
		Exists:         true,
		MaxReads:       secret.MaxReads,
		ReadsRemaining: secret.ReadsRemaining(),
		CreatedAt:      secret.CreatedAt,
		ExpiresAt:      secret.ExpiresAt,
		Metadata:       secret.Metadata,
	}, nil
}

// AtomicReadAndUpdate atomically reads a secret and updates its read count
func (r *RedisStorage) AtomicReadAndUpdate(ctx context.Context, token string) (*types.Secret, error) {
	// Use Redis transaction for atomic operation
	txf := func(tx *redis.Tx) error {
		// Get current secret
		secretData, err := tx.Get(ctx, r.secretKey(token)).Result()
		if err != nil {
			if err == redis.Nil {
				return &SecretNotFoundError{Token: token}
			}
			return fmt.Errorf("failed to get secret: %w", err)
		}

		var secret types.Secret
		if err := json.Unmarshal([]byte(secretData), &secret); err != nil {
			return fmt.Errorf("failed to unmarshal secret: %w", err)
		}

		// Check if secret can be read
		if !secret.CanRead() {
			if secret.IsExpired() {
				return &SecretExpiredError{Token: token}
			}
			return &MaxReadsExceededError{Token: token}
		}

		// Increment read count
		secret.IncrementReads()

		// Check if secret should be deleted after this read
		shouldDelete := secret.MaxReads > 0 && secret.CurrentReads >= secret.MaxReads

		// Pipeline the update/delete operation
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			if shouldDelete {
				pipe.Del(ctx, r.secretKey(token))
			} else {
				updatedData, _ := json.Marshal(&secret)
				ttl := time.Until(secret.ExpiresAt)
				pipe.Set(ctx, r.secretKey(token), updatedData, ttl)
			}
			return nil
		})

		return err
	}

	// Execute transaction
	for retries := 0; retries < 3; retries++ {
		err := r.client.Watch(ctx, txf, r.secretKey(token))
		if err == nil {
			break // Success
		}
		if err == redis.TxFailedErr {
			// Retry on transaction failure
			continue
		}
		return nil, err
	}

	// Get the updated secret to return
	return r.GetSecret(ctx, token)
}

// Cleanup removes expired secrets (should be run periodically)
func (r *RedisStorage) Cleanup(ctx context.Context) error {
	// Redis automatically handles TTL cleanup, but we can scan for expired secrets
	// and clean them up manually if needed
	iter := r.client.Scan(ctx, 0, r.secretKey("*"), 0).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		
		// Check if key still exists (might have been cleaned up by Redis TTL)
		exists, err := r.client.Exists(ctx, key).Result()
		if err != nil {
			continue
		}
		if exists == 0 {
			continue
		}

		// Get the secret to check expiration
		secretData, err := r.client.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var secret types.Secret
		if err := json.Unmarshal([]byte(secretData), &secret); err != nil {
			continue
		}

		// Delete if expired
		if secret.IsExpired() {
			r.client.Del(ctx, key)
		}
	}

	return iter.Err()
}

// HealthCheck checks if Redis is healthy
func (r *RedisStorage) HealthCheck(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Close closes the Redis connection
func (r *RedisStorage) Close() error {
	return r.client.Close()
}

// secretKey generates a Redis key for a secret token
func (r *RedisStorage) secretKey(token string) string {
	return fmt.Sprintf("vaultify:secret:%s", token)
}

// Custom error types
type SecretNotFoundError struct {
	Token string
}

func (e *SecretNotFoundError) Error() string {
	return fmt.Sprintf("secret not found: %s", e.Token)
}

type SecretExpiredError struct {
	Token string
}

func (e *SecretExpiredError) Error() string {
	return fmt.Sprintf("secret expired: %s", e.Token)
}

type MaxReadsExceededError struct {
	Token string
}

func (e *MaxReadsExceededError) Error() string {
	return fmt.Sprintf("max reads exceeded for secret: %s", e.Token)
}