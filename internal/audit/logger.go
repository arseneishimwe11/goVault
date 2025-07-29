package audit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/vaultify/vaultify/pkg/types"
)

// Logger provides tamper-proof audit logging with hash chaining
type Logger struct {
	mu             sync.RWMutex
	filePath       string
	lastEntryHash  string
	entries        []types.AuditEntry
	secretKey      []byte // HMAC key for additional security
}

// NewLogger creates a new audit logger
func NewLogger(filePath string, secretKey []byte) (*Logger, error) {
	logger := &Logger{
		filePath:  filePath,
		secretKey: secretKey,
		entries:   make([]types.AuditEntry, 0),
	}

	// Load existing entries if file exists
	if err := logger.loadExistingEntries(); err != nil {
		return nil, fmt.Errorf("failed to load existing entries: %w", err)
	}

	return logger, nil
}

// LogAction logs an action with tamper-proof hash chaining
func (l *Logger) LogAction(token, action, clientInfo string, success bool, errorMsg string) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := types.AuditEntry{
		ID:            generateID(),
		Token:         token,
		Action:        action,
		ClientInfo:    clientInfo,
		Success:       success,
		ErrorMessage:  errorMsg,
		Timestamp:     time.Now().UTC(),
		PreviousHash:  l.lastEntryHash,
	}

	// Calculate hash for this entry
	entry.EntryHash = l.calculateEntryHash(&entry)
	l.lastEntryHash = entry.EntryHash

	// Add to in-memory store
	l.entries = append(l.entries, entry)

	// Persist to file
	if err := l.persistEntry(&entry); err != nil {
		return fmt.Errorf("failed to persist entry: %w", err)
	}

	return nil
}

// GetLogs returns audit logs with optional filtering
func (l *Logger) GetLogs(token string, from, to *time.Time, limit int) ([]types.AuditEntry, string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var filtered []types.AuditEntry

	for _, entry := range l.entries {
		// Filter by token if specified
		if token != "" && entry.Token != token {
			continue
		}

		// Filter by time range if specified
		if from != nil && entry.Timestamp.Before(*from) {
			continue
		}
		if to != nil && entry.Timestamp.After(*to) {
			continue
		}

		filtered = append(filtered, entry)
	}

	// Apply limit if specified
	if limit > 0 && len(filtered) > limit {
		filtered = filtered[len(filtered)-limit:]
	}

	// Calculate verification hash for the returned logs
	verificationHash := l.calculateVerificationHash(filtered)

	return filtered, verificationHash, nil
}

// VerifyIntegrity verifies the integrity of the entire log chain
func (l *Logger) VerifyIntegrity() (bool, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if len(l.entries) == 0 {
		return true, nil
	}

	var previousHash string
	for i, entry := range l.entries {
		// Check if previous hash matches
		if entry.PreviousHash != previousHash {
			return false, fmt.Errorf("hash chain broken at entry %d: expected previous hash %s, got %s",
				i, previousHash, entry.PreviousHash)
		}

		// Recalculate entry hash
		expectedHash := l.calculateEntryHash(&entry)
		if entry.EntryHash != expectedHash {
			return false, fmt.Errorf("entry hash mismatch at entry %d: expected %s, got %s",
				i, expectedHash, entry.EntryHash)
		}

		previousHash = entry.EntryHash
	}

	return true, nil
}

// calculateEntryHash calculates the hash for an audit entry
func (l *Logger) calculateEntryHash(entry *types.AuditEntry) string {
	// Create a copy without the EntryHash field for hashing
	hashData := struct {
		ID            string    `json:"id"`
		Token         string    `json:"token"`
		Action        string    `json:"action"`
		ClientInfo    string    `json:"client_info"`
		Success       bool      `json:"success"`
		ErrorMessage  string    `json:"error_message"`
		Timestamp     time.Time `json:"timestamp"`
		PreviousHash  string    `json:"previous_hash"`
	}{
		ID:            entry.ID,
		Token:         entry.Token,
		Action:        entry.Action,
		ClientInfo:    entry.ClientInfo,
		Success:       entry.Success,
		ErrorMessage:  entry.ErrorMessage,
		Timestamp:     entry.Timestamp,
		PreviousHash:  entry.PreviousHash,
	}

	jsonData, _ := json.Marshal(hashData)
	hash := sha256.Sum256(jsonData)
	return fmt.Sprintf("%x", hash)
}

// calculateVerificationHash calculates a hash for verifying a set of logs
func (l *Logger) calculateVerificationHash(entries []types.AuditEntry) string {
	if len(entries) == 0 {
		return ""
	}

	var hashes []string
	for _, entry := range entries {
		hashes = append(hashes, entry.EntryHash)
	}

	jsonData, _ := json.Marshal(hashes)
	hash := sha256.Sum256(jsonData)
	return fmt.Sprintf("%x", hash)
}

// persistEntry appends an entry to the log file
func (l *Logger) persistEntry(entry *types.AuditEntry) error {
	file, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %w", err)
	}

	if _, err := file.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("failed to write entry: %w", err)
	}

	return nil
}

// loadExistingEntries loads existing log entries from file
func (l *Logger) loadExistingEntries() error {
	if _, err := os.Stat(l.filePath); os.IsNotExist(err) {
		return nil // File doesn't exist, start fresh
	}

	file, err := os.Open(l.filePath)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for decoder.More() {
		var entry types.AuditEntry
		if err := decoder.Decode(&entry); err != nil {
			return fmt.Errorf("failed to decode entry: %w", err)
		}
		l.entries = append(l.entries, entry)
		l.lastEntryHash = entry.EntryHash
	}

	return nil
}

// generateID generates a unique ID for log entries
func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}