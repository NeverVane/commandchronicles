package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
)

// Encryption constants
const (
	// XChaCha20-Poly1305 nonce size (24 bytes)
	NonceSize = chacha20poly1305.NonceSizeX
	
	// Authentication tag size (16 bytes)
	TagSize = 16
	
	// Minimum encrypted data size (nonce + tag)
	MinEncryptedSize = NonceSize + TagSize
	
	// Maximum plaintext size to prevent DoS (16MB)
	MaxPlaintextSize = 16 * 1024 * 1024
)

// Encryptor handles AEAD encryption and decryption operations
type Encryptor struct {
	logger *logger.Logger
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Data      []byte
	Nonce     []byte
	Timestamp int64
	Version   int
}

// NewEncryptor creates a new encryptor instance
func NewEncryptor() *Encryptor {
	return &Encryptor{
		logger: logger.GetLogger().Security(),
	}
}

// EncryptRecord encrypts a CommandRecord using XChaCha20-Poly1305 AEAD
func (e *Encryptor) EncryptRecord(record *storage.CommandRecord, key []byte) ([]byte, error) {
	if record == nil {
		return nil, fmt.Errorf("record cannot be nil")
	}
	
	if err := e.validateKey(key); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	
	if !record.IsValid() {
		return nil, fmt.Errorf("record is not valid")
	}
	
	start := time.Now()
	
	// Serialize record to JSON
	plaintext, err := json.Marshal(record)
	if err != nil {
		e.logger.WithError(err).Error().Msg("Failed to marshal record to JSON")
		return nil, fmt.Errorf("failed to marshal record: %w", err)
	}
	
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("plaintext too large: %d bytes (max: %d)", len(plaintext), MaxPlaintextSize)
	}
	
	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		e.logger.WithError(err).Error().Msg("Failed to generate random nonce")
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	// Use appropriate key length for XChaCha20-Poly1305 (32 bytes)
	var encKey []byte
	if len(key) == 64 {
		encKey = key[:32]  // Use first 32 bytes of 64-byte key
	} else {
		encKey = key  // Use 32-byte key as-is
	}

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		e.logger.WithError(err).Error().Msg("Failed to create XChaCha20-Poly1305 cipher")
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	// Encrypt with authentication
	// Format: [nonce][ciphertext+auth_tag]
	ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
	
	duration := time.Since(start)
	
	e.logger.WithFields(map[string]interface{}{
		"plaintext_size":  len(plaintext),
		"ciphertext_size": len(ciphertext),
		"duration_ms":     duration.Milliseconds(),
		"nonce_size":      len(nonce),
	}).Debug().Msg("Record encryption completed")
	
	// Clear sensitive data from memory
	for i := range plaintext {
		plaintext[i] = 0
	}
	
	return ciphertext, nil
}

// DecryptRecord decrypts encrypted data back to a CommandRecord
func (e *Encryptor) DecryptRecord(encryptedData []byte, key []byte) (*storage.CommandRecord, error) {
	if len(encryptedData) < MinEncryptedSize {
		return nil, fmt.Errorf("encrypted data too small: %d bytes (min: %d)", len(encryptedData), MinEncryptedSize)
	}
	
	if err := e.validateKey(key); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	
	start := time.Now()
	
	// Extract nonce (first 24 bytes)
	nonce := encryptedData[:NonceSize]
	ciphertext := encryptedData[NonceSize:]
	
	// Use appropriate key length for XChaCha20-Poly1305 (32 bytes)
	var encKey []byte
	if len(key) == 64 {
		encKey = key[:32]  // Use first 32 bytes of 64-byte key
	} else {
		encKey = key  // Use 32-byte key as-is
	}

	// Create XChaCha20-Poly1305 AEAD cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		e.logger.WithError(err).Error().Msg("Failed to create XChaCha20-Poly1305 cipher")
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	// Decrypt and verify authentication tag
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		e.logger.WithError(err).Error().Msg("Failed to decrypt data - authentication failed")
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	// Deserialize JSON back to CommandRecord
	var record storage.CommandRecord
	if err := json.Unmarshal(plaintext, &record); err != nil {
		e.logger.WithError(err).Error().Msg("Failed to unmarshal decrypted JSON")
		// Clear decrypted data before returning error
		for i := range plaintext {
			plaintext[i] = 0
		}
		return nil, fmt.Errorf("failed to unmarshal record: %w", err)
	}
	
	duration := time.Since(start)
	
	e.logger.WithFields(map[string]interface{}{
		"ciphertext_size": len(encryptedData),
		"plaintext_size":  len(plaintext),
		"duration_ms":     duration.Milliseconds(),
		"command_length":  len(record.Command),
	}).Debug().Msg("Record decryption completed")
	
	// Clear sensitive data from memory
	for i := range plaintext {
		plaintext[i] = 0
	}
	
	// Validate decrypted record
	if !record.IsValid() {
		return nil, fmt.Errorf("decrypted record is invalid")
	}
	
	return &record, nil
}

// EncryptBytes encrypts arbitrary byte data
func (e *Encryptor) EncryptBytes(data []byte, key []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}
	
	if len(data) > MaxPlaintextSize {
		return nil, fmt.Errorf("data too large: %d bytes (max: %d)", len(data), MaxPlaintextSize)
	}
	
	if err := e.validateKey(key); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	
	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	// Use appropriate key length for XChaCha20-Poly1305 (32 bytes)
	var encKey []byte
	if len(key) == 64 {
		encKey = key[:32]  // Use first 32 bytes of 64-byte key
	} else {
		encKey = key  // Use 32-byte key as-is
	}

	// Create cipher and encrypt
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	ciphertext := aead.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// DecryptBytes decrypts arbitrary byte data
func (e *Encryptor) DecryptBytes(encryptedData []byte, key []byte) ([]byte, error) {
	if len(encryptedData) < MinEncryptedSize {
		return nil, fmt.Errorf("encrypted data too small: %d bytes (min: %d)", len(encryptedData), MinEncryptedSize)
	}
	
	if err := e.validateKey(key); err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	
	// Extract nonce and ciphertext
	nonce := encryptedData[:NonceSize]
	ciphertext := encryptedData[NonceSize:]
	
	// Use appropriate key length for XChaCha20-Poly1305 (32 bytes)
	var encKey []byte
	if len(key) == 64 {
		encKey = key[:32]  // Use first 32 bytes of 64-byte key
	} else {
		encKey = key  // Use 32-byte key as-is
	}

	// Create cipher and decrypt
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}
	
	return plaintext, nil
}

// ValidateEncryptedData checks if encrypted data has valid format
func (e *Encryptor) ValidateEncryptedData(data []byte) error {
	if len(data) < MinEncryptedSize {
		return fmt.Errorf("data too small: %d bytes (min: %d)", len(data), MinEncryptedSize)
	}
	
	if len(data) > MaxPlaintextSize+MinEncryptedSize {
		return fmt.Errorf("data too large: %d bytes", len(data))
	}
	
	// Check if nonce looks random (basic entropy check)
	nonce := data[:NonceSize]
	if err := e.validateNonce(nonce); err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}
	
	return nil
}

// GenerateNonce generates a cryptographically secure random nonce
func (e *Encryptor) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		e.logger.WithError(err).Error().Msg("Failed to generate random nonce")
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// GetEncryptionOverhead returns the encryption overhead in bytes
func (e *Encryptor) GetEncryptionOverhead() int {
	return NonceSize + TagSize
}

// EstimateEncryptedSize estimates the size of encrypted data
func (e *Encryptor) EstimateEncryptedSize(plaintextSize int) int {
	return plaintextSize + e.GetEncryptionOverhead()
}

// validateKey validates encryption key requirements
func (e *Encryptor) validateKey(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	
	if len(key) != 32 && len(key) != 64 {
		return fmt.Errorf("key must be 32 or 64 bytes, got %d", len(key))
	}
	
	// Check key is not all zeros (weak key)
	allZeros := true
	for _, b := range key {
		if b != 0 {
			allZeros = false
			break
		}
	}
	
	if allZeros {
		return fmt.Errorf("key cannot be all zeros")
	}
	
	return nil
}

// validateNonce performs basic validation on nonce
func (e *Encryptor) validateNonce(nonce []byte) error {
	if len(nonce) != NonceSize {
		return fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(nonce))
	}
	
	// Basic entropy check - nonce should not be all zeros
	allZeros := true
	for _, b := range nonce {
		if b != 0 {
			allZeros = false
			break
		}
	}
	
	if allZeros {
		return fmt.Errorf("nonce cannot be all zeros")
	}
	
	return nil
}

// SecureErase overwrites sensitive data in EncryptedData
func (ed *EncryptedData) SecureErase() {
	if ed.Data != nil {
		SecureWipe(ed.Data)
		ed.Data = nil
	}
	
	if ed.Nonce != nil {
		SecureWipe(ed.Nonce)
		ed.Nonce = nil
	}
	
	ed.Timestamp = 0
	ed.Version = 0
}

// CreateEncryptedData creates an EncryptedData structure with metadata
func (e *Encryptor) CreateEncryptedData(data []byte, nonce []byte) *EncryptedData {
	return &EncryptedData{
		Data:      append([]byte(nil), data...),
		Nonce:     append([]byte(nil), nonce...),
		Timestamp: time.Now().UnixMilli(),
		Version:   1,
	}
}

// SecureWipe performs a secure wipe of a byte slice with multiple passes
func SecureWipe(data []byte) {
	if len(data) == 0 {
		return
	}
	
	// Multiple-pass secure wipe
	// Pass 1: Fill with zeros
	for i := range data {
		data[i] = 0
	}
	
	// Pass 2: Fill with 0xFF
	for i := range data {
		data[i] = 0xFF
	}
	
	// Pass 3: Fill with random data
	rand.Read(data)
	
	// Pass 4: Final zero pass
	for i := range data {
		data[i] = 0
	}
}

// SecureClearBytes overwrites a byte slice with zeros for security
// Deprecated: Use SecureWipe for enhanced multi-pass security
func SecureClearBytes(b []byte) {
	SecureWipe(b)
}