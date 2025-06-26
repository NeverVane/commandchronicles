package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
	"github.com/NeverVane/commandchronicles/internal/logger"
)

// Argon2id parameters optimized for security vs performance
const (
	// Time parameter (iterations)
	Argon2Time = 3
	
	// Memory parameter in KB (64MB)
	Argon2Memory = 64 * 1024
	
	// Parallelism parameter (number of threads)
	Argon2Threads = 4
	
	// Salt length in bytes
	SaltLength = 32
	
	// Key length in bytes (256 bits)
	KeyLength = 32
	
	// Minimum password length
	MinPasswordLength = 8
	
	// Maximum password length to prevent DoS
	MaxPasswordLength = 128
)

// KeyDerivationParams holds the parameters for Argon2id key derivation
type KeyDerivationParams struct {
	Time      uint32
	Memory    uint32
	Threads   uint8
	SaltBytes []byte
	KeyLength uint32
}

// KeyDerivator handles secure password-based key derivation
type KeyDerivator struct {
	params *KeyDerivationParams
	logger *logger.Logger
}

// DerivedKey represents a derived key with its parameters
type DerivedKey struct {
	Key    []byte
	Salt   []byte
	Params *KeyDerivationParams
}

// NewKeyDerivator creates a new key derivator with default parameters
func NewKeyDerivator() *KeyDerivator {
	return &KeyDerivator{
		params: &KeyDerivationParams{
			Time:      Argon2Time,
			Memory:    Argon2Memory,
			Threads:   Argon2Threads,
			KeyLength: KeyLength,
		},
		logger: logger.GetLogger().Security(),
	}
}

// NewKeyDerivatorWithParams creates a key derivator with custom parameters
func NewKeyDerivatorWithParams(params *KeyDerivationParams) *KeyDerivator {
	if params.SaltBytes == nil {
		params.SaltBytes = make([]byte, SaltLength)
	}
	
	return &KeyDerivator{
		params: params,
		logger: logger.GetLogger().Security(),
	}
}

// GenerateSalt creates a cryptographically secure random salt
func (kd *KeyDerivator) GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLength)
	if _, err := rand.Read(salt); err != nil {
		kd.logger.WithError(err).Error().Msg("Failed to generate random salt")
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	
	kd.logger.Debug().Int("salt_length", len(salt)).Msg("Generated new salt")
	return salt, nil
}

// DeriveKey derives a key from password and salt using Argon2id
func (kd *KeyDerivator) DeriveKey(password string, salt []byte) (*DerivedKey, error) {
	if err := kd.validateInputs(password, salt); err != nil {
		return nil, err
	}
	
	start := time.Now()
	
	// Derive key using Argon2id
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		kd.params.Time,
		kd.params.Memory,
		kd.params.Threads,
		kd.params.KeyLength,
	)
	
	duration := time.Since(start)
	
	kd.logger.WithFields(map[string]interface{}{
		"duration_ms": duration.Milliseconds(),
		"time_param":  kd.params.Time,
		"memory_kb":   kd.params.Memory,
		"threads":     kd.params.Threads,
		"key_length":  len(derivedKey),
	}).Info().Msg("Key derivation completed")
	
	// Create a copy of parameters for the result
	paramsCopy := &KeyDerivationParams{
		Time:      kd.params.Time,
		Memory:    kd.params.Memory,
		Threads:   kd.params.Threads,
		KeyLength: kd.params.KeyLength,
		SaltBytes: make([]byte, len(salt)),
	}
	copy(paramsCopy.SaltBytes, salt)
	
	return &DerivedKey{
		Key:    derivedKey,
		Salt:   salt,
		Params: paramsCopy,
	}, nil
}

// DeriveKeyFromCredentials derives a key using username as salt (deterministic)
func (kd *KeyDerivator) DeriveKeyFromCredentials(username, password string) (*DerivedKey, error) {
	if username == "" {
		return nil, fmt.Errorf("username cannot be empty")
	}
	
	// Use username as salt for deterministic key derivation
	// This ensures the same credentials always produce the same key
	salt := []byte(username)
	
	// Pad or truncate username to standard salt length for consistency
	standardSalt := make([]byte, SaltLength)
	if len(salt) >= SaltLength {
		copy(standardSalt, salt[:SaltLength])
	} else {
		copy(standardSalt, salt)
		// Fill remaining bytes with username repeated
		for i := len(salt); i < SaltLength; i++ {
			standardSalt[i] = salt[i%len(salt)]
		}
	}
	
	kd.logger.WithField("username", username).Debug().Msg("Deriving key from credentials")
	return kd.DeriveKey(password, standardSalt)
}

// DeriveKeyWithRandomSalt derives a key with a newly generated random salt
func (kd *KeyDerivator) DeriveKeyWithRandomSalt(password string) (*DerivedKey, error) {
	salt, err := kd.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	
	return kd.DeriveKey(password, salt)
}

// VerifyPassword verifies a password against a derived key
func (kd *KeyDerivator) VerifyPassword(password string, derivedKey *DerivedKey) (bool, error) {
	if derivedKey == nil {
		return false, fmt.Errorf("derived key cannot be nil")
	}
	
	// Temporarily update parameters to match the derived key
	originalParams := kd.params
	kd.params = derivedKey.Params
	
	// Derive key with same parameters
	testKey, err := kd.DeriveKey(password, derivedKey.Salt)
	
	// Restore original parameters
	kd.params = originalParams
	
	if err != nil {
		return false, fmt.Errorf("failed to derive verification key: %w", err)
	}
	
	// Constant-time comparison to prevent timing attacks
	match := subtle.ConstantTimeCompare(derivedKey.Key, testKey.Key) == 1
	
	kd.logger.WithField("match", match).Debug().Msg("Password verification completed")
	return match, nil
}

// ValidateParameters checks if the key derivation parameters are secure
func (kd *KeyDerivator) ValidateParameters() error {
	if kd.params.Time < 1 {
		return fmt.Errorf("time parameter must be at least 1")
	}
	
	if kd.params.Memory < 1024 {
		return fmt.Errorf("memory parameter must be at least 1024 KB")
	}
	
	if kd.params.Threads < 1 {
		return fmt.Errorf("threads parameter must be at least 1")
	}
	
	if kd.params.KeyLength < 16 {
		return fmt.Errorf("key length must be at least 16 bytes")
	}
	
	return nil
}

// GetParameters returns a copy of the current parameters
func (kd *KeyDerivator) GetParameters() *KeyDerivationParams {
	return &KeyDerivationParams{
		Time:      kd.params.Time,
		Memory:    kd.params.Memory,
		Threads:   kd.params.Threads,
		KeyLength: kd.params.KeyLength,
		SaltBytes: append([]byte(nil), kd.params.SaltBytes...),
	}
}

// EstimateDerivationTime estimates how long key derivation will take
func (kd *KeyDerivator) EstimateDerivationTime() (time.Duration, error) {
	// Run a quick benchmark with a test password
	testPassword := "benchmark_password_test"
	testSalt := make([]byte, SaltLength)
	
	start := time.Now()
	_, err := kd.DeriveKey(testPassword, testSalt)
	if err != nil {
		return 0, fmt.Errorf("failed to benchmark key derivation: %w", err)
	}
	
	duration := time.Since(start)
	kd.logger.WithField("estimated_duration_ms", duration.Milliseconds()).
		Debug().Msg("Key derivation timing benchmark completed")
	
	return duration, nil
}

// SecureErase overwrites sensitive data in memory
func (dk *DerivedKey) SecureErase() {
	if dk.Key != nil {
		secureWipe(dk.Key)
		dk.Key = nil
	}
	
	if dk.Salt != nil {
		secureWipe(dk.Salt)
		dk.Salt = nil
	}
	
	dk.Params = nil
}

// secureWipe performs a secure wipe of a byte slice with multiple passes
func secureWipe(data []byte) {
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
	if _, err := rand.Read(data); err == nil {
		// Only do random pass if it succeeds
	}
	
	// Pass 4: Final zero pass
	for i := range data {
		data[i] = 0
	}
}

// validateInputs validates password and salt inputs
func (kd *KeyDerivator) validateInputs(password string, salt []byte) error {
	if len(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", MinPasswordLength)
	}
	
	if len(password) > MaxPasswordLength {
		return fmt.Errorf("password must be no more than %d characters long", MaxPasswordLength)
	}
	
	if len(salt) == 0 {
		return fmt.Errorf("salt cannot be empty")
	}
	
	if len(salt) < 16 {
		return fmt.Errorf("salt must be at least 16 bytes long")
	}
	
	return nil
}

// GetRecommendedParams returns recommended parameters based on security level
func GetRecommendedParams(securityLevel string) *KeyDerivationParams {
	switch securityLevel {
	case "low":
		return &KeyDerivationParams{
			Time:      1,
			Memory:    32 * 1024, // 32MB
			Threads:   2,
			KeyLength: KeyLength,
		}
	case "medium":
		return &KeyDerivationParams{
			Time:      Argon2Time,
			Memory:    Argon2Memory, // 64MB
			Threads:   Argon2Threads,
			KeyLength: KeyLength,
		}
	case "high":
		return &KeyDerivationParams{
			Time:      5,
			Memory:    128 * 1024, // 128MB
			Threads:   8,
			KeyLength: KeyLength,
		}
	default:
		return &KeyDerivationParams{
			Time:      Argon2Time,
			Memory:    Argon2Memory,
			Threads:   Argon2Threads,
			KeyLength: KeyLength,
		}
	}
}