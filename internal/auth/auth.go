package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/sentry"
	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/NeverVane/commandchronicles/pkg/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// Activity timeout: 1 month (renewable on activity)
	ActivityTimeoutSeconds = 30 * 24 * 60 * 60 // 30 days in seconds

	// Maximum lifetime uses config value (3 months, not renewable)
)

// SessionData represents the structured session file format
type SessionData struct {
	SessionKey   []byte        `json:"session_key"`
	EncryptedKey []byte        `json:"encrypted_key"`
	CreatedAt    time.Time     `json:"created_at"`
	LastActivity time.Time     `json:"last_activity"`
	MaxLifetime  time.Duration `json:"max_lifetime"`
	Version      int           `json:"version"`
}

// User represents a user in the system with authentication data
type User struct {
	Username   string    `json:"username"`
	KeySalt    []byte    `json:"key_salt"`  // Salt for key derivation
	KeyCheck   []byte    `json:"key_check"` // Encrypted verification data
	CreatedAt  time.Time `json:"created_at"`
	LastAccess time.Time `json:"last_access"`
	Version    int       `json:"version"` // Schema version
}

// KeyDerivationResult contains both local and remote keys derived from password
type KeyDerivationResult struct {
	LocalKey      []byte // Full 64-byte key
	EncryptionKey []byte // Full 64 bytes for encryption
	RemoteAuthKey []byte // Bytes 32-63 for server auth
	Salt          []byte // Salt used for derivation
}

// AuthManager handles user authentication and key management
type AuthManager struct {
	config       *config.Config
	logger       *logger.Logger
	keyDerivator *crypto.KeyDerivator
	userFile     string
	sessionFile  string

	// Session timeout and renewal
	cleanupTicker  *time.Ticker
	cleanupStop    chan bool
	cleanupRunning bool
	mu             sync.RWMutex
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(cfg *config.Config) (*AuthManager, error) {
	userFile := filepath.Join(cfg.DataDir, "user.json")
	sessionFile := cfg.Security.SessionKeyPath

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	am := &AuthManager{
		config:       cfg,
		logger:       logger.GetLogger().WithComponent("auth"),
		keyDerivator: crypto.NewKeyDerivator(),
		userFile:     userFile,
		sessionFile:  sessionFile,
		cleanupStop:  make(chan bool, 1),
	}

	// Start background cleanup if session timeout is configured
	if cfg.Security.SessionTimeout > 0 {
		am.StartBackgroundCleanup()
	}

	return am, nil
}

// InitUser initializes a new user with username and password
func (am *AuthManager) InitUser(username, password string) (*User, *KeyDerivationResult, error) {
	if username == "" {
		err := errors.New("username cannot be empty")
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	if len(password) < 8 {
		err := errors.New("password must be at least 8 characters")
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	if len(password) > 128 {
		err := errors.New("password too long (max 128 characters)")
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	// Check if user already exists
	if am.UserExists() {
		err := errors.New("user already exists")
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	// Generate deterministic salt for cross-device compatibility
	salt := am.generateDeterministicSalt(username)

	// Derive both local and remote keys
	keys, err := am.DeriveKeys(password, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Create key check data for password verification (use local key)
	// Create key verification data
	keyCheck, err := am.createKeyCheck(keys.LocalKey)
	if err != nil {
		err = fmt.Errorf("failed to create key check: %w", err)
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	// Create user
	user := &User{
		Username:   username,
		KeySalt:    salt,
		KeyCheck:   keyCheck,
		CreatedAt:  time.Now(),
		LastAccess: time.Now(),
		Version:    1,
	}

	// Save user
	if err := am.saveUser(user); err != nil {
		err = fmt.Errorf("failed to save user: %w", err)
		sentry.CaptureError(err, "auth", "init_user")
		return nil, nil, err
	}

	am.logger.WithFields(map[string]interface{}{
		"username": username,
		"user_id":  user.Username,
	}).Info().Msg("User initialized successfully with dual keys")

	return user, keys, nil
}

// VerifyPassword verifies a password and returns the derived key
func (am *AuthManager) VerifyPassword(username, password string) (*KeyDerivationResult, error) {
	user, err := am.loadUser()
	if err != nil {
		err = fmt.Errorf("failed to load user: %w", err)
		sentry.CaptureError(err, "auth", "verify_password")
		return nil, err
	}

	if user.Username != username {
		err := errors.New("invalid username")
		sentry.CaptureError(err, "auth", "verify_password", map[string]string{
			"reason": "username_mismatch",
		})
		return nil, err
	}

	// Derive both keys from password
	keys, err := am.DeriveKeys(password, user.KeySalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys: %w", err)
	}

	// Verify key check using local key
	if err := am.verifyKeyCheck(keys.LocalKey, user.KeyCheck); err != nil {
		return nil, errors.New("invalid password")
	}

	// Update last access time
	user.LastAccess = time.Now()
	if err := am.saveUser(user); err != nil {
		am.logger.WithError(err).Warn().Msg("Failed to update user last access time")
		sentry.CaptureError(err, "auth", "verify_password", map[string]string{
			"reason": "failed_to_update_last_access",
		})
	}

	am.logger.WithField("username", user.Username).Debug().Msg("Password verified successfully with dual keys")

	// Renew session on successful password verification
	if err := am.RenewSession(); err != nil {
		am.logger.WithError(err).Warn().Msg("Failed to renew session after password verification")
	}

	return keys, nil
}

// StoreSessionKey stores the key in a session file for later use
func (am *AuthManager) StoreSessionKey(key []byte) error {
	if len(key) != 32 && len(key) != 64 {
		err := errors.New("invalid key length")
		sentry.CaptureError(err, "auth", "store_session_key")
		return err
	}

	// Generate random session key for encrypting the main key
	randomSessionKey := make([]byte, 32)
	if _, err := rand.Read(randomSessionKey); err != nil {
		err = fmt.Errorf("failed to generate session key: %w", err)
		sentry.CaptureError(err, "auth", "store_session_key")
		return err
	}

	// Create cipher for encrypting the key
	// Encrypt the main key with ChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(randomSessionKey)
	if err != nil {
		err = fmt.Errorf("failed to create cipher: %w", err)
		sentry.CaptureError(err, "auth", "store_session_key")
		return err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		err = fmt.Errorf("failed to generate nonce: %w", err)
		sentry.CaptureError(err, "auth", "store_session_key")
		return err
	}

	ciphertext := aead.Seal(nil, nonce, key, nil)
	encryptedKey := append(nonce, ciphertext...)

	// Create structured session data with timestamps
	now := time.Now()
	maxLifetime := time.Duration(am.config.Security.SessionTimeout) * time.Second // 3 months from config
	sessionData := &SessionData{
		SessionKey:   randomSessionKey,
		EncryptedKey: encryptedKey,
		CreatedAt:    now,
		LastActivity: now,
		MaxLifetime:  maxLifetime,
		Version:      1,
	}

	// Serialize session data to JSON
	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Ensure session directory exists
	if err := os.MkdirAll(filepath.Dir(am.sessionFile), 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}

	// Write session file with secure permissions
	if err := os.WriteFile(am.sessionFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}

	am.logger.Debug().Msg("Session key stored successfully")
	return nil
}

// LoadSessionKey loads and decrypts the session key
func (am *AuthManager) LoadSessionKey() ([]byte, error) {
	// Read session file
	data, err := os.ReadFile(am.sessionFile)
	if err != nil {
		if os.IsNotExist(err) {
			err := errors.New("no active session")
			sentry.CaptureError(err, "auth", "load_session_key", map[string]string{
				"reason": "session_file_not_found",
			})
			return nil, err
		}
		err = fmt.Errorf("failed to read session file: %w", err)
		sentry.CaptureError(err, "auth", "load_session_key")
		return nil, err
	}

	// Try to parse as new JSON format first
	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		// Fallback to legacy format for backward compatibility
		return am.loadLegacySessionKey(data)
	}

	// Check session validity
	now := time.Now()

	// Check maximum session lifetime (hard limit)
	sessionAge := now.Sub(sessionData.CreatedAt)
	if sessionAge > sessionData.MaxLifetime {
		am.logger.WithFields(map[string]interface{}{
			"session_age":  sessionAge.String(),
			"max_lifetime": sessionData.MaxLifetime.String(),
			"created_at":   sessionData.CreatedAt.Format(time.RFC3339),
		}).Info().Msg("Session exceeded maximum lifetime, requires re-authentication")

		// Remove expired session
		am.LockSession()
		return nil, errors.New("session exceeded maximum lifetime")
	}

	// Check activity timeout (soft limit - can be renewed) - 1 month
	activityTimeout := time.Duration(ActivityTimeoutSeconds) * time.Second
	timeSinceActivity := now.Sub(sessionData.LastActivity)
	if timeSinceActivity > activityTimeout {
		am.logger.WithFields(map[string]interface{}{
			"time_since_activity": timeSinceActivity.String(),
			"activity_timeout":    activityTimeout.String(),
			"last_activity":       sessionData.LastActivity.Format(time.RFC3339),
		}).Info().Msg("Session timed out due to inactivity")

		// Remove inactive session
		am.LockSession()
		return nil, errors.New("session timed out due to inactivity")
	}

	// Create cipher
	aead, err := chacha20poly1305.NewX(sessionData.SessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Extract nonce and ciphertext
	if len(sessionData.EncryptedKey) < aead.NonceSize() {
		return nil, errors.New("invalid encrypted key format")
	}

	nonce := sessionData.EncryptedKey[:aead.NonceSize()]
	ciphertext := sessionData.EncryptedKey[aead.NonceSize():]

	// Decrypt main key
	key, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session key: %w", err)
	}

	am.logger.Debug().Msg("Session key loaded successfully")

	// Renew session on successful key load (respects maximum lifetime)
	if err := am.RenewSession(); err != nil {
		am.logger.WithError(err).Warn().Msg("Failed to renew session after loading key")
	}

	return key, nil
}

// loadLegacySessionKey handles the old session file format for backward compatibility
func (am *AuthManager) loadLegacySessionKey(data []byte) ([]byte, error) {
	am.logger.Warn().Msg("Loading legacy session format - consider re-authentication")

	// Check minimum length for legacy format
	minLength := 32 + chacha20poly1305.NonceSizeX + 1
	if len(data) < minLength {
		return nil, errors.New("invalid legacy session file format")
	}

	// Extract session key and encrypted main key (legacy format)
	sessionKey := data[:32]
	encryptedKey := data[32:]

	// Create cipher
	aead, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher for legacy session: %w", err)
	}

	// Extract nonce and ciphertext
	if len(encryptedKey) < aead.NonceSize() {
		return nil, errors.New("invalid encrypted key format in legacy session")
	}

	nonce := encryptedKey[:aead.NonceSize()]
	ciphertext := encryptedKey[aead.NonceSize():]

	// Decrypt main key
	key, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt legacy session key: %w", err)
	}

	return key, nil
}

// LockSession removes the session file, effectively locking the session
func (am *AuthManager) LockSession() error {
	if err := os.Remove(am.sessionFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove session file: %w", err)
	}

	am.logger.Info().Msg("Session locked successfully")
	return nil
}

// IsSessionActive checks if there's an active session
func (am *AuthManager) IsSessionActive() bool {
	_, err := os.Stat(am.sessionFile)
	return err == nil
}

// UserExists checks if a user has been initialized
func (am *AuthManager) UserExists() bool {
	_, err := os.Stat(am.userFile)
	return err == nil
}

// GetUser returns the current user information
func (am *AuthManager) GetUser() (*User, error) {
	return am.loadUser()
}

// ChangePassword changes the user's password and re-encrypts all stored data
func (am *AuthManager) ChangePassword(currentPassword, newPassword string) error {
	// Load user and verify current password
	user, err := am.loadUser()
	if err != nil {
		return fmt.Errorf("failed to load user: %w", err)
	}

	// Verify current password through auth system
	keys, err := am.VerifyPassword(user.Username, currentPassword)
	if err != nil {
		return fmt.Errorf("current password verification failed: %w", err)
	}
	_ = keys // We only need verification, not the keys

	// Get the actual working session key from auth system
	oldKey, err := am.LoadSessionKey()
	if err != nil {
		return fmt.Errorf("failed to load current session key: %w", err)
	}
	defer crypto.SecureWipe(oldKey)

	// Debug: Log key info (first 4 bytes only for security)
	am.logger.WithFields(map[string]interface{}{
		"key_length": len(oldKey),
		"key_prefix": fmt.Sprintf("%x", oldKey[:min(4, len(oldKey))]),
	}).Debug().Msg("Loaded session key for password change")

	// Validate new password
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
	}

	if len(newPassword) > 128 {
		return errors.New("new password too long (max 128 characters)")
	}

	// Use existing salt for deterministic key derivation (multi-device sync)
	newKeys, err := am.DeriveKeys(newPassword, user.KeySalt)
	if err != nil {
		return fmt.Errorf("failed to derive new keys: %w", err)
	}

	// Create new key check using LocalKey
	newKeyCheck, err := am.createKeyCheck(newKeys.LocalKey)
	if err != nil {
		return fmt.Errorf("failed to create new key check: %w", err)
	}

	// Re-encrypt all stored data with new encryption key
	if err := am.reencryptStoredData(user.Username, currentPassword, oldKey, newKeys.EncryptionKey); err != nil {
		return fmt.Errorf("failed to re-encrypt stored data: %w", err)
	}

	// Create backup of current user data for rollback
	originalKeyCheck := make([]byte, len(user.KeyCheck))
	copy(originalKeyCheck, user.KeyCheck)

	// Update user data (salt remains same for deterministic derivation)
	user.KeyCheck = newKeyCheck
	user.LastAccess = time.Now()

	// Save updated user data
	if err := am.saveUser(user); err != nil {
		// Attempt to rollback user data
		user.KeyCheck = originalKeyCheck
		am.saveUser(user) // Best effort rollback

		// Attempt to rollback data encryption (re-encrypt with old key)
		am.reencryptStoredData(user.Username, currentPassword, newKeys.EncryptionKey, oldKey) // Best effort rollback

		return fmt.Errorf("failed to save updated user data: %w", err)
	}

	// Session will be renewed by caller with new key (no need to lock)

	am.logger.WithField("username", user.Username).Info().Msg("Password changed successfully with data re-encryption")
	return nil
}

// ReencryptDataForPasswordChange re-encrypts stored data for cross-device password change recovery
func (am *AuthManager) ReencryptDataForPasswordChange(username, newPassword string, oldKey, newKey []byte) error {
	am.logger.Info().Msg("Starting data re-encryption for password change recovery")
	return am.reencryptStoredData(username, newPassword, oldKey, newKey)
}

// UpdatePasswordStateAtomic atomically updates password-related state for recovery
func (am *AuthManager) UpdatePasswordStateAtomic(newPassword string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Get current user
	user, err := am.loadUser()
	if err != nil {
		return fmt.Errorf("failed to load user for password state update: %w", err)
	}

	// Derive new keys using existing salt
	newKeys, err := am.DeriveKeys(newPassword, user.KeySalt)
	if err != nil {
		return fmt.Errorf("failed to derive new keys for state update: %w", err)
	}

	// Create new key check
	newKeyCheck, err := am.createKeyCheck(newKeys.LocalKey)
	if err != nil {
		return fmt.Errorf("failed to create new key check: %w", err)
	}

	// Update user data atomically
	user.KeyCheck = newKeyCheck
	user.LastAccess = time.Now()

	// Save updated user data
	if err := am.saveUser(user); err != nil {
		return fmt.Errorf("failed to save updated user data: %w", err)
	}

	// Store new session key
	if err := am.StoreSessionKey(newKeys.LocalKey); err != nil {
		return fmt.Errorf("failed to store new session key: %w", err)
	}

	am.logger.Info().Msg("Password state updated successfully")
	return nil
}

// CreateKeyCheck exposes key check creation for password recovery
func (am *AuthManager) CreateKeyCheck(key []byte) ([]byte, error) {
	return am.createKeyCheck(key)
}

// SaveUser exposes user data saving for password recovery
func (am *AuthManager) SaveUser(user *User) error {
	return am.saveUser(user)
}

// reencryptStoredData re-encrypts all stored command history with a new key
func (am *AuthManager) reencryptStoredData(username, password string, oldKey, newKey []byte) error {
	// Initialize database connection
	db, err := storage.NewDatabase(am.config, nil)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Initialize crypto components
	encryptor := crypto.NewEncryptor()
	keyDerivator := crypto.NewKeyDerivator()

	// Begin transaction for atomicity
	tx, err := db.BeginTransaction()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // Will be a no-op if we commit successfully

	// Get all encrypted records
	records, err := db.GetAllEncryptedRecords(tx)
	if err != nil {
		return fmt.Errorf("failed to retrieve encrypted records: %w", err)
	}

	am.logger.WithField("record_count", len(records)).Info().Msg("Re-encrypting stored command data with migration support")

	// Track re-encryption statistics
	var successCount, skippedCount int

	// Re-encrypt each record with migration logic
	for _, encRecord := range records {
		var decryptedRecord *storage.CommandRecord
		var decryptErr error

		// Debug: Log detailed record info
		am.logger.WithFields(map[string]interface{}{
			"record_id":   encRecord.ID,
			"data_length": len(encRecord.EncryptedData),
			"data_prefix": fmt.Sprintf("%x", encRecord.EncryptedData[:min(8, len(encRecord.EncryptedData))]),
			"timestamp":   encRecord.Timestamp,
			"session":     encRecord.Session,
			"hostname":    encRecord.Hostname,
			"created_at":  encRecord.CreatedAt,
		}).Info().Msg("Processing record for re-encryption")

		// Try to decrypt with auth system key first
		am.logger.WithFields(map[string]interface{}{
			"record_id":  encRecord.ID,
			"key_prefix": fmt.Sprintf("%x", oldKey[:min(4, len(oldKey))]),
			"key_length": len(oldKey),
		}).Info().Msg("Attempting decryption with auth system key")

		decryptedRecord, decryptErr = encryptor.DecryptRecord(encRecord.EncryptedData, oldKey)

		if decryptErr != nil {
			am.logger.WithFields(map[string]interface{}{
				"record_id": encRecord.ID,
				"error":     decryptErr.Error(),
			}).Error().Msg("Auth system key failed to decrypt record")
		}

		if decryptErr != nil {
			// Fallback: try with storage system key derivation for migration
			am.logger.WithField("record_id", encRecord.ID).Info().Msg("Auth key failed, trying storage system key for migration")

			// Derive key using storage system method (for migration compatibility)
			storageKey, err := keyDerivator.DeriveKeyFromCredentials(username, password)
			if err != nil {
				return fmt.Errorf("failed to derive storage system key for migration: %w", err)
			}
			defer storageKey.SecureErase()

			am.logger.WithFields(map[string]interface{}{
				"record_id":          encRecord.ID,
				"storage_key_prefix": fmt.Sprintf("%x", storageKey.Key[:min(4, len(storageKey.Key))]),
				"storage_key_length": len(storageKey.Key),
				"salt_prefix":        fmt.Sprintf("%x", storageKey.Salt[:min(4, len(storageKey.Salt))]),
			}).Info().Msg("Attempting decryption with storage system key")

			decryptedRecord, decryptErr = encryptor.DecryptRecord(encRecord.EncryptedData, storageKey.Key)

			if decryptErr != nil {
				am.logger.WithFields(map[string]interface{}{
					"record_id": encRecord.ID,
					"error":     decryptErr.Error(),
				}).Error().Msg("Storage system key also failed to decrypt record")
			}
			if decryptErr != nil {
				// Try one more approach: derive key with user's salt from auth system
				am.logger.WithField("record_id", encRecord.ID).Info().Msg("Both standard keys failed, trying with user's original salt")

				user, err := am.loadUser()
				if err == nil {
					userSaltKey, err := keyDerivator.DeriveKey(password, user.KeySalt)
					if err == nil {
						defer userSaltKey.SecureErase()

						am.logger.WithFields(map[string]interface{}{
							"record_id":            encRecord.ID,
							"user_salt_key_prefix": fmt.Sprintf("%x", userSaltKey.Key[:min(4, len(userSaltKey.Key))]),
							"user_salt_prefix":     fmt.Sprintf("%x", user.KeySalt[:min(4, len(user.KeySalt))]),
						}).Info().Msg("Attempting decryption with user's salt-derived key")

						decryptedRecord, decryptErr = encryptor.DecryptRecord(encRecord.EncryptedData, userSaltKey.Key)
					}
				}

				if decryptErr != nil {
					am.logger.WithFields(map[string]interface{}{
						"record_id":          encRecord.ID,
						"session":            encRecord.Session,
						"auth_key_prefix":    fmt.Sprintf("%x", oldKey[:min(4, len(oldKey))]),
						"storage_key_prefix": fmt.Sprintf("%x", storageKey.Key[:min(4, len(storageKey.Key))]),
						"data_sample":        fmt.Sprintf("%x", encRecord.EncryptedData[:min(16, len(encRecord.EncryptedData))]),
					}).Warn().Msg("Skipping undecryptable record (likely from old encryption system)")
					skippedCount++
					continue // Skip this record and continue with others
				} else {
					am.logger.WithField("record_id", encRecord.ID).Info().Msg("Successfully decrypted with user's salt-derived key")
				}
			} else {
				am.logger.WithField("record_id", encRecord.ID).Info().Msg("Successfully decrypted with storage system key (migration)")
			}
		} else {
			am.logger.WithField("record_id", encRecord.ID).Info().Msg("Successfully decrypted with auth system key")
		}

		// Re-encrypt with new auth system key
		newEncryptedData, err := encryptor.EncryptRecord(decryptedRecord, newKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt record %d with new key: %w", encRecord.ID, err)
		}

		// Update record in database
		if err := db.UpdateEncryptedData(tx, encRecord.ID, newEncryptedData); err != nil {
			return fmt.Errorf("failed to update encrypted data for record %d: %w", encRecord.ID, err)
		}

		successCount++
	}

	// Check if we managed to re-encrypt at least some records
	if successCount == 0 && len(records) > 0 {
		return fmt.Errorf("failed to decrypt any records - no records could be re-encrypted")
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit re-encryption transaction: %w", err)
	}

	am.logger.WithFields(map[string]interface{}{
		"total_records": len(records),
		"success_count": successCount,
		"skipped_count": skippedCount,
	}).Info().Msg("Re-encryption completed")

	if skippedCount > 0 {
		am.logger.WithField("skipped_count", skippedCount).Warn().Msg("Some records could not be re-encrypted and were skipped (likely from old encryption system)")
	}

	return nil
}

// StartBackgroundCleanup starts the automatic session cleanup routine
func (am *AuthManager) StartBackgroundCleanup() {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.cleanupRunning {
		return // Already running
	}

	// Default cleanup interval: every 5 minutes
	cleanupInterval := 5 * time.Minute
	// Set cleanup interval to 1/10th of activity timeout, min 1 minute, max 10 minutes
	interval := time.Duration(ActivityTimeoutSeconds/10) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > 10*time.Minute {
		interval = 10 * time.Minute
	}
	cleanupInterval = interval

	am.cleanupTicker = time.NewTicker(cleanupInterval)
	am.cleanupRunning = true

	am.logger.WithFields(map[string]interface{}{
		"cleanup_interval": cleanupInterval.String(),
		"activity_timeout": time.Duration(ActivityTimeoutSeconds).String(),
		"max_lifetime":     time.Duration(am.config.Security.SessionTimeout).String(),
	}).Info().Msg("Starting background session cleanup")

	go am.backgroundCleanupLoop()
}

// StopBackgroundCleanup stops the automatic session cleanup routine
func (am *AuthManager) StopBackgroundCleanup() {
	am.mu.Lock()
	defer am.mu.Unlock()

	if !am.cleanupRunning {
		return // Not running
	}

	am.logger.Info().Msg("Stopping background session cleanup")

	am.cleanupRunning = false

	if am.cleanupTicker != nil {
		am.cleanupTicker.Stop()
		am.cleanupTicker = nil
	}

	// Signal the background routine to stop
	select {
	case am.cleanupStop <- true:
	default:
		// Channel might be full, that's okay
	}
}

// backgroundCleanupLoop runs the periodic session cleanup
func (am *AuthManager) backgroundCleanupLoop() {
	for {
		select {
		case <-am.cleanupTicker.C:
			// Perform cleanup
			if err := am.CleanupExpiredSessions(); err != nil {
				am.logger.WithError(err).Warn().Msg("Background session cleanup failed")
			}

		case <-am.cleanupStop:
			am.logger.Debug().Msg("Background cleanup loop stopped")
			return
		}
	}
}

// RenewSession extends the session timeout by updating the session file timestamp
func (am *AuthManager) RenewSession() error {
	// Check if session is active
	if !am.IsSessionActive() {
		return nil // No session to renew
	}

	// Read current session data
	data, err := os.ReadFile(am.sessionFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Session file doesn't exist, nothing to renew
		}
		return fmt.Errorf("failed to read session file for renewal: %w", err)
	}

	// Try to parse as new JSON format
	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		// Legacy format - just update file timestamp (no maximum lifetime enforcement)
		now := time.Now()
		if err := os.Chtimes(am.sessionFile, now, now); err != nil {
			return fmt.Errorf("failed to renew legacy session: %w", err)
		}
		am.logger.WithField("renewed_at", now.Format(time.RFC3339)).Debug().Msg("Legacy session renewed")
		return nil
	}

	now := time.Now()

	// Check if session has exceeded maximum lifetime
	sessionAge := now.Sub(sessionData.CreatedAt)
	if sessionAge > sessionData.MaxLifetime {
		am.logger.WithFields(map[string]interface{}{
			"session_age":  sessionAge.String(),
			"max_lifetime": sessionData.MaxLifetime.String(),
		}).Warn().Msg("Cannot renew session - maximum lifetime exceeded")

		// Remove expired session
		am.LockSession()
		return errors.New("session cannot be renewed - maximum lifetime exceeded")
	}

	// Update last activity time
	sessionData.LastActivity = now

	// Write updated session data
	jsonData, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	if err := os.WriteFile(am.sessionFile, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write renewed session: %w", err)
	}

	am.logger.WithFields(map[string]interface{}{
		"renewed_at":         now.Format(time.RFC3339),
		"session_age":        sessionAge.String(),
		"remaining_lifetime": (sessionData.MaxLifetime - sessionAge).String(),
	}).Debug().Msg("Session renewed successfully")

	return nil
}

// GetSessionTimeRemaining returns the time remaining before session expires
func (am *AuthManager) GetSessionTimeRemaining() (time.Duration, error) {
	if !am.IsSessionActive() {
		return 0, errors.New("no active session")
	}

	// Read session data
	data, err := os.ReadFile(am.sessionFile)
	if err != nil {
		return 0, fmt.Errorf("failed to read session file: %w", err)
	}

	// Try to parse as new JSON format
	var sessionData SessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		// Fallback to legacy format
		sessionInfo, err := os.Stat(am.sessionFile)
		if err != nil {
			return 0, fmt.Errorf("failed to get legacy session info: %w", err)
		}

		timeout := time.Duration(ActivityTimeoutSeconds) * time.Second
		elapsed := time.Since(sessionInfo.ModTime())
		remaining := timeout - elapsed

		if remaining < 0 {
			return 0, nil // Session has expired
		}
		return remaining, nil
	}

	now := time.Now()

	// Calculate time remaining based on both limits
	// 1. Maximum lifetime limit (hard limit from creation)
	sessionAge := now.Sub(sessionData.CreatedAt)
	lifetimeRemaining := sessionData.MaxLifetime - sessionAge

	// 2. Activity timeout limit (soft limit from last activity) - 1 month
	activityTimeout := time.Duration(ActivityTimeoutSeconds) * time.Second
	timeSinceActivity := now.Sub(sessionData.LastActivity)
	activityRemaining := activityTimeout - timeSinceActivity

	// Return the smaller of the two (whichever expires first)
	var remaining time.Duration
	if lifetimeRemaining < activityRemaining {
		remaining = lifetimeRemaining
	} else {
		remaining = activityRemaining
	}

	if remaining < 0 {
		return 0, nil // Session has expired
	}

	return remaining, nil
}

// Close stops background cleanup and cleans up resources
func (am *AuthManager) Close() error {
	am.StopBackgroundCleanup()
	return nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// secureWipeString securely wipes a string's memory
func secureWipeString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Convert to byte slice and clear
	bytes := []byte(*s)
	crypto.SecureWipe(bytes)
	*s = ""
}

// generateSalt creates a cryptographically secure random salt
func (am *AuthManager) generateSalt() ([]byte, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// generateDeterministicSalt creates a deterministic salt from email for cross-device compatibility
func (am *AuthManager) generateDeterministicSalt(email string) []byte {
	// Use SHA-256 to generate a deterministic 32-byte salt from email
	// This ensures the same email always produces the same salt across devices
	hash := sha256.Sum256([]byte("commandchronicles-salt-v1:" + email))

	am.logger.Debug().
		Str("email", email).
		Msg("Generated deterministic salt for cross-device compatibility")

	return hash[:]
}

// DeriveKeys derives both local and remote keys from password and salt
func (am *AuthManager) DeriveKeys(password string, salt []byte) (*KeyDerivationResult, error) {
	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if len(salt) == 0 {
		return nil, errors.New("salt cannot be empty")
	}

	// Derive 64-byte key directly using Argon2id
	// Use the same parameters as the KeyDerivator but with 64 bytes output
	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		am.config.Security.Argon2Time,
		am.config.Security.Argon2Memory,
		am.config.Security.Argon2Threads,
		64, // Explicitly request 64 bytes
	)

	result := &KeyDerivationResult{
		LocalKey:      derivedKey,        // Full 64 bytes
		EncryptionKey: derivedKey,        // Full 64 bytes for encryption
		RemoteAuthKey: derivedKey[32:64], // Bytes 32-63 for server auth
		Salt:          salt,
	}

	am.logger.Debug().
		Int("local_key_length", len(result.LocalKey)).
		Int("encryption_key_length", len(result.EncryptionKey)).
		Int("remote_auth_key_length", len(result.RemoteAuthKey)).
		Msg("Derived keys with secure separation")

	return result, nil
}

// createKeyCheck creates encrypted verification data
func (am *AuthManager) createKeyCheck(key []byte) ([]byte, error) {
	// Generate random verification data
	checkData := make([]byte, 32)
	if _, err := rand.Read(checkData); err != nil {
		return nil, err
	}

	// Create cipher (use first 32 bytes for ChaCha20-Poly1305)
	aead, err := chacha20poly1305.NewX(key[:32])
	if err != nil {
		return nil, err
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt verification data
	encryptedCheck := aead.Seal(nonce, nonce, checkData, nil)
	return encryptedCheck, nil
}

// verifyKeyCheck verifies the key against stored verification data
func (am *AuthManager) verifyKeyCheck(key []byte, keyCheck []byte) error {
	// Create cipher (use first 32 bytes for ChaCha20-Poly1305)
	aead, err := chacha20poly1305.NewX(key[:32])
	if err != nil {
		return err
	}

	// Extract nonce and ciphertext
	if len(keyCheck) < aead.NonceSize() {
		return errors.New("invalid key check format")
	}

	nonce := keyCheck[:aead.NonceSize()]
	ciphertext := keyCheck[aead.NonceSize():]

	// Attempt to decrypt
	_, err = aead.Open(nil, nonce, ciphertext, nil)
	return err
}

// loadUser loads user data from file
func (am *AuthManager) loadUser() (*User, error) {
	data, err := os.ReadFile(am.userFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("user not initialized")
		}
		return nil, err
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	return &user, nil
}

// saveUser saves user data to file
func (am *AuthManager) saveUser(user *User) error {
	data, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(am.userFile), 0700); err != nil {
		return err
	}

	// Write with secure permissions
	return os.WriteFile(am.userFile, data, 0600)
}

// CleanupExpiredSessions removes expired session files
func (am *AuthManager) CleanupExpiredSessions() error {
	if !am.IsSessionActive() {
		return nil
	}

	// Check session timeout
	sessionInfo, err := os.Stat(am.sessionFile)
	if err != nil {
		return nil // Session file doesn't exist
	}

	timeout := time.Duration(ActivityTimeoutSeconds) * time.Second
	timeSinceLastActivity := time.Since(sessionInfo.ModTime())

	if timeSinceLastActivity > timeout {
		am.logger.WithFields(map[string]interface{}{
			"last_activity": sessionInfo.ModTime().Format(time.RFC3339),
			"timeout":       timeout.String(),
			"idle_time":     timeSinceLastActivity.String(),
		}).Info().Msg("Session expired, cleaning up")

		if err := am.LockSession(); err != nil {
			am.logger.WithError(err).Warn().Msg("Failed to cleanup expired session")
			return fmt.Errorf("failed to cleanup expired session: %w", err)
		} else {
			am.logger.Info().Msg("Expired session cleaned up successfully")
		}
	} else {
		// Log remaining time for debugging
		remaining := timeout - timeSinceLastActivity
		am.logger.WithFields(map[string]interface{}{
			"remaining_time": remaining.String(),
			"last_activity":  sessionInfo.ModTime().Format(time.RFC3339),
		}).Debug().Msg("Session still active")
	}

	return nil
}
