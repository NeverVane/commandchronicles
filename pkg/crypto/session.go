package crypto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// Session key management constants
const (
	// Default session timeout (3 months in seconds)
	DefaultSessionTimeout = 90 * 24 * 60 * 60 // 3 months
	
	// Session key length (32 bytes for XChaCha20-Poly1305)
	SessionKeyLength = 32
	
	// Session file version for future compatibility
	SessionFileVersion = 1
	
	// Memory protection constants
	MaxSessionKeys = 10
	SessionCleanupInterval = 5 * time.Minute
)

// SessionKeyManager handles secure session key storage and management
type SessionKeyManager struct {
	mu               sync.RWMutex
	sessionPath      string
	timeout          time.Duration
	keyDerivator     *KeyDerivator
	encryptor        *Encryptor
	logger           *logger.Logger
	activeKeys       map[string]*SessionKey
	lastCleanup      time.Time
	autoCleanupTicker *time.Ticker
}

// SessionKey represents an active session key with metadata
type SessionKey struct {
	Key        []byte
	CreatedAt  time.Time
	LastUsed   time.Time
	Username   string
	ExpiresAt  time.Time
	SessionID  string
}

// SessionFile represents the encrypted session file structure
type SessionFile struct {
	Version      int                    `json:"version"`
	CreatedAt    int64                  `json:"created_at"`
	Username     string                 `json:"username"`
	SessionID    string                 `json:"session_id"`
	ExpiresAt    int64                  `json:"expires_at"`
	WrappedKey   []byte                 `json:"wrapped_key"`
	KeySalt      []byte                 `json:"key_salt"`
	WrapperSalt  []byte                 `json:"wrapper_salt"`
	LastUsed     int64                  `json:"last_used"`
}

// NewSessionKeyManager creates a new session key manager
func NewSessionKeyManager(sessionPath string, timeout time.Duration) *SessionKeyManager {
	if timeout == 0 {
		timeout = DefaultSessionTimeout * time.Second
	}
	
	manager := &SessionKeyManager{
		sessionPath:  sessionPath,
		timeout:      timeout,
		keyDerivator: NewKeyDerivator(),
		encryptor:    NewEncryptor(),
		logger:       logger.GetLogger().Security(),
		activeKeys:   make(map[string]*SessionKey),
		lastCleanup:  time.Now(),
	}
	
	// Start automatic cleanup
	manager.startAutoCleanup()
	
	return manager
}

// StoreSessionKey securely stores a session key to disk
func (skm *SessionKeyManager) StoreSessionKey(username, password string, masterKey []byte) error {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	if len(masterKey) != SessionKeyLength {
		return fmt.Errorf("invalid master key length: %d, expected %d", len(masterKey), SessionKeyLength)
	}
	
	now := time.Now()
	sessionID := skm.generateSessionID()
	
	skm.logger.WithFields(map[string]interface{}{
		"username":   username,
		"session_id": sessionID,
	}).Info().Msg("Storing session key")
	
	// Generate wrapper key from password
	wrapperSalt, err := skm.keyDerivator.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate wrapper salt: %w", err)
	}
	
	wrapperKey, err := skm.keyDerivator.DeriveKey(password, wrapperSalt)
	if err != nil {
		return fmt.Errorf("failed to derive wrapper key: %w", err)
	}
	defer wrapperKey.SecureErase()
	
	// Encrypt the master key with wrapper key
	wrappedKey, err := skm.encryptor.EncryptBytes(masterKey, wrapperKey.Key)
	if err != nil {
		return fmt.Errorf("failed to wrap master key: %w", err)
	}
	
	// Create session file structure
	sessionFile := &SessionFile{
		Version:     SessionFileVersion,
		CreatedAt:   now.UnixMilli(),
		Username:    username,
		SessionID:   sessionID,
		ExpiresAt:   now.Add(skm.timeout).UnixMilli(),
		WrappedKey:  wrappedKey,
		KeySalt:     wrapperKey.Salt,
		WrapperSalt: wrapperSalt,
		LastUsed:    now.UnixMilli(),
	}
	
	// Serialize and write to file
	if err := skm.writeSessionFile(sessionFile); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}
	
	// Store in memory for immediate use
	sessionKey := &SessionKey{
		Key:       append([]byte(nil), masterKey...),
		CreatedAt: now,
		LastUsed:  now,
		Username:  username,
		ExpiresAt: now.Add(skm.timeout),
		SessionID: sessionID,
	}
	
	skm.activeKeys[sessionID] = sessionKey
	
	skm.logger.WithField("session_id", sessionID).Info().Msg("Session key stored successfully")
	return nil
}

// LoadSessionKey loads a session key from storage
func (skm *SessionKeyManager) LoadSessionKey(username, password string) (*SessionKey, error) {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	skm.logger.WithField("username", username).Debug().Msg("Loading session key")
	
	// Check if session file exists
	if _, err := os.Stat(skm.sessionPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("no session file found")
	}
	
	// Read and parse session file
	sessionFile, err := skm.readSessionFile()
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}
	
	// Verify username matches
	if sessionFile.Username != username {
		return nil, fmt.Errorf("session username mismatch")
	}
	
	// Check if session has expired
	if time.Now().UnixMilli() > sessionFile.ExpiresAt {
		skm.logger.WithField("username", username).Info().Msg("Session expired, removing")
		skm.removeSessionFile()
		return nil, fmt.Errorf("session expired")
	}
	
	// Derive wrapper key
	wrapperKey, err := skm.keyDerivator.DeriveKey(password, sessionFile.WrapperSalt)
	if err != nil {
		return nil, fmt.Errorf("failed to derive wrapper key: %w", err)
	}
	defer wrapperKey.SecureErase()
	
	// Unwrap master key
	masterKey, err := skm.encryptor.DecryptBytes(sessionFile.WrappedKey, wrapperKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap master key: %w", err)
	}
	
	// Update last used time
	sessionFile.LastUsed = time.Now().UnixMilli()
	if err := skm.writeSessionFile(sessionFile); err != nil {
		skm.logger.WithError(err).Warn().Msg("Failed to update session last used time")
	}
	
	// Create session key
	sessionKey := &SessionKey{
		Key:       masterKey,
		CreatedAt: time.UnixMilli(sessionFile.CreatedAt),
		LastUsed:  time.Now(),
		Username:  sessionFile.Username,
		ExpiresAt: time.UnixMilli(sessionFile.ExpiresAt),
		SessionID: sessionFile.SessionID,
	}
	
	skm.activeKeys[sessionFile.SessionID] = sessionKey
	
	skm.logger.WithField("session_id", sessionFile.SessionID).Info().Msg("Session key loaded successfully")
	return sessionKey, nil
}

// GetActiveKey returns an active session key if available
func (skm *SessionKeyManager) GetActiveKey(sessionID string) (*SessionKey, bool) {
	skm.mu.RLock()
	defer skm.mu.RUnlock()
	
	key, exists := skm.activeKeys[sessionID]
	if !exists {
		return nil, false
	}
	
	// Check if expired
	if time.Now().After(key.ExpiresAt) {
		skm.mu.RUnlock()
		skm.mu.Lock()
		delete(skm.activeKeys, sessionID)
		skm.mu.Unlock()
		skm.mu.RLock()
		return nil, false
	}
	
	// Update last used time
	key.LastUsed = time.Now()
	return key, true
}

// InvalidateSession removes a session from memory and disk
func (skm *SessionKeyManager) InvalidateSession(sessionID string) error {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	skm.logger.WithField("session_id", sessionID).Info().Msg("Invalidating session")
	
	// Remove from memory
	if key, exists := skm.activeKeys[sessionID]; exists {
		key.SecureErase()
		delete(skm.activeKeys, sessionID)
	}
	
	// Remove session file
	return skm.removeSessionFile()
}

// InvalidateAllSessions removes all active sessions
func (skm *SessionKeyManager) InvalidateAllSessions() error {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	skm.logger.Info().Msg("Invalidating all sessions")
	
	// Secure erase all keys in memory
	for sessionID, key := range skm.activeKeys {
		key.SecureErase()
		delete(skm.activeKeys, sessionID)
	}
	
	// Remove session file
	return skm.removeSessionFile()
}

// CleanupExpiredSessions removes expired sessions from memory
func (skm *SessionKeyManager) CleanupExpiredSessions() {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	now := time.Now()
	expired := 0
	
	for sessionID, key := range skm.activeKeys {
		if now.After(key.ExpiresAt) {
			key.SecureErase()
			delete(skm.activeKeys, sessionID)
			expired++
		}
	}
	
	if expired > 0 {
		skm.logger.WithField("expired_count", expired).Info().Msg("Cleaned up expired sessions")
	}
	
	skm.lastCleanup = now
}

// RotateSessionKey creates a new session with the same master key
func (skm *SessionKeyManager) RotateSessionKey(sessionID, password string) error {
	skm.mu.Lock()
	
	key, exists := skm.activeKeys[sessionID]
	if !exists {
		skm.mu.Unlock()
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	skm.logger.WithField("session_id", sessionID).Info().Msg("Rotating session key")
	
	// Create new session with same master key
	masterKeyCopy := append([]byte(nil), key.Key...)
	defer func() {
		for i := range masterKeyCopy {
			masterKeyCopy[i] = 0
		}
	}()
	
	username := key.Username
	
	// Remove old session
	key.SecureErase()
	delete(skm.activeKeys, sessionID)
	
	// Release lock before calling StoreSessionKey to avoid deadlock
	skm.mu.Unlock()
	
	// Store new session
	return skm.StoreSessionKey(username, password, masterKeyCopy)
}

// GetSessionStats returns statistics about active sessions
func (skm *SessionKeyManager) GetSessionStats() map[string]interface{} {
	skm.mu.RLock()
	defer skm.mu.RUnlock()
	
	return map[string]interface{}{
		"active_sessions":  len(skm.activeKeys),
		"last_cleanup":     skm.lastCleanup.Format(time.RFC3339),
		"session_timeout":  skm.timeout.String(),
		"max_sessions":     MaxSessionKeys,
	}
}

// Close stops the session manager and cleans up resources
func (skm *SessionKeyManager) Close() error {
	skm.mu.Lock()
	defer skm.mu.Unlock()
	
	skm.logger.Info().Msg("Closing session key manager")
	
	// Stop auto cleanup
	if skm.autoCleanupTicker != nil {
		skm.autoCleanupTicker.Stop()
	}
	
	// Secure erase all keys
	for sessionID, key := range skm.activeKeys {
		key.SecureErase()
		delete(skm.activeKeys, sessionID)
	}
	
	return nil
}

// SecureErase overwrites sensitive data in SessionKey
func (sk *SessionKey) SecureErase() {
	if sk.Key != nil {
		for i := range sk.Key {
			sk.Key[i] = 0
		}
		sk.Key = nil
	}
	sk.Username = ""
	sk.SessionID = ""
}

// IsExpired checks if the session key has expired
func (sk *SessionKey) IsExpired() bool {
	return time.Now().After(sk.ExpiresAt)
}

// TimeUntilExpiry returns the time until session expiry
func (sk *SessionKey) TimeUntilExpiry() time.Duration {
	return time.Until(sk.ExpiresAt)
}

// writeSessionFile writes session data to disk with secure permissions
func (skm *SessionKeyManager) writeSessionFile(sessionFile *SessionFile) error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(skm.sessionPath), 0700); err != nil {
		return fmt.Errorf("failed to create session directory: %w", err)
	}
	
	// Serialize to JSON
	data, err := json.Marshal(sessionFile)
	if err != nil {
		return fmt.Errorf("failed to marshal session file: %w", err)
	}
	
	// Write with secure permissions
	if err := os.WriteFile(skm.sessionPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write session file: %w", err)
	}
	
	return nil
}

// readSessionFile reads and parses session data from disk
func (skm *SessionKeyManager) readSessionFile() (*SessionFile, error) {
	data, err := os.ReadFile(skm.sessionPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read session file: %w", err)
	}
	
	var sessionFile SessionFile
	if err := json.Unmarshal(data, &sessionFile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session file: %w", err)
	}
	
	return &sessionFile, nil
}

// removeSessionFile securely removes the session file
func (skm *SessionKeyManager) removeSessionFile() error {
	if _, err := os.Stat(skm.sessionPath); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to remove
	}
	
	// Overwrite file with random data before deletion
	if file, err := os.OpenFile(skm.sessionPath, os.O_WRONLY, 0600); err == nil {
		stat, _ := file.Stat()
		if stat != nil {
			randomData := make([]byte, stat.Size())
			rand.Read(randomData)
			file.WriteAt(randomData, 0)
		}
		file.Close()
	}
	
	return os.Remove(skm.sessionPath)
}

// generateSessionID generates a unique session identifier
func (skm *SessionKeyManager) generateSessionID() string {
	sessionBytes := make([]byte, 16)
	rand.Read(sessionBytes)
	return fmt.Sprintf("%x", sessionBytes)
}

// startAutoCleanup starts the automatic cleanup routine
func (skm *SessionKeyManager) startAutoCleanup() {
	skm.autoCleanupTicker = time.NewTicker(SessionCleanupInterval)
	go func() {
		for range skm.autoCleanupTicker.C {
			skm.CleanupExpiredSessions()
		}
	}()
}