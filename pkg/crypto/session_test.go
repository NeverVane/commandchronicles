package crypto

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionKeyManager(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	assert.NotNil(t, manager)
	assert.Equal(t, sessionPath, manager.sessionPath)
	assert.Equal(t, time.Hour, manager.timeout)
	assert.NotNil(t, manager.keyDerivator)
	assert.NotNil(t, manager.encryptor)
	assert.NotNil(t, manager.logger)
	assert.NotNil(t, manager.activeKeys)
}

func TestNewSessionKeyManager_DefaultTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, 0)
	defer manager.Close()

	assert.Equal(t, DefaultSessionTimeout*time.Second, manager.timeout)
}

func TestStoreSessionKey_ValidKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword123"
	masterKey := make([]byte, SessionKeyLength)
	copy(masterKey, "test_master_key_32_bytes_long!!!")

	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Verify session file was created
	assert.FileExists(t, sessionPath)

	// Verify file permissions
	info, err := os.Stat(sessionPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Verify session was added to memory
	assert.Len(t, manager.activeKeys, 1)
}

func TestStoreSessionKey_InvalidKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	tests := []struct {
		name      string
		keyLength int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			masterKey := make([]byte, tt.keyLength)
			err := manager.StoreSessionKey("user", "pass", masterKey)
			assert.Error(t, err)
		})
	}
}

func TestLoadSessionKey_ValidSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword123"
	masterKey := make([]byte, SessionKeyLength)
	copy(masterKey, "test_master_key_32_bytes_long!!!")

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Clear memory to test loading from disk
	manager.activeKeys = make(map[string]*SessionKey)

	// Load session
	sessionKey, err := manager.LoadSessionKey(username, password)
	require.NoError(t, err)
	require.NotNil(t, sessionKey)

	// Verify key data
	assert.True(t, bytes.Equal(masterKey, sessionKey.Key))
	assert.Equal(t, username, sessionKey.Username)
	assert.False(t, sessionKey.IsExpired())
}

func TestLoadSessionKey_NoSessionFile(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "nonexistent")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	_, err := manager.LoadSessionKey("user", "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no session file found")
}

func TestLoadSessionKey_WrongPassword(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "correctpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store with correct password
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Try to load with wrong password
	_, err = manager.LoadSessionKey(username, "wrongpassword")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unwrap master key")
}

func TestLoadSessionKey_WrongUsername(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Try to load with different username
	_, err = manager.LoadSessionKey("wronguser", password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session username mismatch")
}

func TestLoadSessionKey_ExpiredSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	// Create manager with very short timeout
	manager := NewSessionKeyManager(sessionPath, time.Millisecond)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to load expired session
	_, err = manager.LoadSessionKey(username, password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session expired")

	// Verify session file was removed
	assert.NoFileExists(t, sessionPath)
}

func TestGetActiveKey_ValidKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Get session ID
	require.Len(t, manager.activeKeys, 1)
	var sessionID string
	for id := range manager.activeKeys {
		sessionID = id
		break
	}

	// Get active key
	key, exists := manager.GetActiveKey(sessionID)
	assert.True(t, exists)
	assert.NotNil(t, key)
	assert.Equal(t, username, key.Username)
}

func TestGetActiveKey_NonExistentKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	key, exists := manager.GetActiveKey("nonexistent")
	assert.False(t, exists)
	assert.Nil(t, key)
}

func TestGetActiveKey_ExpiredKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Millisecond)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Get session ID
	var sessionID string
	for id := range manager.activeKeys {
		sessionID = id
		break
	}

	// Wait for expiration
	time.Sleep(10 * time.Millisecond)

	// Try to get expired key
	key, exists := manager.GetActiveKey(sessionID)
	assert.False(t, exists)
	assert.Nil(t, key)

	// Verify key was removed from memory
	assert.Len(t, manager.activeKeys, 0)
}

func TestInvalidateSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Get session ID
	var sessionID string
	for id := range manager.activeKeys {
		sessionID = id
		break
	}

	// Verify session exists
	assert.Len(t, manager.activeKeys, 1)
	assert.FileExists(t, sessionPath)

	// Invalidate session
	err = manager.InvalidateSession(sessionID)
	assert.NoError(t, err)

	// Verify session was removed
	assert.Len(t, manager.activeKeys, 0)
	assert.NoFileExists(t, sessionPath)
}

func TestInvalidateAllSessions(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	// Store multiple sessions (simulate multiple keys in memory)
	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Add another key to memory directly for testing
	sessionKey := &SessionKey{
		Key:       make([]byte, SessionKeyLength),
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Username:  "user2",
		ExpiresAt: time.Now().Add(time.Hour),
		SessionID: "test-session-2",
	}
	manager.activeKeys["test-session-2"] = sessionKey

	// Verify sessions exist
	assert.Len(t, manager.activeKeys, 2)
	assert.FileExists(t, sessionPath)

	// Invalidate all sessions
	err = manager.InvalidateAllSessions()
	assert.NoError(t, err)

	// Verify all sessions were removed
	assert.Len(t, manager.activeKeys, 0)
	assert.NoFileExists(t, sessionPath)
}

func TestCleanupExpiredSessions(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	now := time.Now()

	// Add expired and valid sessions to memory
	expiredKey := &SessionKey{
		Key:       make([]byte, SessionKeyLength),
		CreatedAt: now.Add(-2 * time.Hour),
		LastUsed:  now.Add(-time.Hour),
		Username:  "expired_user",
		ExpiresAt: now.Add(-time.Minute), // Expired
		SessionID: "expired-session",
	}

	validKey := &SessionKey{
		Key:       make([]byte, SessionKeyLength),
		CreatedAt: now,
		LastUsed:  now,
		Username:  "valid_user",
		ExpiresAt: now.Add(time.Hour), // Still valid
		SessionID: "valid-session",
	}

	manager.activeKeys["expired-session"] = expiredKey
	manager.activeKeys["valid-session"] = validKey

	// Verify both sessions exist
	assert.Len(t, manager.activeKeys, 2)

	// Cleanup expired sessions
	manager.CleanupExpiredSessions()

	// Verify only valid session remains
	assert.Len(t, manager.activeKeys, 1)
	_, exists := manager.activeKeys["valid-session"]
	assert.True(t, exists)
	_, exists = manager.activeKeys["expired-session"]
	assert.False(t, exists)
}

func TestRotateSessionKey(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)
	copy(masterKey, "original_master_key_32_bytes!!")

	// Store initial session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Get original session ID
	var originalSessionID string
	for id := range manager.activeKeys {
		originalSessionID = id
		break
	}

	// Rotate session key
	err = manager.RotateSessionKey(originalSessionID, password)
	require.NoError(t, err)

	// Verify old session was removed and new one exists
	_, exists := manager.activeKeys[originalSessionID]
	assert.False(t, exists)
	assert.Len(t, manager.activeKeys, 1)

	// Verify new session has same master key
	for _, key := range manager.activeKeys {
		assert.True(t, bytes.Equal(masterKey, key.Key))
		assert.Equal(t, username, key.Username)
	}
}

func TestRotateSessionKey_NonExistentSession(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	err := manager.RotateSessionKey("nonexistent", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session not found")
}

func TestGetSessionStats(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	// Add some sessions
	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	stats := manager.GetSessionStats()

	assert.Equal(t, 1, stats["active_sessions"])
	assert.Equal(t, time.Hour.String(), stats["session_timeout"])
	assert.Equal(t, MaxSessionKeys, stats["max_sessions"])
	assert.Contains(t, stats, "last_cleanup")
}

func TestClose(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)

	// Add a session
	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)

	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Verify session exists
	assert.Len(t, manager.activeKeys, 1)

	// Close manager
	err = manager.Close()
	assert.NoError(t, err)

	// Verify all sessions were securely erased
	assert.Len(t, manager.activeKeys, 0)
}

func TestSessionKey_SecureErase(t *testing.T) {
	key := &SessionKey{
		Key:       make([]byte, SessionKeyLength),
		Username:  "testuser",
		SessionID: "test-session",
	}

	// Fill key with test data
	copy(key.Key, "test_key_data_32_bytes_long!!")

	// Verify data exists
	assert.NotNil(t, key.Key)
	assert.NotEmpty(t, key.Username)
	assert.NotEmpty(t, key.SessionID)

	// Secure erase
	key.SecureErase()

	// Verify data was cleared
	assert.Nil(t, key.Key)
	assert.Empty(t, key.Username)
	assert.Empty(t, key.SessionID)
}

func TestSessionKey_IsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"not expired", now.Add(time.Hour), false},
		{"expired", now.Add(-time.Hour), true},
		{"just expired", now.Add(-time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &SessionKey{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, key.IsExpired())
		})
	}
}

func TestSessionKey_TimeUntilExpiry(t *testing.T) {
	now := time.Now()
	key := &SessionKey{ExpiresAt: now.Add(time.Hour)}

	duration := key.TimeUntilExpiry()

	// Should be approximately 1 hour (within a few milliseconds)
	assert.True(t, duration > 59*time.Minute)
	assert.True(t, duration <= time.Hour)
}

func TestCrossDeviceSessionCompatibility(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	// Simulate Device 1
	manager1 := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager1.Close()

	username := "testuser"
	password := "testpassword123"

	// Derive master key using same credentials (simulating deterministic key derivation)
	kd := NewKeyDerivator()
	derivedKey, err := kd.DeriveKeyFromCredentials(username, password)
	require.NoError(t, err)
	defer derivedKey.SecureErase()

	// Store session on Device 1
	err = manager1.StoreSessionKey(username, password, derivedKey.Key)
	require.NoError(t, err)

	// Simulate Device 2 (new manager instance)
	manager2 := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager2.Close()

	// Load session on Device 2 with same credentials
	sessionKey, err := manager2.LoadSessionKey(username, password)
	require.NoError(t, err)

	// Verify same master key was recovered
	assert.True(t, bytes.Equal(derivedKey.Key, sessionKey.Key))
	assert.Equal(t, username, sessionKey.Username)
}

func TestSessionFileSecurity(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "testuser"
	password := "testpassword"
	masterKey := make([]byte, SessionKeyLength)
	copy(masterKey, "secret_master_key_32_bytes!!!")

	// Store session
	err := manager.StoreSessionKey(username, password, masterKey)
	require.NoError(t, err)

	// Read session file directly
	data, err := os.ReadFile(sessionPath)
	require.NoError(t, err)

	// Verify master key is not stored in plaintext
	assert.NotContains(t, string(data), "secret_master_key_32_bytes!!!")

	// Verify password is not stored
	assert.NotContains(t, string(data), password)

	// Verify username is stored (needed for verification)
	assert.Contains(t, string(data), username)
}

func TestAutoCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	now := time.Now()

	// Add expired session
	expiredKey := &SessionKey{
		Key:       make([]byte, SessionKeyLength),
		ExpiresAt: now.Add(-time.Minute),
		SessionID: "expired",
	}
	manager.activeKeys["expired"] = expiredKey

	// Verify expired session exists
	assert.Len(t, manager.activeKeys, 1)

	// Trigger cleanup manually (auto cleanup runs in background)
	manager.CleanupExpiredSessions()

	// Verify expired session was removed
	assert.Len(t, manager.activeKeys, 0)
}

// Benchmark tests
func BenchmarkStoreSessionKey(b *testing.B) {
	tmpDir := b.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	masterKey := make([]byte, SessionKeyLength)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		username := fmt.Sprintf("user%d", i)
		password := "password"

		err := manager.StoreSessionKey(username, password, masterKey)
		if err != nil {
			b.Fatal(err)
		}

		// Clean up for next iteration
		manager.InvalidateAllSessions()
	}
}

func BenchmarkLoadSessionKey(b *testing.B) {
	tmpDir := b.TempDir()
	sessionPath := filepath.Join(tmpDir, "session")

	manager := NewSessionKeyManager(sessionPath, time.Hour)
	defer manager.Close()

	username := "benchuser"
	password := "password"
	masterKey := make([]byte, SessionKeyLength)

	// Store once
	err := manager.StoreSessionKey(username, password, masterKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Clear memory to force loading from disk
		manager.activeKeys = make(map[string]*SessionKey)

		_, err := manager.LoadSessionKey(username, password)
		if err != nil {
			b.Fatal(err)
		}
	}
}
