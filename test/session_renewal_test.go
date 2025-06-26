package test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/login"
)

func TestSessionRenewalAfterPasswordChange(t *testing.T) {
	// Setup test environment
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tempDir, "test.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			Argon2Time:     1, // Reduced for testing speed
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: filepath.Join(tempDir, "session.json"),
		},
		Sync: config.SyncConfig{
			Enabled: false, // Disable sync for this test
		},
	}

	// Create login manager
	loginMgr, err := login.NewLoginManager(cfg)
	require.NoError(t, err)
	defer loginMgr.Close()

	username := "testuser"
	initialPassword := "initialPassword123"
	newPassword := "newPassword456"

	t.Run("Initialize User and Session", func(t *testing.T) {
		// Initialize user
		err := loginMgr.InitUser(username, initialPassword, false, "")
		require.NoError(t, err)

		// Verify we can login with initial password
		result, err := loginMgr.Login(initialPassword)
		require.NoError(t, err)
		assert.True(t, result.LocalSuccess)

		// Verify session is active
		assert.True(t, loginMgr.AuthManager.IsSessionActive())
	})

	t.Run("Verify Session Active Before Password Change", func(t *testing.T) {
		// Session should be active
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), "Session should be active before password change")
	})

	t.Run("Change Password and Verify Session Renewal", func(t *testing.T) {
		// Change password
		err := loginMgr.ChangePassword(initialPassword, newPassword)
		require.NoError(t, err)

		// Critical test: Session should still be active after password change
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), 
			"Session should remain active after password change")
	})

	t.Run("Verify Session Remains Active After Password Change", func(t *testing.T) {
		// Session should still be active with new key
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), 
			"Session should remain active after password change")
	})

	t.Run("Verify New Password Works", func(t *testing.T) {
		// Lock session to test new password
		err := loginMgr.AuthManager.LockSession()
		require.NoError(t, err)

		// Should be able to login with new password
		result, err := loginMgr.Login(newPassword)
		require.NoError(t, err)
		assert.True(t, result.LocalSuccess)
	})

	t.Run("Verify Old Password No Longer Works", func(t *testing.T) {
		// Lock session to test old password
		err := loginMgr.AuthManager.LockSession()
		require.NoError(t, err)

		// Should NOT be able to login with old password
		_, err = loginMgr.Login(initialPassword)
		assert.Error(t, err, "Old password should not work after password change")
		assert.Contains(t, err.Error(), "invalid password")
	})
}

func TestSessionRenewalWithKeyVerification(t *testing.T) {
	// Setup test environment
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tempDir, "test.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			Argon2Time:     1,
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: filepath.Join(tempDir, "session.json"),
		},
		Sync: config.SyncConfig{
			Enabled: false,
		},
	}

	loginMgr, err := login.NewLoginManager(cfg)
	require.NoError(t, err)
	defer loginMgr.Close()

	username := "testuser2"
	oldPassword := "oldPassword123"
	newPassword := "newPassword456"

	// Initialize and login
	err = loginMgr.InitUser(username, oldPassword, false, "")
	require.NoError(t, err)

	t.Run("Change Password and Verify Session Continuity", func(t *testing.T) {
		// Verify session is active before
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), "Session should be active before password change")

		// Change password
		err := loginMgr.ChangePassword(oldPassword, newPassword)
		require.NoError(t, err)

		// Verify session remains active after
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), "Session should remain active after password change")
	})
}

func TestPasswordChangeSessionEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tempDir, "test.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			Argon2Time:     1,
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: filepath.Join(tempDir, "session.json"),
		},
		Sync: config.SyncConfig{
			Enabled: false,
		},
	}

	t.Run("Password Change With Expired Session", func(t *testing.T) {
		loginMgr, err := login.NewLoginManager(cfg)
		require.NoError(t, err)
		defer loginMgr.Close()

		// Initialize user
		err = loginMgr.InitUser("testuser3", "password123", false, "")
		require.NoError(t, err)

		// Manually expire session by removing session file
		err = loginMgr.AuthManager.LockSession()
		require.NoError(t, err)

		// Should still be able to change password (will require re-authentication)
		err = loginMgr.ChangePassword("password123", "newPassword789")
		require.NoError(t, err)

		// Verify new password works
		result, err := loginMgr.Login("newPassword789")
		require.NoError(t, err)
		assert.True(t, result.LocalSuccess)
	})

	t.Run("Multiple Rapid Password Changes", func(t *testing.T) {
		loginMgr, err := login.NewLoginManager(cfg)
		require.NoError(t, err)
		defer loginMgr.Close()

		// Initialize user
		err = loginMgr.InitUser("testuser4", "initial123", false, "")
		require.NoError(t, err)

		passwords := []string{"initial123", "second456", "third789", "final012"}

		// Perform multiple password changes
		for i := 0; i < len(passwords)-1; i++ {
			currentPassword := passwords[i]
			nextPassword := passwords[i+1]

			err = loginMgr.ChangePassword(currentPassword, nextPassword)
			require.NoError(t, err, "Password change %d should succeed", i+1)

			// Session should remain active after each change
			assert.True(t, loginMgr.AuthManager.IsSessionActive(), 
				"Session should be active after password change %d", i+1)
		}

		// Final verification with last password
		err = loginMgr.AuthManager.LockSession()
		require.NoError(t, err)

		result, err := loginMgr.Login("final012")
		require.NoError(t, err)
		assert.True(t, result.LocalSuccess)
	})
}

func TestSessionKeyUpdate(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Database: config.DatabaseConfig{
			Path: filepath.Join(tempDir, "test.db"),
		},
		Security: config.SecurityConfig{
			Argon2Time:     1,
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: filepath.Join(tempDir, "session.json"),
		},
		Sync: config.SyncConfig{
			Enabled: false,
		},
	}

	loginMgr, err := login.NewLoginManager(cfg)
	require.NoError(t, err)
	defer loginMgr.Close()

	// Initialize user and get initial session
	err = loginMgr.InitUser("testuser5", "password123", false, "")
	require.NoError(t, err)

	// Get session key before password change
	oldSessionKey, err := loginMgr.AuthManager.LoadSessionKey()
	require.NoError(t, err)

	// Change password
	err = loginMgr.ChangePassword("password123", "newPassword456")
	require.NoError(t, err)

	// Get session key after password change
	newSessionKey, err := loginMgr.AuthManager.LoadSessionKey()
	require.NoError(t, err)

	t.Run("Session Key Updated", func(t *testing.T) {
		// Session keys should be different (derived from different passwords)
		assert.NotEqual(t, oldSessionKey, newSessionKey, 
			"Session key should be updated after password change")
	})

	t.Run("New Session Key Works", func(t *testing.T) {
		// Should have active session with new session key
		assert.True(t, loginMgr.AuthManager.IsSessionActive(), "Session should be active with new session key")
	})
}

// Benchmark to ensure password change with session renewal is performant
func BenchmarkPasswordChangeWithSessionRenewal(b *testing.B) {
	tempDir := b.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tempDir, "bench.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			Argon2Time:     1, // Fast for benchmarking
			Argon2Memory:   1024,
			Argon2Threads:  1,
			SessionKeyPath: filepath.Join(tempDir, "session.json"),
		},
		Sync: config.SyncConfig{
			Enabled: false,
		},
	}

	loginMgr, err := login.NewLoginManager(cfg)
	if err != nil {
		b.Fatal(err)
	}
	defer loginMgr.Close()

	// Initialize user
	err = loginMgr.InitUser("benchuser", "password123", false, "")
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oldPassword := "password123"
		newPassword := "newPassword456"
		
		if i%2 == 1 {
			oldPassword, newPassword = newPassword, oldPassword
		}

		err := loginMgr.ChangePassword(oldPassword, newPassword)
		if err != nil {
			b.Fatal(err)
		}

		// Verify session is still active
		if !loginMgr.AuthManager.IsSessionActive() {
			b.Fatal("Session should remain active after password change")
		}
	}
}