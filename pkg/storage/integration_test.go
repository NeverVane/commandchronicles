package storage

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/NeverVane/commandchronicles/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureStorage_CompleteWorkflow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

	t.Run("complete storage lifecycle", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		// 1. Initial state - storage should be locked
		assert.True(t, ss.IsLocked())

		// 2. Unlock with credentials
		err := ss.Unlock("testuser", "securepassword123")
		require.NoError(t, err)
		assert.False(t, ss.IsLocked())

		// 3. Store multiple command records
		commands := []string{
			"git clone https://github.com/user/repo.git",
			"cd repo && npm install",
			"npm run build",
			"docker build -t myapp .",
			"docker run -p 3000:3000 myapp",
		}

		var storedRecords []*StoreResult
		for i, cmd := range commands {
			record := storage.NewCommandRecord(
				cmd,
				0,
				int64(100*(i+1)), // Varying durations
				"/workspace",
				"dev-session-123",
				"dev-machine",
			)
			record.User = "testuser"
			record.Shell = "zsh"

			result, err := ss.Store(record)
			require.NoError(t, err)
			require.NotNil(t, result)
			storedRecords = append(storedRecords, result)
		}

		// 4. Retrieve all records
		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, retrieveResult.Records, 5)
		assert.Equal(t, int64(5), retrieveResult.TotalCount)
		assert.False(t, retrieveResult.HasMore)

		// 5. Verify record integrity
		for i, record := range retrieveResult.Records {
			assert.Equal(t, commands[len(commands)-1-i], record.Command) // Reverse order (newest first)
			assert.Equal(t, "testuser", record.User)
			assert.Equal(t, "zsh", record.Shell)
			assert.Equal(t, "dev-session-123", record.SessionID)
		}

		// 6. Query with filters
		sessionFilterResult, err := ss.Retrieve(&QueryOptions{
			SessionID: "dev-session-123",
			Limit:     10,
		})
		require.NoError(t, err)
		assert.Len(t, sessionFilterResult.Records, 5)

		// 7. Delete some records
		err = ss.Delete([]int64{storedRecords[0].RecordID, storedRecords[1].RecordID})
		require.NoError(t, err)

		// 8. Verify deletion
		afterDeleteResult, err := ss.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, afterDeleteResult.Records, 3)

		// 9. Check statistics
		stats := ss.GetStats()
		assert.Equal(t, int64(5), stats.RecordsStored)
		assert.Equal(t, int64(2), stats.RecordsRetrieved) // Two retrieve operations
		assert.Greater(t, stats.BytesEncrypted, int64(0))
		assert.Greater(t, stats.BytesDecrypted, int64(0))

		// 10. Validate integrity
		err = ss.ValidateIntegrity()
		assert.NoError(t, err)

		// 11. Lock storage
		err = ss.Lock()
		require.NoError(t, err)
		assert.True(t, ss.IsLocked())

		// 12. Verify operations fail when locked
		_, err = ss.Store(storage.NewCommandRecord("test", 0, 100, "/tmp", "session", "host"))
		assert.Error(t, err)
		assert.Equal(t, ErrStorageLocked, err)
	})
}

func TestSecureStorage_CrossDeviceCompatibility(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	// Simulate two different "devices" with shared credentials
	device1Dir := t.TempDir()
	device2Dir := t.TempDir()

	// Create same database file path for both devices
	sharedDBPath := filepath.Join(device1Dir, "shared.db")

	cfg1 := createTestConfig(device1Dir)
	cfg1.Database.Path = sharedDBPath

	cfg2 := createTestConfig(device2Dir)
	cfg2.Database.Path = sharedDBPath

	username := "crossdeviceuser"
	password := "crossdevicepassword123"

	t.Run("encrypt on device1 and decrypt on device2", func(t *testing.T) {
		// Device 1: Store encrypted data
		ss1 := createSecureStorage(t, cfg1)
		defer ss1.Close()

		err := ss1.Unlock(username, password)
		require.NoError(t, err)

		originalRecord := storage.NewCommandRecord(
			"kubectl apply -f deployment.yaml",
			0,
			2500,
			"/k8s/manifests",
			"deploy-session",
			"ci-server",
		)
		originalRecord.User = username
		originalRecord.Shell = "bash"

		storeResult, err := ss1.Store(originalRecord)
		require.NoError(t, err)
		require.NotNil(t, storeResult)

		// Close device 1
		ss1.Close()

		// Device 2: Retrieve and decrypt same data
		ss2 := createSecureStorage(t, cfg2)
		defer ss2.Close()

		err = ss2.Unlock(username, password)
		require.NoError(t, err)

		retrieveResult, err := ss2.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		require.Len(t, retrieveResult.Records, 1)

		decryptedRecord := retrieveResult.Records[0]
		assert.Equal(t, originalRecord.Command, decryptedRecord.Command)
		assert.Equal(t, originalRecord.User, decryptedRecord.User)
		assert.Equal(t, originalRecord.Shell, decryptedRecord.Shell)
		assert.Equal(t, originalRecord.SessionID, decryptedRecord.SessionID)
		assert.Equal(t, originalRecord.Hostname, decryptedRecord.Hostname)
	})
}

func TestSecureStorage_SecurityIntegration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

	t.Run("permission enforcement integration", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		// Verify all files have secure permissions
		pe := security.NewPermissionEnforcer()

		// Check database file permissions
		assert.True(t, pe.IsFileSecure(cfg.Database.Path))

		// Unlock to create session file
		err := ss.Unlock("securityuser", "securitypass123")
		require.NoError(t, err)

		// Check session file permissions
		assert.True(t, pe.IsFileSecure(cfg.Security.SessionKeyPath))

		// Store a record to ensure database operations work with secure permissions
		record := storage.NewCommandRecord(
			"rm -rf /tmp/sensitive-data",
			0,
			150,
			"/tmp",
			"security-session",
			"secure-host",
		)

		result, err := ss.Store(record)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Verify record can be retrieved
		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: 1})
		require.NoError(t, err)
		assert.Len(t, retrieveResult.Records, 1)
		assert.Equal(t, record.Command, retrieveResult.Records[0].Command)
	})

	t.Run("crypto component integration", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		err := ss.Unlock("cryptouser", "cryptopass123")
		require.NoError(t, err)

		// Test that the same credentials produce consistent encryption/decryption
		record1 := storage.NewCommandRecord("echo 'test1'", 0, 100, "/tmp", "session1", "host1")
		record2 := storage.NewCommandRecord("echo 'test2'", 0, 100, "/tmp", "session1", "host1")

		// Store both records
		_, err = ss.Store(record1)
		require.NoError(t, err)
		_, err = ss.Store(record2)
		require.NoError(t, err)

		// Lock and unlock again
		ss.Lock()
		err = ss.Unlock("cryptouser", "cryptopass123")
		require.NoError(t, err)

		// Should still be able to decrypt existing records
		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, retrieveResult.Records, 2)

		// Verify both records are correctly decrypted
		commands := make(map[string]bool)
		for _, record := range retrieveResult.Records {
			commands[record.Command] = true
		}
		assert.True(t, commands["echo 'test1'"])
		assert.True(t, commands["echo 'test2'"])
	})
}

func TestSecureStorage_PerformanceAndConcurrency(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

	t.Run("bulk operations performance", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		err := ss.Unlock("perfuser", "perfpass123")
		require.NoError(t, err)

		const numRecords = 100
		start := time.Now()

		// Bulk store
		var storeResults []*StoreResult
		for i := 0; i < numRecords; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("command_%d", i),
				i%2, // Alternate exit codes
				int64(50+i*10),
				"/workspace",
				fmt.Sprintf("session_%d", i%10),
				"perf-host",
			)

			result, err := ss.Store(record)
			require.NoError(t, err)
			storeResults = append(storeResults, result)
		}

		storeTime := time.Since(start)
		t.Logf("Stored %d records in %v (avg: %v per record)",
			numRecords, storeTime, storeTime/numRecords)

		// Bulk retrieve
		start = time.Now()
		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: numRecords * 2})
		require.NoError(t, err)
		retrieveTime := time.Since(start)

		assert.Len(t, retrieveResult.Records, numRecords)
		t.Logf("Retrieved %d records in %v (avg: %v per record)",
			numRecords, retrieveTime, retrieveTime/numRecords)

		// Verify reasonable performance (should be much faster than 1 second per record)
		assert.Less(t, storeTime, time.Duration(numRecords)*100*time.Millisecond)
		assert.Less(t, retrieveTime, time.Duration(numRecords)*10*time.Millisecond)
	})

	t.Run("concurrent read operations", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		err := ss.Unlock("concurrentuser", "concurrentpass123")
		require.NoError(t, err)

		// Store some initial data
		for i := 0; i < 20; i++ {
			record := storage.NewCommandRecord(
				fmt.Sprintf("concurrent_cmd_%d", i),
				0,
				100,
				"/tmp",
				"concurrent-session",
				"concurrent-host",
			)
			_, err := ss.Store(record)
			require.NoError(t, err)
		}

		// Concurrent read operations
		const numGoroutines = 10
		const readsPerGoroutine = 5

		var wg sync.WaitGroup
		errChan := make(chan error, numGoroutines*readsPerGoroutine)

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()

				for j := 0; j < readsPerGoroutine; j++ {
					result, err := ss.Retrieve(&QueryOptions{
						Limit:  5,
						Offset: j * 2,
					})
					if err != nil {
						errChan <- err
						return
					}
					if len(result.Records) == 0 {
						errChan <- fmt.Errorf("worker %d: no records retrieved", workerID)
						return
					}
				}
			}(i)
		}

		wg.Wait()
		close(errChan)

		// Check for errors
		for err := range errChan {
			require.NoError(t, err)
		}
	})
}

func TestSecureStorage_ErrorRecovery(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

	t.Run("recovery from locked state", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		// Initial unlock and store
		err := ss.Unlock("recoveryuser", "recoverypass123")
		require.NoError(t, err)

		record := storage.NewCommandRecord("test command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		// Lock the storage
		err = ss.Lock()
		require.NoError(t, err)
		assert.True(t, ss.IsLocked())

		// Verify operations fail when locked
		_, err = ss.Store(record)
		assert.Error(t, err)
		assert.Equal(t, ErrStorageLocked, err)

		// Unlock again and verify operations work
		err = ss.Unlock("recoveryuser", "recoverypass123")
		require.NoError(t, err)
		assert.False(t, ss.IsLocked())

		// Should be able to store and retrieve again
		_, err = ss.Store(record)
		assert.NoError(t, err)

		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, retrieveResult.Records, 2) // Original + new record
	})

	t.Run("wrong credentials handling", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		// Set up with correct credentials
		err := ss.Unlock("wrongcreduser", "correctpass123")
		require.NoError(t, err)

		record := storage.NewCommandRecord("important command", 0, 100, "/tmp", "session", "host")
		_, err = ss.Store(record)
		require.NoError(t, err)

		// Lock and try wrong credentials
		ss.Lock()

		err = ss.Unlock("wrongcreduser", "wrongpassword")
		assert.Error(t, err)
		assert.True(t, ss.IsLocked())

		err = ss.Unlock("wronguser", "correctpass123")
		assert.Error(t, err)
		assert.True(t, ss.IsLocked())

		// Correct credentials should still work
		err = ss.Unlock("wrongcreduser", "correctpass123")
		require.NoError(t, err)
		assert.False(t, ss.IsLocked())

		// Data should still be accessible
		retrieveResult, err := ss.Retrieve(&QueryOptions{Limit: 10})
		require.NoError(t, err)
		assert.Len(t, retrieveResult.Records, 1)
		assert.Equal(t, "important command", retrieveResult.Records[0].Command)
	})
}

func TestSecureStorage_RealWorldScenarios(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping integration tests on Windows")
	}

	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

	t.Run("development workflow simulation", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		err := ss.Unlock("developer", "devpass123")
		require.NoError(t, err)

		// Simulate a development session
		devCommands := []struct {
			command   string
			exitCode  int
			duration  int64
			directory string
		}{
			{"git status", 0, 150, "/home/dev/project"},
			{"git add .", 0, 200, "/home/dev/project"},
			{"git commit -m 'Add new feature'", 0, 300, "/home/dev/project"},
			{"npm test", 1, 15000, "/home/dev/project"}, // Failed test
			{"npm test", 0, 12000, "/home/dev/project"}, // Fixed test
			{"git push origin main", 0, 2000, "/home/dev/project"},
			{"docker build -t myapp:latest .", 0, 45000, "/home/dev/project"},
			{"docker run -p 3000:3000 myapp:latest", 0, 1000, "/home/dev/project"},
		}

		sessionID := "dev-session-" + fmt.Sprintf("%d", time.Now().Unix())

		for i, cmd := range devCommands {
			record := storage.NewCommandRecord(
				cmd.command,
				cmd.exitCode,
				cmd.duration,
				cmd.directory,
				sessionID,
				"dev-laptop",
			)
			record.User = "developer"
			record.Shell = "zsh"

			// Add some realistic timestamps
			record.Timestamp = time.Now().Add(-time.Duration(len(devCommands)-i) * time.Minute).UnixMilli()

			_, err := ss.Store(record)
			require.NoError(t, err)
		}

		// Query failed commands
		failedResult, err := ss.Retrieve(&QueryOptions{
			SessionID: sessionID,
			Limit:     10,
		})
		require.NoError(t, err)

		failedCommands := 0
		for _, record := range failedResult.Records {
			if record.ExitCode != 0 {
				failedCommands++
			}
		}
		assert.Equal(t, 1, failedCommands) // One failed test

		// Query by directory
		projectResult, err := ss.Retrieve(&QueryOptions{
			Limit: 20,
		})
		require.NoError(t, err)
		assert.Len(t, projectResult.Records, len(devCommands))

		// Verify command order (should be reverse chronological)
		assert.Equal(t, "docker run -p 3000:3000 myapp:latest", projectResult.Records[0].Command)
		assert.Equal(t, "git status", projectResult.Records[len(devCommands)-1].Command)
	})

	t.Run("long running session simulation", func(t *testing.T) {
		ss := createSecureStorage(t, cfg)
		defer ss.Close()

		err := ss.Unlock("sysadmin", "adminpass123")
		require.NoError(t, err)

		// Simulate system administration tasks over time
		adminTasks := []string{
			"sudo systemctl status nginx",
			"sudo tail -f /var/log/nginx/access.log",
			"sudo apt update",
			"sudo apt upgrade -y",
			"sudo systemctl restart nginx",
			"sudo ufw status",
			"sudo netstat -tulpn | grep :80",
			"sudo du -sh /var/log/*",
			"sudo find /tmp -type f -atime +7 -delete",
			"sudo crontab -l",
		}

		sessionID := "admin-session-maintenance"

		for i, task := range adminTasks {
			record := storage.NewCommandRecord(
				task,
				0,
				int64(1000+i*500), // Varying durations
				"/home/admin",
				sessionID,
				"production-server",
			)
			record.User = "sysadmin"
			record.Shell = "bash"

			_, err := ss.Store(record)
			require.NoError(t, err)
		}

		// Query all admin tasks
		adminResult, err := ss.Retrieve(&QueryOptions{
			SessionID: sessionID,
			Limit:     20,
		})
		require.NoError(t, err)
		assert.Len(t, adminResult.Records, len(adminTasks))

		// Verify all tasks are for the correct user and session
		for _, record := range adminResult.Records {
			assert.Equal(t, "sysadmin", record.User)
			assert.Equal(t, sessionID, record.SessionID)
			assert.Equal(t, "bash", record.Shell)
			assert.Equal(t, "production-server", record.Hostname)
		}

		// Test pagination through results
		page1, err := ss.Retrieve(&QueryOptions{
			SessionID: sessionID,
			Limit:     5,
			Offset:    0,
		})
		require.NoError(t, err)
		assert.Len(t, page1.Records, 5)
		assert.True(t, page1.HasMore)

		page2, err := ss.Retrieve(&QueryOptions{
			SessionID: sessionID,
			Limit:     5,
			Offset:    5,
		})
		require.NoError(t, err)
		assert.Len(t, page2.Records, 5)
		assert.False(t, page2.HasMore)
	})
}

// Helper functions for integration tests

func createSecureStorage(t *testing.T, cfg *config.Config) *SecureStorage {
	opts := &StorageOptions{
		Config:              cfg,
		AutoLockTimeout:     5 * time.Minute,
		EnableSecureDelete:  true,
		ValidatePermissions: true,
		CreateIfMissing:     true,
	}

	ss, err := NewSecureStorage(opts)
	require.NoError(t, err)
	require.NotNil(t, ss)

	return ss
}
