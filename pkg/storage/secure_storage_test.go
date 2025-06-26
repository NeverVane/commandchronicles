package storage

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecureStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	t.Run("valid configuration", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := createTestConfig(tmpDir)

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
		defer ss.Close()

		assert.True(t, ss.IsLocked())
	})

	t.Run("nil options", func(t *testing.T) {
		ss, err := NewSecureStorage(nil)
		assert.Error(t, err)
		assert.Nil(t, ss)
		assert.Contains(t, err.Error(), "options cannot be nil")
	})

	t.Run("nil config", func(t *testing.T) {
		opts := &StorageOptions{}
		ss, err := NewSecureStorage(opts)
		assert.Error(t, err)
		assert.Nil(t, ss)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})
}

func TestSecureStorage_UnlockLock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	t.Run("successful unlock", func(t *testing.T) {
		err := ss.Unlock("testuser", "testpassword123")
		assert.NoError(t, err)
		assert.False(t, ss.IsLocked())
	})

	t.Run("lock after unlock", func(t *testing.T) {
		// First unlock
		err := ss.Unlock("testuser", "testpassword123")
		require.NoError(t, err)

		// Then lock
		err = ss.Lock()
		assert.NoError(t, err)
		assert.True(t, ss.IsLocked())
	})

	t.Run("invalid credentials", func(t *testing.T) {
		err := ss.Unlock("", "")
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidCredentials, err)
		assert.True(t, ss.IsLocked())
	})

	t.Run("wrong password", func(t *testing.T) {
		err := ss.Unlock("testuser", "wrongpassword")
		assert.Error(t, err)
		assert.True(t, ss.IsLocked())
	})

	t.Run("consistent unlock with same credentials", func(t *testing.T) {
		// First unlock
		err := ss.Unlock("testuser", "testpassword123")
		require.NoError(t, err)
		ss.Lock()

		// Second unlock with same credentials
		err = ss.Unlock("testuser", "testpassword123")
		assert.NoError(t, err)
		assert.False(t, ss.IsLocked())
	})
}

func TestSecureStorage_Store(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	// Unlock storage first
	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	t.Run("store valid record", func(t *testing.T) {
		record := storage.NewCommandRecord(
			"ls -la",
			0,
			150,
			"/home/user",
			"session123",
			"testhost",
		)

		result, err := ss.Store(record)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Greater(t, result.RecordID, int64(0))
		assert.Greater(t, result.BytesStored, int64(0))
		assert.Greater(t, result.EncryptedSize, int64(0))
	})

	t.Run("store nil record", func(t *testing.T) {
		result, err := ss.Store(nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, ErrInvalidInput, err)
	})

	t.Run("store invalid record", func(t *testing.T) {
		record := &storage.CommandRecord{
			Command: "", // Invalid - empty command
		}

		result, err := ss.Store(record)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "invalid command record")
	})

	t.Run("store when locked", func(t *testing.T) {
		ss.Lock()

		record := storage.NewCommandRecord(
			"echo test",
			0,
			50,
			"/tmp",
			"session456",
			"testhost",
		)

		result, err := ss.Store(record)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, ErrStorageLocked, err)
	})
}

func TestSecureStorage_Retrieve(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	// Unlock and store test records
	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	// Store multiple test records
	records := []*storage.CommandRecord{
		storage.NewCommandRecord("ls -la", 0, 150, "/home/user", "session1", "host1"),
		storage.NewCommandRecord("git status", 0, 200, "/repo", "session1", "host1"),
		storage.NewCommandRecord("npm install", 0, 5000, "/project", "session2", "host2"),
		storage.NewCommandRecord("docker ps", 0, 120, "/", "session2", "host2"),
	}

	for _, record := range records {
		_, err := ss.Store(record)
		require.NoError(t, err)
	}

	t.Run("retrieve all records", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{Limit: 10})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Records, 4)
		assert.Equal(t, int64(4), result.TotalCount)
		assert.False(t, result.HasMore)
	})

	t.Run("retrieve with session filter", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			SessionID: "session1",
			Limit:     10,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 2)
		assert.Equal(t, int64(2), result.TotalCount)
	})

	t.Run("retrieve with hostname filter", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			Hostname: "host2",
			Limit:    10,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 2)
		assert.Equal(t, int64(2), result.TotalCount)
	})

	t.Run("retrieve with pagination", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			Limit:  2,
			Offset: 0,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 2)
		assert.True(t, result.HasMore)

		// Second page
		result, err = ss.Retrieve(&QueryOptions{
			Limit:  2,
			Offset: 2,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 2)
		assert.False(t, result.HasMore)
	})

	t.Run("retrieve with time range", func(t *testing.T) {
		since := time.Now().Add(-1 * time.Hour)
		until := time.Now()

		result, err := ss.Retrieve(&QueryOptions{
			Since: &since,
			Until: &until,
			Limit: 10,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 4)
	})

	t.Run("retrieve when locked", func(t *testing.T) {
		ss.Lock()

		result, err := ss.Retrieve(&QueryOptions{Limit: 10})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Equal(t, ErrStorageLocked, err)
	})

	t.Run("retrieve with nil options", func(t *testing.T) {
		require.NoError(t, ss.Unlock("testuser", "testpassword123"))

		result, err := ss.Retrieve(nil)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.LessOrEqual(t, len(result.Records), 100) // Default limit
	})

	t.Run("retrieve with large limit gets capped", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{Limit: 50000})
		assert.NoError(t, err)
		assert.NotNil(t, result)
		// Should be capped at 10000, but we only have 4 records
		assert.Len(t, result.Records, 4)
	})
}

func TestSecureStorage_Delete(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	// Unlock and store test records
	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	// Store test records and collect IDs
	var recordIDs []int64
	for i := 0; i < 3; i++ {
		record := storage.NewCommandRecord(
			fmt.Sprintf("command_%d", i),
			0,
			100,
			"/tmp",
			"session",
			"host",
		)
		result, err := ss.Store(record)
		require.NoError(t, err)
		recordIDs = append(recordIDs, result.RecordID)
	}

	t.Run("delete existing records", func(t *testing.T) {
		err := ss.Delete(recordIDs[:2]) // Delete first 2 records
		assert.NoError(t, err)

		// Verify records are deleted
		result, err := ss.Retrieve(&QueryOptions{Limit: 10})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 1) // Only 1 record left
	})

	t.Run("delete empty list", func(t *testing.T) {
		err := ss.Delete([]int64{})
		assert.Error(t, err)
		assert.Equal(t, ErrInvalidInput, err)
	})

	t.Run("delete when locked", func(t *testing.T) {
		ss.Lock()

		err := ss.Delete([]int64{999})
		assert.Error(t, err)
		assert.Equal(t, ErrStorageLocked, err)
	})

	t.Run("delete non-existent records", func(t *testing.T) {
		require.NoError(t, ss.Unlock("testuser", "testpassword123"))

		err := ss.Delete([]int64{99999, 99998})
		assert.NoError(t, err) // Should not error, just affect 0 rows
	})
}

func TestSecureStorage_Statistics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	// Initial stats
	stats := ss.GetStats()
	assert.Equal(t, int64(0), stats.RecordsStored)
	assert.Equal(t, int64(0), stats.RecordsRetrieved)

	// Store a record
	record := storage.NewCommandRecord("test", 0, 100, "/tmp", "session", "host")
	_, err := ss.Store(record)
	require.NoError(t, err)

	// Check updated stats
	stats = ss.GetStats()
	assert.Equal(t, int64(1), stats.RecordsStored)
	assert.Greater(t, stats.BytesEncrypted, int64(0))

	// Retrieve records
	_, err = ss.Retrieve(&QueryOptions{Limit: 10})
	require.NoError(t, err)

	// Check retrieve stats
	stats = ss.GetStats()
	assert.Equal(t, int64(1), stats.RecordsRetrieved)
	assert.Greater(t, stats.BytesDecrypted, int64(0))
}

func TestSecureStorage_ValidateIntegrity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	t.Run("integrity validation passes", func(t *testing.T) {
		err := ss.ValidateIntegrity()
		assert.NoError(t, err)
	})

	t.Run("integrity validation when locked", func(t *testing.T) {
		ss.Lock()

		err := ss.ValidateIntegrity()
		assert.Error(t, err)
		assert.Equal(t, ErrStorageLocked, err)
	})
}

func TestSecureStorage_SecurityViolations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	t.Run("security violation on invalid credentials", func(t *testing.T) {
		initialStats := ss.GetStats()

		err := ss.Unlock("", "")
		assert.Error(t, err)

		stats := ss.GetStats()
		assert.Greater(t, stats.SecurityViolations, initialStats.SecurityViolations)
	})

	t.Run("security violation on wrong password", func(t *testing.T) {
		initialStats := ss.GetStats()

		err := ss.Unlock("user", "wrongpass")
		assert.Error(t, err)

		stats := ss.GetStats()
		assert.Greater(t, stats.SecurityViolations, initialStats.SecurityViolations)
	})
}

func TestSecureStorage_QueryOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	// Store records with different timestamps
	now := time.Now()
	records := []*storage.CommandRecord{
		createRecordWithTime("cmd1", now.Add(-2*time.Hour)),
		createRecordWithTime("cmd2", now.Add(-1*time.Hour)),
		createRecordWithTime("cmd3", now),
	}

	for _, record := range records {
		_, err := ss.Store(record)
		require.NoError(t, err)
	}

	t.Run("order by timestamp descending", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			OrderBy:   "timestamp",
			Ascending: false,
			Limit:     10,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 3)

		// Should be in descending order (newest first)
		assert.Equal(t, "cmd3", result.Records[0].Command)
		assert.Equal(t, "cmd2", result.Records[1].Command)
		assert.Equal(t, "cmd1", result.Records[2].Command)
	})

	t.Run("order by timestamp ascending", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			OrderBy:   "timestamp",
			Ascending: true,
			Limit:     10,
		})
		assert.NoError(t, err)
		assert.Len(t, result.Records, 3)

		// Should be in ascending order (oldest first)
		assert.Equal(t, "cmd1", result.Records[0].Command)
		assert.Equal(t, "cmd2", result.Records[1].Command)
		assert.Equal(t, "cmd3", result.Records[2].Command)
	})

	t.Run("invalid order by column", func(t *testing.T) {
		result, err := ss.Retrieve(&QueryOptions{
			OrderBy: "invalid_column",
			Limit:   10,
		})
		// Should fallback to default ordering (timestamp)
		assert.NoError(t, err)
		assert.Len(t, result.Records, 3)
	})
}

func TestSecureStorage_ConcurrentAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)
	defer ss.Close()

	require.NoError(t, ss.Unlock("testuser", "testpassword123"))

	t.Run("concurrent store operations", func(t *testing.T) {
		const numGoroutines = 10
		const recordsPerGoroutine = 5

		errChan := make(chan error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(workerID int) {
				defer func() { errChan <- nil }()

				for j := 0; j < recordsPerGoroutine; j++ {
					record := storage.NewCommandRecord(
						fmt.Sprintf("worker_%d_cmd_%d", workerID, j),
						0,
						100,
						"/tmp",
						fmt.Sprintf("session_%d", workerID),
						"host",
					)

					if _, err := ss.Store(record); err != nil {
						errChan <- err
						return
					}
				}
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numGoroutines; i++ {
			err := <-errChan
			assert.NoError(t, err)
		}

		// Verify all records were stored
		result, err := ss.Retrieve(&QueryOptions{Limit: 100})
		assert.NoError(t, err)
		assert.Len(t, result.Records, numGoroutines*recordsPerGoroutine)
	})
}

func TestSecureStorage_Close(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Skipping permission tests on Windows")
	}

	ss := setupTestStorage(t)

	// Unlock first
	require.NoError(t, ss.Unlock("testuser", "testpassword123"))
	assert.False(t, ss.IsLocked())

	// Close should lock the storage
	err := ss.Close()
	assert.NoError(t, err)
	assert.True(t, ss.IsLocked())
}

// Helper functions

func setupTestStorage(t *testing.T) *SecureStorage {
	tmpDir := t.TempDir()
	cfg := createTestConfig(tmpDir)

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

func createTestConfig(tmpDir string) *config.Config {
	return &config.Config{
		Database: config.DatabaseConfig{
			Path:         filepath.Join(tmpDir, "test.db"),
			MaxOpenConns: 5,
			MaxIdleConns: 2,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Security: config.SecurityConfig{
			SessionKeyPath:    filepath.Join(tmpDir, "session.key"),
			SessionTimeout:    3600, // 1 hour
			Argon2Time:        3,
			Argon2Memory:      65536,
			Argon2Threads:     4,
			AutoLockTimeout:   0,
			SecureMemoryClear: true,
		},
	}
}

func createRecordWithTime(command string, timestamp time.Time) *storage.CommandRecord {
	record := storage.NewCommandRecord(
		command,
		0,
		100,
		"/tmp",
		"session",
		"host",
	)
	record.Timestamp = timestamp.UnixMilli()
	return record
}
