package history

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/storage"
	secureStorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

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
		DataDir:   tmpDir,
		ConfigDir: tmpDir,
	}
}

func createTestSecureStorage(t *testing.T, tmpDir string) *secureStorage.SecureStorage {
	cfg := createTestConfig(tmpDir)
	
	opts := &secureStorage.StorageOptions{
		Config:              cfg,
		AutoLockTimeout:     5 * time.Minute,
		EnableSecureDelete:  true,
		ValidatePermissions: false, // Skip for tests
		CreateIfMissing:     true,
	}

	store, err := secureStorage.NewSecureStorage(opts)
	require.NoError(t, err)
	
	// Unlock with test key (bypass authentication for tests)
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}
	err = store.UnlockWithKey(testKey)
	require.NoError(t, err)
	
	return store
}

func createTestSecureStorageForBench(b *testing.B, tmpDir string) *secureStorage.SecureStorage {
	cfg := createTestConfig(tmpDir)
	
	opts := &secureStorage.StorageOptions{
		Config:              cfg,
		AutoLockTimeout:     5 * time.Minute,
		EnableSecureDelete:  true,
		ValidatePermissions: false, // Skip for benchmarks
		CreateIfMissing:     true,
	}

	store, err := secureStorage.NewSecureStorage(opts)
	if err != nil {
		b.Fatal(err)
	}
	
	// Unlock with test key (bypass authentication for benchmarks)
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}
	err = store.UnlockWithKey(testKey)
	if err != nil {
		b.Fatal(err)
	}
	
	return store
}

func createTestRecords() []*storage.CommandRecord {
	baseTime := time.Now().Add(-24 * time.Hour)
	
	return []*storage.CommandRecord{
		{
			Command:    "ls -la",
			ExitCode:   0,
			Duration:   150,
			WorkingDir: "/home/user",
			Timestamp:  baseTime.UnixMilli(),
			SessionID:  "session-1",
			Hostname:   "testhost",
			User:       "testuser",
			Shell:      "bash",
			Version:    1,
			CreatedAt:  baseTime.UnixMilli(),
		},
		{
			Command:    "cd /tmp && ls",
			ExitCode:   0,
			Duration:   200,
			WorkingDir: "/home/user",
			Timestamp:  baseTime.Add(time.Minute).UnixMilli(),
			SessionID:  "session-1",
			Hostname:   "testhost",
			User:       "testuser",
			Shell:      "bash",
			GitRoot:    "/home/user/project",
			GitBranch:  "main",
			GitCommit:  "abc123",
			Version:    1,
			CreatedAt:  baseTime.Add(time.Minute).UnixMilli(),
		},
		{
			Command:    "grep 'pattern' file.txt",
			ExitCode:   1,
			Duration:   500,
			WorkingDir: "/tmp",
			Timestamp:  baseTime.Add(2 * time.Minute).UnixMilli(),
			SessionID:  "session-2",
			Hostname:   "testhost",
			User:       "testuser",
			Shell:      "zsh",
			TTY:        "/dev/pts/0",
			Environment: map[string]string{"PATH": "/usr/bin", "HOME": "/home/user"},
			Version:    1,
			CreatedAt:  baseTime.Add(2 * time.Minute).UnixMilli(),
		},
	}
}

func setupTestStorageWithData(t *testing.T, tmpDir string) *secureStorage.SecureStorage {
	store := createTestSecureStorage(t, tmpDir)
	
	// Add test records
	records := createTestRecords()
	for _, record := range records {
		_, err := store.Store(record)
		require.NoError(t, err)
	}
	
	return store
}

func setupTestStorageWithDataForBench(b *testing.B, tmpDir string) *secureStorage.SecureStorage {
	store := createTestSecureStorageForBench(b, tmpDir)
	
	// Add test records
	records := createTestRecords()
	for _, record := range records {
		_, err := store.Store(record)
		if err != nil {
			b.Fatal(err)
		}
	}
	
	return store
}