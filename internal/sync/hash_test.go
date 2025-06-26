package sync

import (
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/stretchr/testify/assert"
)

func TestNewHashGenerator(t *testing.T) {
	hg := NewHashGenerator()
	assert.NotNil(t, hg)
}

func TestGenerateRecordHash_BasicFunctionality(t *testing.T) {
	hg := NewHashGenerator()
	
	record := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  time.Now().UnixMilli(),
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash := hg.GenerateRecordHash(record)
	
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA256 hex string length
}

func TestGenerateRecordHash_Consistency(t *testing.T) {
	hg := NewHashGenerator()
	
	record := &storage.CommandRecord{
		Command:    "ls -la",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp",
		ExitCode:   0,
		Hostname:   "testhost",
		User:       "testuser",
	}
	
	hash1 := hg.GenerateRecordHash(record)
	hash2 := hg.GenerateRecordHash(record)
	
	assert.Equal(t, hash1, hash2, "Same record should produce same hash")
}

func TestGenerateRecordHash_Uniqueness(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "git diff",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.NotEqual(t, hash1, hash2, "Different commands should produce different hashes")
}

func TestGenerateRecordHash_DifferentTimestamps(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890001, // Different timestamp
		WorkingDir: "/tmp",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.NotEqual(t, hash1, hash2, "Different timestamps should produce different hashes")
}

func TestGenerateRecordHash_DifferentDirectories(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "ls",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "ls",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp", // Different directory
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.NotEqual(t, hash1, hash2, "Different directories should produce different hashes")
}

func TestGenerateRecordHash_DifferentExitCodes(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "false",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "false",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp",
		ExitCode:   1, // Different exit code
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.NotEqual(t, hash1, hash2, "Different exit codes should produce different hashes")
}

func TestGenerateRecordHash_WithEnvironmentVariables(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:     "echo $HOME",
		Timestamp:   1234567890000,
		WorkingDir:  "/tmp",
		ExitCode:    0,
		Hostname:    "localhost",
		User:        "testuser",
		Environment: map[string]string{
			"HOME": "/home/user",
			"PATH": "/usr/bin:/bin",
		},
	}
	
	record2 := &storage.CommandRecord{
		Command:     "echo $HOME",
		Timestamp:   1234567890000,
		WorkingDir:  "/tmp",
		ExitCode:    0,
		Hostname:    "localhost",
		User:        "testuser",
		Environment: map[string]string{
			"HOME": "/home/user",
			"PATH": "/usr/local/bin:/usr/bin:/bin", // Different PATH
		},
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.NotEqual(t, hash1, hash2, "Different environment variables should produce different hashes")
}

func TestGenerateRecordHash_EnvironmentVariableOrdering(t *testing.T) {
	hg := NewHashGenerator()
	
	// Test that environment variables are sorted for consistent hashing
	record1 := &storage.CommandRecord{
		Command:     "test",
		Timestamp:   1234567890000,
		WorkingDir:  "/tmp",
		ExitCode:    0,
		Hostname:    "localhost",
		User:        "testuser",
		Environment: map[string]string{
			"A": "1",
			"B": "2",
			"C": "3",
		},
	}
	
	record2 := &storage.CommandRecord{
		Command:     "test",
		Timestamp:   1234567890000,
		WorkingDir:  "/tmp",
		ExitCode:    0,
		Hostname:    "localhost",
		User:        "testuser",
		Environment: map[string]string{
			"C": "3",
			"A": "1",
			"B": "2",
		},
	}
	
	hash1 := hg.GenerateRecordHash(record1)
	hash2 := hg.GenerateRecordHash(record2)
	
	assert.Equal(t, hash1, hash2, "Same environment variables in different order should produce same hash")
}

func TestGenerateRecordHash_NoEnvironmentVariables(t *testing.T) {
	hg := NewHashGenerator()
	
	record := &storage.CommandRecord{
		Command:    "ls",
		Timestamp:  1234567890000,
		WorkingDir: "/tmp",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	hash := hg.GenerateRecordHash(record)
	
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64)
}

func TestCompareRecords_Identical(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	result := hg.CompareRecords(record1, record2)
	assert.True(t, result, "Identical records should compare as equal")
}

func TestCompareRecords_Different(t *testing.T) {
	hg := NewHashGenerator()
	
	record1 := &storage.CommandRecord{
		Command:    "git status",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	record2 := &storage.CommandRecord{
		Command:    "git diff",
		Timestamp:  1234567890000,
		WorkingDir: "/home/user/project",
		ExitCode:   0,
		Hostname:   "localhost",
		User:       "testuser",
	}
	
	result := hg.CompareRecords(record1, record2)
	assert.False(t, result, "Different records should not compare as equal")
}

func TestGenerateRecordHash_EmptyRecord(t *testing.T) {
	hg := NewHashGenerator()
	
	record := &storage.CommandRecord{}
	
	hash := hg.GenerateRecordHash(record)
	
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64)
}

func BenchmarkGenerateRecordHash(b *testing.B) {
	hg := NewHashGenerator()
	
	record := &storage.CommandRecord{
		Command:    "git log --oneline --graph --decorate --all",
		Timestamp:  time.Now().UnixMilli(),
		WorkingDir: "/home/user/very/long/path/to/project/with/many/subdirectories",
		ExitCode:   0,
		Hostname:   "very-long-hostname-for-testing",
		User:       "username",
		Environment: map[string]string{
			"PATH":    "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
			"HOME":    "/home/username",
			"SHELL":   "/bin/bash",
			"TERM":    "xterm-256color",
			"LANG":    "en_US.UTF-8",
			"PWD":     "/home/user/very/long/path/to/project/with/many/subdirectories",
			"OLDPWD":  "/home/user/previous/directory",
			"USER":    "username",
			"LOGNAME": "username",
		},
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hg.GenerateRecordHash(record)
	}
}