package history

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestImportBashHistory(t *testing.T) {
	tmpDir := t.TempDir()
	store := createTestSecureStorage(t, tmpDir)
	defer store.Close()

	t.Run("valid bash history", func(t *testing.T) {
		// Create test bash history file
		historyContent := `#1234567890
ls -la
#1234567891
cd /tmp
#1234567892
grep pattern file.txt
ls -la
`
		historyFile := filepath.Join(tmpDir, "bash_history")
		err := os.WriteFile(historyFile, []byte(historyContent), 0600)
		require.NoError(t, err)

		opts := &ImportOptions{
			Deduplicate: true,
			SkipErrors:  true,
			SessionID:   "test-bash",
		}

		result, err := ImportBashHistory(store, historyFile, opts)
		require.NoError(t, err)
		assert.Equal(t, 7, result.TotalRecords)    // 3 timestamps + 4 commands
		assert.Equal(t, 3, result.ImportedRecords) // 3 unique commands (ls -la deduplicated)
		assert.Equal(t, 1, result.SkippedRecords)  // 1 duplicate command
	})

	t.Run("empty file", func(t *testing.T) {
		historyFile := filepath.Join(tmpDir, "empty_history")
		err := os.WriteFile(historyFile, []byte(""), 0600)
		require.NoError(t, err)

		result, err := ImportBashHistory(store, historyFile, nil)
		require.NoError(t, err)
		assert.Equal(t, 0, result.ImportedRecords)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := ImportBashHistory(store, "/nonexistent/file", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open bash history file")
	})

	t.Run("without deduplication", func(t *testing.T) {
		historyContent := `ls -la
ls -la
cd /tmp
`
		historyFile := filepath.Join(tmpDir, "bash_history_no_dedup")
		err := os.WriteFile(historyFile, []byte(historyContent), 0600)
		require.NoError(t, err)

		opts := &ImportOptions{
			Deduplicate: false,
			SessionID:   "test-bash-no-dedup",
		}

		result, err := ImportBashHistory(store, historyFile, opts)
		require.NoError(t, err)
		assert.Equal(t, 3, result.ImportedRecords) // All commands imported
		assert.Equal(t, 0, result.SkippedRecords)
	})
}

func TestImportZshHistory(t *testing.T) {
	tmpDir := t.TempDir()
	store := createTestSecureStorage(t, tmpDir)
	defer store.Close()

	t.Run("valid zsh history", func(t *testing.T) {
		// Create test zsh history file
		historyContent := `: 1234567890:0;ls -la
: 1234567891:5;cd /tmp && ls
: 1234567892:2;grep pattern file.txt
: 1234567893:0;ls -la
`
		historyFile := filepath.Join(tmpDir, "zsh_history")
		err := os.WriteFile(historyFile, []byte(historyContent), 0600)
		require.NoError(t, err)

		opts := &ImportOptions{
			Deduplicate: true,
			SkipErrors:  true,
			SessionID:   "test-zsh",
		}

		result, err := ImportZshHistory(store, historyFile, opts)
		require.NoError(t, err)
		assert.Equal(t, 4, result.TotalRecords)
		assert.Equal(t, 3, result.ImportedRecords) // 3 unique commands
		assert.Equal(t, 1, result.SkippedRecords)  // 1 duplicate
	})

	t.Run("invalid zsh format", func(t *testing.T) {
		historyContent := `: 1234567890;no_duration_field
invalid line
: 1234567891:0;valid command
`
		historyFile := filepath.Join(tmpDir, "invalid_zsh_history")
		err := os.WriteFile(historyFile, []byte(historyContent), 0600)
		require.NoError(t, err)

		opts := &ImportOptions{
			SkipErrors: true,
			SessionID:  "test-zsh-invalid",
		}

		result, err := ImportZshHistory(store, historyFile, opts)
		require.NoError(t, err)
		assert.Equal(t, 2, result.ImportedRecords) // Both zsh format lines successfully imported
		assert.Equal(t, 0, result.SkippedRecords)  // No records skipped in this test
		assert.Equal(t, 0, len(result.Errors))     // No errors with SkipErrors=true
	})

	t.Run("strict error handling", func(t *testing.T) {
		historyContent := `: invalid_timestamp:0;command
`
		historyFile := filepath.Join(tmpDir, "strict_zsh_history")
		err := os.WriteFile(historyFile, []byte(historyContent), 0600)
		require.NoError(t, err)

		opts := &ImportOptions{
			SkipErrors: false,
			SessionID:  "test-zsh-strict",
		}

		_, err = ImportZshHistory(store, historyFile, opts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid timestamp")
	})
}

func TestDetectHistoryFile(t *testing.T) {
	// Create a temporary home directory
	tmpHome := t.TempDir()

	// Save original HOME
	originalHome := os.Getenv("HOME")
	defer func() {
		os.Setenv("HOME", originalHome)
	}()

	// Set temporary HOME
	os.Setenv("HOME", tmpHome)

	t.Run("detect bash history", func(t *testing.T) {
		bashHistoryPath := filepath.Join(tmpHome, ".bash_history")
		err := os.WriteFile(bashHistoryPath, []byte("test"), 0600)
		require.NoError(t, err)

		path, err := DetectHistoryFile("bash")
		require.NoError(t, err)
		assert.Equal(t, bashHistoryPath, path)
	})

	t.Run("detect zsh history", func(t *testing.T) {
		zshHistoryPath := filepath.Join(tmpHome, ".zsh_history")
		err := os.WriteFile(zshHistoryPath, []byte("test"), 0600)
		require.NoError(t, err)

		path, err := DetectHistoryFile("zsh")
		require.NoError(t, err)
		assert.Equal(t, zshHistoryPath, path)
	})

	t.Run("unsupported shell", func(t *testing.T) {
		_, err := DetectHistoryFile("fish")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported shell")
	})

	t.Run("history file not found", func(t *testing.T) {
		// Clean up any existing files
		os.RemoveAll(filepath.Join(tmpHome, ".bash_history"))

		_, err := DetectHistoryFile("bash")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "bash history file not found")
	})
}

func TestImportOptionsDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	store := createTestSecureStorage(t, tmpDir)
	defer store.Close()

	historyContent := `ls -la
cd /tmp
`
	historyFile := filepath.Join(tmpDir, "test_history")
	err := os.WriteFile(historyFile, []byte(historyContent), 0600)
	require.NoError(t, err)

	// Test with nil options
	result, err := ImportBashHistory(store, historyFile, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, result.ImportedRecords)
}

func TestImportWithMaxRecords(t *testing.T) {
	tmpDir := t.TempDir()
	store := createTestSecureStorage(t, tmpDir)
	defer store.Close()

	historyContent := `command1
command2
command3
command4
command5
`
	historyFile := filepath.Join(tmpDir, "large_history")
	err := os.WriteFile(historyFile, []byte(historyContent), 0600)
	require.NoError(t, err)

	opts := &ImportOptions{
		MaxRecords: 3,
		SessionID:  "test-max",
	}

	result, err := ImportBashHistory(store, historyFile, opts)
	require.NoError(t, err)
	assert.Equal(t, 3, result.ImportedRecords) // Should stop at max
}

func TestUtilityFunctions(t *testing.T) {
	t.Run("getHostname", func(t *testing.T) {
		hostname := getHostname()
		assert.NotEmpty(t, hostname)
		// Should not be "unknown" unless hostname really can't be determined
	})

	t.Run("getCurrentUser", func(t *testing.T) {
		user := getCurrentUser()
		assert.NotEmpty(t, user)
		// Should not be "unknown" unless user really can't be determined
	})
}

func BenchmarkImportBashHistory(b *testing.B) {
	tmpDir := b.TempDir()
	store := createTestSecureStorageForBench(b, tmpDir)
	defer store.Close()

	// Create a large history file
	var historyContent string
	for i := 0; i < 1000; i++ {
		historyContent += "#1234567890\n"
		historyContent += "command" + string(rune(i)) + "\n"
	}

	historyFile := filepath.Join(tmpDir, "large_history")
	err := os.WriteFile(historyFile, []byte(historyContent), 0600)
	require.NoError(b, err)

	opts := &ImportOptions{
		Deduplicate: true,
		SkipErrors:  true,
		SessionID:   "bench-test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ImportBashHistory(store, historyFile, opts)
		require.NoError(b, err)
	}
}
