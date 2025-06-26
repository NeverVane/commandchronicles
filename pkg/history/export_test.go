package history

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportHistory(t *testing.T) {
	tmpDir := t.TempDir()
	store := setupTestStorageWithData(t, tmpDir)
	defer store.Close()

	t.Run("export to JSON", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "export.json")
		
		result, err := ExportHistory(store, FormatJSON, outputFile, nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		assert.Equal(t, outputFile, result.OutputFile)
		assert.Equal(t, FormatJSON, result.Format)
		assert.Greater(t, result.BytesWritten, int64(0))
		
		// Verify file exists and has content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		var jsonRecords []JSONExportRecord
		err = json.Unmarshal(data, &jsonRecords)
		require.NoError(t, err)
		assert.Len(t, jsonRecords, 3)
		
		// Verify first record (records are returned newest first)
		assert.Equal(t, "grep 'pattern' file.txt", jsonRecords[0].Command)
		assert.Equal(t, 1, jsonRecords[0].ExitCode)
		assert.Equal(t, int64(500), jsonRecords[0].Duration)
		assert.Equal(t, "testuser", jsonRecords[0].User)
		assert.Equal(t, "zsh", jsonRecords[0].Shell)
	})

	t.Run("export to bash format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "export.bash")
		
		result, err := ExportHistory(store, FormatBash, outputFile, nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		assert.Equal(t, FormatBash, result.Format)
		
		// Verify file content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		content := string(data)
		lines := strings.Split(strings.TrimSpace(content), "\n")
		
		// Should have 6 lines (3 timestamps + 3 commands)
		assert.Len(t, lines, 6)
		
		// Check format: timestamp lines start with #, command lines don't (newest first)
		assert.True(t, strings.HasPrefix(lines[0], "#"))
		assert.Equal(t, "grep 'pattern' file.txt", lines[1])
		assert.True(t, strings.HasPrefix(lines[2], "#"))
		assert.Equal(t, "cd /tmp && ls", lines[3])
	})

	t.Run("export to zsh format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "export.zsh")
		
		result, err := ExportHistory(store, FormatZsh, outputFile, nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		
		// Verify file content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		content := string(data)
		lines := strings.Split(strings.TrimSpace(content), "\n")
		assert.Len(t, lines, 3)
		
		// Check zsh format: : timestamp:duration;command
		for _, line := range lines {
			assert.True(t, strings.HasPrefix(line, ": "))
			assert.Contains(t, line, ";")
		}
	})

	t.Run("export to CSV format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "export.csv")
		
		result, err := ExportHistory(store, FormatCSV, outputFile, nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		
		// Verify file content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		content := string(data)
		lines := strings.Split(strings.TrimSpace(content), "\n")
		
		// Should have 4 lines (1 header + 3 records)
		assert.Len(t, lines, 4)
		
		// Check header
		assert.Contains(t, lines[0], "timestamp,command,exit_code")
		
		// Check data format (newest first)
		assert.Contains(t, lines[1], "grep 'pattern' file.txt")
		assert.Contains(t, lines[1], ",1,")
	})

	t.Run("export to plain format", func(t *testing.T) {
		outputFile := filepath.Join(tmpDir, "export.txt")
		
		result, err := ExportHistory(store, FormatPlain, outputFile, nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		
		// Verify file content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		content := string(data)
		lines := strings.Split(strings.TrimSpace(content), "\n")
		assert.Len(t, lines, 3)
		
		// Check plain format: [timestamp] command
		for _, line := range lines {
			assert.True(t, strings.HasPrefix(line, "["))
			assert.Contains(t, line, "] ")
		}
	})

	t.Run("export to stdout", func(t *testing.T) {
		result, err := ExportHistory(store, FormatJSON, "-", nil)
		require.NoError(t, err)
		
		assert.Equal(t, 3, result.ExportedRecords)
		assert.Equal(t, "stdout", result.OutputFile)
	})

	t.Run("export with time filters", func(t *testing.T) {
		baseTime := time.Now().Add(-24 * time.Hour)
		since := baseTime.Add(30 * time.Second)
		until := baseTime.Add(90 * time.Second)
		
		opts := &ExportOptions{
			Since: &since,
			Until: &until,
		}
		
		outputFile := filepath.Join(tmpDir, "export_filtered.json")
		result, err := ExportHistory(store, FormatJSON, outputFile, opts)
		require.NoError(t, err)
		
		// Should export only the second record (cd /tmp && ls)
		assert.Equal(t, 1, result.ExportedRecords)
		
		// Verify content
		data, err := os.ReadFile(outputFile)
		require.NoError(t, err)
		
		var jsonRecords []JSONExportRecord
		err = json.Unmarshal(data, &jsonRecords)
		require.NoError(t, err)
		assert.Len(t, jsonRecords, 1)
		assert.Equal(t, "cd /tmp && ls", jsonRecords[0].Command)
	})

	t.Run("export with session filter", func(t *testing.T) {
		opts := &ExportOptions{
			SessionID: "session-1",
		}
		
		outputFile := filepath.Join(tmpDir, "export_session.json")
		result, err := ExportHistory(store, FormatJSON, outputFile, opts)
		require.NoError(t, err)
		
		// Should export only records from session-1 (first 2 records)
		assert.Equal(t, 2, result.ExportedRecords)
	})

	t.Run("unsupported format", func(t *testing.T) {
		_, err := ExportHistory(store, ExportFormat("invalid"), "output.txt", nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported export format")
	})
}

func TestValidateExportFormat(t *testing.T) {
	tests := []struct {
		input    string
		expected ExportFormat
		hasError bool
	}{
		{"json", FormatJSON, false},
		{"JSON", FormatJSON, false},
		{"bash", FormatBash, false},
		{"zsh", FormatZsh, false},
		{"csv", FormatCSV, false},
		{"plain", FormatPlain, false},
		{"invalid", "", true},
		{"", "", true},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := ValidateExportFormat(test.input)
			if test.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, result)
			}
		})
	}
}

func TestGetSupportedFormats(t *testing.T) {
	formats := GetSupportedFormats()
	
	expectedFormats := []ExportFormat{
		FormatJSON, FormatBash, FormatZsh, FormatCSV, FormatPlain,
	}
	
	assert.Len(t, formats, len(expectedFormats))
	for _, expected := range expectedFormats {
		assert.Contains(t, formats, expected)
	}
}

func TestGenerateDefaultOutputPath(t *testing.T) {
	t.Run("with output directory", func(t *testing.T) {
		path := GenerateDefaultOutputPath(FormatJSON, "/tmp")
		assert.True(t, strings.HasPrefix(path, "/tmp/"))
		assert.True(t, strings.HasSuffix(path, ".json"))
		assert.Contains(t, path, "commandchronicles_export_")
	})

	t.Run("without output directory", func(t *testing.T) {
		path := GenerateDefaultOutputPath(FormatBash, "")
		assert.True(t, strings.HasSuffix(path, ".bash"))
		assert.Contains(t, path, "commandchronicles_export_")
	})

	t.Run("different formats", func(t *testing.T) {
		formats := []ExportFormat{FormatJSON, FormatBash, FormatZsh, FormatCSV, FormatPlain}
		
		for _, format := range formats {
			path := GenerateDefaultOutputPath(format, "/tmp")
			assert.True(t, strings.HasSuffix(path, "."+string(format)))
		}
	})
}

func TestEscapeCSVField(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with,comma", "\"with,comma\""},
		{"with\"quote", "\"with\"\"quote\""},
		{"with\nNewline", "\"with\nNewline\""},
		{"with\rCarriageReturn", "\"with\rCarriageReturn\""},
		{"complex,with\"quotes\nand,commas", "\"complex,with\"\"quotes\nand,commas\""},
		{"", ""},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result := escapeCSVField(test.input)
			assert.Equal(t, test.expected, result)
		})
	}
}

func TestExportWithDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	store := setupTestStorageWithData(t, tmpDir)
	defer store.Close()

	// Test creating nested directories
	outputFile := filepath.Join(tmpDir, "nested", "deep", "export.json")
	
	result, err := ExportHistory(store, FormatJSON, outputFile, nil)
	require.NoError(t, err)
	
	assert.Equal(t, 3, result.ExportedRecords)
	
	// Verify file was created
	_, err = os.Stat(outputFile)
	assert.NoError(t, err)
}

func TestExportEmptyHistory(t *testing.T) {
	tmpDir := t.TempDir()
	store := createTestSecureStorage(t, tmpDir)
	defer store.Close()

	outputFile := filepath.Join(tmpDir, "empty_export.json")
	
	result, err := ExportHistory(store, FormatJSON, outputFile, nil)
	require.NoError(t, err)
	
	assert.Equal(t, 0, result.ExportedRecords)
	assert.Greater(t, result.BytesWritten, int64(0)) // Should still write empty array
	
	// Verify empty JSON array
	data, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	
	var jsonRecords []JSONExportRecord
	err = json.Unmarshal(data, &jsonRecords)
	require.NoError(t, err)
	assert.Len(t, jsonRecords, 0)
}

func TestExportErrorHandling(t *testing.T) {
	tmpDir := t.TempDir()
	store := setupTestStorageWithData(t, tmpDir)
	defer store.Close()

	t.Run("invalid output directory permissions", func(t *testing.T) {
		// Create a read-only directory
		readOnlyDir := filepath.Join(tmpDir, "readonly")
		err := os.Mkdir(readOnlyDir, 0444)
		require.NoError(t, err)
		
		outputFile := filepath.Join(readOnlyDir, "subdir", "export.json")
		
		_, err = ExportHistory(store, FormatJSON, outputFile, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create output directory")
	})

	t.Run("invalid time filter", func(t *testing.T) {
		until := time.Now().Add(-1 * time.Hour)
		since := time.Now() // since > until
		
		opts := &ExportOptions{
			Since: &since,
			Until: &until,
		}
		
		outputFile := filepath.Join(tmpDir, "invalid_time.json")
		result, err := ExportHistory(store, FormatJSON, outputFile, opts)
		
		// Should succeed but return 0 records
		require.NoError(t, err)
		assert.Equal(t, 0, result.ExportedRecords)
	})
}

func BenchmarkExportJSON(b *testing.B) {
	tmpDir := b.TempDir()
	store := setupTestStorageWithDataForBench(b, tmpDir)
	defer store.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputFile := filepath.Join(tmpDir, "bench_export.json")
		_, err := ExportHistory(store, FormatJSON, outputFile, nil)
		require.NoError(b, err)
		
		// Clean up for next iteration
		os.Remove(outputFile)
	}
}

func BenchmarkExportBash(b *testing.B) {
	tmpDir := b.TempDir()
	store := setupTestStorageWithDataForBench(b, tmpDir)
	defer store.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		outputFile := filepath.Join(tmpDir, "bench_export.bash")
		_, err := ExportHistory(store, FormatBash, outputFile, nil)
		require.NoError(b, err)
		
		// Clean up for next iteration
		os.Remove(outputFile)
	}
}