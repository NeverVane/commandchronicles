package storage

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommandRecord_NewCommandRecord(t *testing.T) {
	command := "ls -la"
	exitCode := 0
	duration := int64(150)
	workingDir := "/home/user"
	sessionID := "test-session-123"
	hostname := "test-host"

	record := NewCommandRecord(command, exitCode, duration, workingDir, sessionID, hostname)

	assert.Equal(t, command, record.Command)
	assert.Equal(t, exitCode, record.ExitCode)
	assert.Equal(t, duration, record.Duration)
	assert.Equal(t, workingDir, record.WorkingDir)
	assert.Equal(t, sessionID, record.SessionID)
	assert.Equal(t, hostname, record.Hostname)
	assert.Equal(t, 1, record.Version)
	assert.True(t, record.Timestamp > 0)
	assert.True(t, record.CreatedAt > 0)
	assert.True(t, record.IsValid())
}

func TestCommandRecord_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		record   CommandRecord
		expected bool
	}{
		{
			name: "valid record",
			record: CommandRecord{
				Command:   "echo hello",
				SessionID: "session-123",
				Hostname:  "host-1",
				Timestamp: time.Now().UnixMilli(),
				CreatedAt: time.Now().UnixMilli(),
			},
			expected: true,
		},
		{
			name: "empty command",
			record: CommandRecord{
				Command:   "",
				SessionID: "session-123",
				Hostname:  "host-1",
				Timestamp: time.Now().UnixMilli(),
				CreatedAt: time.Now().UnixMilli(),
			},
			expected: false,
		},
		{
			name: "empty session ID",
			record: CommandRecord{
				Command:   "echo hello",
				SessionID: "",
				Hostname:  "host-1",
				Timestamp: time.Now().UnixMilli(),
				CreatedAt: time.Now().UnixMilli(),
			},
			expected: false,
		},
		{
			name: "empty hostname",
			record: CommandRecord{
				Command:   "echo hello",
				SessionID: "session-123",
				Hostname:  "",
				Timestamp: time.Now().UnixMilli(),
				CreatedAt: time.Now().UnixMilli(),
			},
			expected: false,
		},
		{
			name: "zero timestamp",
			record: CommandRecord{
				Command:   "echo hello",
				SessionID: "session-123",
				Hostname:  "host-1",
				Timestamp: 0,
				CreatedAt: time.Now().UnixMilli(),
			},
			expected: false,
		},
		{
			name: "zero created at",
			record: CommandRecord{
				Command:   "echo hello",
				SessionID: "session-123",
				Hostname:  "host-1",
				Timestamp: time.Now().UnixMilli(),
				CreatedAt: 0,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.record.IsValid())
		})
	}
}

func TestEncryptedHistoryRecord_GetSearchableFields(t *testing.T) {
	record := &EncryptedHistoryRecord{
		ID:            123,
		EncryptedData: []byte("encrypted-data"),
		Timestamp:     1640995200000,
		Session:       "session-123",
		Hostname:      "test-host",
		CreatedAt:     1640995200000,
	}

	fields := record.GetSearchableFields()

	expected := map[string]interface{}{
		"timestamp":  int64(1640995200000),
		"session":    "session-123",
		"hostname":   "test-host",
		"created_at": int64(1640995200000),
	}

	assert.Equal(t, expected, fields)
}

func TestGetCurrentSchema(t *testing.T) {
	schema := GetCurrentSchema()

	assert.Equal(t, 1, schema.Version)
	assert.NotEmpty(t, schema.Tables)
	assert.NotEmpty(t, schema.Indexes)
	assert.NotNil(t, schema.Migrations)

	// Verify specific tables exist
	tableNames := []string{"history", "schema_version", "session_metadata"}
	for _, tableName := range tableNames {
		found := false
		for _, table := range schema.Tables {
			if contains(table, tableName) {
				found = true
				break
			}
		}
		assert.True(t, found, "Table %s should be in schema", tableName)
	}

	// Verify specific indexes exist
	indexNames := []string{"idx_history_timestamp", "idx_history_session", "idx_history_hostname"}
	for _, indexName := range indexNames {
		found := false
		for _, index := range schema.Indexes {
			if contains(index, indexName) {
				found = true
				break
			}
		}
		assert.True(t, found, "Index %s should be in schema", indexName)
	}
}

func TestMigrator_InitializeSchema(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	err := migrator.InitializeSchema()
	require.NoError(t, err)

	// Verify schema version was recorded
	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 1, version)

	// Verify tables were created
	tables := []string{"history", "schema_version", "session_metadata"}
	for _, table := range tables {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "Table %s should exist", table)
	}

	// Verify indexes were created
	indexes := []string{"idx_history_timestamp", "idx_history_session", "idx_history_hostname"}
	for _, index := range indexes {
		var count int
		err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", index).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count, "Index %s should exist", index)
	}
}

func TestMigrator_GetCurrentVersion(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Fresh database should return version 0
	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 0, version)

	// Initialize schema
	err = migrator.InitializeSchema()
	require.NoError(t, err)

	// Should return version 1 after initialization
	version, err = migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 1, version)
}

func TestMigrator_MigrateToLatest(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Migrate fresh database
	err := migrator.MigrateToLatest()
	require.NoError(t, err)

	// Verify final version
	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, schema.Version, version)

	// Running migrate again should be idempotent
	err = migrator.MigrateToLatest()
	require.NoError(t, err)

	version, err = migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, schema.Version, version)
}

func TestMigrator_ValidateSchema(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Initialize schema first
	err := migrator.InitializeSchema()
	require.NoError(t, err)

	// Validation should pass
	err = migrator.ValidateSchema()
	assert.NoError(t, err)
}

func TestMigrator_ValidateSchema_MissingTable(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Don't initialize schema, validation should fail
	err := migrator.ValidateSchema()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "table validation failed")
}

func TestMigrator_CheckIntegrity(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Initialize schema
	err := migrator.InitializeSchema()
	require.NoError(t, err)

	// Integrity check should pass
	err = migrator.CheckIntegrity()
	assert.NoError(t, err)
}

func TestMigrator_GetMigrationHistory(t *testing.T) {
	db := createTestDB(t)
	defer db.Close()

	schema := GetCurrentSchema()
	migrator := NewMigrator(db, schema)

	// Initialize schema
	err := migrator.InitializeSchema()
	require.NoError(t, err)

	// Get migration history
	history, err := migrator.GetMigrationHistory()
	require.NoError(t, err)
	assert.Len(t, history, 1)
	assert.Equal(t, 1, history[0].Version)
	assert.Equal(t, "Initial schema creation", history[0].Description)
	assert.True(t, history[0].AppliedAt > 0)
}

func TestDatabaseConstraints(t *testing.T) {
	assert.Equal(t, 65536, DatabaseConstraints["max_command_length"])
	assert.Equal(t, 4096, DatabaseConstraints["max_working_dir_length"])
	assert.Equal(t, 253, DatabaseConstraints["max_hostname_length"])
	assert.Equal(t, 36, DatabaseConstraints["max_session_id_length"])
	assert.Equal(t, 1, DatabaseConstraints["current_schema_version"])
}

func TestConstants(t *testing.T) {
	assert.Equal(t, 65536, MaxCommandLength)
	assert.Equal(t, 4096, MaxWorkingDirLength)
	assert.Equal(t, 253, MaxHostnameLength)
	assert.Equal(t, 36, MaxSessionIDLength)
	assert.Equal(t, 100, MaxEnvironmentVars)
	assert.Equal(t, 8192, MaxEnvironmentSize)
	assert.Equal(t, 1, CurrentSchemaVersion)
	assert.Equal(t, 1, MinSupportedVersion)
}

func TestSessionMetadata(t *testing.T) {
	now := time.Now().UnixMilli()
	metadata := &SessionMetadata{
		SessionID: "test-session",
		StartTime: now,
		EndTime:   nil, // Session still active
		Hostname:  "test-host",
		UserName:  "testuser",
		ShellType: "bash",
		CreatedAt: now,
	}

	assert.Equal(t, "test-session", metadata.SessionID)
	assert.Equal(t, now, metadata.StartTime)
	assert.Nil(t, metadata.EndTime)
	assert.Equal(t, "test-host", metadata.Hostname)
	assert.Equal(t, "testuser", metadata.UserName)
	assert.Equal(t, "bash", metadata.ShellType)
	assert.Equal(t, now, metadata.CreatedAt)
}

func TestSchemaVersion(t *testing.T) {
	now := time.Now().UnixMilli()
	sv := &SchemaVersion{
		Version:     1,
		AppliedAt:   now,
		Description: "Test migration",
	}

	assert.Equal(t, 1, sv.Version)
	assert.Equal(t, now, sv.AppliedAt)
	assert.Equal(t, "Test migration", sv.Description)
}

// Helper functions

func createTestDB(t *testing.T) *sql.DB {
	// Create temporary database file
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath+"?_foreign_keys=on")
	require.NoError(t, err)

	return db
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
		    (len(s) > len(substr) && 
		     (s[:len(substr)] == substr || 
		      s[len(s)-len(substr):] == substr ||
		      containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func BenchmarkNewCommandRecord(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewCommandRecord("test command", 0, 100, "/tmp", "session", "hostname")
	}
}

func BenchmarkCommandRecord_IsValid(b *testing.B) {
	record := NewCommandRecord("test command", 0, 100, "/tmp", "session", "hostname")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = record.IsValid()
	}
}

func BenchmarkGetSearchableFields(b *testing.B) {
	record := &EncryptedHistoryRecord{
		ID:        1,
		Timestamp: time.Now().UnixMilli(),
		Session:   "session-123",
		Hostname:  "hostname",
		CreatedAt: time.Now().UnixMilli(),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = record.GetSearchableFields()
	}
}