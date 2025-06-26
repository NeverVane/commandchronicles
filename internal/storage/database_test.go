package storage

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/NeverVane/commandchronicles/internal/config"
	_ "modernc.org/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, db)

	defer db.Close()

	// Verify database was created
	assert.FileExists(t, dbPath)

	// Verify connection is working
	assert.True(t, db.IsConnected())

	// Verify file permissions
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestNewDatabase_WithOptions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 5,
			MaxIdleConns: 2,
			WALMode:      true,
			SyncMode:     "FULL",
		},
	}

	opts := &DatabaseOptions{
		CreateIfMissing: true,
		MigrateOnOpen:   true,
		ValidateSchema:  true,
	}

	db, err := NewDatabase(cfg, opts)
	require.NoError(t, err)
	require.NotNil(t, db)

	defer db.Close()

	// Verify database configuration
	assert.Equal(t, dbPath, db.GetPath())
	assert.Equal(t, &cfg.Database, db.GetConfig())
}

func TestNewDatabase_ExistingDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "existing.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	// Create database first
	db1, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	db1.Close()

	// Open existing database
	db2, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	require.NotNil(t, db2)

	defer db2.Close()

	assert.True(t, db2.IsConnected())
}

func TestNewDatabase_CreateIfMissingFalse(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nonexistent.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	opts := &DatabaseOptions{
		CreateIfMissing: false,
		MigrateOnOpen:   false,
		ValidateSchema:  false,
	}

	_, err := NewDatabase(cfg, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "database file does not exist")
}

func TestDatabase_BuildConnectionString(t *testing.T) {
	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:     "/tmp/test.db",
			SyncMode: "NORMAL",
		},
	}

	db := &Database{
		config: &cfg.Database,
		path:   cfg.Database.Path,
	}

	connStr := db.buildConnectionString()

	assert.Contains(t, connStr, "/tmp/test.db?")
	assert.Contains(t, connStr, "_foreign_keys=on")
	assert.Contains(t, connStr, "_journal_mode=WAL")
	assert.Contains(t, connStr, "_synchronous=NORMAL")
	assert.Contains(t, connStr, "_secure_delete=on")
}

func TestDatabase_SetSecurePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a test file
	file, err := os.Create(dbPath)
	require.NoError(t, err)
	file.Close()

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path: dbPath,
		},
	}

	db := &Database{
		config: &cfg.Database,
		path:   dbPath,
	}

	err = db.setSecurePermissions()
	require.NoError(t, err)

	// Verify file permissions
	info, err := os.Stat(dbPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestDatabase_Ping(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	err = db.ping()
	assert.NoError(t, err)
}

func TestDatabase_Stats(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	stats := db.Stats()
	assert.Equal(t, 10, stats.MaxOpenConnections)
}

func TestDatabase_Vacuum(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	err = db.Vacuum()
	assert.NoError(t, err)
}

func TestDatabase_CheckIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	err = db.CheckIntegrity()
	assert.NoError(t, err)
}

func TestDatabase_GetSize(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	size, err := db.GetSize()
	require.NoError(t, err)
	assert.Greater(t, size, int64(0))
}

func TestDatabase_BeginTx(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.BeginTx()
	require.NoError(t, err)
	assert.NotNil(t, tx)

	err = tx.Rollback()
	assert.NoError(t, err)
}

func TestDatabase_ExecContext(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	result, err := db.ExecContext("SELECT 1")
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestDatabase_QueryContext(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	rows, err := db.QueryContext("SELECT 1")
	require.NoError(t, err)
	assert.NotNil(t, rows)
	rows.Close()
}

func TestDatabase_QueryRowContext(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	row := db.QueryRowContext("SELECT 1")
	assert.NotNil(t, row)

	var result int
	err = row.Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)
}

func TestDatabase_SetSecureDeleteMode(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	// Test enabling secure delete
	err = db.SetSecureDeleteMode(true)
	assert.NoError(t, err)

	// Test disabling secure delete
	err = db.SetSecureDeleteMode(false)
	assert.NoError(t, err)
}

func TestDatabase_Close(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)

	assert.True(t, db.IsConnected())

	err = db.Close()
	assert.NoError(t, err)

	assert.False(t, db.IsConnected())

	// Closing again should not error
	err = db.Close()
	assert.NoError(t, err)
}

func TestDatabase_GetMigrator(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	migrator := db.GetMigrator()
	assert.NotNil(t, migrator)
}

func TestDatabase_GetDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	sqlDB := db.GetDB()
	assert.NotNil(t, sqlDB)
	assert.IsType(t, &sql.DB{}, sqlDB)
}

func TestDatabase_DirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "nested", "deep", "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(t, err)
	defer db.Close()

	// Verify nested directories were created
	assert.DirExists(t, filepath.Dir(dbPath))

	// Verify directory permissions
	info, err := os.Stat(filepath.Dir(dbPath))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())
}

func TestDatabase_SchemaValidation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	opts := &DatabaseOptions{
		CreateIfMissing: true,
		MigrateOnOpen:   true,
		ValidateSchema:  true,
	}

	db, err := NewDatabase(cfg, opts)
	require.NoError(t, err)
	defer db.Close()

	// Schema should be valid after initialization
	err = db.GetMigrator().ValidateSchema()
	assert.NoError(t, err)
}

func BenchmarkDatabase_Ping(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(b, err)
	defer db.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = db.ping()
	}
}

func BenchmarkDatabase_QueryRowContext(b *testing.B) {
	tmpDir := b.TempDir()
	dbPath := filepath.Join(tmpDir, "bench.db")

	cfg := &config.Config{
		Database: config.DatabaseConfig{
			Path:         dbPath,
			MaxOpenConns: 10,
			MaxIdleConns: 5,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
	}

	db, err := NewDatabase(cfg, nil)
	require.NoError(b, err)
	defer db.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		row := db.QueryRowContext("SELECT 1")
		var result int
		_ = row.Scan(&result)
	}
}
