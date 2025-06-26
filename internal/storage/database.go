package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// Database wraps sql.DB with additional functionality for CommandChronicles
type Database struct {
	db       *sql.DB
	config   *config.DatabaseConfig
	logger   *logger.Logger
	migrator *Migrator
	path     string
}

// DatabaseOptions contains options for database initialization
type DatabaseOptions struct {
	Config          *config.DatabaseConfig
	CreateIfMissing bool
	MigrateOnOpen   bool
	ValidateSchema  bool
}

// NewDatabase creates a new database instance with the given configuration
func NewDatabase(cfg *config.Config, opts *DatabaseOptions) (*Database, error) {
	if opts == nil {
		opts = &DatabaseOptions{
			Config:          &cfg.Database,
			CreateIfMissing: true,
			MigrateOnOpen:   true,
			ValidateSchema:  true,
		}
	}

	if opts.Config == nil {
		opts.Config = &cfg.Database
	}

	logger := logger.GetLogger().Database()
	
	db := &Database{
		config: opts.Config,
		logger: logger,
		path:   opts.Config.Path,
	}

	if err := db.initialize(opts); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return db, nil
}

// initialize sets up the database connection and configuration
func (db *Database) initialize(opts *DatabaseOptions) error {
	// Ensure database directory exists with secure permissions
	dbDir := filepath.Dir(db.path)
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Check if database file exists
	dbExists := true
	if _, err := os.Stat(db.path); os.IsNotExist(err) {
		dbExists = false
		if !opts.CreateIfMissing {
			return fmt.Errorf("database file does not exist: %s", db.path)
		}
	}

	// Build connection string with secure options
	connStr := db.buildConnectionString()
	
	db.logger.Debug().
		Str("path", db.path).
		Str("connection_string", connStr).
		Msg("Opening database connection")

	// Open database connection
	sqlDB, err := sql.Open("sqlite3", connStr)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	db.db = sqlDB

	// Configure connection pool
	if err := db.configureConnectionPool(); err != nil {
		db.db.Close()
		return fmt.Errorf("failed to configure connection pool: %w", err)
	}

	// Apply SQLite pragmas for security and performance
	if err := db.applySecurityPragmas(); err != nil {
		db.db.Close()
		return fmt.Errorf("failed to apply security pragmas: %w", err)
	}

	// Set secure file permissions
	if err := db.setSecurePermissions(); err != nil {
		db.db.Close()
		return fmt.Errorf("failed to set secure permissions: %w", err)
	}

	// Initialize migrator
	schema := GetCurrentSchema()
	db.migrator = NewMigrator(db.db, schema)

	// Handle database initialization or migration
	if !dbExists {
		db.logger.Info().Str("path", db.path).Msg("Creating new database")
		if err := db.migrator.InitializeSchema(); err != nil {
			db.db.Close()
			return fmt.Errorf("failed to initialize schema: %w", err)
		}
	} else if opts.MigrateOnOpen {
		db.logger.Debug().Msg("Checking for database migrations")
		if err := db.migrator.MigrateToLatest(); err != nil {
			db.db.Close()
			return fmt.Errorf("failed to migrate database: %w", err)
		}
	}

	// Validate schema if requested
	if opts.ValidateSchema {
		if err := db.migrator.ValidateSchema(); err != nil {
			db.db.Close()
			return fmt.Errorf("schema validation failed: %w", err)
		}
	}

	// Test connection
	if err := db.ping(); err != nil {
		db.db.Close()
		return fmt.Errorf("database connection test failed: %w", err)
	}

	db.logger.Info().
		Str("path", db.path).
		Bool("new_database", !dbExists).
		Msg("Database initialized successfully")

	return nil
}

// buildConnectionString creates a secure SQLite connection string
func (db *Database) buildConnectionString() string {
	params := map[string]string{
		"_foreign_keys": "on",          // Enable foreign key constraints
		"_journal_mode": "WAL",         // Use WAL mode for better concurrency
		"_synchronous":  db.config.SyncMode, // Synchronous mode
		"_cache_size":   "-2000",       // 2MB cache
		"_temp_store":   "memory",      // Store temporary tables in memory
		"_secure_delete": "on",         // Securely delete data
		"_recursive_triggers": "on",    // Enable recursive triggers
	}

	connStr := db.path + "?"
	first := true
	for key, value := range params {
		if !first {
			connStr += "&"
		}
		connStr += key + "=" + value
		first = false
	}

	return connStr
}

// configureConnectionPool sets up connection pool parameters
func (db *Database) configureConnectionPool() error {
	// Set maximum number of open connections
	db.db.SetMaxOpenConns(db.config.MaxOpenConns)
	
	// Set maximum number of idle connections
	db.db.SetMaxIdleConns(db.config.MaxIdleConns)
	
	// Set maximum lifetime for connections
	db.db.SetConnMaxLifetime(30 * time.Minute)
	
	// Set maximum idle time for connections
	db.db.SetConnMaxIdleTime(5 * time.Minute)

	return nil
}

// applySecurityPragmas applies security-focused SQLite pragmas
func (db *Database) applySecurityPragmas() error {
	pragmas := map[string]string{
		"foreign_keys":       "ON",     // Enable foreign key constraints
		"secure_delete":      "ON",     // Overwrite deleted data
		"auto_vacuum":        "INCREMENTAL", // Enable incremental vacuum
		"journal_mode":       "WAL",    // Use WAL mode
		"synchronous":        db.config.SyncMode,
		"temp_store":         "memory", // Store temp data in memory
		"cache_spill":        "FALSE",  // Don't spill cache to disk
		"query_only":         "FALSE",  // Allow write operations
		"recursive_triggers": "ON",     // Enable recursive triggers
	}

	for pragma, value := range pragmas {
		query := fmt.Sprintf("PRAGMA %s = %s", pragma, value)
		if _, err := db.db.Exec(query); err != nil {
			return fmt.Errorf("failed to set pragma %s: %w", pragma, err)
		}
		db.logger.Debug().Str("pragma", pragma).Str("value", value).Msg("Applied pragma")
	}

	return nil
}

// setSecurePermissions sets secure file permissions on the database file
func (db *Database) setSecurePermissions() error {
	// Set file permissions to 0600 (read/write owner only)
	if err := os.Chmod(db.path, 0600); err != nil {
		return fmt.Errorf("failed to set database file permissions: %w", err)
	}

	// Also set permissions on WAL and SHM files if they exist
	walPath := db.path + "-wal"
	if _, err := os.Stat(walPath); err == nil {
		if err := os.Chmod(walPath, 0600); err != nil {
			db.logger.Warn().Err(err).Str("file", walPath).Msg("Failed to set WAL file permissions")
		}
	}

	shmPath := db.path + "-shm"
	if _, err := os.Stat(shmPath); err == nil {
		if err := os.Chmod(shmPath, 0600); err != nil {
			db.logger.Warn().Err(err).Str("file", shmPath).Msg("Failed to set SHM file permissions")
		}
	}

	return nil
}

// ping tests the database connection
func (db *Database) ping() error {
	ctx, cancel := db.getContextWithTimeout(5 * time.Second)
	defer cancel()

	if err := db.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	// Test a simple query
	var result int
	if err := db.db.QueryRowContext(ctx, "SELECT 1").Scan(&result); err != nil {
		return fmt.Errorf("test query failed: %w", err)
	}

	if result != 1 {
		return fmt.Errorf("test query returned unexpected result: %d", result)
	}

	return nil
}

// GetDB returns the underlying sql.DB instance
func (db *Database) GetDB() *sql.DB {
	return db.db
}

// GetMigrator returns the database migrator
func (db *Database) GetMigrator() *Migrator {
	return db.migrator
}

// Close closes the database connection
func (db *Database) Close() error {
	if db.db == nil {
		return nil
	}

	db.logger.Info().Msg("Closing database connection")

	// Perform final WAL checkpoint
	if _, err := db.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		db.logger.Warn().Err(err).Msg("Failed to perform final WAL checkpoint")
	}

	if err := db.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	db.db = nil
	return nil
}

// Stats returns database statistics
func (db *Database) Stats() sql.DBStats {
	if db.db == nil {
		return sql.DBStats{}
	}
	return db.db.Stats()
}

// Vacuum performs database maintenance
func (db *Database) Vacuum() error {
	db.logger.Info().Msg("Starting database vacuum")
	
	ctx, cancel := db.getContextWithTimeout(5 * time.Minute)
	defer cancel()

	// Perform incremental vacuum
	if _, err := db.db.ExecContext(ctx, "PRAGMA incremental_vacuum(1000)"); err != nil {
		return fmt.Errorf("incremental vacuum failed: %w", err)
	}

	// Update statistics
	if _, err := db.db.ExecContext(ctx, "ANALYZE"); err != nil {
		db.logger.Warn().Err(err).Msg("Failed to update statistics")
	}

	db.logger.Info().Msg("Database vacuum completed")
	return nil
}

// CheckIntegrity performs database integrity check
func (db *Database) CheckIntegrity() error {
	return db.migrator.CheckIntegrity()
}

// GetSize returns the size of the database file in bytes
func (db *Database) GetSize() (int64, error) {
	info, err := os.Stat(db.path)
	if err != nil {
		return 0, fmt.Errorf("failed to get database file info: %w", err)
	}
	return info.Size(), nil
}

// GetPath returns the database file path
func (db *Database) GetPath() string {
	return db.path
}

// IsConnected returns true if the database connection is active
func (db *Database) IsConnected() bool {
	if db.db == nil {
		return false
	}
	return db.ping() == nil
}

// getContextWithTimeout creates a context with timeout for database operations
func (db *Database) getContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// BeginTx starts a database transaction with proper context
func (db *Database) BeginTx() (*sql.Tx, error) {
	// Use background context for transactions to avoid premature cancellation
	// The transaction lifetime is managed by the caller
	return db.db.BeginTx(context.Background(), nil)
}

// BeginTransaction is an alias for BeginTx for compatibility
func (db *Database) BeginTransaction() (*sql.Tx, error) {
	return db.BeginTx()
}

// GetAllEncryptedRecords retrieves all encrypted records from the database
func (db *Database) GetAllEncryptedRecords(tx *sql.Tx) ([]EncryptedHistoryRecord, error) {
	query := `SELECT id, encrypted_data, timestamp, session, hostname, created_at FROM history ORDER BY id`
	
	var rows *sql.Rows
	var err error
	
	if tx != nil {
		rows, err = tx.Query(query)
	} else {
		rows, err = db.db.Query(query)
	}
	
	if err != nil {
		return nil, fmt.Errorf("failed to query encrypted records: %w", err)
	}
	defer rows.Close()
	
	var records []EncryptedHistoryRecord
	for rows.Next() {
		var record EncryptedHistoryRecord
		if err := rows.Scan(
			&record.ID,
			&record.EncryptedData,
			&record.Timestamp,
			&record.Session,
			&record.Hostname,
			&record.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan encrypted record: %w", err)
		}
		records = append(records, record)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating encrypted records: %w", err)
	}
	
	return records, nil
}

// UpdateEncryptedData updates the encrypted data for a specific record
func (db *Database) UpdateEncryptedData(tx *sql.Tx, recordID int64, newEncryptedData []byte) error {
	query := `UPDATE history SET encrypted_data = ? WHERE id = ?`
	
	var err error
	if tx != nil {
		_, err = tx.Exec(query, newEncryptedData, recordID)
	} else {
		_, err = db.db.Exec(query, newEncryptedData, recordID)
	}
	
	if err != nil {
		return fmt.Errorf("failed to update encrypted data for record %d: %w", recordID, err)
	}
	
	return nil
}

// ExecContext executes a query with context and timeout
func (db *Database) ExecContext(query string, args ...interface{}) (sql.Result, error) {
	ctx, cancel := db.getContextWithTimeout(30 * time.Second)
	defer cancel()

	return db.db.ExecContext(ctx, query, args...)
}

// QueryContext executes a query with context and timeout
func (db *Database) QueryContext(query string, args ...interface{}) (*sql.Rows, error) {
	// Use background context for queries that return rows since the rows
	// need to be iterated over after the function returns
	return db.db.QueryContext(context.Background(), query, args...)
}

// QueryRowContext executes a query expecting a single row with context and timeout
func (db *Database) QueryRowContext(query string, args ...interface{}) *sql.Row {
	// Don't use timeout context for QueryRowContext since scanning happens after return
	return db.db.QueryRowContext(context.Background(), query, args...)
}

// GetConfig returns the database configuration
func (db *Database) GetConfig() *config.DatabaseConfig {
	return db.config
}

// SetSecureDeleteMode enables or disables secure delete
func (db *Database) SetSecureDeleteMode(enabled bool) error {
	value := "OFF"
	if enabled {
		value = "ON"
	}
	
	query := fmt.Sprintf("PRAGMA secure_delete = %s", value)
	if _, err := db.db.Exec(query); err != nil {
		return fmt.Errorf("failed to set secure delete mode: %w", err)
	}

	db.logger.Debug().Bool("enabled", enabled).Msg("Updated secure delete mode")
	return nil
}

