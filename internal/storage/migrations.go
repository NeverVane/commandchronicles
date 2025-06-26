package storage

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/NeverVane/commandchronicles/internal/logger"
)

// Migrator handles database schema migrations
type Migrator struct {
	db     *sql.DB
	schema *DatabaseSchema
	logger *logger.Logger
}

// NewMigrator creates a new database migrator
func NewMigrator(db *sql.DB, schema *DatabaseSchema) *Migrator {
	return &Migrator{
		db:     db,
		schema: schema,
		logger: logger.GetLogger().Database(),
	}
}

// GetCurrentVersion returns the current schema version from the database
func (m *Migrator) GetCurrentVersion() (int, error) {
	// First check if the schema_version table exists
	var tableExists int
	checkTableQuery := `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_version'`
	err := m.db.QueryRow(checkTableQuery).Scan(&tableExists)
	if err != nil {
		return 0, fmt.Errorf("failed to check if schema_version table exists: %w", err)
	}
	
	if tableExists == 0 {
		// No schema version table exists, this is a fresh database
		return 0, nil
	}
	
	// Table exists, get the current version
	var version int
	query := `SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`
	
	err = m.db.QueryRow(query).Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			// Table exists but no rows, treat as version 0
			return 0, nil
		}
		return 0, fmt.Errorf("failed to get current schema version: %w", err)
	}
	
	return version, nil
}

// InitializeSchema creates the initial database schema
func (m *Migrator) InitializeSchema() error {
	m.logger.Info().Msg("Initializing database schema")
	
	// Start transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Create all tables
	for i, table := range m.schema.Tables {
		m.logger.Debug().Int("table_index", i).Msg("Creating table")
		if _, err := tx.Exec(table); err != nil {
			return fmt.Errorf("failed to create table %d: %w", i, err)
		}
	}
	
	// Create all indexes
	for i, index := range m.schema.Indexes {
		m.logger.Debug().Int("index", i).Msg("Creating index")
		if _, err := tx.Exec(index); err != nil {
			return fmt.Errorf("failed to create index %d: %w", i, err)
		}
	}
	
	// Record schema version
	if err := m.recordSchemaVersion(tx, m.schema.Version, "Initial schema creation"); err != nil {
		return fmt.Errorf("failed to record schema version: %w", err)
	}
	
	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit schema initialization: %w", err)
	}
	
	m.logger.Info().Int("version", m.schema.Version).Msg("Database schema initialized successfully")
	return nil
}

// MigrateToLatest migrates the database to the latest schema version
func (m *Migrator) MigrateToLatest() error {
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}
	
	targetVersion := m.schema.Version
	
	if currentVersion == 0 {
		// Fresh database, initialize schema
		return m.InitializeSchema()
	}
	
	if currentVersion == targetVersion {
		m.logger.Info().Int("version", currentVersion).Msg("Database schema is up to date")
		return nil
	}
	
	if currentVersion > targetVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", currentVersion, targetVersion)
	}
	
	// Apply migrations from current version to target version
	for version := currentVersion + 1; version <= targetVersion; version++ {
		if err := m.applyMigration(version); err != nil {
			return fmt.Errorf("failed to apply migration to version %d: %w", version, err)
		}
	}
	
	return nil
}

// applyMigration applies a specific migration version
func (m *Migrator) applyMigration(version int) error {
	migrations, exists := m.schema.Migrations[version]
	if !exists {
		return fmt.Errorf("no migration found for version %d", version)
	}
	
	m.logger.Info().Int("version", version).Msg("Applying database migration")
	
	// Start transaction
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin migration transaction: %w", err)
	}
	defer tx.Rollback()
	
	// Apply all migration statements
	for i, statement := range migrations {
		m.logger.Debug().Int("version", version).Int("statement", i).Msg("Executing migration statement")
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("failed to execute migration statement %d for version %d: %w", i, version, err)
		}
	}
	
	// Record the migration
	description := fmt.Sprintf("Migration to version %d", version)
	if err := m.recordSchemaVersion(tx, version, description); err != nil {
		return fmt.Errorf("failed to record migration version: %w", err)
	}
	
	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration: %w", err)
	}
	
	m.logger.Info().Int("version", version).Msg("Migration applied successfully")
	return nil
}

// recordSchemaVersion records a schema version in the database
func (m *Migrator) recordSchemaVersion(tx *sql.Tx, version int, description string) error {
	query := `INSERT INTO schema_version (version, applied_at, description) VALUES (?, ?, ?)`
	_, err := tx.Exec(query, version, time.Now().UnixMilli(), description)
	return err
}

// ValidateSchema performs integrity checks on the database schema
func (m *Migrator) ValidateSchema() error {
	m.logger.Info().Msg("Validating database schema")
	
	// Check if all required tables exist
	requiredTables := []string{"history", "schema_version", "session_metadata"}
	for _, table := range requiredTables {
		if err := m.validateTableExists(table); err != nil {
			return fmt.Errorf("table validation failed: %w", err)
		}
	}
	
	// Check if all required indexes exist
	requiredIndexes := []string{
		"idx_history_timestamp",
		"idx_history_session", 
		"idx_history_hostname",
	}
	for _, index := range requiredIndexes {
		if err := m.validateIndexExists(index); err != nil {
			return fmt.Errorf("index validation failed: %w", err)
		}
	}
	
	// Validate schema version consistency
	if err := m.validateSchemaVersion(); err != nil {
		return fmt.Errorf("schema version validation failed: %w", err)
	}
	
	m.logger.Info().Msg("Database schema validation completed successfully")
	return nil
}

// validateTableExists checks if a table exists in the database
func (m *Migrator) validateTableExists(tableName string) error {
	query := `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
	var name string
	err := m.db.QueryRow(query, tableName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("required table %s does not exist", tableName)
		}
		return fmt.Errorf("failed to check table %s: %w", tableName, err)
	}
	return nil
}

// validateIndexExists checks if an index exists in the database
func (m *Migrator) validateIndexExists(indexName string) error {
	query := `SELECT name FROM sqlite_master WHERE type='index' AND name=?`
	var name string
	err := m.db.QueryRow(query, indexName).Scan(&name)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("required index %s does not exist", indexName)
		}
		return fmt.Errorf("failed to check index %s: %w", indexName, err)
	}
	return nil
}

// validateSchemaVersion ensures the schema version is consistent
func (m *Migrator) validateSchemaVersion() error {
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}
	
	if currentVersion < MinSupportedVersion {
		return fmt.Errorf("schema version %d is below minimum supported version %d", currentVersion, MinSupportedVersion)
	}
	
	if currentVersion > m.schema.Version {
		return fmt.Errorf("schema version %d is newer than application version %d", currentVersion, m.schema.Version)
	}
	
	return nil
}

// GetMigrationHistory returns the migration history
func (m *Migrator) GetMigrationHistory() ([]SchemaVersion, error) {
	query := `SELECT version, applied_at, description FROM schema_version ORDER BY version ASC`
	
	rows, err := m.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migration history: %w", err)
	}
	defer rows.Close()
	
	var history []SchemaVersion
	for rows.Next() {
		var sv SchemaVersion
		if err := rows.Scan(&sv.Version, &sv.AppliedAt, &sv.Description); err != nil {
			return nil, fmt.Errorf("failed to scan migration history row: %w", err)
		}
		history = append(history, sv)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating migration history: %w", err)
	}
	
	return history, nil
}

// CheckIntegrity performs a comprehensive database integrity check
func (m *Migrator) CheckIntegrity() error {
	m.logger.Info().Msg("Running database integrity check")
	
	// SQLite PRAGMA integrity_check
	var result string
	err := m.db.QueryRow("PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return fmt.Errorf("failed to run integrity check: %w", err)
	}
	
	if result != "ok" {
		return fmt.Errorf("database integrity check failed: %s", result)
	}
	
	// Check for orphaned records
	if err := m.checkOrphanedRecords(); err != nil {
		return fmt.Errorf("orphaned records check failed: %w", err)
	}
	
	m.logger.Info().Msg("Database integrity check passed")
	return nil
}

// checkOrphanedRecords looks for data inconsistencies
func (m *Migrator) checkOrphanedRecords() error {
	// Check for history records with invalid session references
	query := `
		SELECT COUNT(*) FROM history h 
		LEFT JOIN session_metadata sm ON h.session = sm.session_id 
		WHERE sm.session_id IS NULL
	`
	
	var orphanedCount int
	err := m.db.QueryRow(query).Scan(&orphanedCount)
	if err != nil {
		return fmt.Errorf("failed to check for orphaned history records: %w", err)
	}
	
	if orphanedCount > 0 {
		m.logger.Warn().Int("count", orphanedCount).Msg("Found orphaned history records")
		// Note: We could clean these up automatically or just warn
	}
	
	return nil
}