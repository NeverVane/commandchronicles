package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/NeverVane/commandchronicles/pkg/crypto"
	"github.com/NeverVane/commandchronicles/pkg/security"
)

// DeviceIDProvider interface for dependency injection
type DeviceIDProvider interface {
	GetDeviceID() (string, error)
}

// RecordHashProvider interface for dependency injection
type RecordHashProvider interface {
	GenerateRecordHash(record *storage.CommandRecord) string
}

type SecureStorage struct {
	db                 *storage.Database
	keyDerivator       *crypto.KeyDerivator
	encryptor          *crypto.Encryptor
	sessionManager     *crypto.SessionKeyManager
	permissionEnforcer *security.PermissionEnforcer
	logger             *logger.Logger
	config             *config.Config

	// Security state
	mu             sync.RWMutex
	isLocked       bool
	currentSession *crypto.SessionKey
	lastActivity   time.Time

	// Statistics
	stats *StorageStats

	// Sync dependencies (injected)
	deviceIDProvider   DeviceIDProvider
	recordHashProvider RecordHashProvider
}

// StorageStats tracks storage operations
type StorageStats struct {
	mu                 sync.RWMutex
	RecordsStored      int64
	RecordsRetrieved   int64
	BytesEncrypted     int64
	BytesDecrypted     int64
	SecurityViolations int64
	LastOperation      time.Time
}

// StorageOptions contains configuration options for secure storage
type StorageOptions struct {
	Config              *config.Config
	AutoLockTimeout     time.Duration
	EnableSecureDelete  bool
	ValidatePermissions bool
	CreateIfMissing     bool
}

// RecordWithHash represents a command record with its hash for Perfect Sync
type RecordWithHash struct {
	Record storage.CommandRecord `json:"record"`
	Hash   string                `json:"hash"`
}

// IntegrityReport contains the results of storage integrity validation
type IntegrityReport struct {
	TotalRecords      int64         `json:"total_records"`
	RecordsWithHashes int64         `json:"records_with_hashes"`
	MissingHashes     int64         `json:"missing_hashes"`
	InvalidHashes     []InvalidHash `json:"invalid_hashes"`
	IntegrityScore    float64       `json:"integrity_score"`
}

// InvalidHash represents a record with an invalid hash
type InvalidHash struct {
	RecordID     int64  `json:"record_id"`
	StoredHash   string `json:"stored_hash"`
	ComputedHash string `json:"computed_hash"`
}

// QueryOptions provides options for querying command history
type QueryOptions struct {
	Limit      int
	Offset     int
	SessionID  string
	Hostname   string
	Since      *time.Time
	Until      *time.Time
	Command    string
	ExitCode   *int
	WorkingDir string
	OrderBy    string
	Ascending  bool
}

// StoreResult contains the result of a store operation
type StoreResult struct {
	RecordID      int64
	BytesStored   int64
	EncryptedSize int64
	StoredAt      time.Time
}

// RetrieveResult contains the result of a retrieve operation
type RetrieveResult struct {
	Records       []*storage.CommandRecord
	TotalCount    int64
	HasMore       bool
	DecryptedSize int64
	RetrievedAt   time.Time
}

// Various error types
var (
	ErrStorageLocked       = errors.New("storage is locked")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrPermissionViolation = errors.New("permission violation")
	ErrRecordNotFound      = errors.New("record not found")
	ErrInvalidInput        = errors.New("invalid input")
	ErrSessionExpired      = errors.New("session expired")
	ErrStorageCorrupted    = errors.New("storage corrupted")
)

// NewSecureStorage creates a new secure storage instance
func NewSecureStorage(opts *StorageOptions) (*SecureStorage, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	if opts.Config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	logger := logger.GetLogger().Storage()

	// Initialize permission enforcer
	permissionEnforcer := security.NewPermissionEnforcer()

	// Validate and secure the data environment
	if opts.ValidatePermissions {
		configDir := filepath.Dir(opts.Config.Database.Path)
		dataDir := filepath.Dir(opts.Config.Database.Path)
		sessionPath := opts.Config.Security.SessionKeyPath

		if err := permissionEnforcer.SecureDataEnvironment(configDir, dataDir, opts.Config.Database.Path, sessionPath); err != nil {
			return nil, fmt.Errorf("failed to secure data environment: %w", err)
		}
	}

	// Initialize database
	dbOpts := &storage.DatabaseOptions{
		Config:          &opts.Config.Database,
		CreateIfMissing: opts.CreateIfMissing,
		MigrateOnOpen:   true,
		ValidateSchema:  true,
	}

	db, err := storage.NewDatabase(opts.Config, dbOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize crypto components
	keyDerivator := crypto.NewKeyDerivator()
	encryptor := crypto.NewEncryptor()
	sessionManager := crypto.NewSessionKeyManager(
		opts.Config.Security.SessionKeyPath,
		opts.Config.GetSessionTimeoutDuration(),
	)

	// Configure secure delete if requested
	if opts.EnableSecureDelete {
		if err := db.SetSecureDeleteMode(true); err != nil {
			logger.WithError(err).Warn().Msg("Failed to enable secure delete mode")
		}
	}

	ss := &SecureStorage{
		db:                 db,
		keyDerivator:       keyDerivator,
		encryptor:          encryptor,
		sessionManager:     sessionManager,
		permissionEnforcer: permissionEnforcer,
		logger:             logger,
		config:             opts.Config,
		isLocked:           true, // Start locked
		lastActivity:       time.Now(),
		stats:              &StorageStats{},
	}

	logger.Info().Msg("Secure storage initialized successfully")
	return ss, nil
}

// Unlock unlocks the storage with username and password
func (ss *SecureStorage) Unlock(username, password string) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if len(username) == 0 || len(password) == 0 {
		ss.recordSecurityViolation()
		return ErrInvalidCredentials
	}

	ss.logger.WithFields(map[string]interface{}{
		"username": username,
	}).Info().Msg("Attempting to unlock storage")

	// Delegate to auth system for consistency
	authMgr, err := auth.NewAuthManager(ss.config)
	if err != nil {
		ss.recordSecurityViolation()
		return fmt.Errorf("failed to create auth manager: %w", err)
	}

	// Verify password and get keys from auth system
	keys, err := authMgr.VerifyPassword(username, password)
	if err != nil {
		ss.recordSecurityViolation()
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Create session key object
	sessionKey := &crypto.SessionKey{
		Key:       keys.LocalKey,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Username:  username,
		ExpiresAt: time.Now().Add(time.Duration(ss.config.Security.SessionTimeout) * time.Second),
		SessionID: "auth-session",
	}

	ss.currentSession = sessionKey
	ss.isLocked = false
	ss.lastActivity = time.Now()

	ss.logger.WithFields(map[string]interface{}{
		"username": username,
	}).Info().Msg("Storage unlocked successfully")
	return nil
}

// Lock locks the storage and clears session keys
func (ss *SecureStorage) Lock() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if ss.currentSession != nil {
		ss.currentSession.SecureErase()
		ss.currentSession = nil
	}

	ss.isLocked = true
	ss.logger.Info().Msg("Storage locked")
	return nil
}

// IsLocked returns true if the storage is currently locked
func (ss *SecureStorage) IsLocked() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.isLocked
}

// UnlockWithKey unlocks the storage using a pre-derived key from the auth system
func (ss *SecureStorage) UnlockWithKey(key []byte) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if len(key) != 32 && len(key) != 64 {
		ss.recordSecurityViolation()
		return ErrInvalidCredentials
	}

	// Use first 32 bytes for storage encryption (ChaCha20-Poly1305 compatibility)
	storageKey := key
	if len(key) == 64 {
		storageKey = key[:32]
	}

	ss.logger.Info().Msg("Unlocking storage with provided key")

	// Create session key object
	sessionKey := &crypto.SessionKey{
		Key:       storageKey,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Username:  "unknown", // Username not available when unlocking with key directly
		ExpiresAt: time.Now().Add(time.Duration(ss.config.Security.SessionTimeout) * time.Second),
		SessionID: "direct-key-session",
	}

	ss.currentSession = sessionKey
	ss.isLocked = false
	ss.lastActivity = time.Now()

	ss.logger.Info().Msg("Storage unlocked successfully with provided key")
	return nil
}

// GetCurrentSessionKey returns the current session key used for encryption
func (ss *SecureStorage) GetCurrentSessionKey() []byte {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.isLocked || ss.currentSession == nil {
		return nil
	}

	return ss.currentSession.Key
}

// Store securely stores a command record
func (ss *SecureStorage) Store(record *storage.CommandRecord) (*StoreResult, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if record == nil {
		return nil, ErrInvalidInput
	}

	if !record.IsValid() {
		return nil, fmt.Errorf("%w: invalid command record", ErrInvalidInput)
	}

	ss.mu.RLock()
	sessionKey := ss.currentSession
	ss.mu.RUnlock()

	ss.logger.WithFields(map[string]interface{}{
		"command": record.Command[:min(50, len(record.Command))],
		"session": record.SessionID,
	}).Debug().Msg("Storing command record")

	// Debug: Log key info before encryption (first 4 bytes only for security)
	ss.logger.WithFields(map[string]interface{}{
		"key_length": len(sessionKey.Key),
		"key_prefix": fmt.Sprintf("%x", sessionKey.Key[:min(4, len(sessionKey.Key))]),
		"session_id": sessionKey.SessionID,
	}).Debug().Msg("Using session key for encryption")

	// Encrypt the record
	encryptedData, err := ss.encryptor.EncryptRecord(record, sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Generate sync metadata if sync is enabled and providers are available
	var deviceID, recordHash string
	syncStatus := 0 // Default: local only

	// Check sync configuration and providers
	ss.logger.Debug().
		Bool("sync_enabled", ss.config.Sync.Enabled).
		Bool("device_provider_available", ss.deviceIDProvider != nil).
		Bool("hash_provider_available", ss.recordHashProvider != nil).
		Msg("Checking sync providers for metadata generation")

	if ss.config.Sync.Enabled && ss.deviceIDProvider != nil && ss.recordHashProvider != nil {
		// Generate device ID
		if devID, err := ss.deviceIDProvider.GetDeviceID(); err == nil {
			deviceID = devID
		} else {
			ss.logger.Warn().Err(err).Msg("Failed to get device ID for sync")
		}

		// Generate record hash
		recordHash = ss.recordHashProvider.GenerateRecordHash(record)

		ss.logger.Debug().
			Str("device_id", deviceID).
			Str("record_hash", recordHash).
			Msg("Generated sync metadata for record")
	}

	// Validate database permissions before writing
	if !ss.permissionEnforcer.IsFileSecure(ss.db.GetPath()) {
		ss.recordSecurityViolation()
		return nil, fmt.Errorf("%w: database file has insecure permissions", ErrPermissionViolation)
	}

	// Store encrypted record in database
	tx, err := ss.db.BeginTx()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	// Insert encrypted history record with sync metadata
	insertQuery := `
		INSERT INTO history (encrypted_data, timestamp, session, hostname, created_at, device_id, record_hash, sync_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	result, err := tx.Exec(insertQuery, encryptedData, record.Timestamp, record.SessionID, record.Hostname, time.Now().UnixMilli(), deviceID, recordHash, syncStatus)
	if err != nil {
		return nil, fmt.Errorf("failed to insert record: %w", err)
	}

	recordID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get record ID: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	committed = true

	// Update statistics
	ss.updateStats(func(stats *StorageStats) {
		stats.RecordsStored++
		stats.BytesEncrypted += int64(len(encryptedData))
		stats.LastOperation = time.Now()
	})

	ss.updateActivity()

	storeResult := &StoreResult{
		RecordID:      recordID,
		BytesStored:   int64(len(encryptedData)),
		EncryptedSize: int64(len(encryptedData)),
		StoredAt:      time.Now(),
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id":      recordID,
		"encrypted_size": storeResult.EncryptedSize,
	}).Debug().Msg("Command record stored successfully")

	return storeResult, nil
}

// Retrieve securely retrieves command records based on query options
func (ss *SecureStorage) Retrieve(opts *QueryOptions) (*RetrieveResult, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if opts == nil {
		opts = &QueryOptions{Limit: 100}
	}

	// Apply default limit if not specified
	if opts.Limit <= 0 {
		opts.Limit = 100
	}

	// Cap maximum limit for security
	if opts.Limit > 10000 {
		opts.Limit = 10000
	}

	ss.mu.RLock()
	sessionKey := ss.currentSession
	ss.mu.RUnlock()

	ss.logger.WithFields(map[string]interface{}{
		"limit":          opts.Limit,
		"offset":         opts.Offset,
		"session_filter": opts.SessionID,
	}).Debug().Msg("Retrieving command records")

	// Build query with security-conscious parameter binding
	query, args := ss.buildRetrieveQuery(opts)

	// Validate database permissions before reading
	if !ss.permissionEnforcer.IsFileSecure(ss.db.GetPath()) {
		ss.recordSecurityViolation()
		return nil, fmt.Errorf("%w: database file has insecure permissions", ErrPermissionViolation)
	}

	// Execute query
	rows, err := ss.db.QueryContext(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var records []*storage.CommandRecord
	var totalDecryptedSize int64

	for rows.Next() {
		var encryptedRecord storage.EncryptedHistoryRecord
		if err := rows.Scan(&encryptedRecord.ID, &encryptedRecord.EncryptedData, &encryptedRecord.Timestamp, &encryptedRecord.Session, &encryptedRecord.Hostname, &encryptedRecord.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Decrypt the record
		decryptedRecord, err := ss.encryptor.DecryptRecord(encryptedRecord.EncryptedData, sessionKey.Key)
		if err != nil {
			ss.logger.WithError(err).WithFields(map[string]interface{}{
				"record_id": encryptedRecord.ID,
			}).Warn().Msg("Failed to decrypt record")
			continue // Skip corrupted records
		}

		// Set the database ID for deletion operations
		decryptedRecord.ID = encryptedRecord.ID

		records = append(records, decryptedRecord)
		totalDecryptedSize += int64(len(encryptedRecord.EncryptedData))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("row iteration error: %w", err)
	}

	// Get total count for pagination
	totalCount, err := ss.getTotalCount(opts)
	if err != nil {
		ss.logger.WithError(err).Warn().Msg("Failed to get total count")
		totalCount = int64(len(records)) // Fallback
	}

	// Update statistics
	ss.updateStats(func(stats *StorageStats) {
		stats.RecordsRetrieved += int64(len(records))
		stats.BytesDecrypted += totalDecryptedSize
		stats.LastOperation = time.Now()
	})

	ss.updateActivity()

	result := &RetrieveResult{
		Records:       records,
		TotalCount:    totalCount,
		HasMore:       int64(opts.Offset+len(records)) < totalCount,
		DecryptedSize: totalDecryptedSize,
		RetrievedAt:   time.Now(),
	}

	ss.logger.WithFields(map[string]interface{}{
		"retrieved_count": len(records),
		"total_count":     totalCount,
		"has_more":        result.HasMore,
	}).Debug().Msg("Command records retrieved successfully")

	return result, nil
}

// Delete securely deletes command records
func (ss *SecureStorage) Delete(recordIDs []int64) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if len(recordIDs) == 0 {
		return ErrInvalidInput
	}

	ss.logger.WithFields(map[string]interface{}{
		"count": len(recordIDs),
	}).Info().Msg("Deleting command records")

	// Validate database permissions
	if !ss.permissionEnforcer.IsFileSecure(ss.db.GetPath()) {
		ss.recordSecurityViolation()
		return fmt.Errorf("%w: database file has insecure permissions", ErrPermissionViolation)
	}

	tx, err := ss.db.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	// Build parameterized query to prevent SQL injection
	placeholders := make([]string, len(recordIDs))
	args := make([]interface{}, len(recordIDs))
	for i, id := range recordIDs {
		placeholders[i] = "?"
		args[i] = id
	}

	deleteQuery := fmt.Sprintf("DELETE FROM history WHERE id IN (%s)", strings.Join(placeholders, ","))
	result, err := tx.Exec(deleteQuery, args...)
	if err != nil {
		return fmt.Errorf("failed to delete records: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit deletion: %w", err)
	}
	committed = true

	ss.updateActivity()

	ss.logger.WithFields(map[string]interface{}{
		"rows_affected": rowsAffected,
	}).Info().Msg("Records deleted successfully")

	return nil
}

// DeleteRecord removes a command record by ID with secure deletion
func (ss *SecureStorage) DeleteRecord(recordID int64) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if recordID <= 0 {
		return fmt.Errorf("invalid record ID: %d", recordID)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id": recordID,
	}).Debug().Msg("Deleting command record")

	// Begin transaction for safe deletion
	tx, err := ss.db.BeginTx()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// First, verify the record exists and get its encrypted data for secure wiping
	var encryptedData []byte
	err = tx.QueryRow("SELECT encrypted_data FROM history WHERE id = ?", recordID).Scan(&encryptedData)
	if err != nil {
		if err == sql.ErrNoRows {
			return ErrRecordNotFound
		}
		return fmt.Errorf("failed to verify record existence: %w", err)
	}

	// Perform the deletion
	result, err := tx.Exec("DELETE FROM history WHERE id = ?", recordID)
	if err != nil {
		return fmt.Errorf("failed to delete record: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return ErrRecordNotFound
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit deletion: %w", err)
	}

	// Secure wipe of the encrypted data from memory
	ss.secureWipeBytes(encryptedData)

	// Update statistics
	ss.updateStats(func(stats *StorageStats) {
		stats.LastOperation = time.Now()
	})

	ss.updateActivity()

	ss.logger.WithFields(map[string]interface{}{
		"record_id": recordID,
	}).Info().Msg("Record deleted successfully")

	return nil
}

// GetRecordsForSync retrieves records that need to be synced (sync_status = 0)
func (ss *SecureStorage) GetRecordsForSync(limit int) ([]*storage.CommandRecord, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if limit <= 0 {
		limit = 100 // Default batch size
	}

	ss.logger.WithFields(map[string]interface{}{
		"limit": limit,
	}).Debug().Msg("Getting records for sync")

	query := `SELECT id, encrypted_data, timestamp, session, hostname, created_at, device_id, record_hash, sync_status, last_synced
	          FROM history
	          WHERE sync_status = 0 OR sync_status IS NULL
	          ORDER BY timestamp ASC
	          LIMIT ?`

	rows, err := ss.db.GetDB().Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query records for sync: %w", err)
	}
	defer rows.Close()

	ss.mu.RLock()
	sessionKey := ss.currentSession
	ss.mu.RUnlock()

	var records []*storage.CommandRecord
	for rows.Next() {
		var encryptedRecord storage.EncryptedHistoryRecord
		var deviceID, recordHash sql.NullString
		var syncStatus sql.NullInt64
		var lastSynced sql.NullInt64

		if err := rows.Scan(&encryptedRecord.ID, &encryptedRecord.EncryptedData,
			&encryptedRecord.Timestamp, &encryptedRecord.Session,
			&encryptedRecord.Hostname, &encryptedRecord.CreatedAt,
			&deviceID, &recordHash, &syncStatus, &lastSynced); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Decrypt the record
		decryptedRecord, err := ss.encryptor.DecryptRecord(encryptedRecord.EncryptedData, sessionKey.Key)
		if err != nil {
			ss.logger.WithError(err).WithFields(map[string]interface{}{
				"record_id": encryptedRecord.ID,
			}).Warn().Msg("Failed to decrypt record for sync")
			continue
		}

		// Set the database ID and sync metadata
		decryptedRecord.ID = encryptedRecord.ID
		if deviceID.Valid {
			decryptedRecord.DeviceID = deviceID.String
		}
		if recordHash.Valid {
			decryptedRecord.RecordHash = recordHash.String
		}
		if syncStatus.Valid {
			decryptedRecord.SyncStatus = int(syncStatus.Int64)
		}
		if lastSynced.Valid {
			decryptedRecord.LastSynced = &lastSynced.Int64
		}

		records = append(records, decryptedRecord)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating sync records: %w", err)
	}

	ss.logger.WithFields(map[string]interface{}{
		"count": len(records),
	}).Debug().Msg("Retrieved records for sync")

	return records, nil
}

// MarkRecordSyncedByHash marks a record as synced using its hash
func (ss *SecureStorage) MarkRecordSyncedByHash(hash string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if hash == "" {
		return fmt.Errorf("hash cannot be empty")
	}

	ss.logger.WithFields(map[string]interface{}{
		"hash": hash,
	}).Debug().Msg("Marking record as synced by hash")

	query := `UPDATE history SET sync_status = 1, last_synced = ? WHERE record_hash = ?`
	result, err := ss.db.GetDB().Exec(query, time.Now().UnixMilli(), hash)
	if err != nil {
		return fmt.Errorf("failed to mark record as synced: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no record found with hash: %s", hash)
	}

	ss.logger.WithFields(map[string]interface{}{
		"hash":          hash,
		"rows_affected": rowsAffected,
	}).Debug().Msg("Record marked as synced")

	return nil
}

// MarkConflictResolvedByHash marks a record's conflict as resolved
func (ss *SecureStorage) MarkConflictResolvedByHash(hash string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if hash == "" {
		return fmt.Errorf("hash cannot be empty")
	}

	ss.logger.WithFields(map[string]interface{}{
		"hash": hash,
	}).Debug().Msg("Marking conflict as resolved by hash")

	query := `UPDATE history SET sync_status = 2 WHERE record_hash = ?`
	result, err := ss.db.GetDB().Exec(query, hash)
	if err != nil {
		return fmt.Errorf("failed to mark conflict as resolved: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no record found with hash: %s", hash)
	}

	ss.logger.WithFields(map[string]interface{}{
		"hash":          hash,
		"rows_affected": rowsAffected,
	}).Debug().Msg("Conflict marked as resolved")

	return nil
}

// GetRecordByHash retrieves a record by its hash for conflict resolution
func (ss *SecureStorage) GetRecordByHash(hash string) (*storage.CommandRecord, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if hash == "" {
		return nil, fmt.Errorf("hash cannot be empty")
	}

	ss.logger.WithFields(map[string]interface{}{
		"hash": hash,
	}).Debug().Msg("Getting record by hash")

	query := `SELECT id, encrypted_data, timestamp, session, hostname, created_at
	          FROM history
	          WHERE record_hash = ?
	          LIMIT 1`

	row := ss.db.GetDB().QueryRow(query, hash)

	var encryptedRecord storage.EncryptedHistoryRecord
	if err := row.Scan(&encryptedRecord.ID, &encryptedRecord.EncryptedData,
		&encryptedRecord.Timestamp, &encryptedRecord.Session,
		&encryptedRecord.Hostname, &encryptedRecord.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrRecordNotFound
		}
		return nil, fmt.Errorf("failed to scan record: %w", err)
	}

	ss.mu.RLock()
	sessionKey := ss.currentSession
	ss.mu.RUnlock()

	// Decrypt the record
	decryptedRecord, err := ss.encryptor.DecryptRecord(encryptedRecord.EncryptedData, sessionKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt record: %w", err)
	}

	// Set the database ID
	decryptedRecord.ID = encryptedRecord.ID

	ss.logger.WithFields(map[string]interface{}{
		"hash":      hash,
		"record_id": decryptedRecord.ID,
	}).Debug().Msg("Retrieved record by hash")

	return decryptedRecord, nil
}

// UpdateRecordSyncMetadata updates sync-related metadata for a record
func (ss *SecureStorage) UpdateRecordSyncMetadata(recordID int64, hash, deviceID string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if recordID <= 0 {
		return fmt.Errorf("invalid record ID: %d", recordID)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id": recordID,
		"hash":      hash,
		"device_id": deviceID,
	}).Debug().Msg("Updating record sync metadata")

	query := `UPDATE history SET record_hash = ?, device_id = ?, sync_status = 1, last_synced = ? WHERE id = ?`
	result, err := ss.db.GetDB().Exec(query, hash, deviceID, time.Now().UnixMilli(), recordID)
	if err != nil {
		return fmt.Errorf("failed to update sync metadata: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no record found with ID: %d", recordID)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id":     recordID,
		"rows_affected": rowsAffected,
	}).Debug().Msg("Sync metadata updated")

	return nil
}

// GetLastCommandTimestamp returns the timestamp of the most recent command
func (ss *SecureStorage) GetLastCommandTimestamp() (int64, error) {
	if err := ss.checkAccess(); err != nil {
		return 0, err
	}

	timestamp, err := ss.db.GetLastCommandTimestamp()
	if err != nil {
		return 0, fmt.Errorf("failed to get last command timestamp: %w", err)
	}

	return timestamp, nil
}

// GetStats returns storage statistics
func (ss *SecureStorage) GetStats() *StorageStats {
	ss.stats.mu.RLock()
	defer ss.stats.mu.RUnlock()

	stats := &StorageStats{
		RecordsStored:      ss.stats.RecordsStored,
		RecordsRetrieved:   ss.stats.RecordsRetrieved,
		BytesEncrypted:     ss.stats.BytesEncrypted,
		BytesDecrypted:     ss.stats.BytesDecrypted,
		SecurityViolations: ss.stats.SecurityViolations,
		LastOperation:      ss.stats.LastOperation,
	}

	return stats
}

// secureWipeBytes securely wipes byte data from memory
func (ss *SecureStorage) secureWipeBytes(data []byte) {
	if len(data) == 0 {
		return
	}

	// Overwrite with zeros
	for i := range data {
		data[i] = 0
	}

	// Overwrite with random pattern
	for i := range data {
		data[i] = 0xFF
	}

	// Final overwrite with zeros
	for i := range data {
		data[i] = 0
	}
}

// Close closes the secure storage and cleans up resources
func (ss *SecureStorage) Close() error {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.logger.Info().Msg("Closing secure storage")

	// Lock storage and clear session
	if ss.currentSession != nil {
		ss.currentSession.SecureErase()
		ss.currentSession = nil
	}
	ss.isLocked = true

	// Close session manager
	if err := ss.sessionManager.Close(); err != nil {
		ss.logger.WithError(err).Warn().Msg("Failed to close session manager")
	}

	// Close database
	if err := ss.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}

	ss.logger.Info().Msg("Secure storage closed successfully")
	return nil
}

// ValidateIntegrity performs comprehensive integrity checks on the storage
func (ss *SecureStorage) ValidateIntegrity() error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	ss.logger.Info().Msg("Starting storage integrity validation")

	// Validate file permissions
	if err := ss.permissionEnforcer.ValidateDataFiles(ss.db.GetPath(), ss.config.Security.SessionKeyPath); err != nil {
		return fmt.Errorf("permission validation failed: %w", err)
	}

	// Validate database integrity
	if err := ss.db.CheckIntegrity(); err != nil {
		return fmt.Errorf("database integrity check failed: %w", err)
	}

	// Test encryption/decryption with a sample record
	if err := ss.validateCrypto(); err != nil {
		return fmt.Errorf("cryptographic validation failed: %w", err)
	}

	ss.logger.Info().Msg("Storage integrity validation completed successfully")
	return nil
}

// AddNote adds a note to an existing command record
func (ss *SecureStorage) AddNote(recordID int64, note string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if recordID <= 0 {
		return fmt.Errorf("invalid record ID: %d", recordID)
	}

	if len(strings.TrimSpace(note)) > storage.MaxNoteLength {
		return fmt.Errorf("note exceeds maximum length of %d characters", storage.MaxNoteLength)
	}

	// Get the existing record
	record, err := ss.getRecordByID(recordID)
	if err != nil {
		return fmt.Errorf("failed to get record: %w", err)
	}

	// Set the note
	if err := record.SetNote(note); err != nil {
		return fmt.Errorf("failed to set note: %w", err)
	}

	// Update the record
	if err := ss.updateRecord(record); err != nil {
		return fmt.Errorf("failed to update record with note: %w", err)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id":   recordID,
		"note_length": len(strings.TrimSpace(note)),
	}).Info().Msg("Note added to command record")

	return nil
}

// GetNote retrieves the note for a specific command record
func (ss *SecureStorage) GetNote(recordID int64) (string, error) {
	if err := ss.checkAccess(); err != nil {
		return "", err
	}

	if recordID <= 0 {
		return "", fmt.Errorf("invalid record ID: %d", recordID)
	}

	record, err := ss.getRecordByID(recordID)
	if err != nil {
		return "", fmt.Errorf("failed to get record: %w", err)
	}

	return record.Note, nil
}

// UpdateNote updates the note for an existing command record
func (ss *SecureStorage) UpdateNote(recordID int64, note string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if recordID <= 0 {
		return fmt.Errorf("invalid record ID: %d", recordID)
	}

	if len(strings.TrimSpace(note)) > storage.MaxNoteLength {
		return fmt.Errorf("note exceeds maximum length of %d characters", storage.MaxNoteLength)
	}

	// Get the existing record
	record, err := ss.getRecordByID(recordID)
	if err != nil {
		return fmt.Errorf("failed to get record: %w", err)
	}

	// Update the note
	if err := record.SetNote(note); err != nil {
		return fmt.Errorf("failed to set note: %w", err)
	}

	// Update the record
	if err := ss.updateRecord(record); err != nil {
		return fmt.Errorf("failed to update record with note: %w", err)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id":   recordID,
		"note_length": len(strings.TrimSpace(note)),
	}).Info().Msg("Note updated for command record")

	return nil
}

// DeleteNote removes the note from a command record
func (ss *SecureStorage) DeleteNote(recordID int64) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if recordID <= 0 {
		return fmt.Errorf("invalid record ID: %d", recordID)
	}

	// Get the existing record
	record, err := ss.getRecordByID(recordID)
	if err != nil {
		return fmt.Errorf("failed to get record: %w", err)
	}

	// Clear the note
	record.ClearNote()

	// Update the record
	if err := ss.updateRecord(record); err != nil {
		return fmt.Errorf("failed to update record after deleting note: %w", err)
	}

	ss.logger.WithFields(map[string]interface{}{
		"record_id": recordID,
	}).Info().Msg("Note deleted from command record")

	return nil
}

// HasNote checks if a command record has a note
func (ss *SecureStorage) HasNote(recordID int64) (bool, error) {
	if err := ss.checkAccess(); err != nil {
		return false, err
	}

	if recordID <= 0 {
		return false, fmt.Errorf("invalid record ID: %d", recordID)
	}

	record, err := ss.getRecordByID(recordID)
	if err != nil {
		return false, fmt.Errorf("failed to get record: %w", err)
	}

	return record.HasNote(), nil
}

// SearchNotes searches for commands that contain notes matching the query
func (ss *SecureStorage) SearchNotes(query string, opts *QueryOptions) (*RetrieveResult, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("search query cannot be empty")
	}

	// Get all records (we need to decrypt to search notes)
	allRecords, err := ss.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	// Filter records that have notes matching the query
	var matchingRecords []*storage.CommandRecord
	query = strings.ToLower(strings.TrimSpace(query))

	for _, record := range allRecords.Records {
		if record.HasNote() {
			noteText := strings.ToLower(record.Note)
			if strings.Contains(noteText, query) {
				matchingRecords = append(matchingRecords, record)
			}
		}
	}

	result := &RetrieveResult{
		Records:    matchingRecords,
		TotalCount: int64(len(matchingRecords)),
		HasMore:    false,
	}

	ss.logger.WithFields(map[string]interface{}{
		"query":         query,
		"total_records": allRecords.TotalCount,
		"matches":       len(matchingRecords),
	}).Info().Msg("Note search completed")

	return result, nil
}

// GetNotesContaining returns all records with notes containing the specified text
func (ss *SecureStorage) GetNotesContaining(searchText string, opts *QueryOptions) (*RetrieveResult, error) {
	return ss.SearchNotes(searchText, opts)
}

// GetCommandByID retrieves a specific command by its ID
func (ss *SecureStorage) GetCommandByID(commandID string) (*storage.CommandRecord, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if commandID == "" {
		return nil, fmt.Errorf("command ID cannot be empty")
	}

	// Convert string ID to int64
	recordID, err := strconv.ParseInt(commandID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid command ID: %s", commandID)
	}

	return ss.getRecordByID(recordID)
}

// UpdateCommand updates an existing command record
func (ss *SecureStorage) UpdateCommand(record *storage.CommandRecord) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	if record == nil {
		return fmt.Errorf("record cannot be nil")
	}

	return ss.updateRecord(record)
}

// SearchCommandsWithTags retrieves all commands that have tags
func (ss *SecureStorage) SearchCommandsWithTags() ([]*storage.CommandRecord, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	// Get all records and filter for those with tags
	opts := &QueryOptions{Limit: 10000} // Large limit to get all records
	allRecords, err := ss.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	var taggedRecords []*storage.CommandRecord
	for _, record := range allRecords.Records {
		if record.HasTags() {
			taggedRecords = append(taggedRecords, record)
		}
	}

	return taggedRecords, nil
}

// SearchCommandsByTag retrieves all commands that have a specific tag
func (ss *SecureStorage) SearchCommandsByTag(tag string) ([]*storage.CommandRecord, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	if strings.TrimSpace(tag) == "" {
		return nil, fmt.Errorf("tag cannot be empty")
	}

	// Get all records and filter for those with the specific tag
	opts := &QueryOptions{Limit: 10000} // Large limit to get all records
	allRecords, err := ss.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	var matchingRecords []*storage.CommandRecord
	for _, record := range allRecords.Records {
		if record.HasTag(tag) {
			matchingRecords = append(matchingRecords, record)
		}
	}

	return matchingRecords, nil
}

// GetAllNotedCommands returns all commands that have notes
func (ss *SecureStorage) GetAllNotedCommands(opts *QueryOptions) (*RetrieveResult, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	// Get all records
	allRecords, err := ss.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	// Filter records that have notes
	var notedRecords []*storage.CommandRecord
	for _, record := range allRecords.Records {
		if record.HasNote() {
			notedRecords = append(notedRecords, record)
		}
	}

	result := &RetrieveResult{
		Records:    notedRecords,
		TotalCount: int64(len(notedRecords)),
		HasMore:    false,
	}

	ss.logger.WithFields(map[string]interface{}{
		"total_records": allRecords.TotalCount,
		"noted_records": len(notedRecords),
	}).Info().Msg("Retrieved all noted commands")

	return result, nil
}

// getRecordByID retrieves a single record by ID
func (ss *SecureStorage) getRecordByID(recordID int64) (*storage.CommandRecord, error) {

	// Query the database for the specific record
	query := `SELECT id, encrypted_data, timestamp, session, hostname, created_at
			  FROM history WHERE id = ? LIMIT 1`

	row := ss.db.GetDB().QueryRow(query, recordID)

	var encRecord storage.EncryptedHistoryRecord
	err := row.Scan(&encRecord.ID, &encRecord.EncryptedData, &encRecord.Timestamp,
		&encRecord.Session, &encRecord.Hostname, &encRecord.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("record not found with ID %d", recordID)
		}
		return nil, fmt.Errorf("failed to query record: %w", err)
	}

	// Decrypt the record
	decryptedData, err := ss.encryptor.DecryptBytes(encRecord.EncryptedData, ss.currentSession.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt record: %w", err)
	}

	// Parse the JSON
	var record storage.CommandRecord
	if err := json.Unmarshal(decryptedData, &record); err != nil {
		return nil, fmt.Errorf("failed to parse record JSON: %w", err)
	}

	// Set the ID from the database
	record.ID = encRecord.ID

	return &record, nil
}

// GetDatabase returns the underlying database instance
func (ss *SecureStorage) GetDatabase() *storage.Database {
	return ss.db
}

// updateRecord updates an existing record in the database
func (ss *SecureStorage) updateRecord(record *storage.CommandRecord) error {
	if record.ID <= 0 {
		return fmt.Errorf("invalid record ID: %d", record.ID)
	}

	// Validate the record
	if !record.IsValid() {
		return fmt.Errorf("invalid record data")
	}

	// Ensure note is within limits
	if !record.IsNoteValid() {
		return fmt.Errorf("note exceeds maximum length")
	}

	// Generate hash if using sync
	if ss.recordHashProvider != nil {
		record.RecordHash = ss.recordHashProvider.GenerateRecordHash(record)
	}

	// Set device ID if available
	if ss.deviceIDProvider != nil {
		if deviceID, err := ss.deviceIDProvider.GetDeviceID(); err == nil {
			record.DeviceID = deviceID
		}
	}

	// Reset sync status since we're updating
	record.SyncStatus = storage.SyncStatusLocal
	record.LastSynced = nil

	// Serialize to JSON
	jsonData, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to serialize record: %w", err)
	}

	// Encrypt the data
	encryptedData, err := ss.encryptor.EncryptBytes(jsonData, ss.currentSession.Key)
	if err != nil {
		return fmt.Errorf("failed to encrypt record: %w", err)
	}

	// Update in database
	query := `UPDATE history
			  SET encrypted_data = ?, record_hash = ?, device_id = ?, sync_status = ?, last_synced = ?
			  WHERE id = ?`

	_, err = ss.db.GetDB().Exec(query, encryptedData, record.RecordHash, record.DeviceID,
		record.SyncStatus, record.LastSynced, record.ID)

	if err != nil {
		return fmt.Errorf("failed to update record in database: %w", err)
	}

	// Update stats
	ss.stats.mu.Lock()
	ss.stats.BytesEncrypted += int64(len(encryptedData))
	ss.stats.LastOperation = time.Now()
	ss.stats.mu.Unlock()

	return nil
}

// Internal helper methods

func (ss *SecureStorage) checkAccess() error {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	if ss.isLocked {
		return ErrStorageLocked
	}

	if ss.currentSession == nil {
		return ErrSessionExpired
	}

	if ss.currentSession.IsExpired() {
		return ErrSessionExpired
	}

	return nil
}

func (ss *SecureStorage) updateActivity() {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.lastActivity = time.Now()
}

func (ss *SecureStorage) recordSecurityViolation() {
	ss.updateStats(func(stats *StorageStats) {
		stats.SecurityViolations++
	})
	ss.logger.Warn().Msg("Security violation recorded")
}

func (ss *SecureStorage) updateStats(updateFunc func(*StorageStats)) {
	ss.stats.mu.Lock()
	defer ss.stats.mu.Unlock()
	updateFunc(ss.stats)
}

func (ss *SecureStorage) buildRetrieveQuery(opts *QueryOptions) (string, []interface{}) {
	query := `SELECT id, encrypted_data, timestamp, session, hostname, created_at FROM history WHERE 1=1`
	var args []interface{}

	if opts.SessionID != "" {
		query += " AND session = ?"
		args = append(args, opts.SessionID)
	}

	if opts.Hostname != "" {
		query += " AND hostname = ?"
		args = append(args, opts.Hostname)
	}

	if opts.Since != nil {
		query += " AND timestamp >= ?"
		args = append(args, opts.Since.UnixMilli())
	}

	if opts.Until != nil {
		query += " AND timestamp <= ?"
		args = append(args, opts.Until.UnixMilli())
	}

	// Add ordering
	orderBy := "timestamp"
	if opts.OrderBy != "" {
		// Whitelist allowed order by columns for security
		allowedColumns := map[string]bool{
			"timestamp":  true,
			"created_at": true,
			"hostname":   true,
			"session":    true,
		}
		if allowedColumns[opts.OrderBy] {
			orderBy = opts.OrderBy
		}
	}

	direction := "DESC"
	if opts.Ascending {
		direction = "ASC"
	}

	query += fmt.Sprintf(" ORDER BY %s %s", orderBy, direction)

	// Add limit and offset
	query += " LIMIT ? OFFSET ?"
	args = append(args, opts.Limit, opts.Offset)

	return query, args
}

func (ss *SecureStorage) getTotalCount(opts *QueryOptions) (int64, error) {
	query := `SELECT COUNT(*) FROM history WHERE 1=1`
	var args []interface{}

	if opts.SessionID != "" {
		query += " AND session = ?"
		args = append(args, opts.SessionID)
	}

	if opts.Hostname != "" {
		query += " AND hostname = ?"
		args = append(args, opts.Hostname)
	}

	if opts.Since != nil {
		query += " AND timestamp >= ?"
		args = append(args, opts.Since.UnixMilli())
	}

	if opts.Until != nil {
		query += " AND timestamp <= ?"
		args = append(args, opts.Until.UnixMilli())
	}

	var count int64
	if err := ss.db.QueryRowContext(query, args...).Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

func (ss *SecureStorage) updateSessionMetadata(tx *sql.Tx, record *storage.CommandRecord) error {
	// Insert or update session metadata
	query := `
		INSERT INTO session_metadata (session_id, start_time, hostname, user_name, shell_type, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id) DO UPDATE SET
			end_time = NULL
	`

	_, err := tx.Exec(query, record.SessionID, record.Timestamp, record.Hostname, record.User, record.Shell, time.Now().UnixMilli())
	return err
}

func (ss *SecureStorage) validateCrypto() error {
	ss.mu.RLock()
	sessionKey := ss.currentSession
	ss.mu.RUnlock()

	// Create a test record
	testRecord := storage.NewCommandRecord(
		"echo test",
		0,
		10,
		"/tmp",
		"test-session",
		"test-host",
	)

	// Test encryption
	encrypted, err := ss.encryptor.EncryptRecord(testRecord, sessionKey.Key)
	if err != nil {
		return fmt.Errorf("test encryption failed: %w", err)
	}

	// Test decryption
	decrypted, err := ss.encryptor.DecryptRecord(encrypted, sessionKey.Key)
	if err != nil {
		return fmt.Errorf("test decryption failed: %w", err)
	}

	// Verify data integrity
	if decrypted.Command != testRecord.Command {
		return fmt.Errorf("decrypted data does not match original")
	}

	return nil
}

// GetAllRecordsWithHashes retrieves all records with their hashes for Perfect Sync
func (ss *SecureStorage) GetAllRecordsWithHashes() ([]RecordWithHash, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	ss.logger.Debug().Msg("Getting all records with hashes for Perfect Sync")

	// Get all encrypted records from database
	encryptedRecords, err := ss.db.GetAllEncryptedRecords(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted records: %w", err)
	}

	sessionKey := ss.currentSession
	if sessionKey == nil {
		return nil, ErrStorageLocked
	}

	var recordsWithHashes []RecordWithHash

	for _, encRecord := range encryptedRecords {
		// Decrypt the record
		decrypted, err := ss.encryptor.DecryptRecord(encRecord.EncryptedData, sessionKey.Key)
		if err != nil {
			ss.logger.Warn().Err(err).Int64("id", encRecord.ID).Msg("Failed to decrypt record for hash collection")
			continue
		}

		// Generate hash if missing
		recordHash := decrypted.RecordHash
		if recordHash == "" && ss.recordHashProvider != nil {
			recordHash = ss.recordHashProvider.GenerateRecordHash(decrypted)
			// Update the record with the generated hash
			decrypted.RecordHash = recordHash
			// TODO: Consider updating the stored record with the hash
		}

		recordsWithHashes = append(recordsWithHashes, RecordWithHash{
			Record: *decrypted,
			Hash:   recordHash,
		})
	}

	ss.logger.Info().Int("count", len(recordsWithHashes)).Msg("Retrieved all records with hashes")
	return recordsWithHashes, nil
}

// UpdateRecordHash updates the hash value for a specific record
func (ss *SecureStorage) UpdateRecordHash(recordID int64, newHash string) error {
	if err := ss.checkAccess(); err != nil {
		return err
	}

	ss.logger.Debug().Int64("record_id", recordID).Str("hash", newHash).Msg("Updating record hash")

	// Get the current encrypted record
	query := `SELECT encrypted_data FROM history WHERE id = ?`
	row := ss.db.QueryRowContext(query, recordID)

	var encryptedData []byte
	if err := row.Scan(&encryptedData); err != nil {
		if err == sql.ErrNoRows {
			return ErrRecordNotFound
		}
		return fmt.Errorf("failed to get record for hash update: %w", err)
	}

	// Decrypt the record
	sessionKey := ss.currentSession
	if sessionKey == nil {
		return ErrStorageLocked
	}

	decrypted, err := ss.encryptor.DecryptRecord(encryptedData, sessionKey.Key)
	if err != nil {
		return fmt.Errorf("failed to decrypt record for hash update: %w", err)
	}

	// Update the hash
	decrypted.RecordHash = newHash

	// Re-encrypt and store
	newEncryptedData, err := ss.encryptor.EncryptRecord(decrypted, sessionKey.Key)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt record with new hash: %w", err)
	}

	// Update the database
	if err := ss.db.UpdateEncryptedData(nil, recordID, newEncryptedData); err != nil {
		return fmt.Errorf("failed to update record with new hash: %w", err)
	}

	ss.logger.Info().Int64("record_id", recordID).Msg("Record hash updated successfully")
	return nil
}

// GetRecordCountByStatus returns the count of records by sync status
func (ss *SecureStorage) GetRecordCountByStatus(syncStatus int) (int64, error) {
	if err := ss.checkAccess(); err != nil {
		return 0, err
	}

	query := `SELECT COUNT(*) FROM history WHERE sync_status = ?`
	row := ss.db.QueryRowContext(query, syncStatus)

	var count int64
	if err := row.Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to get record count by status: %w", err)
	}

	return count, nil
}

// ValidateHashIntegrity performs hash integrity validation on stored records for Perfect Sync
func (ss *SecureStorage) ValidateHashIntegrity() (*IntegrityReport, error) {
	if err := ss.checkAccess(); err != nil {
		return nil, err
	}

	ss.logger.Info().Msg("Starting storage integrity validation")

	// Get all records with hashes
	recordsWithHashes, err := ss.GetAllRecordsWithHashes()
	if err != nil {
		return nil, fmt.Errorf("failed to get records for integrity check: %w", err)
	}

	report := &IntegrityReport{
		TotalRecords:      int64(len(recordsWithHashes)),
		RecordsWithHashes: 0,
		MissingHashes:     0,
		InvalidHashes:     []InvalidHash{},
	}

	if ss.recordHashProvider == nil {
		ss.logger.Warn().Msg("No hash provider available for integrity validation")
		report.IntegrityScore = 0.0
		return report, nil
	}

	for _, rwh := range recordsWithHashes {
		if rwh.Hash == "" {
			report.MissingHashes++
			continue
		}

		report.RecordsWithHashes++

		// Compute expected hash
		expectedHash := ss.recordHashProvider.GenerateRecordHash(&rwh.Record)
		if rwh.Hash != expectedHash {
			report.InvalidHashes = append(report.InvalidHashes, InvalidHash{
				RecordID:     rwh.Record.ID,
				StoredHash:   rwh.Hash,
				ComputedHash: expectedHash,
			})
		}
	}

	// Calculate integrity score
	if report.TotalRecords > 0 {
		validHashes := report.RecordsWithHashes - int64(len(report.InvalidHashes))
		report.IntegrityScore = float64(validHashes) / float64(report.TotalRecords)
	} else {
		report.IntegrityScore = 1.0 // Empty storage is considered fully integral
	}

	ss.logger.Info().
		Int64("total", report.TotalRecords).
		Int64("with_hashes", report.RecordsWithHashes).
		Int64("missing_hashes", report.MissingHashes).
		Int("invalid_hashes", len(report.InvalidHashes)).
		Float64("integrity_score", report.IntegrityScore).
		Msg("Storage integrity validation completed")

	return report, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SetSyncProviders injects sync dependencies for metadata generation
func (ss *SecureStorage) SetSyncProviders(deviceProvider DeviceIDProvider, hashProvider RecordHashProvider) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	ss.deviceIDProvider = deviceProvider
	ss.recordHashProvider = hashProvider

	ss.logger.Debug().
		Bool("device_provider_set", ss.deviceIDProvider != nil).
		Bool("hash_provider_set", ss.recordHashProvider != nil).
		Msg("Sync providers successfully injected")
}
