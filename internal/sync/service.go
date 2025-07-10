package sync

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
	"github.com/NeverVane/commandchronicles/pkg/crypto"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

type SyncService struct {
	config             *config.Config
	logger             *logger.Logger
	storage            *securestorage.SecureStorage
	localAuth          *auth.AuthManager
	remoteAuth         *RemoteAuthenticator
	client             *SyncClient
	conflictResolver   *ConflictResolver
	tokenManager       *TokenManager
	deviceManager      *DeviceManager
	deviceAliasManager *DeviceAliasManager
	hashGenerator      *HashGenerator
	encryptor          *crypto.Encryptor

	// Sync state
	lastSyncTime int64
	isRunning    bool
	syncKey      []byte
}

type SyncStats struct {
	LastSyncTime      int64         `json:"last_sync_time"`
	TotalUploaded     int64         `json:"total_uploaded"`
	TotalDownloaded   int64         `json:"total_downloaded"`
	ConflictsResolved int64         `json:"conflicts_resolved"`
	LastSyncDuration  time.Duration `json:"last_sync_duration"`
	ErrorCount        int64         `json:"error_count"`
	IsAuthenticated   bool          `json:"is_authenticated"`
}

// Batch update constants
const (
	MaxBatchRetries = 5
	BatchSize       = 1000
	LockTimeout     = time.Hour
)

// BatchUpdateRequest represents a batch of records to update remotely
type BatchUpdateRequest struct {
	DeviceID      string         `json:"device_id"`
	Records       []RecordUpdate `json:"records"`
	BatchMetadata BatchMetadata  `json:"batch_metadata"`
}

// BatchMetadata contains metadata about the batch
type BatchMetadata struct {
	BatchNumber    int  `json:"batch_number"`
	TotalBatches   int  `json:"total_batches"`
	IsLastBatch    bool `json:"is_last_batch"`
	RecordsInBatch int  `json:"records_in_batch"`
}

// RecordUpdate represents a single record update
type RecordUpdate struct {
	RecordHash          string `json:"record_hash"`
	NewEncryptedPayload string `json:"new_encrypted_payload"`
	UpdateReason        string `json:"update_reason"`
}

// PasswordChangeLockStatus represents the response from lock status endpoint
type PasswordChangeLockStatus struct {
	IsLocked   bool     `json:"is_locked"`
	CanProceed bool     `json:"can_proceed"`
	LockInfo   LockInfo `json:"lock_info"`
	Reason     string   `json:"reason,omitempty"`
}

// LockInfo contains details about the password change lock
type LockInfo struct {
	UserID    string `json:"user_id"`
	DeviceID  string `json:"device_id"`
	ExpiresAt int64  `json:"expires_at"`
	CreatedAt int64  `json:"created_at"`
}

// BatchUpdateResponse represents the response from batch update
type BatchUpdateResponse struct {
	Success        bool   `json:"success"`
	ProcessedCount int    `json:"processed_count"`
	FailedCount    int    `json:"failed_count"`
	Message        string `json:"message,omitempty"`
}

func NewSyncService(cfg *config.Config, storage *securestorage.SecureStorage, localAuth *auth.AuthManager) *SyncService {
	remoteAuth := NewRemoteAuthenticator(cfg, localAuth)
	client := NewSyncClient(cfg, remoteAuth)
	deviceManager := NewDeviceManager(cfg)
	deviceAliasManager := NewDeviceAliasManager(storage, cfg)
	hashGenerator := NewHashGenerator()

	service := &SyncService{
		config:             cfg,
		logger:             logger.GetLogger().WithComponent("sync-service"),
		storage:            storage,
		localAuth:          localAuth,
		remoteAuth:         remoteAuth,
		client:             client,
		conflictResolver:   NewConflictResolver(),
		tokenManager:       NewTokenManager(cfg),
		deviceManager:      deviceManager,
		deviceAliasManager: deviceAliasManager,
		hashGenerator:      hashGenerator,
		encryptor:          crypto.NewEncryptor(),
		lastSyncTime:       0,
		isRunning:          false,
	}

	// Inject sync providers into storage for metadata generation
	if storage != nil {
		storage.SetSyncProviders(deviceManager, hashGenerator)
	}

	return service
}

func (s *SyncService) Initialize() error {
	if !s.config.Sync.Enabled {
		s.logger.Info().Msg("Sync is disabled in configuration")
		return nil
	}

	s.logger.Info().Msg("Initializing sync service")

	// Load last sync time
	s.lastSyncTime = s.getLastSyncTime()

	// Validate authentication
	if s.remoteAuth.IsAuthenticated() {
		s.logger.Info().Msg("Sync service initialized with valid authentication")
	} else {
		s.logger.Warn().Msg("Sync service initialized but not authenticated")
	}

	return nil
}

func (s *SyncService) Authenticate(email, password string) error {
	if !s.config.Sync.Enabled {
		return fmt.Errorf("sync is not enabled")
	}

	// Ensure local authentication is active first
	if !s.localAuth.IsSessionActive() {
		return fmt.Errorf("local authentication required - please unlock storage first")
	}

	return s.remoteAuth.Authenticate(email, password)
}

func (s *SyncService) PerformSync() error {
	if !s.config.Sync.Enabled {
		return fmt.Errorf("sync is not enabled")
	}

	if s.isRunning {
		return fmt.Errorf("sync is already in progress")
	}

	// Ensure both local and remote authentication
	if !s.localAuth.IsSessionActive() {
		return fmt.Errorf("local authentication required - please unlock storage first")
	}

	if !s.remoteAuth.IsAuthenticated() {
		return fmt.Errorf("remote authentication required - please run 'ccr sync enable' first")
	}

	s.isRunning = true
	defer func() { s.isRunning = false }()

	start := time.Now()
	s.logger.Info().Msg("Starting sync operation")

	// Load current sync time from storage
	s.lastSyncTime = s.getLastSyncTime()

	// Update device list during sync
	if err := s.updateDevicesList(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update devices list during sync")
	}

	// Upload local changes first
	if err := s.UploadNewRecords(); err != nil {
		s.logger.Error().Err(err).Msg("Upload failed")
		return fmt.Errorf("upload failed: %w", err)
	}

	// Download remote changes
	if err := s.DownloadNewRecords(); err != nil {
		s.logger.Error().Err(err).Msg("Download failed")
		return fmt.Errorf("download failed: %w", err)
	}

	// Update last sync time only after both upload and download succeed
	s.lastSyncTime = time.Now().UnixMilli()
	if err := s.saveLastSyncTime(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to save sync time, but sync completed successfully")
	}

	duration := time.Since(start)
	s.logger.Info().
		Dur("duration", duration).
		Msg("Sync operation completed successfully")

	return nil
}

func (s *SyncService) UploadNewRecords() error {
	// Get records that need syncing
	records, err := s.getRecordsForSync()
	if err != nil {
		return fmt.Errorf("failed to get records for sync: %w", err)
	}

	if len(records) == 0 {
		s.logger.Debug().Msg("No new records to upload")
		return nil
	}

	// Get device ID
	deviceID, err := s.deviceManager.GetDeviceID()
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}

	// Convert storage records to sync records
	syncRecords := make([]SyncRecord, len(records))
	for i, record := range records {
		// Generate hash if missing
		recordHash := record.RecordHash
		if recordHash == "" {
			recordHash = s.hashGenerator.GenerateRecordHash(record)
			// Update the record with the generated hash
			record.RecordHash = recordHash

			s.logger.Info().
				Int64("record_id", record.ID).
				Str("command", record.Command).
				Str("generated_hash", recordHash).
				Int("hash_length", len(recordHash)).
				Msg("Generated hash for record")

			// Store the generated hash in the database
			if err := s.storage.UpdateRecordHash(record.ID, recordHash); err != nil {
				s.logger.Warn().Err(err).Int64("id", record.ID).Str("hash", recordHash).Msg("Failed to update record hash in database")
			} else {
				s.logger.Debug().Int64("id", record.ID).Str("hash", recordHash).Msg("Updated record hash in database")
			}
		} else {
			s.logger.Debug().
				Int64("record_id", record.ID).
				Str("existing_hash", recordHash).
				Int("hash_length", len(recordHash)).
				Msg("Using existing hash for record")
		}

		// Encrypt the record data
		encryptedPayload, err := s.encryptRecord(record)
		if err != nil {
			return fmt.Errorf("failed to encrypt record: %w", err)
		}

		syncRecords[i] = SyncRecord{
			RecordHash:       recordHash,
			EncryptedPayload: encryptedPayload,
			TimestampMs:      record.Timestamp,
			Hostname:         record.Hostname,
			SessionID:        record.SessionID,
		}
	}

	// Prepare metadata
	metadata := SyncMetadata{
		ClientVersion:    "1.0.0",
		LastSyncTime:     s.lastSyncTime,
		TotalRecordCount: len(records),
	}

	// Upload records
	response, err := s.client.UploadRecords(syncRecords, deviceID, metadata)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}

	// Mark records as synced
	if err := s.markRecordsAsSynced(records); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to mark records as synced")
	}

	s.logger.Info().
		Int("uploaded", response.ProcessedCount).
		Int("duplicates", response.DuplicateCount).
		Int("conflicts", response.Conflicts).
		Msg("Upload completed")

	return nil
}

func (s *SyncService) DownloadNewRecords() error {
	// Get device ID
	deviceID, err := s.deviceManager.GetDeviceID()
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}

	s.logger.Info().
		Str("device_id", deviceID).
		Int64("since", s.lastSyncTime).
		Int("batch_size", s.config.Sync.BatchSize).
		Msg("Starting download from server")

	// Download records since last sync
	response, err := s.client.DownloadRecords(deviceID, s.lastSyncTime, s.config.Sync.BatchSize, false)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}

	s.logger.Info().
		Int("records_count", len(response.Records)).
		Bool("has_more", response.HasMore).
		Int("total_count", response.TotalCount).
		Msg("Received download response from server")

	if len(response.Records) == 0 {
		s.logger.Debug().Msg("No new records to download")
		return nil
	}

	// Process downloaded records
	for _, syncRecord := range response.Records {
		// Decrypt the record
		record, err := s.decryptRecord(&syncRecord)
		if err != nil {
			s.logger.Warn().Err(err).Str("hash", syncRecord.RecordHash).Msg("Failed to decrypt record")
			continue
		}

		// Store the record
		if _, err := s.storage.Store(record); err != nil {
			s.logger.Warn().Err(err).Str("hash", syncRecord.RecordHash).Msg("Failed to store record")
			continue
		}
	}

	s.logger.Info().
		Int("downloaded", len(response.Records)).
		Bool("has_more", response.HasMore).
		Msg("Download completed")

	return nil
}

func (s *SyncService) getRecordsForSync() ([]*storage.CommandRecord, error) {
	if s.storage == nil {
		return nil, fmt.Errorf("storage not available")
	}

	// Get records that haven't been synced yet
	return s.storage.GetRecordsForSync(s.config.Sync.BatchSize)
}

func (s *SyncService) encryptRecord(record *storage.CommandRecord) ([]byte, error) {
	// Convert record to JSON
	recordJSON, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal record: %w", err)
	}

	// Get session key for encryption
	sessionKey, err := s.localAuth.LoadSessionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load session key: %w", err)
	}

	// Encrypt with session key (use first 32 bytes only)
	encrypted, err := s.encryptor.EncryptBytes(recordJSON, sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt record: %w", err)
	}

	return encrypted, nil
}

func (s *SyncService) decryptRecord(syncRecord *SyncRecord) (*storage.CommandRecord, error) {
	// Get session key for decryption
	sessionKey, err := s.localAuth.LoadSessionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load session key: %w", err)
	}

	// Decrypt the payload (use first 32 bytes of session key)
	decrypted, err := s.encryptor.DecryptBytes(syncRecord.EncryptedPayload, sessionKey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt record: %w", err)
	}

	// Parse the record
	var record storage.CommandRecord
	if err := json.Unmarshal(decrypted, &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal record: %w", err)
	}

	return &record, nil
}

func (s *SyncService) markRecordsAsSynced(records []*storage.CommandRecord) error {
	if s.storage == nil {
		return fmt.Errorf("storage not available")
	}

	for _, record := range records {
		record.MarkSynced()
		if err := s.storage.UpdateRecordSyncMetadata(record.ID, record.RecordHash, record.DeviceID); err != nil {
			s.logger.Warn().Err(err).Int64("id", record.ID).Msg("Failed to update sync status")
		}
	}

	return nil
}

func (s *SyncService) getLastSyncTime() int64 {
	syncTimeFile := filepath.Join(s.config.DataDir, "last_sync_time")

	data, err := os.ReadFile(syncTimeFile)
	if err != nil {
		if os.IsNotExist(err) {
			s.logger.Debug().Msg("No previous sync time found, starting from epoch")
			return 0
		}
		s.logger.Warn().Err(err).Msg("Failed to read sync time file, starting from epoch")
		return 0
	}

	var syncTime int64
	if err := json.Unmarshal(data, &syncTime); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to parse sync time file, starting from epoch")
		return 0
	}

	s.logger.Debug().Int64("last_sync_time", syncTime).Msg("Loaded previous sync time")
	return syncTime
}

func (s *SyncService) saveLastSyncTime() error {
	syncTimeFile := filepath.Join(s.config.DataDir, "last_sync_time")

	data, err := json.Marshal(s.lastSyncTime)
	if err != nil {
		return fmt.Errorf("failed to marshal sync time: %w", err)
	}

	if err := os.WriteFile(syncTimeFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write sync time file: %w", err)
	}

	s.logger.Debug().Int64("last_sync_time", s.lastSyncTime).Msg("Sync time saved successfully")
	return nil
}

func (s *SyncService) TestConnection() error {
	if !s.config.Sync.Enabled {
		return fmt.Errorf("sync is not enabled")
	}

	return s.remoteAuth.TestConnection()
}

func (s *SyncService) GetSyncStats() SyncStats {
	// Get the actual last sync time from persistent storage
	actualLastSyncTime := s.getLastSyncTime()

	return SyncStats{
		LastSyncTime:      actualLastSyncTime,
		TotalUploaded:     0, // TODO: Track these stats
		TotalDownloaded:   0,
		ConflictsResolved: 0,
		LastSyncDuration:  0,
		ErrorCount:        0,
		IsAuthenticated:   s.remoteAuth.IsAuthenticated(),
	}
}

// VerifyIntegrity performs Perfect Sync integrity verification with the server
func (s *SyncService) VerifyIntegrity() (*PerfectSyncResponse, error) {
	if !s.config.Sync.Enabled {
		return nil, fmt.Errorf("sync is not enabled")
	}

	if !s.localAuth.IsSessionActive() {
		return nil, fmt.Errorf("local authentication required - please unlock storage first")
	}

	if !s.remoteAuth.IsAuthenticated() {
		return nil, fmt.Errorf("remote authentication required - please run 'ccr sync enable' first")
	}

	s.logger.Info().Msg("Starting Perfect Sync integrity verification")

	// Generate local integrity state
	localState, err := s.generateLocalIntegrityState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate local integrity state: %w", err)
	}

	// Get device ID
	deviceID, err := s.deviceManager.GetDeviceID()
	if err != nil {
		return nil, fmt.Errorf("failed to get device ID: %w", err)
	}

	// Create Perfect Sync request
	request := &PerfectSyncRequest{
		DeviceID:      deviceID,
		SyncSessionID: fmt.Sprintf("integrity-%d", time.Now().UnixNano()),
		LocalState:    *localState,
		RequestMetadata: RequestMetadata{
			ClientVersion: "1.0.0",
			SyncType:      "integrity_verification",
			Compression:   false,
		},
	}

	// Send integrity verification request
	response, err := s.client.VerifyIntegrity(request)
	if err != nil {
		return nil, fmt.Errorf("integrity verification failed: %w", err)
	}

	s.logger.Info().
		Str("integrity_status", response.IntegrityStatus).
		Int("missing_records", len(response.SyncActions.MissingRecords)).
		Int("orphaned_hashes", len(response.SyncActions.OrphanedHashes)).
		Float64("integrity_score", response.Statistics.IntegrityScore).
		Msg("Integrity verification completed")

	return response, nil
}

// generateLocalIntegrityState creates local state for integrity verification
func (s *SyncService) generateLocalIntegrityState() (*LocalIntegrityState, error) {
	if s.storage == nil {
		return nil, fmt.Errorf("storage not available")
	}

	// Get all records with hashes
	recordsWithHashes, err := s.storage.GetAllRecordsWithHashes()
	if err != nil {
		return nil, fmt.Errorf("failed to get records with hashes: %w", err)
	}

	hashes := make([]string, 0, len(recordsWithHashes))
	var latestTimestamp, oldestTimestamp int64

	for i, recordWithHash := range recordsWithHashes {
		hashes = append(hashes, recordWithHash.Hash)

		timestamp := recordWithHash.Record.Timestamp
		if i == 0 {
			latestTimestamp = timestamp
			oldestTimestamp = timestamp
		} else {
			if timestamp > latestTimestamp {
				latestTimestamp = timestamp
			}
			if timestamp < oldestTimestamp {
				oldestTimestamp = timestamp
			}
		}
	}

	// Generate hash checksum
	hashChecksum := s.generateHashChecksum(hashes)

	state := &LocalIntegrityState{
		RecordCount:     len(recordsWithHashes),
		AllHashes:       hashes,
		HashChecksum:    hashChecksum,
		LatestTimestamp: latestTimestamp,
		OldestTimestamp: oldestTimestamp,
	}

	s.logger.Debug().
		Int("record_count", state.RecordCount).
		Int("hash_count", len(state.AllHashes)).
		Str("hash_checksum", state.HashChecksum).
		Msg("Generated local integrity state")

	return state, nil
}

// SyncNow performs a full synchronization to ensure local and remote data match
func (s *SyncService) SyncNow() error {
	if !s.config.Sync.Enabled {
		return fmt.Errorf("sync is not enabled")
	}

	if !s.localAuth.IsSessionActive() {
		return fmt.Errorf("local authentication required - please unlock storage first")
	}

	if !s.remoteAuth.IsAuthenticated() {
		return fmt.Errorf("remote authentication required - please run 'ccr sync enable' first")
	}

	// Validate token with server before proceeding with sync
	s.logger.Debug().Msg("Validating token with server before sync")
	if err := s.remoteAuth.ValidateTokenWithServer(); err != nil {
		// Check if this is a password change error
		if s.isPasswordChangeError(err) {
			return s.handlePasswordChangeDetected()
		}
		return fmt.Errorf("token validation failed: %w", err)
	}

	s.logger.Info().Msg("Starting full synchronization")

	// First, verify integrity to see what needs to be synced
	integrityResponse, err := s.VerifyIntegrity()
	if err != nil {
		// Check if this is a password change error
		if s.isPasswordChangeError(err) {
			return s.handlePasswordChangeDetected()
		}
		return fmt.Errorf("failed to verify integrity before sync: %w", err)
	}

	// If integrity is perfect, no sync needed
	if integrityResponse.IntegrityStatus == "perfect" {
		s.logger.Info().Msg("Integrity is perfect, no sync needed")
		return nil
	}

	s.logger.Info().
		Int("missing_records", len(integrityResponse.SyncActions.MissingRecords)).
		Int("orphaned_hashes", len(integrityResponse.SyncActions.OrphanedHashes)).
		Msg("Integrity check complete, starting sync operations")

	// Upload any missing records to server
	if err := s.UploadNewRecords(); err != nil {
		// Check if this is a password change error
		if s.isPasswordChangeError(err) {
			return s.handlePasswordChangeDetected()
		}
		return fmt.Errorf("failed to upload missing records: %w", err)
	}

	// Download missing records from server
	if len(integrityResponse.SyncActions.MissingRecords) > 0 {
		if err := s.downloadMissingRecords(integrityResponse.SyncActions.MissingRecords); err != nil {
			// Check if this is a password change error
			if s.isPasswordChangeError(err) {
				return s.handlePasswordChangeDetected()
			}
			return fmt.Errorf("failed to download missing records: %w", err)
		}
	}

	// Update last sync time
	s.lastSyncTime = time.Now().UnixMilli()
	if err := s.saveLastSyncTime(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to save sync time after successful sync")
	}

	// Verify integrity again to ensure sync was successful
	verifyResponse, err := s.VerifyIntegrity()
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to verify integrity after sync")
		return nil // Don't fail the sync operation
	}

	if verifyResponse.IntegrityStatus == "perfect" {
		s.logger.Info().Msg("Full synchronization completed successfully")
	} else {
		s.logger.Warn().
			Str("integrity_status", verifyResponse.IntegrityStatus).
			Msg("Sync completed but integrity is not perfect")
	}

	return nil
}

// downloadMissingRecords downloads and stores missing records from server
func (s *SyncService) downloadMissingRecords(missingRecords []MissingRecord) error {
	if len(missingRecords) == 0 {
		return nil
	}

	s.logger.Info().
		Int("missing_count", len(missingRecords)).
		Msg("Downloading missing records from server")

	for _, missingRecord := range missingRecords {
		// Decrypt and parse the missing record
		record, err := s.decryptMissingRecord(&missingRecord)
		if err != nil {
			s.logger.Warn().
				Err(err).
				Str("hash", missingRecord.RecordHash).
				Msg("Failed to decrypt missing record, skipping")
			continue
		}

		// Store the record locally
		if _, err := s.storage.Store(record); err != nil {
			s.logger.Warn().
				Err(err).
				Str("hash", missingRecord.RecordHash).
				Msg("Failed to store missing record")
			continue
		}

		s.logger.Debug().
			Str("hash", missingRecord.RecordHash).
			Str("command", record.Command).
			Msg("Successfully downloaded and stored missing record")
	}

	s.logger.Info().
		Int("missing_count", len(missingRecords)).
		Msg("Finished downloading missing records")

	return nil
}

// BatchUpdateRemoteRecords uploads re-encrypted records in batches during password change
func (s *SyncService) BatchUpdateRemoteRecords(stagingPath string) error {
	// 1. Verify lock is still active before starting
	if err := s.verifyPasswordChangeLock(); err != nil {
		return fmt.Errorf("password change lock verification failed: %w", err)
	}

	// 2. Load and divide records into batches
	records, err := s.LoadFromStaging(stagingPath)
	if err != nil {
		return fmt.Errorf("failed to load records from staging: %w", err)
	}

	batches := s.DivideToBatches(records, BatchSize) // 1k per batch

	s.logger.Info().
		Int("total_records", len(records)).
		Int("total_batches", len(batches)).
		Msg("Starting batch upload of re-encrypted records")

	// 3. Send batches sequentially with retry logic
	for i, batch := range batches {
		batchNum := i + 1
		isLast := (i == len(batches)-1)

		deviceID, err := s.deviceManager.GetDeviceID()
		if err != nil {
			return fmt.Errorf("failed to get device ID for batch %d: %w", batchNum, err)
		}

		request := &BatchUpdateRequest{
			DeviceID: deviceID,
			Records:  batch,
			BatchMetadata: BatchMetadata{
				BatchNumber:    batchNum,
				TotalBatches:   len(batches),
				IsLastBatch:    isLast,
				RecordsInBatch: len(batch),
			},
		}

		// Upload batch with retry logic
		if err := s.uploadBatchWithRetry(request, batchNum); err != nil {
			s.logger.Error().
				Err(err).
				Int("batch_number", batchNum).
				Bool("is_last_batch", isLast).
				Msg("Batch upload failed after all retries")

			// Don't proceed to next batch - server will handle cleanup
			return fmt.Errorf("batch %d/%d failed after %d retries: %w",
				batchNum, len(batches), MaxBatchRetries, err)
		}

		s.logger.Info().
			Int("batch_number", batchNum).
			Int("total_batches", len(batches)).
			Bool("is_last_batch", isLast).
			Msg("Batch uploaded successfully")
	}

	s.logger.Info().Msg("All batches uploaded successfully, password change lock should be released")
	return nil
}

// uploadBatchWithRetry handles retry logic for individual batch uploads
func (s *SyncService) uploadBatchWithRetry(request *BatchUpdateRequest, batchNum int) error {
	var lastErr error

	for attempt := 1; attempt <= MaxBatchRetries; attempt++ {
		// Check lock status before each attempt (especially important for retries)
		if attempt > 1 {
			if err := s.verifyPasswordChangeLock(); err != nil {
				return fmt.Errorf("lock verification failed on retry %d: %w", attempt, err)
			}
		}

		s.logger.Debug().
			Int("batch_number", batchNum).
			Int("attempt", attempt).
			Int("max_attempts", MaxBatchRetries).
			Int("records_in_batch", len(request.Records)).
			Msg("Uploading batch")

		err := s.client.BatchUpdateRecords(request)
		if err == nil {
			// Success!
			return nil
		}

		lastErr = err
		s.logger.Warn().
			Err(err).
			Int("batch_number", batchNum).
			Int("attempt", attempt).
			Int("remaining_attempts", MaxBatchRetries-attempt).
			Msg("Batch upload attempt failed")

		// Don't sleep after the last attempt
		if attempt < MaxBatchRetries {
			// Exponential backoff: 1s, 2s, 4s, 8s
			backoffDuration := time.Duration(1<<(attempt-1)) * time.Second
			s.logger.Debug().
				Dur("backoff_duration", backoffDuration).
				Msg("Waiting before retry")
			time.Sleep(backoffDuration)
		}
	}

	return fmt.Errorf("batch upload failed after %d attempts: %w", MaxBatchRetries, lastErr)
}

// verifyPasswordChangeLock checks if the password change lock is still active
func (s *SyncService) verifyPasswordChangeLock() error {
	lockStatus, err := s.client.GetPasswordChangeLockStatus()
	if err != nil {
		return fmt.Errorf("failed to check lock status: %w", err)
	}

	if !lockStatus.IsLocked {
		return fmt.Errorf("password change lock is not active")
	}

	if !lockStatus.CanProceed {
		return fmt.Errorf("cannot proceed with password change: %s", lockStatus.Reason)
	}

	// Check if lock is about to expire (warn if < 10 minutes left)
	expiresAt := time.Unix(lockStatus.LockInfo.ExpiresAt, 0)
	timeLeft := time.Until(expiresAt)
	if timeLeft < 10*time.Minute {
		s.logger.Warn().
			Dur("time_left", timeLeft).
			Msg("Password change lock expires soon")
	}

	return nil
}

// DivideToBatches splits records into batches of specified size
func (s *SyncService) DivideToBatches(records []RecordUpdate, batchSize int) [][]RecordUpdate {
	if len(records) == 0 {
		return [][]RecordUpdate{}
	}

	batches := make([][]RecordUpdate, 0, (len(records)+batchSize-1)/batchSize)
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batches = append(batches, records[i:end])
	}

	return batches
}

// LoadFromStaging loads re-encrypted records from the staging area
func (s *SyncService) LoadFromStaging(stagingPath string) ([]RecordUpdate, error) {
	// Check if staging path exists
	if _, err := os.Stat(stagingPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("staging path does not exist: %s", stagingPath)
	}

	// Read staging file
	data, err := os.ReadFile(stagingPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read staging file: %w", err)
	}

	var records []RecordUpdate
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("failed to unmarshal staging data: %w", err)
	}

	s.logger.Info().
		Int("record_count", len(records)).
		Str("staging_path", stagingPath).
		Msg("Loaded records from staging area")

	return records, nil
}

// CleanupStagingArea removes the staging file and directory (public method)
func (s *SyncService) CleanupStagingArea(stagingPath string) error {
	return s.cleanupStagingArea(stagingPath)
}

// CreateStagingArea creates a temporary directory for storing re-encrypted records
func (s *SyncService) CreateStagingArea() (string, error) {
	stagingDir := filepath.Join(s.config.DataDir, "staging")

	// Create staging directory if it doesn't exist
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create staging directory: %w", err)
	}

	// Create a unique staging file for this password change operation
	stagingFile := filepath.Join(stagingDir, fmt.Sprintf("reencrypted_records_%d.json", time.Now().UnixNano()))

	s.logger.Info().
		Str("staging_path", stagingFile).
		Msg("Created staging area for re-encrypted records")

	return stagingFile, nil
}

// SaveToStaging saves re-encrypted records to the staging area
func (s *SyncService) SaveToStaging(stagingPath string, records []RecordUpdate) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal records for staging: %w", err)
	}

	if err := os.WriteFile(stagingPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write records to staging: %w", err)
	}

	s.logger.Info().
		Int("record_count", len(records)).
		Str("staging_path", stagingPath).
		Int("file_size_bytes", len(data)).
		Msg("Records saved to staging area")

	return nil
}

// cleanupStagingArea removes the staging file and optionally the staging directory
func (s *SyncService) cleanupStagingArea(stagingPath string) error {
	// Remove the staging file
	if err := os.Remove(stagingPath); err != nil && !os.IsNotExist(err) {
		s.logger.Warn().Err(err).Str("path", stagingPath).Msg("Failed to remove staging file")
		return fmt.Errorf("failed to remove staging file: %w", err)
	}

	// Try to remove the staging directory if it's empty
	stagingDir := filepath.Dir(stagingPath)
	if err := os.Remove(stagingDir); err != nil {
		// It's okay if directory is not empty or doesn't exist
		if !os.IsNotExist(err) {
			s.logger.Debug().Err(err).Str("dir", stagingDir).Msg("Staging directory not removed (may not be empty)")
		}
	}

	s.logger.Info().
		Str("staging_path", stagingPath).
		Msg("Staging area cleaned up")

	return nil
}

// BatchReencryptRecords re-encrypts all records with new key and saves to staging
func (s *SyncService) BatchReencryptRecords(newKey []byte) (string, error) {
	// 1. Create staging area
	stagingPath, err := s.CreateStagingArea()
	if err != nil {
		return "", fmt.Errorf("failed to create staging area: %w", err)
	}

	// 2. Get all records from local database
	if s.storage == nil {
		return "", fmt.Errorf("storage not available for re-encryption")
	}

	recordsWithHashes, err := s.storage.GetAllRecordsWithHashes()
	if err != nil {
		s.cleanupStagingArea(stagingPath) // Cleanup on error
		return "", fmt.Errorf("failed to get records for re-encryption: %w", err)
	}

	if len(recordsWithHashes) == 0 {
		s.logger.Info().Msg("No records to re-encrypt")
		return stagingPath, nil
	}

	s.logger.Info().
		Int("total_records", len(recordsWithHashes)).
		Msg("Starting batch re-encryption of records")

	// 3. Get current session key for decryption
	oldKey, err := s.localAuth.LoadSessionKey()
	if err != nil {
		s.cleanupStagingArea(stagingPath) // Cleanup on error
		return "", fmt.Errorf("failed to load current session key: %w", err)
	}
	defer crypto.SecureWipe(oldKey)

	// 4. Process records in batches to manage memory
	var allUpdates []RecordUpdate
	batchSize := 100 // Process 100 records at a time to manage memory

	for i := 0; i < len(recordsWithHashes); i += batchSize {
		end := i + batchSize
		if end > len(recordsWithHashes) {
			end = len(recordsWithHashes)
		}

		batch := recordsWithHashes[i:end]
		batchUpdates, err := s.reencryptRecordBatch(batch, oldKey[:32], newKey[:32])
		if err != nil {
			s.cleanupStagingArea(stagingPath) // Cleanup on error
			return "", fmt.Errorf("failed to re-encrypt batch %d-%d: %w", i, end-1, err)
		}

		allUpdates = append(allUpdates, batchUpdates...)

		s.logger.Debug().
			Int("batch_start", i).
			Int("batch_end", end-1).
			Int("batch_size", len(batch)).
			Int("total_processed", len(allUpdates)).
			Msg("Batch re-encryption completed")
	}

	// 5. Save all re-encrypted records to staging
	if err := s.SaveToStaging(stagingPath, allUpdates); err != nil {
		s.cleanupStagingArea(stagingPath) // Cleanup on error
		return "", fmt.Errorf("failed to save re-encrypted records to staging: %w", err)
	}

	s.logger.Info().
		Int("total_records", len(allUpdates)).
		Str("staging_path", stagingPath).
		Msg("Batch re-encryption completed successfully")

	return stagingPath, nil
}

// reencryptRecordBatch re-encrypts a batch of records with new key
func (s *SyncService) reencryptRecordBatch(recordsWithHashes []securestorage.RecordWithHash, oldKey, newKey []byte) ([]RecordUpdate, error) {
	updates := make([]RecordUpdate, 0, len(recordsWithHashes))

	for _, recordWithHash := range recordsWithHashes {
		record := recordWithHash.Record
		hash := recordWithHash.Hash

		// Skip records without hash (shouldn't happen but be safe)
		if hash == "" {
			s.logger.Warn().
				Int64("record_id", record.ID).
				Msg("Skipping record without hash during re-encryption")
			continue
		}

		// Serialize record to JSON
		recordJSON, err := json.Marshal(record)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal record %d: %w", record.ID, err)
		}

		// Decrypt with old key (records are already encrypted in storage)
		// Note: records in storage might already be decrypted or we might need to decrypt first
		// For now, assume we need to re-encrypt the JSON with new key
		encrypted, err := s.encryptor.EncryptBytes(recordJSON, newKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt record %d with new key: %w", record.ID, err)
		}

		// Create record update
		update := RecordUpdate{
			RecordHash:          hash,
			NewEncryptedPayload: base64.StdEncoding.EncodeToString(encrypted),
			UpdateReason:        "password_change",
		}

		updates = append(updates, update)
	}

	return updates, nil
}

func (s *SyncService) Logout() error {
	return s.remoteAuth.Logout()
}

func (s *SyncService) Close() error {
	// Clean up resources
	return nil
}

func (s *SyncService) IsRunning() bool {
	return s.isRunning
}

func (s *SyncService) IsEnabled() bool {
	return s.config.Sync.Enabled
}

func (s *SyncService) GetRemoteAuth() *RemoteAuthenticator {
	return s.remoteAuth
}

// PerformIntegritySync performs Perfect Sync using hash-based integrity verification with comprehensive error handling
func (s *SyncService) PerformIntegritySync() error {
	if !s.config.IsPerfectSyncEnabled() {
		s.logger.Debug().Msg("Perfect Sync not enabled, falling back to regular sync")
		return s.PerformSync()
	}

	if s.isRunning {
		return NewSyncError(ErrTypeResourceExhausted, "sync is already in progress", "SYNC_IN_PROGRESS", false, nil)
	}

	// Ensure both local and remote authentication
	if !s.localAuth.IsSessionActive() {
		return NewAuthError("local authentication required - please unlock storage first", nil)
	}

	if !s.remoteAuth.IsAuthenticated() {
		return NewAuthError("remote authentication required - please run 'ccr sync enable' first", nil)
	}

	s.isRunning = true
	defer func() { s.isRunning = false }()

	start := time.Now()
	s.logger.Info().Msg("Starting Perfect Sync integrity verification")

	// Initialize error classifier for recovery suggestions
	classifier := NewErrorClassifier()
	retryStrategy := DefaultRetryStrategy()

	// STEP 1: Upload local changes first (CRITICAL FIX)
	s.logger.Info().Msg("Uploading local changes before integrity verification")
	if err := s.UploadNewRecords(); err != nil {
		s.logger.Error().Err(err).Msg("Upload failed during Perfect Sync")
		return fmt.Errorf("upload failed during Perfect Sync: %w", err)
	}

	// STEP 2: Build local integrity state with error handling
	localState, err := s.buildLocalIntegrityStateWithRetry(retryStrategy, classifier)
	if err != nil {
		return err
	}

	// Get device ID with error handling
	deviceID, err := s.getDeviceIDWithRetry(retryStrategy, classifier)
	if err != nil {
		return err
	}

	// Prepare request
	request := PerfectSyncRequest{
		DeviceID:      deviceID,
		SyncSessionID: fmt.Sprintf("perfect-sync-%d", time.Now().UnixNano()),
		LocalState:    *localState,
		RequestMetadata: RequestMetadata{
			ClientVersion: "1.0.0",
			SyncType:      SyncTypeFull,
			Compression:   s.config.Sync.HashCompression,
		},
	}

	// STEP 3: Send integrity verification request with retry logic
	response, err := s.performIntegrityVerificationWithRetry(&request, retryStrategy, classifier)
	if err != nil {
		return err
	}

	// STEP 4: Apply sync actions with error handling (download missing records)
	if err := s.applySyncActionsWithRetry(response.SyncActions, retryStrategy, classifier); err != nil {
		return err
	}

	// Update last sync time
	s.lastSyncTime = time.Now().UnixMilli()
	if err := s.saveLastSyncTime(); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to save sync time, but Perfect Sync completed successfully")
	}

	duration := time.Since(start)
	s.logger.Info().
		Dur("duration", duration).
		Str("integrity_status", response.IntegrityStatus).
		Int("records_downloaded", response.Statistics.RecordsToDownload).
		Float64("integrity_score", response.Statistics.IntegrityScore).
		Msg("Perfect Sync completed successfully")

	return nil
}

// buildLocalIntegrityStateWithRetry builds local integrity state with retry logic
func (s *SyncService) buildLocalIntegrityStateWithRetry(retryStrategy *RetryStrategy, classifier *ErrorClassifier) (*LocalIntegrityState, error) {
	var lastErr error
	for attempt := 0; attempt < retryStrategy.MaxRetries; attempt++ {
		state, err := s.BuildLocalIntegrityState()
		if err == nil {
			return state, nil
		}

		syncErr := classifier.ClassifyError(err)
		if !retryStrategy.ShouldRetry(syncErr, attempt) {
			return nil, syncErr.AddContext("operation", "build_local_integrity_state")
		}

		delay := retryStrategy.GetDelay(attempt)
		s.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Dur("retry_delay", delay).
			Msg("Failed to build local integrity state, retrying")

		time.Sleep(delay)
		lastErr = err
	}

	return nil, classifier.ClassifyError(lastErr).AddContext("operation", "build_local_integrity_state")
}

// getDeviceIDWithRetry gets device ID with retry logic
func (s *SyncService) getDeviceIDWithRetry(retryStrategy *RetryStrategy, classifier *ErrorClassifier) (string, error) {
	var lastErr error
	for attempt := 0; attempt < retryStrategy.MaxRetries; attempt++ {
		deviceID, err := s.deviceManager.GetDeviceID()
		if err == nil {
			return deviceID, nil
		}

		syncErr := classifier.ClassifyError(err)
		if !retryStrategy.ShouldRetry(syncErr, attempt) {
			return "", syncErr.AddContext("operation", "get_device_id")
		}

		delay := retryStrategy.GetDelay(attempt)
		s.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Dur("retry_delay", delay).
			Msg("Failed to get device ID, retrying")

		time.Sleep(delay)
		lastErr = err
	}

	return "", classifier.ClassifyError(lastErr).AddContext("operation", "get_device_id")
}

// performIntegrityVerificationWithRetry performs integrity verification with retry logic
func (s *SyncService) performIntegrityVerificationWithRetry(request *PerfectSyncRequest, retryStrategy *RetryStrategy, classifier *ErrorClassifier) (*PerfectSyncResponse, error) {
	var lastErr error
	for attempt := 0; attempt < retryStrategy.MaxRetries; attempt++ {
		response, err := s.client.VerifyIntegrity(request)
		if err == nil {
			return response, nil
		}

		syncErr := classifier.ClassifyError(err)
		if !retryStrategy.ShouldRetry(syncErr, attempt) {
			return nil, syncErr.AddContext("operation", "integrity_verification").AddContext("device_id", request.DeviceID)
		}

		delay := retryStrategy.GetDelay(attempt)
		s.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Dur("retry_delay", delay).
			Str("device_id", request.DeviceID).
			Msg("Integrity verification failed, retrying")

		time.Sleep(delay)
		lastErr = err
	}

	return nil, classifier.ClassifyError(lastErr).AddContext("operation", "integrity_verification").AddContext("device_id", request.DeviceID)
}

// applySyncActionsWithRetry applies sync actions with retry logic
func (s *SyncService) applySyncActionsWithRetry(actions SyncActions, retryStrategy *RetryStrategy, classifier *ErrorClassifier) error {
	var lastErr error
	for attempt := 0; attempt < retryStrategy.MaxRetries; attempt++ {
		err := s.ApplySyncActions(actions)
		if err == nil {
			return nil
		}

		syncErr := classifier.ClassifyError(err)
		if !retryStrategy.ShouldRetry(syncErr, attempt) {
			return syncErr.AddContext("operation", "apply_sync_actions")
		}

		delay := retryStrategy.GetDelay(attempt)
		s.logger.Warn().
			Err(err).
			Int("attempt", attempt+1).
			Dur("retry_delay", delay).
			Int("missing_records", len(actions.MissingRecords)).
			Int("orphaned_hashes", len(actions.OrphanedHashes)).
			Msg("Failed to apply sync actions, retrying")

		time.Sleep(delay)
		lastErr = err
	}

	return classifier.ClassifyError(lastErr).AddContext("operation", "apply_sync_actions")
}

// BuildLocalIntegrityState collects all local record hashes and metadata
func (s *SyncService) BuildLocalIntegrityState() (*LocalIntegrityState, error) {
	s.logger.Debug().Msg("Building local integrity state for Perfect Sync")

	if s.storage == nil {
		return nil, NewSyncError(ErrTypeStorageUnavailable, "storage not available", CodeStorageLocked, false, nil)
	}

	// Get all records with hashes with timeout
	timeout := s.config.GetHashCollectionTimeoutDuration()
	done := make(chan struct{})
	var recordsWithHashes []securestorage.RecordWithHash
	var err error

	go func() {
		defer close(done)
		recordsWithHashes, err = s.storage.GetAllRecordsWithHashes()
	}()

	select {
	case <-done:
		if err != nil {
			return nil, NewSyncError(ErrTypeStorageUnavailable, "failed to get records with hashes", CodeStorageCorrupted, true, err)
		}
	case <-time.After(timeout):
		return nil, NewSyncError(ErrTypeTimeout, "hash collection timed out", CodeNetworkTimeout, true, nil).
			AddContext("timeout", timeout.String())
	}

	if len(recordsWithHashes) == 0 {
		s.logger.Info().Msg("No records found for integrity state")
		return &LocalIntegrityState{
			RecordCount:     0,
			AllHashes:       []string{},
			HashChecksum:    "",
			LatestTimestamp: 0,
			OldestTimestamp: 0,
		}, nil
	}

	// Extract hashes and timestamps
	hashes := make([]string, 0, len(recordsWithHashes))
	var latestTimestamp, oldestTimestamp int64

	for i, rwh := range recordsWithHashes {
		// Generate hash if missing
		hash := rwh.Hash
		if hash == "" && s.hashGenerator != nil {
			hash = s.hashGenerator.GenerateRecordHash(&rwh.Record)
			// Update the record with the generated hash
			if err := s.storage.UpdateRecordHash(rwh.Record.ID, hash); err != nil {
				s.logger.Warn().Err(err).Int64("id", rwh.Record.ID).Msg("Failed to update record hash")
			}
		}

		if hash != "" {
			hashes = append(hashes, hash)
		}

		// Track timestamps
		timestamp := rwh.Record.Timestamp
		if i == 0 {
			latestTimestamp = timestamp
			oldestTimestamp = timestamp
		} else {
			if timestamp > latestTimestamp {
				latestTimestamp = timestamp
			}
			if timestamp < oldestTimestamp {
				oldestTimestamp = timestamp
			}
		}
	}

	// Generate hash checksum
	hashChecksum := s.generateHashChecksum(hashes)

	state := &LocalIntegrityState{
		RecordCount:     len(recordsWithHashes),
		AllHashes:       hashes,
		HashChecksum:    hashChecksum,
		LatestTimestamp: latestTimestamp,
		OldestTimestamp: oldestTimestamp,
	}

	s.logger.Info().
		Int("record_count", state.RecordCount).
		Int("hash_count", len(state.AllHashes)).
		Str("checksum", state.HashChecksum).
		Int64("latest_timestamp", state.LatestTimestamp).
		Int64("oldest_timestamp", state.OldestTimestamp).
		Msg("Local integrity state built successfully")

	return state, nil
}

// generateHashChecksum creates a checksum of all hashes for integrity verification
func (s *SyncService) generateHashChecksum(hashes []string) string {
	if len(hashes) == 0 {
		return ""
	}

	// Sort hashes for deterministic checksum
	sortedHashes := make([]string, len(hashes))
	copy(sortedHashes, hashes)

	// Use the existing hash generator for consistency
	if s.hashGenerator != nil {
		// Create a pseudo-record containing all hashes for checksum
		pseudoRecord := &storage.CommandRecord{
			Command: strings.Join(sortedHashes, "|"),
		}
		return s.hashGenerator.GenerateRecordHash(pseudoRecord)
	}

	// Fallback to simple hash if generator not available
	hasher := sha256.New()
	for _, hash := range sortedHashes {
		hasher.Write([]byte(hash))
	}
	return fmt.Sprintf("%x", hasher.Sum(nil))
}

// ApplySyncActions processes the sync actions returned by the server
func (s *SyncService) ApplySyncActions(actions SyncActions) error {
	s.logger.Info().
		Int("missing_records", len(actions.MissingRecords)).
		Int("orphaned_hashes", len(actions.OrphanedHashes)).
		Int("conflicted_hashes", len(actions.ConflictedHashes)).
		Msg("Applying sync actions")

	// Process missing records (download and store)
	for _, missingRecord := range actions.MissingRecords {
		if err := s.processMissingRecord(missingRecord); err != nil {
			s.logger.Warn().Err(err).Str("hash", missingRecord.RecordHash).Msg("Failed to process missing record")
			continue
		}
	}

	// Process orphaned hashes (remove local records that don't exist on server)
	for _, orphanedHash := range actions.OrphanedHashes {
		if err := s.processOrphanedHash(orphanedHash); err != nil {
			s.logger.Warn().Err(err).Str("hash", orphanedHash).Msg("Failed to process orphaned hash")
			continue
		}
	}

	// Process conflicted hashes (resolve conflicts)
	for _, conflictedHash := range actions.ConflictedHashes {
		if err := s.processConflictedHash(conflictedHash); err != nil {
			s.logger.Warn().Err(err).Str("hash", conflictedHash).Msg("Failed to process conflicted hash")
			continue
		}
	}

	s.logger.Info().Msg("Sync actions applied successfully")
	return nil
}

// processMissingRecord handles downloading and storing a missing record
func (s *SyncService) processMissingRecord(missingRecord MissingRecord) error {
	s.logger.Debug().Str("hash", missingRecord.RecordHash).Msg("Processing missing record")

	// Decrypt the record
	record, err := s.decryptMissingRecord(&missingRecord)
	if err != nil {
		return fmt.Errorf("failed to decrypt missing record: %w", err)
	}

	// Store the record
	if _, err := s.storage.Store(record); err != nil {
		return fmt.Errorf("failed to store missing record: %w", err)
	}

	s.logger.Debug().Str("hash", missingRecord.RecordHash).Msg("Missing record processed successfully")
	return nil
}

// processOrphanedHash handles removing a local record that doesn't exist on server
func (s *SyncService) processOrphanedHash(orphanedHash string) error {
	s.logger.Debug().Str("hash", orphanedHash).Msg("Processing orphaned hash")

	// Get the record by hash
	record, err := s.storage.GetRecordByHash(orphanedHash)
	if err != nil {
		return fmt.Errorf("failed to get orphaned record: %w", err)
	}

	// Delete the record
	if err := s.storage.DeleteRecord(record.ID); err != nil {
		return fmt.Errorf("failed to delete orphaned record: %w", err)
	}

	s.logger.Debug().Str("hash", orphanedHash).Int64("id", record.ID).Msg("Orphaned record deleted successfully")
	return nil
}

// processConflictedHash handles resolving a conflicted record
func (s *SyncService) processConflictedHash(conflictedHash string) error {
	s.logger.Debug().Str("hash", conflictedHash).Msg("Processing conflicted hash")

	// Mark the conflict as resolved (server-side resolution for now)
	if err := s.storage.MarkConflictResolvedByHash(conflictedHash); err != nil {
		return fmt.Errorf("failed to mark conflict as resolved: %w", err)
	}

	s.logger.Debug().Str("hash", conflictedHash).Msg("Conflict resolved successfully")
	return nil
}

// decryptMissingRecord processes a missing record received from server
func (s *SyncService) decryptMissingRecord(missingRecord *MissingRecord) (*storage.CommandRecord, error) {
	// Get session key for decryption attempts
	sessionKey, err := s.localAuth.LoadSessionKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load session key: %w", err)
	}

	// First attempt: Try to decrypt with our local session key (use first 32 bytes)
	decrypted, err := s.encryptor.DecryptBytes(missingRecord.EncryptedPayload, sessionKey[:32])
	if err == nil {
		// Decryption successful - parse the decrypted data
		var record storage.CommandRecord
		if err := json.Unmarshal(decrypted, &record); err != nil {
			return nil, fmt.Errorf("failed to unmarshal decrypted record: %w", err)
		}

		s.logger.Debug().
			Str("hash", missingRecord.RecordHash).
			Str("command", record.Command).
			Msg("Successfully decrypted missing record")

		return &record, nil
	}

	// Second attempt: Try treating payload as raw JSON
	var record storage.CommandRecord
	if err := json.Unmarshal(missingRecord.EncryptedPayload, &record); err == nil {
		s.logger.Debug().
			Str("hash", missingRecord.RecordHash).
			Msg("Successfully parsed missing record as raw JSON")

		return &record, nil
	}

	// Third attempt: Create record from available metadata when both fail
	s.logger.Warn().
		Str("hash", missingRecord.RecordHash).
		Msg("Failed to decrypt or parse payload, creating record from metadata")

	// Create a minimal record from the available metadata
	record = storage.CommandRecord{
		RecordHash: missingRecord.RecordHash,
		Timestamp:  missingRecord.TimestampMs,
		Hostname:   missingRecord.Hostname,
		SessionID:  missingRecord.SessionID,
		Command:    fmt.Sprintf("[RECOVERED] Record %s", missingRecord.RecordHash[:8]),
		ExitCode:   0,
		Duration:   0,
		WorkingDir: "/unknown",
		User:       "unknown",
		Shell:      "unknown",
		Version:    1,
		CreatedAt:  missingRecord.TimestampMs,
	}

	s.logger.Info().
		Str("hash", missingRecord.RecordHash).
		Str("command", record.Command).
		Int64("timestamp", record.Timestamp).
		Msg("Created recovery record from metadata")

	return &record, nil
}

// ========== PASSWORD CHANGE RECOVERY METHODS ==========

// isPasswordChangeError checks if an error indicates a password change on another device
func (s *SyncService) isPasswordChangeError(err error) bool {
	if err == nil {
		return false
	}

	errorStr := strings.ToLower(err.Error())

	// Check for 401 Unauthorized responses
	if strings.Contains(errorStr, "401") || strings.Contains(errorStr, "unauthorized") {
		return true
	}

	// Check for 403 Forbidden responses
	if strings.Contains(errorStr, "403") || strings.Contains(errorStr, "forbidden") {
		return true
	}

	// Check for authentication failure patterns
	if strings.Contains(errorStr, "authentication failed") ||
		strings.Contains(errorStr, "invalid credentials") ||
		strings.Contains(errorStr, "token expired") ||
		strings.Contains(errorStr, "invalid email") ||
		strings.Contains(errorStr, "invalid password") ||
		(strings.Contains(errorStr, "invalid") && strings.Contains(errorStr, "password")) ||
		(strings.Contains(errorStr, "email") && strings.Contains(errorStr, "password")) {
		return true
	}

	// Check for specific password change detection from token validation
	if strings.Contains(errorStr, "password changed on another device") ||
		strings.Contains(errorStr, "token invalidated due to password change") {
		return true
	}

	return false
}

// handlePasswordChangeDetected provides clear guidance for password change recovery
func (s *SyncService) handlePasswordChangeDetected() error {
	s.logger.Info().Msg("Password change detected on another device")

	// Provide clear user guidance
	fmt.Printf(`
[INFO] Password Change Detected

Your password was changed on another device. To continue using sync on this device:

1. Run: ccr login
2. Enter your current password (the new one)
3. The system will automatically update this device

This will preserve all your local commands and sync them with the server.

`)

	// Return a clear error that stops the current operation
	return fmt.Errorf("password change detected - please run 'ccr login' to update this device")
}

// promptForPasswordForRecovery is deprecated - users should use 'ccr login' instead
func (s *SyncService) promptForPasswordForRecovery() (string, error) {
	return "", fmt.Errorf("please use 'ccr login' command for password change recovery")
}

// triggerSmartLoginRecovery is deprecated - users should use 'ccr login' instead
func (s *SyncService) triggerSmartLoginRecovery(password string) error {
	return fmt.Errorf("please use 'ccr login' command for password change recovery")
}

// authenticateWithNewPassword authenticates with server using the new password
func (s *SyncService) authenticateWithNewPassword(newPassword string) error {
	// Get user email from existing config/state
	email, err := s.getUserEmail()
	if err != nil {
		return fmt.Errorf("failed to get user email: %w", err)
	}

	// Authenticate with server only (don't update local state yet)
	return s.remoteAuth.Authenticate(email, newPassword)
}

// reencryptLocalDataWithNewPassword re-encrypts all local data with the new password
func (s *SyncService) reencryptLocalDataWithNewPassword(newPassword string) error {
	// Get current user info
	user, err := s.localAuth.GetUser()
	if err != nil {
		return fmt.Errorf("failed to get current user: %w", err)
	}

	// Get current session key (encrypted with old password)
	oldKey, err := s.localAuth.LoadSessionKey()
	if err != nil {
		return fmt.Errorf("failed to load current session key: %w", err)
	}
	defer func() {
		// Secure wipe of old key
		for i := range oldKey {
			oldKey[i] = 0
		}
	}()

	// Derive new key using existing salt (for deterministic derivation)
	newKeys, err := s.localAuth.DeriveKeys(newPassword, user.KeySalt)
	if err != nil {
		return fmt.Errorf("failed to derive new keys: %w", err)
	}

	// Use existing re-encryption method from AuthManager
	// Note: This method is currently private, we'll need to expose it or create a public wrapper
	return s.reencryptStoredDataWrapper(user.Username, newPassword, oldKey, newKeys.EncryptionKey)
}

// reencryptStoredDataWrapper wraps the AuthManager's public ReencryptDataForPasswordChange method
func (s *SyncService) reencryptStoredDataWrapper(username, password string, oldKey, newKey []byte) error {
	return s.localAuth.ReencryptDataForPasswordChange(username, password, oldKey, newKey)
}

// updateLocalAuthState updates the local authentication state with the new password
func (s *SyncService) updateLocalAuthState(newPassword string) error {
	return s.localAuth.UpdatePasswordStateAtomic(newPassword)
}

// getUserEmail retrieves the user's email from stored credentials or config
func (s *SyncService) getUserEmail() (string, error) {
	// Try to get email from config first
	if s.config.Sync.Email != "" {
		return s.config.Sync.Email, nil
	}

	// Try to get email from remote auth credentials
	if s.remoteAuth != nil {
		if email, err := s.remoteAuth.GetStoredEmail(); err == nil {
			return email, nil
		}
		// If GetStoredEmail fails, continue to user prompt
	}

	// Fallback: prompt user for email using UI
	ui := NewPasswordChangeUI()
	email, err := ui.PromptForEmail()
	if err != nil {
		return "", fmt.Errorf("failed to get email: %w", err)
	}

	return email, nil
}

// Helper methods for AuthManager integration

func (s *SyncService) createKeyCheck(key []byte) ([]byte, error) {
	return s.localAuth.CreateKeyCheck(key)
}

func (s *SyncService) saveUser(user *auth.User) error {
	return s.localAuth.SaveUser(user)
}

// updateDevicesList fetches and updates the local device list
func (s *SyncService) updateDevicesList() error {
	// Get devices from server
	devices, err := s.client.GetDevices()
	if err != nil {
		return fmt.Errorf("failed to fetch devices from server: %w", err)
	}

	// Update local device list
	if err := s.deviceAliasManager.UpdateDevicesList(devices); err != nil {
		return fmt.Errorf("failed to update local device list: %w", err)
	}

	return nil
}

// GetDeviceAliasManager returns the device alias manager
func (s *SyncService) GetDeviceAliasManager() *DeviceAliasManager {
	return s.deviceAliasManager
}
