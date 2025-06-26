package sync

import (
	"time"
)

// PerfectSyncRequest represents the request payload for integrity verification
type PerfectSyncRequest struct {
	DeviceID        string              `json:"device_id"`
	SyncSessionID   string              `json:"sync_session_id"`
	LocalState      LocalIntegrityState `json:"local_state"`
	RequestMetadata RequestMetadata     `json:"request_metadata"`
}

// LocalIntegrityState contains the complete local state for integrity verification
type LocalIntegrityState struct {
	RecordCount      int      `json:"record_count"`
	AllHashes        []string `json:"all_hashes"`
	HashChecksum     string   `json:"hash_checksum"`
	LatestTimestamp  int64    `json:"latest_timestamp"`
	OldestTimestamp  int64    `json:"oldest_timestamp"`
}

// RequestMetadata contains metadata about the sync request
type RequestMetadata struct {
	ClientVersion string `json:"client_version"`
	SyncType      string `json:"sync_type"`
	Compression   bool   `json:"compression"`
}

// PerfectSyncResponse represents the response from integrity verification
type PerfectSyncResponse struct {
	SyncSessionID   string         `json:"sync_session_id"`
	IntegrityStatus string         `json:"integrity_status"`
	ServerState     ServerState    `json:"server_state"`
	SyncActions     SyncActions    `json:"sync_actions"`
	Statistics      SyncStatistics `json:"statistics"`
}

// ServerState contains the server's state information
type ServerState struct {
	TotalRecordsForUser int64  `json:"total_records_for_user"`
	HashChecksum        string `json:"hash_checksum"`
	LatestTimestamp     int64  `json:"latest_timestamp"`
}

// SyncActions contains the actions needed to achieve perfect sync
type SyncActions struct {
	MissingRecords    []MissingRecord `json:"missing_records"`
	OrphanedHashes    []string        `json:"orphaned_hashes"`
	ConflictedHashes  []string        `json:"conflicted_hashes"`
}

// MissingRecord represents a record that the client is missing
type MissingRecord struct {
	RecordHash       string                `json:"record_hash"`
	EncryptedPayload []byte                `json:"encrypted_payload"`
	TimestampMs      int64                 `json:"timestamp_ms"`
	Hostname         string                `json:"hostname"`
	SessionID        string                `json:"session_id"`
	Metadata         MissingRecordMetadata `json:"metadata"`
}

// MissingRecordMetadata contains additional metadata for missing records
type MissingRecordMetadata struct {
	DeviceOrigin  string `json:"device_origin"`
	SyncPriority  int    `json:"sync_priority"`
}

// SyncStatistics contains metrics about the sync operation
type SyncStatistics struct {
	RecordsToDownload int     `json:"records_to_download"`
	RecordsToRemove   int     `json:"records_to_remove"`
	PerfectMatches    int     `json:"perfect_matches"`
	IntegrityScore    float64 `json:"integrity_score"`
}

// IntegrityStatus constants
const (
	IntegrityStatusPerfect   = "perfect"
	IntegrityStatusNeedSync  = "needs_sync"
	IntegrityStatusConflicts = "has_conflicts"
	IntegrityStatusCorrupted = "corrupted"
)

// SyncType constants
const (
	SyncTypeFull        = "full"
	SyncTypeIncremental = "incremental"
	SyncTypeRecovery    = "recovery"
)



// SyncMetrics contains detailed metrics for Perfect Sync operations
type SyncMetrics struct {
	IntegritySyncDuration   time.Duration `json:"integrity_sync_duration"`
	HashCollectionDuration  time.Duration `json:"hash_collection_duration"`
	NetworkRequestDuration  time.Duration `json:"network_request_duration"`
	RecordsDownloaded       int64         `json:"records_downloaded"`
	RecordsUploaded         int64         `json:"records_uploaded"`
	IntegrityScore          float64       `json:"integrity_score"`
	RequestSizeBytes        int64         `json:"request_size_bytes"`
	ResponseSizeBytes       int64         `json:"response_size_bytes"`
	HashesProcessed         int64         `json:"hashes_processed"`
	ConflictsResolved       int64         `json:"conflicts_resolved"`
	ErrorsEncountered       int64         `json:"errors_encountered"`
}

// HashCompression contains methods for compressing hash collections
type HashCompression struct {
	Enabled     bool    `json:"enabled"`
	Algorithm   string  `json:"algorithm"`
	Ratio       float64 `json:"ratio"`
	OriginalSize int64  `json:"original_size"`
	CompressedSize int64 `json:"compressed_size"`
}

// PerformanceOptions contains options for optimizing Perfect Sync performance
type PerformanceOptions struct {
	BatchSize              int           `json:"batch_size"`
	MaxHashesPerRequest    int           `json:"max_hashes_per_request"`
	HashCollectionTimeout  time.Duration `json:"hash_collection_timeout"`
	NetworkTimeout         time.Duration `json:"network_timeout"`
	EnableCompression      bool          `json:"enable_compression"`
	ParallelProcessing     bool          `json:"parallel_processing"`
	MaxConcurrentOperations int          `json:"max_concurrent_operations"`
}

// RecoveryStrategy defines how to handle different types of sync failures
type RecoveryStrategy struct {
	MaxRetries        int           `json:"max_retries"`
	BackoffMultiplier float64       `json:"backoff_multiplier"`
	InitialDelay      time.Duration `json:"initial_delay"`
	MaxDelay          time.Duration `json:"max_delay"`
	RetryableErrors   []string      `json:"retryable_errors"`
}