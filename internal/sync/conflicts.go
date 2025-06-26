package sync

import (
	"fmt"
	
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
)

type ConflictResolver struct {
	logger *logger.Logger
}

// ConflictResolutionStrategy defines how conflicts should be resolved
type ConflictResolutionStrategy int

const (
	ResolutionServerDecides ConflictResolutionStrategy = iota
	ResolutionLocalWins
	ResolutionRemoteWins
	ResolutionMerge
)

// ConflictResult contains the outcome of conflict resolution
type ConflictResult struct {
	Resolution   string `json:"resolution"`
	LocalHash    string `json:"local_hash"`
	RemoteHash   string `json:"remote_hash"`
	WinningHash  string `json:"winning_hash"`
	ResolvedAt   int64  `json:"resolved_at"`
}

func NewConflictResolver() *ConflictResolver {
	return &ConflictResolver{
		logger: logger.GetLogger().WithComponent("conflict-resolver"),
	}
}

// ProcessServerConflicts handles conflict resolution decisions from server
func (cr *ConflictResolver) ProcessServerConflicts(conflicts []ConflictInfo, storage StorageInterface) error {
	if len(conflicts) == 0 {
		return nil
	}

	cr.logger.Info().
		Int("conflict_count", len(conflicts)).
		Msg("Processing server conflict resolutions")

	var processedCount int
	var errorCount int

	for _, conflict := range conflicts {
		cr.logger.Debug().
			Str("local_hash", conflict.LocalHash).
			Str("remote_hash", conflict.RemoteHash).
			Str("resolution", conflict.Resolution).
			Int64("timestamp", conflict.Timestamp).
			Msg("Processing individual conflict")
		
		if err := cr.processSingleConflict(conflict, storage); err != nil {
			cr.logger.Error().
				Err(err).
				Str("local_hash", conflict.LocalHash).
				Str("resolution", conflict.Resolution).
				Msg("Failed to process conflict")
			errorCount++
			continue
		}
		
		processedCount++
	}

	cr.logger.Info().
		Int("processed", processedCount).
		Int("errors", errorCount).
		Msg("Conflict resolution processing completed")

	if errorCount > 0 {
		return fmt.Errorf("failed to process %d out of %d conflicts", errorCount, len(conflicts))
	}

	return nil
}

func (cr *ConflictResolver) processSingleConflict(conflict ConflictInfo, storage StorageInterface) error {
	switch conflict.Resolution {
	case "local_wins":
		// Server kept local record, mark it as synced
		if err := storage.MarkRecordSyncedByHash(conflict.LocalHash); err != nil {
			return fmt.Errorf("failed to mark local record as synced: %w", err)
		}
		cr.logger.Debug().
			Str("hash", conflict.LocalHash).
			Msg("Local record won conflict resolution")
		
	case "remote_wins":
		// Server kept remote record, mark local conflict as resolved
		if err := storage.MarkConflictResolvedByHash(conflict.LocalHash); err != nil {
			return fmt.Errorf("failed to mark conflict as resolved: %w", err)
		}
		cr.logger.Debug().
			Str("local_hash", conflict.LocalHash).
			Str("remote_hash", conflict.RemoteHash).
			Msg("Remote record won conflict resolution")
		
	case "duplicate":
		// Records are identical, mark as synced
		if err := storage.MarkRecordSyncedByHash(conflict.LocalHash); err != nil {
			return fmt.Errorf("failed to mark duplicate record as synced: %w", err)
		}
		cr.logger.Debug().
			Str("hash", conflict.LocalHash).
			Msg("Duplicate record marked as synced")
		
	default:
		cr.logger.Warn().
			Str("resolution", conflict.Resolution).
			Str("local_hash", conflict.LocalHash).
			Msg("Unknown conflict resolution type")
		return fmt.Errorf("unknown conflict resolution type: %s", conflict.Resolution)
	}
	
	return nil
}

// DetectLocalConflicts identifies potential conflicts before upload
func (cr *ConflictResolver) DetectLocalConflicts(localRecords []*storage.CommandRecord, remoteHashes []string) []ConflictResult {
	var conflicts []ConflictResult
	
	// Create hash map for quick lookup
	remoteHashMap := make(map[string]bool)
	for _, hash := range remoteHashes {
		remoteHashMap[hash] = true
	}
	
	for _, record := range localRecords {
		if record.RecordHash != "" && remoteHashMap[record.RecordHash] {
			// Potential conflict detected
			conflicts = append(conflicts, ConflictResult{
				Resolution:  "needs_server_decision",
				LocalHash:   record.RecordHash,
				RemoteHash:  record.RecordHash,
				WinningHash: "",
				ResolvedAt:  0,
			})
		}
	}
	
	cr.logger.Debug().
		Int("local_records", len(localRecords)).
		Int("remote_hashes", len(remoteHashes)).
		Int("conflicts_detected", len(conflicts)).
		Msg("Local conflict detection completed")
	
	return conflicts
}

// ResolveConflictLocally applies local conflict resolution strategy
func (cr *ConflictResolver) ResolveConflictLocally(local, remote *storage.CommandRecord, strategy ConflictResolutionStrategy) (*storage.CommandRecord, error) {
	cr.logger.Debug().
		Str("local_hash", local.RecordHash).
		Str("remote_hash", remote.RecordHash).
		Int("strategy", int(strategy)).
		Msg("Resolving conflict locally")

	switch strategy {
	case ResolutionLocalWins:
		return local, nil
		
	case ResolutionRemoteWins:
		return remote, nil
		
	case ResolutionMerge:
		// For MVP, merge is not implemented - use timestamp-based resolution
		if local.Timestamp > remote.Timestamp {
			cr.logger.Debug().Msg("Local record is newer, using local")
			return local, nil
		}
		cr.logger.Debug().Msg("Remote record is newer, using remote")
		return remote, nil
		
	default:
		return nil, fmt.Errorf("unsupported conflict resolution strategy: %d", strategy)
	}
}

// ValidateConflictResolution checks if a conflict resolution is valid
func (cr *ConflictResolver) ValidateConflictResolution(conflict ConflictInfo) error {
	if conflict.LocalHash == "" {
		return fmt.Errorf("local hash is required")
	}
	
	if conflict.RemoteHash == "" {
		return fmt.Errorf("remote hash is required")
	}
	
	validResolutions := map[string]bool{
		"local_wins":  true,
		"remote_wins": true,
		"duplicate":   true,
	}
	
	if !validResolutions[conflict.Resolution] {
		return fmt.Errorf("invalid resolution type: %s", conflict.Resolution)
	}
	
	if conflict.Timestamp <= 0 {
		return fmt.Errorf("timestamp must be positive")
	}
	
	return nil
}

// GetConflictStatistics returns statistics about conflict resolution
func (cr *ConflictResolver) GetConflictStatistics(conflicts []ConflictInfo) map[string]int {
	stats := map[string]int{
		"total":       len(conflicts),
		"local_wins":  0,
		"remote_wins": 0,
		"duplicates":  0,
		"unknown":     0,
	}
	
	for _, conflict := range conflicts {
		switch conflict.Resolution {
		case "local_wins":
			stats["local_wins"]++
		case "remote_wins":
			stats["remote_wins"]++
		case "duplicate":
			stats["duplicates"]++
		default:
			stats["unknown"]++
		}
	}
	
	return stats
}

// StorageInterface defines operations needed by conflict resolver
type StorageInterface interface {
	MarkRecordSyncedByHash(hash string) error
	MarkConflictResolvedByHash(hash string) error
	GetRecordByHash(hash string) (*storage.CommandRecord, error)
	UpdateRecord(record *storage.CommandRecord) error
}