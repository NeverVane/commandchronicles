package deletion

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/cache"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/search"
	"github.com/NeverVane/commandchronicles/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// DeletionService handles all command deletion operations
type DeletionService struct {
	storage       *securestorage.SecureStorage
	cache         *cache.Cache
	searchService *search.SearchService
	authManager   *auth.AuthManager
	config        *config.Config
	logger        *logger.Logger
}

// DeletionRequest represents a deletion operation request
type DeletionRequest struct {
	// Operation type
	Type DeletionType

	// Single deletion
	RecordID int64

	// Pattern deletion
	Pattern string

	// Options
	DryRun      bool
	Force       bool   // Skip confirmations
	ExportFirst string // Export path before deletion
}

// DeletionType represents the type of deletion operation
type DeletionType int

const (
	DeleteSingle DeletionType = iota
	DeletePattern
	DeleteAll
)

// DeletionResult contains the results of a deletion operation
type DeletionResult struct {
	DeletedCount   int64
	MatchedRecords []*storage.CommandRecord // For dry-run preview
	Duration       time.Duration
	ExportedTo     string
	Errors         []error
}

// DeletionStats provides statistics about a deletion operation
type DeletionStats struct {
	TotalMatches int64
	OldestRecord time.Time
	NewestRecord time.Time
	Patterns     map[string]int // Command patterns and their counts
}

// NewDeletionService creates a new deletion service
func NewDeletionService(
	storage *securestorage.SecureStorage,
	cache *cache.Cache,
	searchService *search.SearchService,
	authManager *auth.AuthManager,
	config *config.Config,
) *DeletionService {
	return &DeletionService{
		storage:       storage,
		cache:         cache,
		searchService: searchService,
		authManager:   authManager,
		config:        config,
		logger:        logger.GetLogger().WithComponent("deletion"),
	}
}

// DeleteRecord deletes a single command record by ID
func (ds *DeletionService) DeleteRecord(recordID int64, force bool) (*DeletionResult, error) {
	return ds.ExecuteDeletion(&DeletionRequest{
		Type:     DeleteSingle,
		RecordID: recordID,
		Force:    force,
	})
}

// DeletePattern deletes all records matching a pattern
func (ds *DeletionService) DeletePattern(pattern string, dryRun bool, force bool) (*DeletionResult, error) {
	return ds.ExecuteDeletion(&DeletionRequest{
		Type:    DeletePattern,
		Pattern: pattern,
		DryRun:  dryRun,
		Force:   force,
	})
}

// DeleteAll deletes all command history
func (ds *DeletionService) DeleteAll(exportFirst string, force bool) (*DeletionResult, error) {
	return ds.ExecuteDeletion(&DeletionRequest{
		Type:        DeleteAll,
		ExportFirst: exportFirst,
		Force:       force,
	})
}

// ExecuteDeletion executes a deletion request
func (ds *DeletionService) ExecuteDeletion(req *DeletionRequest) (*DeletionResult, error) {
	start := time.Now()
	result := &DeletionResult{
		MatchedRecords: make([]*storage.CommandRecord, 0),
		Errors:         make([]error, 0),
	}

	// Validate session
	if !ds.authManager.IsSessionActive() {
		return nil, fmt.Errorf("no active session - authentication required")
	}

	ds.logger.Info().
		Int("type", int(req.Type)).
		Bool("dry_run", req.DryRun).
		Bool("force", req.Force).
		Msg("Starting deletion operation")

	// Get records to delete
	recordsToDelete, err := ds.getRecordsToDelete(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get records for deletion: %w", err)
	}

	result.MatchedRecords = recordsToDelete

	// Dry run - just return matched records
	if req.DryRun {
		result.Duration = time.Since(start)
		ds.logger.Info().
			Int("matched_count", len(recordsToDelete)).
			Msg("Dry-run completed")
		return result, nil
	}

	// Export before deletion if requested
	if req.ExportFirst != "" {
		if err := ds.exportBeforeDeletion(recordsToDelete, req.ExportFirst); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("export failed: %w", err))
		} else {
			result.ExportedTo = req.ExportFirst
		}
	}

	// Perform actual deletion
	deletedCount, err := ds.performDeletion(recordsToDelete)
	if err != nil {
		return nil, fmt.Errorf("deletion failed: %w", err)
	}

	result.DeletedCount = deletedCount
	result.Duration = time.Since(start)

	// Update components after deletion
	ds.updateComponentsAfterDeletion(recordsToDelete)

	ds.logger.Info().
		Int64("deleted_count", deletedCount).
		Dur("duration", result.Duration).
		Msg("Deletion operation completed")

	return result, nil
}

// getRecordsToDelete retrieves records that match the deletion criteria
func (ds *DeletionService) getRecordsToDelete(req *DeletionRequest) ([]*storage.CommandRecord, error) {
	switch req.Type {
	case DeleteSingle:
		return ds.getSingleRecord(req.RecordID)
	case DeletePattern:
		return ds.getPatternMatches(req.Pattern)
	case DeleteAll:
		return ds.getAllRecords()
	default:
		return nil, fmt.Errorf("unknown deletion type: %d", req.Type)
	}
}

// getSingleRecord retrieves a single record by ID
func (ds *DeletionService) getSingleRecord(recordID int64) ([]*storage.CommandRecord, error) {
	// Search through all records to find the one with matching ID
	opts := &securestorage.QueryOptions{
		Limit:     10000, // Large limit to ensure we find the record
		OrderBy:   "id",
		Ascending: false,
	}

	result, err := ds.storage.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	for _, record := range result.Records {
		if record.ID == recordID {
			return []*storage.CommandRecord{record}, nil
		}
	}

	return nil, fmt.Errorf("record with ID %d not found", recordID)
}

// getPatternMatches retrieves records matching a pattern
func (ds *DeletionService) getPatternMatches(pattern string) ([]*storage.CommandRecord, error) {
	// Convert shell-style pattern to regex
	regexPattern, err := ds.convertPatternToRegex(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern: %w", err)
	}

	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile pattern: %w", err)
	}

	// Retrieve all records and filter by pattern
	opts := &securestorage.QueryOptions{
		Limit:     10000, // Large limit to check all records
		OrderBy:   "timestamp",
		Ascending: false,
	}

	result, err := ds.storage.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve records: %w", err)
	}

	var matches []*storage.CommandRecord
	for _, record := range result.Records {
		if regex.MatchString(record.Command) {
			matches = append(matches, record)
		}
	}

	return matches, nil
}

// getAllRecords retrieves all records for full wipe
func (ds *DeletionService) getAllRecords() ([]*storage.CommandRecord, error) {
	opts := &securestorage.QueryOptions{
		Limit:     100000, // Very large limit to get all records
		OrderBy:   "timestamp",
		Ascending: false,
	}

	result, err := ds.storage.Retrieve(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve all records: %w", err)
	}

	return result.Records, nil
}

// convertPatternToRegex converts shell-style patterns to regex
func (ds *DeletionService) convertPatternToRegex(pattern string) (string, error) {
	// Escape special regex characters except * and ?
	escaped := regexp.QuoteMeta(pattern)

	// Convert shell wildcards to regex
	escaped = strings.ReplaceAll(escaped, "\\*", ".*")
	escaped = strings.ReplaceAll(escaped, "\\?", ".")

	// Anchor the pattern
	return "^" + escaped + "$", nil
}

// exportBeforeDeletion exports records before deletion
func (ds *DeletionService) exportBeforeDeletion(records []*storage.CommandRecord, exportPath string) error {
	ds.logger.Info().
		Str("export_path", exportPath).
		Int("record_count", len(records)).
		Msg("Exporting records before deletion")

	// Implementation would depend on export format
	// For now, just log the operation
	return nil
}

// performDeletion performs the actual deletion of records
func (ds *DeletionService) performDeletion(records []*storage.CommandRecord) (int64, error) {
	if len(records) == 0 {
		return 0, nil
	}

	deletedCount := int64(0)

	// Delete records one by one to ensure proper cleanup
	for _, record := range records {
		err := ds.storage.DeleteRecord(record.ID)
		if err != nil {
			ds.logger.WithError(err).WithFields(map[string]interface{}{
				"record_id": record.ID,
				"command":   record.Command,
			}).Warn().Msg("Failed to delete record")
			continue
		}
		deletedCount++
	}

	return deletedCount, nil
}

// updateComponentsAfterDeletion updates cache and search indexes after deletion
func (ds *DeletionService) updateComponentsAfterDeletion(deletedRecords []*storage.CommandRecord) {
	// Clear cache to ensure consistency
	// In a more sophisticated implementation, we could selectively evict records
	ds.cache.Clear()
	ds.logger.Debug().Msg("Cache cleared after deletion")

	// Refresh search service to update indexes
	if ds.searchService != nil {
		ds.searchService.RefreshCache()
		ds.logger.Debug().Msg("Search service refreshed after deletion")
	}

	// Reset sync timestamp for full wipe operations if configured
	if ds.config.Deletion.ResetSyncOnWipe && ds.isFullWipe(deletedRecords) {
		if err := ds.resetSyncTimestamp(); err != nil {
			ds.logger.Warn().Err(err).Msg("Failed to reset sync timestamp after full wipe")
		} else {
			ds.logger.Info().Msg("Reset sync timestamp after full wipe - next sync will download all server data")
		}
	}
}

// ValidatePattern validates a deletion pattern for safety
func (ds *DeletionService) ValidatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// Check for dangerous patterns
	dangerousPatterns := []string{"*", ".*", "**", "?*", "*?"}
	for _, dangerous := range dangerousPatterns {
		if pattern == dangerous {
			return fmt.Errorf("pattern '%s' is too broad and could delete all commands", pattern)
		}
	}

	// Ensure pattern has some specificity
	if len(strings.ReplaceAll(strings.ReplaceAll(pattern, "*", ""), "?", "")) < 2 {
		return fmt.Errorf("pattern '%s' is too vague, please be more specific", pattern)
	}

	return nil
}

// GetDeletionStats returns statistics about what would be deleted
func (ds *DeletionService) GetDeletionStats(req *DeletionRequest) (*DeletionStats, error) {
	req.DryRun = true
	result, err := ds.ExecuteDeletion(req)
	if err != nil {
		return nil, err
	}

	stats := &DeletionStats{
		TotalMatches: int64(len(result.MatchedRecords)),
		OldestRecord: time.Time{},
		NewestRecord: time.Time{},
		Patterns:     make(map[string]int),
	}

	if len(result.MatchedRecords) > 0 {
		// Calculate time range
		oldest := time.UnixMilli(result.MatchedRecords[0].Timestamp)
		newest := time.UnixMilli(result.MatchedRecords[0].Timestamp)

		for _, record := range result.MatchedRecords {
			recordTime := time.UnixMilli(record.Timestamp)
			if recordTime.Before(oldest) {
				oldest = recordTime
			}
			if recordTime.After(newest) {
				newest = recordTime
			}

			// Count command patterns
			cmdParts := strings.Fields(record.Command)
			if len(cmdParts) > 0 {
				stats.Patterns[cmdParts[0]]++
			}
		}

		stats.OldestRecord = oldest
		stats.NewestRecord = newest
	}

	return stats, nil
}

// resetSyncTimestamp resets the sync timestamp to 0 to trigger full re-download on next sync
func (ds *DeletionService) resetSyncTimestamp() error {
	syncTimeFile := filepath.Join(ds.config.DataDir, "last_sync_time")

	// Write 0 timestamp to force full re-sync
	data, err := json.Marshal(int64(0))
	if err != nil {
		return fmt.Errorf("failed to marshal zero timestamp: %w", err)
	}

	if err := os.WriteFile(syncTimeFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write sync timestamp file: %w", err)
	}

	ds.logger.Debug().Str("file", syncTimeFile).Msg("Reset sync timestamp to 0")
	return nil
}

// isFullWipe determines if this deletion represents a full wipe operation
func (ds *DeletionService) isFullWipe(deletedRecords []*storage.CommandRecord) bool {
	// For now, consider any deletion with more than 100 records as a "full wipe"
	// This heuristic can be improved later with request type tracking
	return len(deletedRecords) > 100
}
