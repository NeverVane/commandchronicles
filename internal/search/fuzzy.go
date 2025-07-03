package search

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/lang/en"
	"github.com/blevesearch/bleve/v2/mapping"
	"github.com/blevesearch/bleve/v2/search"
	"github.com/blevesearch/bleve/v2/search/query"

	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
)

// FuzzySearchEngine provides fuzzy search capabilities using Bleve
type FuzzySearchEngine struct {
	index       bleve.Index
	indexPath   string
	logger      *logger.Logger
	initialized bool
}

// SearchableCommandRecord represents a command record optimized for search indexing
type SearchableCommandRecord struct {
	ID         string    `json:"id"`
	DatabaseID int64     `json:"database_id"` // Original database record ID
	Command    string    `json:"command"`
	WorkingDir string    `json:"working_dir"`
	Hostname   string    `json:"hostname"`
	SessionID  string    `json:"session_id"`
	GitBranch  string    `json:"git_branch,omitempty"`
	GitRoot    string    `json:"git_root,omitempty"`
	User       string    `json:"user,omitempty"`
	Shell      string    `json:"shell,omitempty"`
	Note       string    `json:"note,omitempty"` // User note for the command
	ExitCode   int       `json:"exit_code"`
	Duration   int64     `json:"duration_ms"`
	Timestamp  time.Time `json:"timestamp"`
	Success    bool      `json:"success"`
	Recent     bool      `json:"recent"`   // Commands from last 24h
	Frequent   bool      `json:"frequent"` // Frequently used commands
}

// FuzzySearchOptions controls fuzzy search behavior
type FuzzySearchOptions struct {
	// Fuzzy matching options
	Fuzziness       int     `json:"fuzziness"`      // Edit distance (0-2)
	PrefixLength    int     `json:"prefix_length"`  // Number of prefix characters that must match exactly
	BoostRecent     float64 `json:"boost_recent"`   // Score boost for recent commands (last 24h)
	BoostFrequent   float64 `json:"boost_frequent"` // Score boost for frequently used commands
	BoostExactMatch float64 `json:"boost_exact"`    // Score boost for exact matches
	BoostPrefix     float64 `json:"boost_prefix"`   // Score boost for prefix matches

	// Search constraints
	MinScore       float64 `json:"min_score"`        // Minimum relevance score to include in results
	IncludeWorkDir bool    `json:"include_work_dir"` // Include working directory in search
	IncludeGitInfo bool    `json:"include_git_info"` // Include git branch/repo in search
	AnalyzeCommand bool    `json:"analyze_command"`  // Use text analysis on commands

	// Performance options
	MaxCandidates int           `json:"max_candidates"` // Maximum candidates to evaluate
	SearchTimeout time.Duration `json:"search_timeout"` // Maximum time for search operation
}

// FuzzySearchResult represents a search result with scoring information
type FuzzySearchResult struct {
	Record      *storage.CommandRecord `json:"record"`
	Score       float64                `json:"score"`
	Explanation map[string]float64     `json:"explanation,omitempty"` // Score breakdown
	Fragments   map[string][]string    `json:"fragments,omitempty"`   // Highlighted text fragments
}

// NewFuzzySearchEngine creates a new fuzzy search engine
func NewFuzzySearchEngine(indexPath string) *FuzzySearchEngine {
	return &FuzzySearchEngine{
		indexPath: indexPath,
		logger:    logger.GetLogger().WithComponent("fuzzy-search"),
	}
}

// Initialize sets up the Bleve index with optimized mapping for command search
func (f *FuzzySearchEngine) Initialize() error {
	if f.initialized {
		return nil
	}

	f.logger.Info().Str("index_path", f.indexPath).Msg("Initializing fuzzy search engine")

	// Create index directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(f.indexPath), 0755); err != nil {
		return fmt.Errorf("failed to create index directory: %w", err)
	}

	// Create custom mapping for command records
	mapping := f.createIndexMapping()

	var index bleve.Index
	var err error

	// Try to open existing index, create if it doesn't exist
	if _, err := os.Stat(f.indexPath); os.IsNotExist(err) {
		f.logger.Info().Msg("Creating new search index")
		index, err = bleve.New(f.indexPath, mapping)
	} else {
		f.logger.Info().Msg("Opening existing search index")
		index, err = bleve.Open(f.indexPath)
	}

	if err != nil {
		return fmt.Errorf("failed to initialize search index: %w", err)
	}

	f.index = index
	f.initialized = true

	f.logger.Info().Msg("Fuzzy search engine initialized successfully")
	return nil
}

// createIndexMapping creates an optimized index mapping for command records
func (f *FuzzySearchEngine) createIndexMapping() mapping.IndexMapping {
	// Create custom mapping
	commandMapping := bleve.NewDocumentMapping()

	// Command field - main search target with analysis
	commandFieldMapping := bleve.NewTextFieldMapping()
	commandFieldMapping.Analyzer = en.AnalyzerName
	commandFieldMapping.Store = true
	commandFieldMapping.Index = true
	commandFieldMapping.IncludeTermVectors = true
	commandMapping.AddFieldMappingsAt("command", commandFieldMapping)

	// Working directory - keyword search
	workDirMapping := bleve.NewTextFieldMapping()
	workDirMapping.Analyzer = "keyword"
	workDirMapping.Store = true
	workDirMapping.Index = true
	commandMapping.AddFieldMappingsAt("working_dir", workDirMapping)

	// Hostname - keyword search
	hostnameMapping := bleve.NewTextFieldMapping()
	hostnameMapping.Analyzer = "keyword"
	hostnameMapping.Store = true
	hostnameMapping.Index = true
	commandMapping.AddFieldMappingsAt("hostname", hostnameMapping)

	// Session ID - keyword search
	sessionMapping := bleve.NewTextFieldMapping()
	sessionMapping.Analyzer = "keyword"
	sessionMapping.Store = true
	sessionMapping.Index = true
	commandMapping.AddFieldMappingsAt("session_id", sessionMapping)

	// Git branch - text search
	gitBranchMapping := bleve.NewTextFieldMapping()
	gitBranchMapping.Analyzer = "keyword"
	gitBranchMapping.Store = true
	gitBranchMapping.Index = true
	commandMapping.AddFieldMappingsAt("git_branch", gitBranchMapping)

	// Git root - keyword search
	gitRootMapping := bleve.NewTextFieldMapping()
	gitRootMapping.Analyzer = "keyword"
	gitRootMapping.Store = true
	gitRootMapping.Index = true
	commandMapping.AddFieldMappingsAt("git_root", gitRootMapping)

	// User - keyword search
	userMapping := bleve.NewTextFieldMapping()
	userMapping.Analyzer = "keyword"
	userMapping.Store = true
	userMapping.Index = true
	commandMapping.AddFieldMappingsAt("user", userMapping)

	// Shell - keyword search
	shellMapping := bleve.NewTextFieldMapping()
	shellMapping.Analyzer = "keyword"
	shellMapping.Store = true
	shellMapping.Index = true
	commandMapping.AddFieldMappingsAt("shell", shellMapping)

	// Note field - text search with analysis (like command field)
	noteMapping := bleve.NewTextFieldMapping()
	noteMapping.Analyzer = en.AnalyzerName
	noteMapping.Store = true
	noteMapping.Index = true
	noteMapping.IncludeTermVectors = true
	commandMapping.AddFieldMappingsAt("note", noteMapping)

	// Numeric fields
	exitCodeMapping := bleve.NewNumericFieldMapping()
	exitCodeMapping.Store = true
	exitCodeMapping.Index = true
	commandMapping.AddFieldMappingsAt("exit_code", exitCodeMapping)

	durationMapping := bleve.NewNumericFieldMapping()
	durationMapping.Store = true
	durationMapping.Index = true
	commandMapping.AddFieldMappingsAt("duration_ms", durationMapping)

	databaseIDMapping := bleve.NewNumericFieldMapping()
	databaseIDMapping.Store = true
	databaseIDMapping.Index = true
	commandMapping.AddFieldMappingsAt("database_id", databaseIDMapping)

	// Timestamp for range queries
	timestampMapping := bleve.NewDateTimeFieldMapping()
	timestampMapping.Store = true
	timestampMapping.Index = true
	commandMapping.AddFieldMappingsAt("timestamp", timestampMapping)

	// Boolean fields for boosting
	successMapping := bleve.NewBooleanFieldMapping()
	successMapping.Store = true
	successMapping.Index = true
	commandMapping.AddFieldMappingsAt("success", successMapping)

	recentMapping := bleve.NewBooleanFieldMapping()
	recentMapping.Store = true
	recentMapping.Index = true
	commandMapping.AddFieldMappingsAt("recent", recentMapping)

	frequentMapping := bleve.NewBooleanFieldMapping()
	frequentMapping.Store = true
	frequentMapping.Index = true
	commandMapping.AddFieldMappingsAt("frequent", frequentMapping)

	// Create index mapping
	indexMapping := bleve.NewIndexMapping()
	indexMapping.AddDocumentMapping("command", commandMapping)
	indexMapping.DefaultMapping = commandMapping

	return indexMapping
}

// IndexCommand adds or updates a command record in the search index
func (f *FuzzySearchEngine) IndexCommand(record *storage.CommandRecord) error {
	if !f.initialized {
		return fmt.Errorf("fuzzy search engine not initialized")
	}

	searchableRecord := f.convertToSearchableRecord(record)

	err := f.index.Index(searchableRecord.ID, searchableRecord)
	if err != nil {
		return fmt.Errorf("failed to index command: %w", err)
	}

	return nil
}

// IndexCommands adds multiple command records to the search index in batch
func (f *FuzzySearchEngine) IndexCommands(records []*storage.CommandRecord) error {
	if !f.initialized {
		return fmt.Errorf("fuzzy search engine not initialized")
	}

	if len(records) == 0 {
		return nil
	}

	f.logger.Debug().Int("count", len(records)).Msg("Batch indexing commands")

	batch := f.index.NewBatch()
	for _, record := range records {
		searchableRecord := f.convertToSearchableRecord(record)
		if err := batch.Index(searchableRecord.ID, searchableRecord); err != nil {
			return fmt.Errorf("failed to add record to batch: %w", err)
		}
	}

	if err := f.index.Batch(batch); err != nil {
		return fmt.Errorf("failed to execute batch index: %w", err)
	}

	f.logger.Debug().Int("indexed", len(records)).Msg("Batch indexing completed")
	return nil
}

// Search performs a fuzzy search with the given query and options
func (f *FuzzySearchEngine) Search(searchQuery string, opts *FuzzySearchOptions) ([]*FuzzySearchResult, error) {
	if !f.initialized {
		return nil, fmt.Errorf("fuzzy search engine not initialized")
	}

	if opts == nil {
		opts = f.getDefaultSearchOptions()
	}

	f.logger.Debug().
		Str("query", searchQuery).
		Int("fuzziness", opts.Fuzziness).
		Float64("min_score", opts.MinScore).
		Msg("Performing fuzzy search")

	// Build the search query
	bleveQuery := f.buildSearchQuery(searchQuery, opts)

	// Create search request
	searchRequest := bleve.NewSearchRequest(bleveQuery)
	searchRequest.Size = opts.MaxCandidates
	searchRequest.Fields = []string{"*"}
	searchRequest.IncludeLocations = true

	// Add highlighting
	searchRequest.Highlight = bleve.NewHighlight()
	searchRequest.Highlight.AddField("command")
	if opts.IncludeWorkDir {
		searchRequest.Highlight.AddField("working_dir")
	}
	if opts.IncludeGitInfo {
		searchRequest.Highlight.AddField("git_branch")
	}

	// Set timeout
	if opts.SearchTimeout > 0 {
		// Bleve doesn't have built-in timeout, but we can implement it at a higher level
	}

	// Execute search
	searchResults, err := f.index.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search execution failed: %w", err)
	}

	// Convert results
	results := make([]*FuzzySearchResult, 0, len(searchResults.Hits))
	for _, hit := range searchResults.Hits {
		if hit.Score < opts.MinScore {
			continue
		}

		result := &FuzzySearchResult{
			Score:     hit.Score,
			Fragments: make(map[string][]string),
		}

		// Extract record data from stored fields
		if record, err := f.extractRecordFromHit(hit); err == nil {
			result.Record = record
		} else {
			f.logger.Warn().Err(err).Str("doc_id", hit.ID).Msg("Failed to extract record from search hit")
			continue
		}

		// Extract highlighted fragments
		if hit.Fragments != nil {
			for field, fragments := range hit.Fragments {
				result.Fragments[field] = fragments
			}
		}

		results = append(results, result)
	}

	f.logger.Debug().
		Int("total_hits", len(searchResults.Hits)).
		Int("filtered_results", len(results)).
		Dur("search_time", searchResults.Took).
		Msg("Fuzzy search completed")

	return results, nil
}

// buildSearchQuery constructs a Bleve query for fuzzy search
func (f *FuzzySearchEngine) buildSearchQuery(searchQuery string, opts *FuzzySearchOptions) query.Query {
	if searchQuery == "" {
		return bleve.NewMatchAllQuery()
	}

	// Create a boolean query to combine multiple search strategies
	boolQuery := bleve.NewBooleanQuery()

	// 1. Exact match (highest boost)
	if opts.BoostExactMatch > 0 {
		exactQuery := bleve.NewMatchQuery(searchQuery)
		exactQuery.SetField("command")
		exactQuery.SetBoost(opts.BoostExactMatch)
		boolQuery.AddShould(exactQuery)
	}

	// 2. Prefix match (high boost)
	if opts.BoostPrefix > 0 {
		prefixQuery := bleve.NewPrefixQuery(searchQuery)
		prefixQuery.SetField("command")
		prefixQuery.SetBoost(opts.BoostPrefix)
		boolQuery.AddShould(prefixQuery)
	}

	// 3. Fuzzy match on command (medium boost)
	fuzzyQuery := bleve.NewFuzzyQuery(searchQuery)
	fuzzyQuery.SetField("command")
	fuzzyQuery.SetFuzziness(opts.Fuzziness)
	// Note: PrefixLength is not directly supported in bleve fuzzy queries
	// The prefix matching is handled by separate prefix queries
	fuzzyQuery.SetBoost(1.0)
	boolQuery.AddShould(fuzzyQuery)

	// 4. Term match with analysis (for partial word matches)
	if opts.AnalyzeCommand {
		termQuery := bleve.NewMatchQuery(searchQuery)
		termQuery.SetField("command")
		termQuery.SetBoost(0.8)
		boolQuery.AddShould(termQuery)
	}

	// 5. Include working directory search if enabled
	if opts.IncludeWorkDir {
		workDirQuery := bleve.NewWildcardQuery("*" + searchQuery + "*")
		workDirQuery.SetField("working_dir")
		workDirQuery.SetBoost(0.5)
		boolQuery.AddShould(workDirQuery)
	}

	// 6. Include git info search if enabled
	if opts.IncludeGitInfo {
		gitQuery := bleve.NewWildcardQuery("*" + searchQuery + "*")
		gitQuery.SetField("git_branch")
		gitQuery.SetBoost(0.3)
		boolQuery.AddShould(gitQuery)
	}

	// 7. Add boost queries for recent and frequent commands
	finalQuery := boolQuery
	if opts.BoostRecent > 0 || opts.BoostFrequent > 0 {
		boostQuery := bleve.NewBooleanQuery()
		boostQuery.AddMust(boolQuery)

		if opts.BoostRecent > 0 {
			recentQuery := bleve.NewBoolFieldQuery(true)
			recentQuery.SetField("recent")
			recentQuery.SetBoost(opts.BoostRecent)
			boostQuery.AddShould(recentQuery)
		}

		if opts.BoostFrequent > 0 {
			frequentQuery := bleve.NewBoolFieldQuery(true)
			frequentQuery.SetField("frequent")
			frequentQuery.SetBoost(opts.BoostFrequent)
			boostQuery.AddShould(frequentQuery)
		}

		finalQuery = boostQuery
	}

	return finalQuery
}

// extractRecordFromHit converts a Bleve search hit back to a CommandRecord
func (f *FuzzySearchEngine) extractRecordFromHit(hit *search.DocumentMatch) (*storage.CommandRecord, error) {
	fields := hit.Fields

	record := &storage.CommandRecord{}

	// Extract string fields
	if cmd, ok := fields["command"].(string); ok {
		record.Command = cmd
	}
	if wd, ok := fields["working_dir"].(string); ok {
		record.WorkingDir = wd
	}
	if hostname, ok := fields["hostname"].(string); ok {
		record.Hostname = hostname
	}
	if sessionID, ok := fields["session_id"].(string); ok {
		record.SessionID = sessionID
	}
	if gitBranch, ok := fields["git_branch"].(string); ok {
		record.GitBranch = gitBranch
	}
	if gitRoot, ok := fields["git_root"].(string); ok {
		record.GitRoot = gitRoot
	}
	if user, ok := fields["user"].(string); ok {
		record.User = user
	}
	if shell, ok := fields["shell"].(string); ok {
		record.Shell = shell
	}
	if note, ok := fields["note"].(string); ok {
		record.Note = note
	}

	// Extract numeric fields
	if exitCode, ok := fields["exit_code"].(float64); ok {
		record.ExitCode = int(exitCode)
	}
	if duration, ok := fields["duration_ms"].(float64); ok {
		record.Duration = int64(duration)
	}
	if databaseID, ok := fields["database_id"].(float64); ok {
		record.ID = int64(databaseID)
	}

	// Extract timestamp
	if timestamp, ok := fields["timestamp"].(string); ok {
		if t, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
			record.Timestamp = t.UnixMilli()
		}
	}

	// Validate required fields
	if record.Command == "" || record.SessionID == "" {
		return nil, fmt.Errorf("invalid record: missing required fields")
	}

	return record, nil
}

// convertToSearchableRecord converts a CommandRecord to a SearchableCommandRecord
func (f *FuzzySearchEngine) convertToSearchableRecord(record *storage.CommandRecord) *SearchableCommandRecord {
	// Generate unique ID
	id := fmt.Sprintf("%s_%d", record.SessionID, record.Timestamp)

	// Determine if command is recent (last 24 hours)
	isRecent := time.Now().UnixMilli()-record.Timestamp < 24*60*60*1000

	// TODO: Implement frequency detection based on command usage patterns
	// For now, mark commonly used commands as frequent
	isFrequent := f.isFrequentCommand(record.Command)

	return &SearchableCommandRecord{
		ID:         id,
		DatabaseID: record.ID,
		Command:    record.Command,
		WorkingDir: record.WorkingDir,
		Hostname:   record.Hostname,
		SessionID:  record.SessionID,
		GitBranch:  record.GitBranch,
		GitRoot:    record.GitRoot,
		User:       record.User,
		Shell:      record.Shell,
		Note:       record.Note,
		ExitCode:   record.ExitCode,
		Duration:   record.Duration,
		Timestamp:  time.UnixMilli(record.Timestamp),
		Success:    record.ExitCode == 0,
		Recent:     isRecent,
		Frequent:   isFrequent,
	}
}

// isFrequentCommand determines if a command is frequently used
func (f *FuzzySearchEngine) isFrequentCommand(command string) bool {
	// Simple heuristic: commands starting with common tools are frequent
	commonCommands := []string{
		"ls", "cd", "pwd", "cat", "grep", "find", "git", "vim", "nano",
		"cp", "mv", "rm", "mkdir", "touch", "chmod", "chown", "ps", "top",
		"ssh", "scp", "curl", "wget", "docker", "kubectl", "make", "npm",
		"go", "python", "node", "java", "cargo", "mvn",
	}

	cmdParts := strings.Fields(command)
	if len(cmdParts) == 0 {
		return false
	}

	baseCmd := strings.ToLower(cmdParts[0])
	for _, common := range commonCommands {
		if baseCmd == common || strings.HasPrefix(baseCmd, common) {
			return true
		}
	}

	return false
}

// getDefaultSearchOptions returns sensible default search options
func (f *FuzzySearchEngine) getDefaultSearchOptions() *FuzzySearchOptions {
	return &FuzzySearchOptions{
		Fuzziness:       1,    // Allow 1 character difference
		PrefixLength:    1,    // First character must match exactly
		BoostRecent:     1.5,  // 50% boost for recent commands
		BoostFrequent:   1.3,  // 30% boost for frequent commands
		BoostExactMatch: 3.0,  // 300% boost for exact matches
		BoostPrefix:     2.0,  // 200% boost for prefix matches
		MinScore:        0.1,  // Minimum relevance score
		IncludeWorkDir:  true, // Include working directory in search
		IncludeGitInfo:  true, // Include git info in search
		AnalyzeCommand:  true, // Use text analysis
		MaxCandidates:   1000, // Maximum candidates to evaluate
		SearchTimeout:   5 * time.Second,
	}
}

// GetIndexStats returns statistics about the search index
func (f *FuzzySearchEngine) GetIndexStats() (map[string]interface{}, error) {
	if !f.initialized {
		return nil, fmt.Errorf("fuzzy search engine not initialized")
	}

	docCount, err := f.index.DocCount()
	if err != nil {
		return nil, fmt.Errorf("failed to get document count: %w", err)
	}

	stats := map[string]interface{}{
		"document_count": docCount,
		"index_path":     f.indexPath,
		"initialized":    f.initialized,
	}

	return stats, nil
}

// DeleteCommand removes a command from the search index
func (f *FuzzySearchEngine) DeleteCommand(sessionID string, timestamp int64) error {
	if !f.initialized {
		return fmt.Errorf("fuzzy search engine not initialized")
	}

	id := fmt.Sprintf("%s_%d", sessionID, timestamp)
	return f.index.Delete(id)
}

// Close closes the search index and releases resources
func (f *FuzzySearchEngine) Close() error {
	if f.index != nil {
		err := f.index.Close()
		f.initialized = false
		return err
	}
	return nil
}

// RebuildIndex rebuilds the entire search index from provided records
func (f *FuzzySearchEngine) RebuildIndex(records []*storage.CommandRecord) error {
	f.logger.Info().Int("record_count", len(records)).Msg("Rebuilding search index")

	// Close existing index
	if f.index != nil {
		f.index.Close()
	}

	// Remove existing index
	if err := os.RemoveAll(f.indexPath); err != nil {
		f.logger.Warn().Err(err).Msg("Failed to remove existing index")
	}

	// Reinitialize
	f.initialized = false
	if err := f.Initialize(); err != nil {
		return fmt.Errorf("failed to reinitialize index: %w", err)
	}

	// Index all records
	if err := f.IndexCommands(records); err != nil {
		return fmt.Errorf("failed to index records: %w", err)
	}

	f.logger.Info().Int("indexed_records", len(records)).Msg("Index rebuild completed")
	return nil
}
