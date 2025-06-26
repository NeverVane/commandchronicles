package search

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/cache"
	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/NeverVane/commandchronicles-cli/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles-cli/pkg/storage"
)

// SearchService provides high-level search functionality using the hybrid cache
type SearchService struct {
	cache        *cache.Cache
	storage      *securestorage.SecureStorage
	config       *config.Config
	logger       *logger.Logger
	stats        *SearchStats
	fuzzyEngine  *FuzzySearchEngine
}

// SearchStats tracks search performance metrics
type SearchStats struct {
	TotalSearches     int64         `json:"total_searches"`
	CacheHits         int64         `json:"cache_hits"`
	CacheMisses       int64         `json:"cache_misses"`
	AverageTime       time.Duration `json:"average_time"`
	LastSearchTime    time.Time     `json:"last_search_time"`
	TotalResultsFound int64         `json:"total_results_found"`
}

// SearchRequest contains search parameters
type SearchRequest struct {
	// Query parameters
	Query  string `json:"query"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`

	// Filter parameters
	WorkingDir string     `json:"working_dir"`
	Hostname   string     `json:"hostname"`
	SessionID  string     `json:"session_id"`
	ExitCode   *int       `json:"exit_code"`
	Since      *time.Time `json:"since"`
	Until      *time.Time `json:"until"`

	// Search options
	CaseSensitive  bool `json:"case_sensitive"`
	ExactMatch     bool `json:"exact_match"`
	IncludeGit     bool `json:"include_git"`
	OnlySuccessful bool `json:"only_successful"`

	// Fuzzy search options
	UseFuzzySearch bool                  `json:"use_fuzzy_search"`
	FuzzyOptions   *FuzzySearchOptions   `json:"fuzzy_options,omitempty"`

	// Performance options
	UseCache   bool          `json:"use_cache"`
	MaxBatches int           `json:"max_batches"`
	Timeout    time.Duration `json:"timeout"`
}

// SearchResponse contains search results and metadata
type SearchResponse struct {
	// Results
	Records      []*storage.CommandRecord `json:"records"`
	TotalMatches int                      `json:"total_matches"`

	// Performance metrics
	SearchTime    time.Duration `json:"search_time"`
	FromCache     int           `json:"from_cache"`
	FromBatches   int           `json:"from_batches"`
	CacheHitRatio float64       `json:"cache_hit_ratio"`

	// Fuzzy search metrics
	UsedFuzzySearch bool     `json:"used_fuzzy_search"`
	FuzzyScores     []float64 `json:"fuzzy_scores,omitempty"`
	MaxFuzzyScore   float64  `json:"max_fuzzy_score,omitempty"`
	MinFuzzyScore   float64  `json:"min_fuzzy_score,omitempty"`

	// Pagination
	HasMore    bool `json:"has_more"`
	NextOffset int  `json:"next_offset"`

	// Query info
	Query          string                 `json:"query"`
	AppliedFilters map[string]interface{} `json:"applied_filters"`
}

// SearchOptions provides service-level configuration
type SearchOptions struct {
	EnableCache       bool
	DefaultLimit      int
	DefaultMaxBatches int
	DefaultTimeout    time.Duration
	WarmupCache       bool
	EnableFuzzySearch bool
	FuzzyIndexPath    string
	RebuildFuzzyIndex bool
}

// NewSearchService creates a new search service
func NewSearchService(cache *cache.Cache, storage *securestorage.SecureStorage, cfg *config.Config) *SearchService {
	return &SearchService{
		cache:   cache,
		storage: storage,
		config:  cfg,
		logger:  logger.GetLogger().WithComponent("search"),
		stats:   &SearchStats{},
	}
}

// Initialize sets up the search service
func (s *SearchService) Initialize(opts *SearchOptions) error {
	if opts == nil {
		opts = &SearchOptions{
			EnableCache:       true,
			DefaultLimit:      50,
			DefaultMaxBatches: 10,
			DefaultTimeout:    30 * time.Second,
			WarmupCache:       true,
			EnableFuzzySearch: true,
			FuzzyIndexPath:    filepath.Join(s.config.DataDir, "search_index"),
			RebuildFuzzyIndex: false,
		}
	}

	s.logger.Info().Msg("Initializing search service")

	// Initialize fuzzy search engine if enabled
	if opts.EnableFuzzySearch {
		s.logger.Info().Str("index_path", opts.FuzzyIndexPath).Msg("Initializing fuzzy search engine")
		
		s.fuzzyEngine = NewFuzzySearchEngine(opts.FuzzyIndexPath)
		if err := s.fuzzyEngine.Initialize(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to initialize fuzzy search engine")
			s.fuzzyEngine = nil
		} else {
			s.logger.Info().Msg("Fuzzy search engine initialized successfully")
			
			// Get initial index stats
			if stats, err := s.fuzzyEngine.GetIndexStats(); err == nil {
				s.logger.Info().Interface("stats", stats).Msg("Initial fuzzy index stats")
			}
			
			// Rebuild index if requested
			if opts.RebuildFuzzyIndex {
				s.logger.Info().Msg("Rebuilding fuzzy search index")
				if err := s.rebuildFuzzyIndex(); err != nil {
					s.logger.Warn().Err(err).Msg("Failed to rebuild fuzzy search index")
				} else {
					// Get post-rebuild stats
					if stats, err := s.fuzzyEngine.GetIndexStats(); err == nil {
						s.logger.Info().Interface("stats", stats).Msg("Post-rebuild fuzzy index stats")
					}
				}
			}
		}
	} else {
		s.logger.Info().Msg("Fuzzy search disabled in options")
	}

	// Warm up cache if requested
	if opts.WarmupCache && opts.EnableCache {
		if err := s.cache.WarmUpCache(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to warm up cache")
		}
	}

	s.logger.Info().
		Bool("cache_enabled", opts.EnableCache).
		Bool("fuzzy_search_enabled", s.fuzzyEngine != nil).
		Int("default_limit", opts.DefaultLimit).
		Msg("Search service initialized")

	return nil
}

// Search performs a search operation
func (s *SearchService) Search(req *SearchRequest) (*SearchResponse, error) {
	start := time.Now()

	// Validate request
	if err := s.validateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid search request: %w", err)
	}

	s.logger.Debug().
		Str("query", req.Query).
		Int("limit", req.Limit).
		Bool("use_cache", req.UseCache).
		Msg("Starting search")

	var response *SearchResponse
	var err error

	// Perform search based on strategy
	s.logger.Debug().
		Bool("use_fuzzy_search", req.UseFuzzySearch).
		Bool("fuzzy_engine_available", s.fuzzyEngine != nil).
		Bool("query_not_empty", req.Query != "").
		Bool("use_cache", req.UseCache).
		Bool("cache_available", s.cache != nil).
		Msg("Determining search strategy")

	if req.UseFuzzySearch && s.fuzzyEngine != nil && req.Query != "" {
		s.logger.Debug().Msg("Using fuzzy search strategy")
		response, err = s.searchWithFuzzy(req)
	} else if req.UseCache && s.cache != nil {
		s.logger.Debug().Msg("Using cache search strategy")
		response, err = s.searchWithCache(req)
	} else {
		s.logger.Debug().Msg("Using direct search strategy")
		response, err = s.searchDirect(req)
	}

	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Update statistics
	s.updateStats(response)

	duration := time.Since(start)
	response.SearchTime = duration

	s.logger.Debug().
		Int("total_matches", response.TotalMatches).
		Int("from_cache", response.FromCache).
		Int("from_batches", response.FromBatches).
		Dur("search_time", duration).
		Msg("Search completed")

	return response, nil
}

// searchWithCache performs search using the hybrid cache
func (s *SearchService) searchWithCache(req *SearchRequest) (*SearchResponse, error) {
	// Build cache search options
	batchOpts := &cache.BatchLoadOptions{
		MaxBatches:   req.MaxBatches,
		MaxResults:   req.Limit,
		SkipHotCache: false,
		QueryFilter:  s.buildQueryFilter(req),
		ParallelLoad: req.MaxBatches > 3,
		CacheBatches: req.Limit > 100,
	}

	// Perform cache search
	cacheResult, err := s.cache.Search(req.Query, batchOpts)
	if err != nil {
		return nil, fmt.Errorf("cache search failed: %w", err)
	}

	// Filter results if needed
	filteredRecords := s.applyPostFilters(cacheResult.Records, req)

	// Build response
	response := &SearchResponse{
		Records:        filteredRecords,
		TotalMatches:   len(filteredRecords),
		FromCache:      cacheResult.FromCache,
		FromBatches:    cacheResult.FromBatches,
		HasMore:        len(filteredRecords) >= req.Limit,
		NextOffset:     req.Offset + len(filteredRecords),
		Query:          req.Query,
		AppliedFilters: s.buildAppliedFilters(req),
	}

	// Calculate cache hit ratio
	totalResults := float64(cacheResult.FromCache + cacheResult.FromBatches)
	if totalResults > 0 {
		response.CacheHitRatio = float64(cacheResult.FromCache) / totalResults
	}

	return response, nil
}

// searchDirect performs search directly against storage
func (s *SearchService) searchDirect(req *SearchRequest) (*SearchResponse, error) {
	// Build storage query options
	queryOpts := s.buildQueryFilter(req)
	queryOpts.Limit = req.Limit
	queryOpts.Offset = req.Offset

	// Execute storage query
	result, err := s.storage.Retrieve(queryOpts)
	if err != nil {
		return nil, fmt.Errorf("storage query failed: %w", err)
	}

	// Filter results based on search query
	var filteredRecords []*storage.CommandRecord
	if req.Query == "" {
		filteredRecords = result.Records
	} else {
		filteredRecords = s.filterRecordsByQuery(result.Records, req)
	}

	// Build response
	response := &SearchResponse{
		Records:        filteredRecords,
		TotalMatches:   len(filteredRecords),
		FromCache:      0,
		FromBatches:    len(filteredRecords),
		HasMore:        result.HasMore,
		NextOffset:     req.Offset + len(filteredRecords),
		Query:          req.Query,
		AppliedFilters: s.buildAppliedFilters(req),
		CacheHitRatio:  0.0,
	}

	return response, nil
}

// validateRequest validates the search request
func (s *SearchService) validateRequest(req *SearchRequest) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 1000 {
		req.Limit = 1000 // Cap maximum limit
	}
	if req.MaxBatches <= 0 {
		req.MaxBatches = 10
	}
	if req.Timeout <= 0 {
		req.Timeout = 30 * time.Second
	}

	// Validate time range
	if req.Since != nil && req.Until != nil && req.Since.After(*req.Until) {
		return fmt.Errorf("since time cannot be after until time")
	}

	return nil
}

// buildQueryFilter creates storage query options from search request
func (s *SearchService) buildQueryFilter(req *SearchRequest) *securestorage.QueryOptions {
	opts := &securestorage.QueryOptions{}

	if req.Hostname != "" {
		opts.Hostname = req.Hostname
	}
	if req.SessionID != "" {
		opts.SessionID = req.SessionID
	}
	if req.Since != nil {
		opts.Since = req.Since
	}
	if req.Until != nil {
		opts.Until = req.Until
	}

	// Set ordering (most recent first by default)
	opts.OrderBy = "timestamp"
	opts.Ascending = false

	return opts
}

// applyPostFilters applies additional filters to search results
func (s *SearchService) applyPostFilters(records []*storage.CommandRecord, req *SearchRequest) []*storage.CommandRecord {
	if len(records) == 0 {
		return records
	}

	var filtered []*storage.CommandRecord

	for _, record := range records {
		if s.recordMatchesFilters(record, req) {
			filtered = append(filtered, record)
			if len(filtered) >= req.Limit {
				break
			}
		}
	}

	return filtered
}

// recordMatchesFilters checks if a record matches the request filters
func (s *SearchService) recordMatchesFilters(record *storage.CommandRecord, req *SearchRequest) bool {
	// Working directory filter
	if req.WorkingDir != "" && !strings.Contains(record.WorkingDir, req.WorkingDir) {
		return false
	}

	// Exit code filter
	if req.ExitCode != nil && record.ExitCode != *req.ExitCode {
		return false
	}

	// Only successful commands filter
	if req.OnlySuccessful && record.ExitCode != 0 {
		return false
	}

	return true
}

// filterRecordsByQuery filters records by search query text
func (s *SearchService) filterRecordsByQuery(records []*storage.CommandRecord, req *SearchRequest) []*storage.CommandRecord {
	if req.Query == "" {
		return records
	}

	query := req.Query
	if !req.CaseSensitive {
		query = strings.ToLower(query)
	}

	var filtered []*storage.CommandRecord

	for _, record := range records {
		if s.recordMatchesQuery(record, query, req) {
			filtered = append(filtered, record)
		}
	}

	return filtered
}

// recordMatchesQuery checks if a record matches the search query
func (s *SearchService) recordMatchesQuery(record *storage.CommandRecord, query string, req *SearchRequest) bool {
	searchText := record.Command
	if !req.CaseSensitive {
		searchText = strings.ToLower(searchText)
	}

	// Exact match
	if req.ExactMatch {
		return searchText == query
	}

	// Substring match in command
	if strings.Contains(searchText, query) {
		return true
	}

	// Search in working directory
	workingDir := record.WorkingDir
	if !req.CaseSensitive {
		workingDir = strings.ToLower(workingDir)
	}
	if strings.Contains(workingDir, query) {
		return true
	}

	// Search in git information if enabled
	if req.IncludeGit {
		gitBranch := record.GitBranch
		if !req.CaseSensitive {
			gitBranch = strings.ToLower(gitBranch)
		}
		if strings.Contains(gitBranch, query) {
			return true
		}
	}

	return false
}

// buildAppliedFilters creates a map of applied filters for the response
func (s *SearchService) buildAppliedFilters(req *SearchRequest) map[string]interface{} {
	filters := make(map[string]interface{})

	if req.WorkingDir != "" {
		filters["working_dir"] = req.WorkingDir
	}
	if req.Hostname != "" {
		filters["hostname"] = req.Hostname
	}
	if req.SessionID != "" {
		filters["session_id"] = req.SessionID
	}
	if req.ExitCode != nil {
		filters["exit_code"] = *req.ExitCode
	}
	if req.Since != nil {
		filters["since"] = req.Since.Format(time.RFC3339)
	}
	if req.Until != nil {
		filters["until"] = req.Until.Format(time.RFC3339)
	}
	if req.OnlySuccessful {
		filters["only_successful"] = true
	}
	if req.CaseSensitive {
		filters["case_sensitive"] = true
	}
	if req.ExactMatch {
		filters["exact_match"] = true
	}

	return filters
}

// updateStats updates search performance statistics
func (s *SearchService) updateStats(response *SearchResponse) {
	s.stats.TotalSearches++
	s.stats.LastSearchTime = time.Now()
	s.stats.TotalResultsFound += int64(response.TotalMatches)

	if response.FromCache > 0 {
		s.stats.CacheHits++
	} else {
		s.stats.CacheMisses++
	}

	// Update average time (simple moving average)
	if s.stats.TotalSearches == 1 {
		s.stats.AverageTime = response.SearchTime
	} else {
		s.stats.AverageTime = time.Duration(
			(int64(s.stats.AverageTime)*int64(s.stats.TotalSearches-1) + int64(response.SearchTime)) /
				int64(s.stats.TotalSearches),
		)
	}
}

// GetStats returns search performance statistics
func (s *SearchService) GetStats() *SearchStats {
	return s.stats
}

// RefreshCache refreshes the underlying cache
func (s *SearchService) RefreshCache() error {
	if s.cache == nil {
		return fmt.Errorf("cache not available")
	}
	return s.cache.LoadHotCache()
}

// GetCacheStats returns cache performance statistics
func (s *SearchService) GetCacheStats() *cache.CacheStats {
	if s.cache == nil {
		return nil
	}
	return s.cache.GetStats()
}

// Close shuts down the search service
func (s *SearchService) Close() error {
	s.logger.Debug().Msg("Closing search service")

	if s.cache != nil {
		if err := s.cache.Close(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to close cache")
		}
	}

	if s.fuzzyEngine != nil {
		if err := s.fuzzyEngine.Close(); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to close fuzzy search engine")
		}
	}

	s.logger.Info().Msg("Search service closed")
	return nil
}

// QuickSearch provides a simple interface for quick searches
func (s *SearchService) QuickSearch(query string, limit int) ([]*storage.CommandRecord, error) {
	req := &SearchRequest{
		Query:    query,
		Limit:    limit,
		UseCache: true,
	}

	response, err := s.Search(req)
	if err != nil {
		return nil, err
	}

	return response.Records, nil
}

// SearchRecent searches for recent commands matching the query
func (s *SearchService) SearchRecent(query string, since time.Duration) ([]*storage.CommandRecord, error) {
	sinceTime := time.Now().Add(-since)

	req := &SearchRequest{
		Query:    query,
		Limit:    100,
		Since:    &sinceTime,
		UseCache: true,
	}

	response, err := s.Search(req)
	if err != nil {
		return nil, err
	}

	return response.Records, nil
}

// SearchByDirectory searches for commands in a specific directory
func (s *SearchService) SearchByDirectory(directory string, limit int) ([]*storage.CommandRecord, error) {
	req := &SearchRequest{
		WorkingDir: directory,
		Limit:      limit,
		UseCache:   true,
	}

	response, err := s.Search(req)
	if err != nil {
		return nil, err
	}

	return response.Records, nil
}

// searchWithFuzzy performs search using the fuzzy search engine
func (s *SearchService) searchWithFuzzy(req *SearchRequest) (*SearchResponse, error) {
	s.logger.Debug().
		Str("query", req.Query).
		Int("limit", req.Limit).
		Bool("fuzzy_engine_nil", s.fuzzyEngine == nil).
		Msg("Starting fuzzy search")

	if s.fuzzyEngine == nil {
		s.logger.Error().Msg("Fuzzy search engine is nil")
		return nil, fmt.Errorf("fuzzy search engine not available")
	}

	// Use default fuzzy options if not provided
	fuzzyOpts := req.FuzzyOptions
	if fuzzyOpts == nil {
		fuzzyOpts = s.getDefaultFuzzyOptions()
	}

	// Apply search constraints from request
	fuzzyOpts.MaxCandidates = req.Limit * 2 // Get more candidates for filtering
	if req.Timeout > 0 {
		fuzzyOpts.SearchTimeout = req.Timeout
	}

	s.logger.Debug().
		Interface("fuzzy_opts", fuzzyOpts).
		Msg("Using fuzzy search options")

	// Get current index stats before search
	if stats, err := s.fuzzyEngine.GetIndexStats(); err == nil {
		s.logger.Debug().Interface("index_stats", stats).Msg("Current fuzzy index stats before search")
	}

	// Perform fuzzy search
	s.logger.Debug().Msg("Calling fuzzy engine search")
	fuzzyResults, err := s.fuzzyEngine.Search(req.Query, fuzzyOpts)
	if err != nil {
		s.logger.Error().
			Err(err).
			Str("query", req.Query).
			Msg("Fuzzy search failed")
		return nil, fmt.Errorf("fuzzy search failed: %w", err)
	}

	s.logger.Debug().
		Int("fuzzy_results_count", len(fuzzyResults)).
		Str("query", req.Query).
		Msg("Fuzzy search completed")

	// Convert fuzzy results to command records and apply additional filters
	var filteredRecords []*storage.CommandRecord
	var fuzzyScores []float64
	var maxScore, minScore float64

	for i, fuzzyResult := range fuzzyResults {
		if s.recordMatchesFilters(fuzzyResult.Record, req) {
			filteredRecords = append(filteredRecords, fuzzyResult.Record)
			fuzzyScores = append(fuzzyScores, fuzzyResult.Score)
			
			if i == 0 || fuzzyResult.Score > maxScore {
				maxScore = fuzzyResult.Score
			}
			if i == 0 || fuzzyResult.Score < minScore {
				minScore = fuzzyResult.Score
			}
			
			if len(filteredRecords) >= req.Limit {
				break
			}
		}
	}

	// Build response
	response := &SearchResponse{
		Records:         filteredRecords,
		TotalMatches:    len(filteredRecords),
		FromCache:       0,
		FromBatches:     len(filteredRecords),
		UsedFuzzySearch: true,
		FuzzyScores:     fuzzyScores,
		MaxFuzzyScore:   maxScore,
		MinFuzzyScore:   minScore,
		HasMore:         len(fuzzyResults) > len(filteredRecords),
		NextOffset:      req.Offset + len(filteredRecords),
		Query:           req.Query,
		AppliedFilters:  s.buildAppliedFilters(req),
		CacheHitRatio:   0.0,
	}

	return response, nil
}

// getDefaultFuzzyOptions returns default fuzzy search options
func (s *SearchService) getDefaultFuzzyOptions() *FuzzySearchOptions {
	return &FuzzySearchOptions{
		Fuzziness:       1,
		PrefixLength:    1,
		BoostRecent:     1.5,
		BoostFrequent:   1.3,
		BoostExactMatch: 3.0,
		BoostPrefix:     2.0,
		MinScore:        0.1,
		IncludeWorkDir:  true,
		IncludeGitInfo:  true,
		AnalyzeCommand:  true,
		MaxCandidates:   1000,
		SearchTimeout:   5 * time.Second,
	}
}

// rebuildFuzzyIndex rebuilds the fuzzy search index from storage
func (s *SearchService) rebuildFuzzyIndex() error {
	if s.fuzzyEngine == nil {
		s.logger.Error().Msg("Fuzzy search engine not available for rebuild")
		return fmt.Errorf("fuzzy search engine not available")
	}

	s.logger.Info().Msg("Loading all records for index rebuild")
	
	// Retrieve all records using batching approach since storage limits to 10000 records per query
	var allRecords []*storage.CommandRecord
	const batchSize = 10000
	offset := 0
	
	for {
		queryOpts := &securestorage.QueryOptions{
			Limit:     batchSize,
			Offset:    offset,
			OrderBy:   "timestamp",
			Ascending: false,
		}

		s.logger.Debug().
			Int("batch_size", batchSize).
			Int("offset", offset).
			Msg("Retrieving batch of records for indexing")
			
		result, err := s.storage.Retrieve(queryOpts)
		if err != nil {
			s.logger.Error().Err(err).Msg("Failed to retrieve records for indexing")
			return fmt.Errorf("failed to retrieve records for indexing: %w", err)
		}

		if len(result.Records) == 0 {
			break // No more records
		}

		allRecords = append(allRecords, result.Records...)
		offset += len(result.Records)

		s.logger.Debug().
			Int("batch_records", len(result.Records)).
			Int("total_so_far", len(allRecords)).
			Int64("total_available", result.TotalCount).
			Msg("Retrieved batch of records")

		// If we got less than batch size, we've reached the end
		if len(result.Records) < batchSize {
			break
		}
	}

	s.logger.Info().
		Int("record_count", len(allRecords)).
		Msg("Retrieved all records for fuzzy index rebuild")

	// Log some sample commands for debugging
	if len(allRecords) > 0 {
		s.logger.Debug().Msg("Sample commands to be indexed:")
		for i, record := range allRecords {
			if i >= 5 { // Only log first 5 for brevity
				break
			}
			s.logger.Debug().
				Int64("id", record.ID).
				Str("command", record.Command).
				Str("session", record.SessionID).
				Msg("Sample record")
		}
	} else {
		s.logger.Warn().Msg("No records found to index - fuzzy search will return empty results")
	}

	// Rebuild the index
	s.logger.Info().Msg("Starting fuzzy index rebuild")
	if err := s.fuzzyEngine.RebuildIndex(allRecords); err != nil {
		s.logger.Error().Err(err).Msg("Failed to rebuild fuzzy index")
		return fmt.Errorf("failed to rebuild fuzzy index: %w", err)
	}

	s.logger.Info().
		Int("indexed_records", len(allRecords)).
		Msg("Fuzzy search index rebuild completed successfully")
	return nil
}

// IndexCommand adds a command to the fuzzy search index
func (s *SearchService) IndexCommand(record *storage.CommandRecord) error {
	if s.fuzzyEngine == nil {
		return nil // Fuzzy search not enabled
	}

	return s.fuzzyEngine.IndexCommand(record)
}

// GetFuzzySearchStats returns fuzzy search engine statistics
func (s *SearchService) GetFuzzySearchStats() (map[string]interface{}, error) {
	if s.fuzzyEngine == nil {
		return map[string]interface{}{
			"enabled": false,
		}, nil
	}

	stats, err := s.fuzzyEngine.GetIndexStats()
	if err != nil {
		return nil, err
	}

	stats["enabled"] = true
	return stats, nil
}
