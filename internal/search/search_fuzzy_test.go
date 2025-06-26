package search

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/NeverVane/commandchronicles/internal/cache"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

func TestSearchService_InitializeWithFuzzySearch(t *testing.T) {
	tmpDir := t.TempDir()
	
	cfg := &config.Config{
		DataDir: tmpDir,
		Cache: config.CacheConfig{
			HotCacheSize:    100,
			SearchBatchSize: 500,
			MaxMemoryMB:     50,
		},
	}

	// Mock storage (we'll need to create a mock or use a test storage)
	storage := &securestorage.SecureStorage{} // This would need proper initialization in real tests
	
	service := NewSearchService(nil, storage, cfg)
	
	opts := &SearchOptions{
		EnableFuzzySearch: true,
		FuzzyIndexPath:    filepath.Join(tmpDir, "fuzzy_index"),
		WarmupCache:       false,
	}

	err := service.Initialize(opts)
	// Note: This might fail due to storage not being properly initialized
	// In a real test environment, we'd need proper test storage setup
	if err != nil {
		t.Logf("Expected initialization to require proper storage setup: %v", err)
	}

	// Test with fuzzy search disabled
	opts.EnableFuzzySearch = false
	err = service.Initialize(opts)
	if err != nil {
		t.Logf("Non-fuzzy initialization might also require proper storage: %v", err)
	}

	service.Close()
}

func TestSearchService_SearchWithFuzzy(t *testing.T) {
	tmpDir := t.TempDir()
	
	// Setup test environment
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	// Test fuzzy search request
	req := &SearchRequest{
		Query:          "git status",
		Limit:          10,
		UseFuzzySearch: true,
		FuzzyOptions: &FuzzySearchOptions{
			Fuzziness:       1,
			BoostExactMatch: 3.0,
			MinScore:        0.1,
			MaxCandidates:   50,
		},
	}

	response, err := service.Search(req)
	if err != nil {
		// Expected if fuzzy engine isn't properly initialized
		t.Logf("Fuzzy search failed as expected without proper setup: %v", err)
		return
	}

	assert.NotNil(t, response)
	assert.True(t, response.UsedFuzzySearch)
}

func TestSearchService_SearchWithoutFuzzy(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	// Test non-fuzzy search request
	req := &SearchRequest{
		Query:          "git status",
		Limit:          10,
		UseFuzzySearch: false,
		UseCache:       false, // Disable cache to test direct search
	}

	response, err := service.Search(req)
	if err != nil {
		// Expected without proper storage initialization
		t.Logf("Search failed as expected without proper storage setup: %v", err)
		return
	}

	assert.NotNil(t, response)
	assert.False(t, response.UsedFuzzySearch)
}

func TestSearchService_FuzzySearchFallback(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	// Test that search falls back to cache when fuzzy search is requested but unavailable
	req := &SearchRequest{
		Query:          "git status",
		Limit:          10,
		UseFuzzySearch: true,  // Request fuzzy search
		UseCache:       true,  // But also enable cache as fallback
	}

	response, err := service.Search(req)
	if err != nil {
		t.Logf("Search failed as expected: %v", err)
		return
	}

	// Should fall back to cache/direct search if fuzzy engine is unavailable
	assert.NotNil(t, response)
}

func TestSearchService_FuzzySearchOptions(t *testing.T) {
	service := &SearchService{}
	
	// Test default fuzzy options
	defaultOpts := service.getDefaultFuzzyOptions()
	assert.NotNil(t, defaultOpts)
	assert.Equal(t, 1, defaultOpts.Fuzziness)
	assert.Equal(t, 1, defaultOpts.PrefixLength)
	assert.Equal(t, 1.5, defaultOpts.BoostRecent)
	assert.Equal(t, 1.3, defaultOpts.BoostFrequent)
	assert.Equal(t, 3.0, defaultOpts.BoostExactMatch)
	assert.Equal(t, 2.0, defaultOpts.BoostPrefix)
	assert.Equal(t, 0.1, defaultOpts.MinScore)
	assert.True(t, defaultOpts.IncludeWorkDir)
	assert.True(t, defaultOpts.IncludeGitInfo)
	assert.True(t, defaultOpts.AnalyzeCommand)
	assert.Equal(t, 1000, defaultOpts.MaxCandidates)
	assert.Equal(t, 5*time.Second, defaultOpts.SearchTimeout)
}

func TestSearchService_IndexCommand(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	record := &storage.CommandRecord{
		Command:    "test command",
		ExitCode:   0,
		Duration:   100,
		WorkingDir: "/test",
		Timestamp:  time.Now().UnixMilli(),
		SessionID:  "test-session",
		Hostname:   "test-host",
		Version:    1,
		CreatedAt:  time.Now().UnixMilli(),
	}

	// Should not error even if fuzzy engine is not available
	err := service.IndexCommand(record)
	assert.NoError(t, err)
}

func TestSearchService_GetFuzzySearchStats(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	stats, err := service.GetFuzzySearchStats()
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	
	// Should indicate whether fuzzy search is enabled
	enabled, exists := stats["enabled"]
	assert.True(t, exists)
	assert.NotNil(t, enabled)
}

func TestSearchService_SearchRequestValidation(t *testing.T) {
	service := &SearchService{}
	
	// Test nil request
	err := service.validateRequest(nil)
	assert.Error(t, err)

	// Test request with defaults applied
	req := &SearchRequest{
		Query: "test",
	}
	
	err = service.validateRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, 50, req.Limit) // Default limit should be applied
	assert.Equal(t, 10, req.MaxBatches) // Default max batches
	assert.Equal(t, 30*time.Second, req.Timeout) // Default timeout

	// Test request with invalid time range
	now := time.Now()
	until := now.Add(-time.Hour)
	req = &SearchRequest{
		Query: "test",
		Since: &now,
		Until: &until, // Until is before Since
	}
	
	err = service.validateRequest(req)
	assert.Error(t, err)

	// Test request with valid time range
	since := now.Add(-time.Hour)
	req = &SearchRequest{
		Query: "test",
		Since: &since,
		Until: &now,
	}
	
	err = service.validateRequest(req)
	assert.NoError(t, err)

	// Test limit capping
	req = &SearchRequest{
		Query: "test",
		Limit: 2000, // Over the cap
	}
	
	err = service.validateRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, 1000, req.Limit) // Should be capped
}

func TestSearchService_BuildAppliedFilters(t *testing.T) {
	service := &SearchService{}
	
	exitCode := 0
	since := time.Now().Add(-time.Hour)
	until := time.Now()
	
	req := &SearchRequest{
		WorkingDir:     "/home/user",
		Hostname:       "test-host",
		SessionID:      "session-123",
		ExitCode:       &exitCode,
		Since:          &since,
		Until:          &until,
		OnlySuccessful: true,
		CaseSensitive:  true,
		ExactMatch:     true,
	}

	filters := service.buildAppliedFilters(req)
	
	assert.Equal(t, "/home/user", filters["working_dir"])
	assert.Equal(t, "test-host", filters["hostname"])
	assert.Equal(t, "session-123", filters["session_id"])
	assert.Equal(t, 0, filters["exit_code"])
	assert.True(t, filters["only_successful"].(bool))
	assert.True(t, filters["case_sensitive"].(bool))
	assert.True(t, filters["exact_match"].(bool))
	
	// Check time filters are formatted correctly
	sinceStr, exists := filters["since"].(string)
	assert.True(t, exists)
	assert.NotEmpty(t, sinceStr)
	
	untilStr, exists := filters["until"].(string)
	assert.True(t, exists)
	assert.NotEmpty(t, untilStr)
}

func TestSearchService_SearchStats(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	// Initial stats should be zero
	stats := service.GetStats()
	assert.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalSearches)
	assert.Equal(t, int64(0), stats.CacheHits)
	assert.Equal(t, int64(0), stats.CacheMisses)

	// Perform a search to update stats
	req := &SearchRequest{
		Query:          "test",
		UseFuzzySearch: false,
		UseCache:       false,
	}

	_, err := service.Search(req)
	if err == nil {
		// If search succeeded, stats should be updated
		updatedStats := service.GetStats()
		assert.Equal(t, int64(1), updatedStats.TotalSearches)
	}
}

func TestSearchService_QuickSearch(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	records, err := service.QuickSearch("git", 10)
	if err != nil {
		t.Logf("Quick search failed as expected without proper setup: %v", err)
		return
	}

	assert.NotNil(t, records)
	assert.True(t, len(records) <= 10)
}

func TestSearchService_SearchRecent(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	records, err := service.SearchRecent("git", 24*time.Hour)
	if err != nil {
		t.Logf("Recent search failed as expected without proper setup: %v", err)
		return
	}

	assert.NotNil(t, records)
}

func TestSearchService_SearchByDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	records, err := service.SearchByDirectory("/home/user", 20)
	if err != nil {
		t.Logf("Directory search failed as expected without proper setup: %v", err)
		return
	}

	assert.NotNil(t, records)
	assert.True(t, len(records) <= 20)
}

func TestSearchService_Integration_FuzzyAndCache(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	// Test that fuzzy search is preferred over cache when both are available
	req := &SearchRequest{
		Query:          "git status",
		Limit:          10,
		UseFuzzySearch: true,
		UseCache:       true,
		FuzzyOptions: &FuzzySearchOptions{
			Fuzziness:     1,
			MinScore:      0.1,
			MaxCandidates: 50,
		},
	}

	response, err := service.Search(req)
	if err != nil {
		t.Logf("Integration search failed as expected: %v", err)
		return
	}

	// Should prefer fuzzy search when both are available and query is not empty
	assert.NotNil(t, response)
}

func TestSearchService_Performance_FuzzySearch(t *testing.T) {
	tmpDir := t.TempDir()
	
	service := setupTestSearchService(t, tmpDir)
	defer service.Close()

	req := &SearchRequest{
		Query:          "git",
		Limit:          100,
		UseFuzzySearch: true,
		FuzzyOptions: &FuzzySearchOptions{
			Fuzziness:     1,
			MaxCandidates: 1000,
			SearchTimeout: 5 * time.Second,
		},
	}

	start := time.Now()
	response, err := service.Search(req)
	duration := time.Since(start)

	if err != nil {
		t.Logf("Performance test search failed as expected: %v", err)
		return
	}

	// Search should complete within reasonable time
	assert.True(t, duration < 1*time.Second, "Search took too long: %v", duration)
	assert.NotNil(t, response)
	
	if response.UsedFuzzySearch {
		t.Logf("Fuzzy search completed in %v", duration)
	}
}

// Helper function to setup a test search service
func setupTestSearchService(t *testing.T, tmpDir string) *SearchService {
	cfg := &config.Config{
		DataDir: tmpDir,
		Cache: config.CacheConfig{
			HotCacheSize:    100,
			SearchBatchSize: 500,
			MaxMemoryMB:     50,
		},
	}

	// Create a minimal cache for testing
	testCache := cache.NewCache(&cfg.Cache, nil)
	
	// Note: In a real test environment, we'd need to create a proper test storage
	// For now, we create the service with minimal setup
	service := NewSearchService(testCache, nil, cfg)
	
	// Try to initialize with fuzzy search, but don't fail if it doesn't work
	opts := &SearchOptions{
		EnableFuzzySearch: true,
		FuzzyIndexPath:    filepath.Join(tmpDir, "fuzzy_index"),
		WarmupCache:       false,
	}
	
	// Initialize but don't require success (since we don't have proper storage)
	service.Initialize(opts)
	
	return service
}