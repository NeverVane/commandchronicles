package cache

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
	"github.com/NeverVane/commandchronicles/internal/storage"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// EvictionPolicy defines the cache eviction strategy
type EvictionPolicy int

const (
	EvictionLRU  EvictionPolicy = iota // Least Recently Used
	EvictionLFU                        // Least Frequently Used
	EvictionTTL                        // Time To Live based
	EvictionSize                       // Size based (oldest entries)
)

// CacheEntry wraps a command record with metadata for eviction policies
type CacheEntry struct {
	Record      *storage.CommandRecord
	AccessTime  time.Time
	AccessCount int64
	InsertTime  time.Time
	Size        int64
}

// Cache provides a hybrid memory cache for command records with hot cache and batch loading
type Cache struct {
	// Hot cache configuration
	hotCache        []*CacheEntry
	hotCacheSize    int
	searchBatchSize int
	maxMemoryMB     int
	refreshInterval time.Duration
	lastRefresh     time.Time

	// Thread safety
	mu sync.RWMutex

	// Dependencies
	storage *securestorage.SecureStorage
	config  *config.CacheConfig
	logger  *logger.Logger

	// Memory management
	currentMemoryMB int64
	totalCacheHits  int64
	totalCacheMiss  int64
	totalBatches    int64

	// Search state
	lastSearchQuery string
	lastSearchTime  time.Time

	// Background refresh
	refreshTicker *time.Ticker
	stopRefresh   chan bool
	refreshActive bool

	// Cache maintenance
	evictionPolicy    EvictionPolicy
	maintenanceTicker *time.Ticker
	stopMaintenance   chan bool
	maintenanceActive bool
	maxCacheAge       time.Duration
	lastMaintenance   time.Time
	evictionThreshold float64 // Percentage of max memory to trigger eviction

	// Secure memory handling
	memoryLocked      bool
	secureAllocations map[uintptr]int // Track secure memory allocations
	mlockSupported    bool
	securityLevel     int // 0=basic, 1=enhanced, 2=paranoid
	poisonPattern     []byte
}

// CacheStats provides cache performance statistics
type CacheStats struct {
	HotCacheSize    int           `json:"hot_cache_size"`
	CurrentMemoryMB int64         `json:"current_memory_mb"`
	CacheHits       int64         `json:"cache_hits"`
	CacheMisses     int64         `json:"cache_misses"`
	BatchesLoaded   int64         `json:"batches_loaded"`
	LastRefresh     time.Time     `json:"last_refresh"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	HitRatio        float64       `json:"hit_ratio"`
}

// SearchResult contains search results with metadata
type SearchResult struct {
	Records      []*storage.CommandRecord `json:"records"`
	TotalMatches int                      `json:"total_matches"`
	FromCache    int                      `json:"from_cache"`
	FromBatches  int                      `json:"from_batches"`
	SearchTime   time.Duration            `json:"search_time"`
}

// BatchLoadOptions controls batch loading behavior
type BatchLoadOptions struct {
	MaxBatches    int
	MaxResults    int
	SkipHotCache  bool
	QueryFilter   *securestorage.QueryOptions
	BatchSize     int  // Override default batch size
	ParallelLoad  bool // Enable parallel batch loading
	CacheBatches  bool // Cache loaded batches temporarily
	RetryAttempts int  // Number of retry attempts for failed batches
}

// HotCacheLoadOptions provides options for loading the hot cache
type HotCacheLoadOptions struct {
	Size           int        `json:"size"`
	ForceRefresh   bool       `json:"force_refresh"`
	SessionFilter  string     `json:"session_filter"`
	HostnameFilter string     `json:"hostname_filter"`
	SinceTime      *time.Time `json:"since_time"`
}

// NewCache creates a new hybrid memory cache instance
func NewCache(cfg *config.CacheConfig, storage *securestorage.SecureStorage) *Cache {
	if cfg == nil {
		cfg = &config.CacheConfig{
			HotCacheSize:       1000,
			SearchBatchSize:    5000,
			MaxMemoryMB:        100,
			RefreshInterval:    300, // 5 minutes
			Compression:        true,
			EvictionThreshold:  0.8,  // 80% memory usage triggers eviction
			MaxCacheAgeHours:   24,   // 24 hours max age
			EvictionPercentage: 0.25, // Remove 25% of entries during eviction
		}
	}

	cache := &Cache{
		hotCache:          make([]*CacheEntry, 0, cfg.HotCacheSize),
		hotCacheSize:      cfg.HotCacheSize,
		searchBatchSize:   cfg.SearchBatchSize,
		maxMemoryMB:       cfg.MaxMemoryMB,
		refreshInterval:   time.Duration(cfg.RefreshInterval) * time.Second,
		storage:           storage,
		config:            cfg,
		logger:            logger.GetLogger().WithComponent("cache"),
		lastRefresh:       time.Now(),
		evictionPolicy:    EvictionLRU, // Default to LRU
		maxCacheAge:       time.Duration(cfg.MaxCacheAgeHours) * time.Hour,
		evictionThreshold: cfg.EvictionThreshold,
		lastMaintenance:   time.Now(),
		secureAllocations: make(map[uintptr]int),
		securityLevel:     1, // Enhanced security by default
		poisonPattern:     make([]byte, 32),
	}

	// Initialize secure memory handling
	cache.initializeSecureMemory()
	return cache
}

// LoadHotCache loads the most recent commands into the hot cache
func (c *Cache) LoadHotCache() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	start := time.Now()
	c.logger.Debug().
		Int("target_size", c.hotCacheSize).
		Msg("Loading hot cache")

	// Clear existing hot cache securely
	c.clearHotCacheUnsafe()

	// Load most recent records
	queryOpts := &securestorage.QueryOptions{
		Limit:     c.hotCacheSize,
		OrderBy:   "timestamp",
		Ascending: false, // Most recent first
	}

	result, err := c.storage.Retrieve(queryOpts)
	if err != nil {
		return fmt.Errorf("failed to load hot cache: %w", err)
	}

	// Store records in hot cache with metadata
	c.hotCache = make([]*CacheEntry, len(result.Records))
	now := time.Now()
	for i, record := range result.Records {
		c.hotCache[i] = &CacheEntry{
			Record:      record,
			AccessTime:  now,
			AccessCount: 0,
			InsertTime:  now,
			Size:        c.estimateRecordSize(record),
		}
	}
	c.lastRefresh = now

	// Update memory usage
	c.updateMemoryUsage()

	duration := time.Since(start)
	c.logger.Info().
		Int("loaded_count", len(c.hotCache)).
		Int64("memory_mb", c.currentMemoryMB).
		Dur("duration", duration).
		Msg("Hot cache loaded successfully")

	return nil
}

// Search performs a search operation using hot cache and batch loading
func (c *Cache) Search(query string, opts *BatchLoadOptions) (*SearchResult, error) {
	start := time.Now()

	if opts == nil {
		opts = &BatchLoadOptions{
			MaxBatches: 10,
			MaxResults: 50,
		}
	}

	c.logger.Debug().
		Str("query", query).
		Int("max_batches", opts.MaxBatches).
		Int("max_results", opts.MaxResults).
		Msg("Starting search operation")

	result := &SearchResult{
		Records: make([]*storage.CommandRecord, 0),
	}

	// First, search the hot cache
	if !opts.SkipHotCache {
		cacheResults := c.searchHotCache(query, opts.QueryFilter)
		result.Records = append(result.Records, cacheResults...)
		result.FromCache = len(cacheResults)
		c.totalCacheHits += int64(len(cacheResults))
	}

	// If we have enough results, return early
	if len(result.Records) >= opts.MaxResults {
		result.Records = result.Records[:opts.MaxResults]
		result.TotalMatches = len(result.Records)
		result.SearchTime = time.Since(start)
		return result, nil
	}

	// Load additional batches if needed
	if opts.MaxBatches > 0 {
		batchResults, err := c.loadSearchBatches(query, opts, len(result.Records))
		if err != nil {
			c.logger.Warn().Err(err).Msg("Failed to load search batches")
		} else {
			result.Records = append(result.Records, batchResults...)
			result.FromBatches = len(batchResults)
			c.totalCacheMiss += int64(len(batchResults))
		}
	}

	// Limit final results
	if len(result.Records) > opts.MaxResults {
		result.Records = result.Records[:opts.MaxResults]
	}

	result.TotalMatches = len(result.Records)
	result.SearchTime = time.Since(start)

	// Cache search state
	c.lastSearchQuery = query
	c.lastSearchTime = time.Now()

	c.logger.Debug().
		Int("total_matches", result.TotalMatches).
		Int("from_cache", result.FromCache).
		Int("from_batches", result.FromBatches).
		Dur("search_time", result.SearchTime).
		Msg("Search completed")

	return result, nil
}

// LoadHotCacheWithOptions loads the hot cache with specific options
func (c *Cache) LoadHotCacheWithOptions(opts *HotCacheLoadOptions) error {
	if opts == nil {
		return c.LoadHotCache()
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	start := time.Now()
	c.logger.Debug().
		Int("target_size", opts.Size).
		Bool("force_refresh", opts.ForceRefresh).
		Msg("Loading hot cache with options")

	// Check if refresh is needed
	if !opts.ForceRefresh && c.isHotCacheValidUnsafe() {
		c.logger.Debug().Msg("Hot cache is still valid, skipping refresh")
		return nil
	}

	// Clear existing hot cache securely
	c.clearHotCacheUnsafe()

	// Determine cache size
	cacheSize := c.hotCacheSize
	if opts.Size > 0 {
		cacheSize = opts.Size
	}

	// Build query options
	queryOpts := &securestorage.QueryOptions{
		Limit:     cacheSize,
		OrderBy:   "timestamp",
		Ascending: false, // Most recent first
	}

	// Apply filters if provided
	if opts.SessionFilter != "" {
		queryOpts.SessionID = opts.SessionFilter
	}
	if opts.HostnameFilter != "" {
		queryOpts.Hostname = opts.HostnameFilter
	}
	if opts.SinceTime != nil {
		queryOpts.Since = opts.SinceTime
	}

	result, err := c.storage.Retrieve(queryOpts)
	if err != nil {
		return fmt.Errorf("failed to load hot cache with options: %w", err)
	}

	// Store records in hot cache
	c.hotCache = make([]*CacheEntry, len(result.Records))
	now := time.Now()
	for i, record := range result.Records {
		c.hotCache[i] = &CacheEntry{
			Record:      record,
			AccessTime:  now,
			AccessCount: 0,
			InsertTime:  now,
			Size:        c.estimateRecordSize(record),
		}
	}
	c.lastRefresh = now

	// Update memory usage
	c.updateMemoryUsage()

	duration := time.Since(start)
	c.logger.Info().
		Int("loaded_count", len(c.hotCache)).
		Int64("memory_mb", c.currentMemoryMB).
		Dur("duration", duration).
		Bool("filtered", opts.SessionFilter != "" || opts.HostnameFilter != "").
		Msg("Hot cache loaded with options")

	return nil
}

// StartBackgroundRefresh starts automatic cache refresh
func (c *Cache) StartBackgroundRefresh() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.refreshActive {
		c.logger.Debug().Msg("Background refresh already active")
		return
	}

	c.refreshTicker = time.NewTicker(c.refreshInterval)
	c.stopRefresh = make(chan bool, 1)
	c.refreshActive = true

	go func() {
		c.logger.Info().
			Dur("interval", c.refreshInterval).
			Msg("Started background cache refresh")

		for {
			select {
			case <-c.refreshTicker.C:
				if err := c.LoadHotCache(); err != nil {
					c.logger.Error().Err(err).Msg("Background cache refresh failed")
				}
			case <-c.stopRefresh:
				c.logger.Info().Msg("Stopping background cache refresh")
				return
			}
		}
	}()
}

// StopBackgroundRefresh stops automatic cache refresh
func (c *Cache) StopBackgroundRefresh() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.refreshActive {
		return
	}

	if c.refreshTicker != nil {
		c.refreshTicker.Stop()
		c.refreshTicker = nil
	}

	if c.stopRefresh != nil {
		close(c.stopRefresh)
		c.stopRefresh = nil
	}

	c.refreshActive = false
	c.logger.Debug().Msg("Background refresh stopped")
}

// IsHotCacheValid checks if the hot cache is still valid
func (c *Cache) IsHotCacheValid() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isHotCacheValidUnsafe()
}

// isHotCacheValidUnsafe checks cache validity without locking
func (c *Cache) isHotCacheValidUnsafe() bool {
	if len(c.hotCache) == 0 {
		return false
	}
	return time.Since(c.lastRefresh) < c.refreshInterval
}

// GetHotCacheAge returns how long since the hot cache was last refreshed
func (c *Cache) GetHotCacheAge() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return time.Since(c.lastRefresh)
}

// WarmUpCache preloads the cache for better performance
func (c *Cache) WarmUpCache() error {
	c.logger.Info().Msg("Warming up cache")

	// Load hot cache
	if err := c.LoadHotCache(); err != nil {
		return fmt.Errorf("failed to warm up hot cache: %w", err)
	}

	// Start background refresh
	c.StartBackgroundRefresh()

	c.logger.Info().
		Int("hot_cache_size", len(c.hotCache)).
		Msg("Cache warmed up successfully")

	return nil
}

// searchHotCache searches within the hot cache
func (c *Cache) searchHotCache(query string, queryFilter *securestorage.QueryOptions) []*storage.CommandRecord {
	c.mu.Lock() // Use write lock to update access times
	defer c.mu.Unlock()

	if len(c.hotCache) == 0 {
		return nil
	}

	query = strings.ToLower(query)
	matches := make([]*storage.CommandRecord, 0)
	now := time.Now()

	for _, entry := range c.hotCache {
		if c.matchesQuery(entry.Record, query, queryFilter) {
			// Update access metadata for LRU/LFU policies
			entry.AccessTime = now
			entry.AccessCount++
			matches = append(matches, entry.Record)
		}
	}

	return matches
}

// loadSearchBatches loads additional command batches for search
func (c *Cache) loadSearchBatches(query string, opts *BatchLoadOptions, skipCount int) ([]*storage.CommandRecord, error) {
	if opts.ParallelLoad && opts.MaxBatches > 1 {
		return c.loadSearchBatchesParallel(query, opts, skipCount)
	}
	return c.loadSearchBatchesSequential(query, opts, skipCount)
}

// loadSearchBatchesSequential loads batches one by one
func (c *Cache) loadSearchBatchesSequential(query string, opts *BatchLoadOptions, skipCount int) ([]*storage.CommandRecord, error) {
	results := make([]*storage.CommandRecord, 0)
	batchSize := c.searchBatchSize
	if opts.BatchSize > 0 {
		batchSize = opts.BatchSize
	}

	for batchNum := 0; batchNum < opts.MaxBatches; batchNum++ {
		batch, err := c.loadSingleBatch(query, batchNum, batchSize, skipCount, opts)
		if err != nil {
			c.logger.Warn().Err(err).Int("batch_num", batchNum).Msg("Failed to load batch")
			continue
		}

		if len(batch) == 0 {
			break // No more records
		}

		results = append(results, batch...)

		// Stop if we have enough results
		if len(results) >= opts.MaxResults {
			break
		}
	}

	return results, nil
}

// loadSearchBatchesParallel loads batches in parallel for better performance
func (c *Cache) loadSearchBatchesParallel(query string, opts *BatchLoadOptions, skipCount int) ([]*storage.CommandRecord, error) {
	type batchResult struct {
		records  []*storage.CommandRecord
		batchNum int
		err      error
	}

	batchSize := c.searchBatchSize
	if opts.BatchSize > 0 {
		batchSize = opts.BatchSize
	}

	resultChan := make(chan batchResult, opts.MaxBatches)
	semaphore := make(chan struct{}, 3) // Limit concurrent batch loads to 3

	// Start batch loading goroutines
	for batchNum := 0; batchNum < opts.MaxBatches; batchNum++ {
		go func(bNum int) {
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			batch, err := c.loadSingleBatch(query, bNum, batchSize, skipCount, opts)
			resultChan <- batchResult{
				records:  batch,
				batchNum: bNum,
				err:      err,
			}
		}(batchNum)
	}

	// Collect results in order
	batchResults := make(map[int][]*storage.CommandRecord)
	var lastError error

	for i := 0; i < opts.MaxBatches; i++ {
		result := <-resultChan
		if result.err != nil {
			c.logger.Warn().Err(result.err).Int("batch_num", result.batchNum).Msg("Parallel batch load failed")
			lastError = result.err
			continue
		}

		if len(result.records) == 0 {
			break
		}

		batchResults[result.batchNum] = result.records
	}

	// Combine results in order
	var finalResults []*storage.CommandRecord
	for batchNum := 0; batchNum < opts.MaxBatches; batchNum++ {
		if batch, exists := batchResults[batchNum]; exists {
			finalResults = append(finalResults, batch...)
			if len(finalResults) >= opts.MaxResults {
				break
			}
		}
	}

	return finalResults, lastError
}

// loadSingleBatch loads a single batch with retry logic
func (c *Cache) loadSingleBatch(query string, batchNum, batchSize, skipCount int, opts *BatchLoadOptions) ([]*storage.CommandRecord, error) {
	maxRetries := 3
	if opts.RetryAttempts > 0 {
		maxRetries = opts.RetryAttempts
	}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		offset := c.hotCacheSize + (batchNum * batchSize) + skipCount

		queryOpts := &securestorage.QueryOptions{
			Limit:     batchSize,
			Offset:    offset,
			OrderBy:   "timestamp",
			Ascending: false,
		}

		// Apply additional query filters if provided
		if opts.QueryFilter != nil {
			if opts.QueryFilter.SessionID != "" {
				queryOpts.SessionID = opts.QueryFilter.SessionID
			}
			if opts.QueryFilter.Hostname != "" {
				queryOpts.Hostname = opts.QueryFilter.Hostname
			}
			if opts.QueryFilter.Since != nil {
				queryOpts.Since = opts.QueryFilter.Since
			}
			if opts.QueryFilter.Until != nil {
				queryOpts.Until = opts.QueryFilter.Until
			}
		}

		batch, err := c.storage.Retrieve(queryOpts)
		if err != nil {
			lastErr = err
			if attempt < maxRetries-1 {
				time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond) // Exponential backoff
				continue
			}
			return nil, fmt.Errorf("failed to load batch %d after %d attempts: %w", batchNum, maxRetries, err)
		}

		if len(batch.Records) == 0 {
			return nil, nil // No more records
		}

		// Search within this batch
		batchMatches := make([]*storage.CommandRecord, 0)
		for _, record := range batch.Records {
			if c.matchesQuery(record, strings.ToLower(query), opts.QueryFilter) {
				batchMatches = append(batchMatches, record)
			}
		}

		c.totalBatches++

		// Clear the batch from memory (secure) if not caching
		if !opts.CacheBatches {
			c.secureClearBatch(batch.Records, batchMatches)
		}

		return batchMatches, nil
	}

	return nil, lastErr
}

// matchesQuery checks if a command record matches the search query
func (c *Cache) matchesQuery(record *storage.CommandRecord, query string, queryFilter *securestorage.QueryOptions) bool {
	// Check time constraints first (most selective)
	if queryFilter != nil {
		recordTime := time.UnixMilli(record.Timestamp)
		
		if queryFilter.Since != nil && recordTime.Before(*queryFilter.Since) {
			return false
		}
		
		if queryFilter.Until != nil && recordTime.After(*queryFilter.Until) {
			return false
		}
		
		// Check other filters
		if queryFilter.SessionID != "" && record.SessionID != queryFilter.SessionID {
			return false
		}
		
		if queryFilter.Hostname != "" && record.Hostname != queryFilter.Hostname {
			return false
		}
		
		if queryFilter.WorkingDir != "" && record.WorkingDir != queryFilter.WorkingDir {
			return false
		}
	}

	// If no text query, return true (time/filter constraints already checked)
	if query == "" {
		return true
	}

	// Search in command text
	if strings.Contains(strings.ToLower(record.Command), query) {
		return true
	}

	// Search in working directory
	if strings.Contains(strings.ToLower(record.WorkingDir), query) {
		return true
	}

	// Search in git branch
	if strings.Contains(strings.ToLower(record.GitBranch), query) {
		return true
	}

	return false
}

// RefreshIfNeeded refreshes the hot cache if the refresh interval has passed
func (c *Cache) RefreshIfNeeded() error {
	c.mu.RLock()
	needsRefresh := time.Since(c.lastRefresh) > c.refreshInterval
	c.mu.RUnlock()

	if needsRefresh {
		return c.LoadHotCache()
	}

	return nil
}

// EvictOldEntries removes entries based on the configured eviction policy
func (c *Cache) EvictOldEntries() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if eviction is needed
	memoryThreshold := float64(c.maxMemoryMB) * c.evictionThreshold
	if float64(c.currentMemoryMB) <= memoryThreshold {
		return
	}

	// Calculate how many entries to evict based on config
	targetSize := int(float64(len(c.hotCache)) * (1.0 - c.config.EvictionPercentage))
	if targetSize >= len(c.hotCache) {
		return
	}

	// Sort entries based on eviction policy
	c.sortEntriesForEviction()

	// Evict entries
	evicted := c.hotCache[targetSize:]
	for _, entry := range evicted {
		c.secureClearRecord(entry.Record)
	}

	c.hotCache = c.hotCache[:targetSize]
	c.updateMemoryUsage()

	c.logger.Debug().
		Int("evicted_count", len(evicted)).
		Int64("new_memory_mb", c.currentMemoryMB).
		Str("policy", c.getEvictionPolicyName()).
		Msg("Evicted cache entries")
}

// Clear removes all entries from the cache securely
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.clearHotCacheUnsafe()
	c.currentMemoryMB = 0
	c.lastRefresh = time.Now()

	c.logger.Debug().Msg("Cache cleared")
}

// GetStats returns cache performance statistics
func (c *Cache) GetStats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalOperations := c.totalCacheHits + c.totalCacheMiss
	hitRatio := 0.0
	if totalOperations > 0 {
		hitRatio = float64(c.totalCacheHits) / float64(totalOperations)
	}

	return &CacheStats{
		HotCacheSize:    len(c.hotCache),
		CurrentMemoryMB: c.currentMemoryMB,
		CacheHits:       c.totalCacheHits,
		CacheMisses:     c.totalCacheMiss,
		BatchesLoaded:   c.totalBatches,
		LastRefresh:     c.lastRefresh,
		RefreshInterval: c.refreshInterval,
		HitRatio:        hitRatio,
	}
}

// updateMemoryUsage estimates current memory usage
func (c *Cache) updateMemoryUsage() {
	memoryBytes := int64(0)

	for _, entry := range c.hotCache {
		memoryBytes += entry.Size
	}

	c.currentMemoryMB = memoryBytes / (1024 * 1024)
}

// estimateRecordSize estimates the memory size of a command record
func (c *Cache) estimateRecordSize(record *storage.CommandRecord) int64 {
	size := int64(unsafe.Sizeof(*record))
	size += int64(len(record.Command))
	size += int64(len(record.WorkingDir))
	size += int64(len(record.SessionID))
	size += int64(len(record.Hostname))
	size += int64(len(record.GitRoot))
	size += int64(len(record.GitBranch))
	size += int64(len(record.GitCommit))
	size += int64(len(record.User))
	size += int64(len(record.Shell))
	size += int64(len(record.TTY))

	// Estimate environment map size
	for k, v := range record.Environment {
		size += int64(len(k) + len(v) + 16) // 16 bytes overhead per map entry
	}

	return size
}

// clearHotCacheUnsafe clears the hot cache without locking (caller must hold lock)
func (c *Cache) clearHotCacheUnsafe() {
	for _, entry := range c.hotCache {
		c.secureClearRecord(entry.Record)
	}
	c.hotCache = c.hotCache[:0]
}

// secureClearRecord securely clears sensitive data from a command record
func (c *Cache) secureClearRecord(record *storage.CommandRecord) {
	if record == nil {
		return
	}

	// Clear string fields by overwriting with zeros
	c.secureClearString(&record.Command)
	c.secureClearString(&record.WorkingDir)
	c.secureClearString(&record.SessionID)
	c.secureClearString(&record.Hostname)
	c.secureClearString(&record.GitRoot)
	c.secureClearString(&record.GitBranch)
	c.secureClearString(&record.GitCommit)
	c.secureClearString(&record.User)
	c.secureClearString(&record.Shell)
	c.secureClearString(&record.TTY)

	// Clear environment map
	for k, v := range record.Environment {
		c.secureClearString(&k)
		c.secureClearString(&v)
		delete(record.Environment, k)
	}
	record.Environment = nil

	// Clear numeric fields
	record.ExitCode = 0
	record.Duration = 0
	record.Timestamp = 0
	record.Version = 0
	record.CreatedAt = 0
}

// secureClearString securely clears a string reference
func (c *Cache) secureClearString(s *string) {
	if s == nil {
		return
	}
	// Simply clear the string reference - Go strings are immutable
	// and attempting to overwrite backing memory is unsafe
	*s = ""
}

// secureClearBatch securely clears a batch of records except for the results we want to keep
func (c *Cache) secureClearBatch(batch []*storage.CommandRecord, keep []*storage.CommandRecord) {
	keepSet := make(map[*storage.CommandRecord]bool)
	for _, record := range keep {
		keepSet[record] = true
	}

	for _, record := range batch {
		if !keepSet[record] {
			c.secureClearRecord(record)
		}
	}

	// Force garbage collection to reclaim memory
	runtime.GC()
}

// StartCacheMaintenance starts automatic cache maintenance
func (c *Cache) StartCacheMaintenance() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.maintenanceActive {
		c.logger.Debug().Msg("Cache maintenance already active")
		return
	}

	maintenanceInterval := c.refreshInterval / 4 // Run maintenance 4x more frequently than refresh
	c.maintenanceTicker = time.NewTicker(maintenanceInterval)
	c.stopMaintenance = make(chan bool, 1)
	c.maintenanceActive = true

	go func() {
		c.logger.Info().
			Dur("interval", maintenanceInterval).
			Msg("Started cache maintenance")

		for {
			select {
			case <-c.maintenanceTicker.C:
				c.performMaintenance()
			case <-c.stopMaintenance:
				c.logger.Info().Msg("Stopping cache maintenance")
				return
			}
		}
	}()
}

// StopCacheMaintenance stops automatic cache maintenance
func (c *Cache) StopCacheMaintenance() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.maintenanceActive {
		return
	}

	if c.maintenanceTicker != nil {
		c.maintenanceTicker.Stop()
		c.maintenanceTicker = nil
	}

	if c.stopMaintenance != nil {
		close(c.stopMaintenance)
		c.stopMaintenance = nil
	}

	c.maintenanceActive = false
	c.logger.Debug().Msg("Cache maintenance stopped")
}

// performMaintenance runs cache maintenance tasks
func (c *Cache) performMaintenance() {
	start := time.Now()

	// Check if eviction is needed
	c.EvictOldEntries()

	// Clean up expired entries
	c.cleanupExpiredEntries()

	// Update cache statistics
	c.updateCacheHealth()

	c.lastMaintenance = time.Now()

	c.logger.Debug().
		Dur("maintenance_duration", time.Since(start)).
		Msg("Cache maintenance completed")
}

// cleanupExpiredEntries removes entries that have exceeded their TTL
func (c *Cache) cleanupExpiredEntries() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.hotCache) == 0 {
		return
	}

	now := time.Now()
	var validEntries []*CacheEntry
	var expiredCount int

	for _, entry := range c.hotCache {
		if now.Sub(entry.InsertTime) <= c.maxCacheAge {
			validEntries = append(validEntries, entry)
		} else {
			c.secureClearRecord(entry.Record)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		c.hotCache = validEntries
		c.updateMemoryUsage()

		c.logger.Debug().
			Int("expired_count", expiredCount).
			Msg("Cleaned up expired cache entries")
	}
}

// updateCacheHealth updates cache health metrics
func (c *Cache) updateCacheHealth() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	totalOperations := c.totalCacheHits + c.totalCacheMiss
	if totalOperations > 0 {
		hitRatio := float64(c.totalCacheHits) / float64(totalOperations)

		if hitRatio < 0.5 {
			c.logger.Warn().
				Float64("hit_ratio", hitRatio).
				Msg("Cache hit ratio is low")
		}
	}

	memoryUsage := float64(c.currentMemoryMB) / float64(c.maxMemoryMB)
	if memoryUsage > 0.9 {
		c.logger.Warn().
			Float64("memory_usage", memoryUsage).
			Msg("Cache memory usage is high")
	}
}

// SetEvictionPolicy changes the cache eviction policy
func (c *Cache) SetEvictionPolicy(policy EvictionPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.evictionPolicy = policy
	c.logger.Info().
		Str("policy", c.getEvictionPolicyName()).
		Msg("Cache eviction policy updated")
}

// SetMaxCacheAge sets the maximum age for cache entries
func (c *Cache) SetMaxCacheAge(maxAge time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.maxCacheAge = maxAge
	c.logger.Info().
		Dur("max_age", maxAge).
		Msg("Cache max age updated")
}

// initializeSecureMemory sets up secure memory handling
func (c *Cache) initializeSecureMemory() {
	// Generate random poison pattern for memory clearing
	if _, err := rand.Read(c.poisonPattern); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to generate poison pattern, using zeros")
		for i := range c.poisonPattern {
			c.poisonPattern[i] = 0
		}
	}

	// Check if mlock is supported
	c.mlockSupported = c.checkMlockSupport()

	// Set security level based on configuration
	if c.config.Compression {
		c.securityLevel = 2 // Higher security for compressed data
	}

	c.logger.Info().
		Bool("mlock_supported", c.mlockSupported).
		Int("security_level", c.securityLevel).
		Msg("Secure memory handling initialized")
}

// checkMlockSupport tests if memory locking is available
func (c *Cache) checkMlockSupport() bool {
	// Test with a small allocation
	testData := make([]byte, 4096)
	err := syscall.Mlock(testData)
	if err == nil {
		syscall.Munlock(testData)
		return true
	}

	c.logger.Debug().Err(err).Msg("Memory locking not available")
	return false
}

// multiPassClear performs multiple-pass memory clearing
func (c *Cache) multiPassClear(data []byte) {
	if len(data) == 0 {
		return
	}

	// Pass 1: Write zeros
	for i := range data {
		data[i] = 0
	}

	// Pass 2: Write ones
	for i := range data {
		data[i] = 0xFF
	}

	// Pass 3: Write random pattern
	patternLen := len(c.poisonPattern)
	for i := range data {
		data[i] = c.poisonPattern[i%patternLen]
	}

	// Pass 4: Final zeros
	for i := range data {
		data[i] = 0
	}

	// Force memory barrier
	runtime.KeepAlive(data)
}

// dodStandardClear implements DoD 5220.22-M standard for memory clearing
func (c *Cache) dodStandardClear(data []byte) {
	if len(data) == 0 {
		return
	}

	// Pass 1: Write character (0x35)
	for i := range data {
		data[i] = 0x35
	}
	runtime.KeepAlive(data)

	// Pass 2: Write complement of pass 1 (0xCA)
	for i := range data {
		data[i] = 0xCA
	}
	runtime.KeepAlive(data)

	// Pass 3: Write random data
	randData := make([]byte, len(data))
	if _, err := rand.Read(randData); err == nil {
		copy(data, randData)
	} else {
		// Fallback to poison pattern
		patternLen := len(c.poisonPattern)
		for i := range data {
			data[i] = c.poisonPattern[i%patternLen]
		}
	}
	runtime.KeepAlive(data)

	// Clear random data securely
	c.multiPassClear(randData)
}

// cleanupSecureMemory cleans up all secure memory allocations
func (c *Cache) cleanupSecureMemory() {
	if !c.memoryLocked {
		return
	}

	// Unlock all tracked allocations
	for addr, size := range c.secureAllocations {
		data := (*[1 << 30]byte)(unsafe.Pointer(addr))[:size:size]
		syscall.Munlock(data)
	}

	c.secureAllocations = make(map[uintptr]int)
	c.memoryLocked = false

	c.logger.Debug().Msg("Secure memory cleanup completed")
}

// SetSecurityLevel configures the memory security level
func (c *Cache) SetSecurityLevel(level int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if level < 0 || level > 2 {
		c.logger.Warn().Int("level", level).Msg("Invalid security level, using default")
		level = 1
	}

	c.securityLevel = level
	c.logger.Info().Int("level", level).Msg("Security level updated")
}

// GetSecurityInfo returns information about secure memory handling
func (c *Cache) GetSecurityInfo() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return map[string]interface{}{
		"memory_locked":      c.memoryLocked,
		"mlock_supported":    c.mlockSupported,
		"security_level":     c.securityLevel,
		"secure_allocations": len(c.secureAllocations),
		"poison_pattern_len": len(c.poisonPattern),
	}
}

// sortEntriesForEviction sorts cache entries based on the eviction policy
func (c *Cache) sortEntriesForEviction() {
	switch c.evictionPolicy {
	case EvictionLRU:
		// Sort by access time (least recently used first)
		sort.Slice(c.hotCache, func(i, j int) bool {
			return c.hotCache[i].AccessTime.Before(c.hotCache[j].AccessTime)
		})
	case EvictionLFU:
		// Sort by access count (least frequently used first)
		sort.Slice(c.hotCache, func(i, j int) bool {
			return c.hotCache[i].AccessCount < c.hotCache[j].AccessCount
		})
	case EvictionTTL:
		// Sort by insert time (oldest first)
		sort.Slice(c.hotCache, func(i, j int) bool {
			return c.hotCache[i].InsertTime.Before(c.hotCache[j].InsertTime)
		})
	case EvictionSize:
		// Sort by size (largest first)
		sort.Slice(c.hotCache, func(i, j int) bool {
			return c.hotCache[i].Size > c.hotCache[j].Size
		})
	}
}

// getEvictionPolicyName returns a string representation of the eviction policy
func (c *Cache) getEvictionPolicyName() string {
	switch c.evictionPolicy {
	case EvictionLRU:
		return "LRU"
	case EvictionLFU:
		return "LFU"
	case EvictionTTL:
		return "TTL"
	case EvictionSize:
		return "SIZE"
	default:
		return "UNKNOWN"
	}
}

// Close safely shuts down the cache
func (c *Cache) Close() error {
	c.logger.Debug().Msg("Closing cache")

	// Stop background refresh
	c.StopBackgroundRefresh()

	// Stop cache maintenance
	c.StopCacheMaintenance()

	// Clear cache securely
	c.Clear()

	// Clean up secure memory
	c.cleanupSecureMemory()

	c.logger.Info().Msg("Cache closed successfully")
	return nil
}
