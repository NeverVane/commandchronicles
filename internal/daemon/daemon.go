package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/NeverVane/commandchronicles/internal/auth"
	"github.com/NeverVane/commandchronicles/internal/cache"
	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"

	// "github.com/NeverVane/commandchronicles/internal/search" // COMMENTED: Removed to eliminate race conditions with TUI fuzzy search
	"github.com/NeverVane/commandchronicles/internal/sync"
	securestorage "github.com/NeverVane/commandchronicles/pkg/storage"
)

// Daemon represents the sync daemon process
type Daemon struct {
	config      *config.Config
	syncService *sync.SyncService
	// searchService *search.SearchService // COMMENTED: Daemon no longer manages fuzzy search to avoid conflicts with TUI
	cache       *cache.Cache
	logger      *logger.Logger
	pidManager  *PIDManager
	authManager *auth.AuthManager
	storage     *securestorage.SecureStorage
	ctx         context.Context
	cancel      context.CancelFunc

	// Runtime state
	isRunning    bool
	lastSyncTime time.Time
	syncCount    int64
	errorCount   int64
}

// NewDaemon creates a new daemon instance
func NewDaemon(cfg *config.Config) (*Daemon, error) {
	logger := logger.GetLogger().WithComponent("daemon")

	// Create auth manager
	authMgr, err := auth.NewAuthManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create auth manager: %w", err)
	}

	// Create secure storage
	storage, err := securestorage.NewSecureStorage(&securestorage.StorageOptions{
		Config:              cfg,
		CreateIfMissing:     false,
		ValidatePermissions: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secure storage: %w", err)
	}

	// Create cache
	hybridCache := cache.NewCache(&cfg.Cache, storage)

	// COMMENTED: Create search service - Removed to eliminate race conditions with TUI
	// The daemon doesn't need fuzzy search functionality. It only needs storage for sync operations.
	// TUI will exclusively manage the fuzzy search index to prevent concurrent access issues.
	// searchService := search.NewSearchService(hybridCache, storage, cfg)

	// Create sync service
	syncService := sync.NewSyncService(cfg, storage, authMgr)

	// Create PID manager
	pidManager := NewPIDManager(cfg.Daemon.PIDFile)

	ctx, cancel := context.WithCancel(context.Background())

	return &Daemon{
		config:      cfg,
		syncService: syncService,
		// searchService: searchService, // COMMENTED: No longer needed in daemon
		cache:       hybridCache,
		logger:      logger,
		pidManager:  pidManager,
		authManager: authMgr,
		storage:     storage,
		ctx:         ctx,
		cancel:      cancel,
		isRunning:   false,
	}, nil
}

// Start starts the daemon process
func (d *Daemon) Start() error {
	d.logger.Info().Msg("Starting CommandChronicles sync daemon")

	// Validate and cleanup any stale PID files
	if err := d.pidManager.ValidatePIDFile(); err != nil {
		d.logger.WithError(err).Warn().Msg("Cleaned up stale PID file")
	}

	// Check if already running
	if d.pidManager.IsRunning() {
		existingPID, _ := d.pidManager.ReadPID()
		return fmt.Errorf("daemon already running with PID %d", existingPID)
	}

	// Write PID file
	if err := d.pidManager.WritePID(); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Ensure PID file cleanup on exit
	defer func() {
		if err := d.pidManager.RemovePID(); err != nil {
			d.logger.WithError(err).Error().Msg("Failed to remove PID file")
		}
	}()

	// COMMENTED: Initialize search service - Removed to eliminate race conditions
	//
	// WHY REMOVED: The daemon was competing with TUI for the same fuzzy search index,
	// causing file locking conflicts and index corruption. The daemon only needs to:
	// 1. Sync data to/from remote server
	// 2. Store records in secure storage
	//
	// The TUI exclusively manages fuzzy search indexing and gets exclusive access
	// to the search_index folder. This eliminates race conditions and allows
	// the TUI status to properly transition from [Indexing...] to ready.
	//
	// fuzzyIndexPath := filepath.Join(d.config.DataDir, "search_index")
	// searchOpts := &search.SearchOptions{
	//     EnableCache:       true,
	//     EnableFuzzySearch: true,
	//     WarmupCache:       false, // Skip cache warmup in daemon to save resources
	//     DefaultLimit:      50,
	//     DefaultTimeout:    30 * time.Second,
	//     FuzzyIndexPath:    fuzzyIndexPath,
	//     RebuildFuzzyIndex: false, // Don't rebuild on startup, let staleness check handle it
	// }
	//
	// if err := d.searchService.Initialize(searchOpts); err != nil {
	//     d.logger.WithError(err).Warn().Msg("Failed to initialize search service in daemon")
	//     // Don't fail daemon startup if search service fails
	// } else {
	//     d.logger.Debug().Msg("Search service initialized in daemon")
	// }

	// Setup signal handling
	d.setupSignalHandling()

	// Mark as running
	d.isRunning = true

	d.logger.WithFields(map[string]interface{}{
		"pid_file":      d.pidManager.GetPIDFile(),
		"pid":           os.Getpid(),
		"sync_interval": d.config.Daemon.SyncInterval,
	}).Info().Msg("Daemon started successfully")

	// Start sync loop
	return d.runSyncLoop()
}

// Stop gracefully stops the daemon
func (d *Daemon) Stop() error {
	d.logger.Info().Msg("Stopping sync daemon")

	d.isRunning = false
	d.cancel()

	// Close services
	if d.syncService != nil {
		d.syncService.Close()
	}

	// COMMENTED: Search service no longer used in daemon
	// if d.searchService != nil {
	//     d.searchService.Close()
	// }

	if d.cache != nil {
		d.cache.Close()
	}

	if d.storage != nil {
		d.storage.Close()
	}

	if d.authManager != nil {
		d.authManager.Close()
	}

	d.logger.WithFields(map[string]interface{}{
		"total_syncs":  d.syncCount,
		"total_errors": d.errorCount,
	}).Info().Msg("Daemon stopped")

	return nil
}

// runSyncLoop runs the main sync scheduling loop
func (d *Daemon) runSyncLoop() error {
	ticker := time.NewTicker(d.config.Daemon.SyncInterval)
	defer ticker.Stop()

	d.logger.WithFields(map[string]interface{}{
		"interval":    d.config.Daemon.SyncInterval,
		"max_retries": d.config.Daemon.MaxRetries,
	}).Info().Msg("Sync loop started")

	// Perform initial sync after a short delay
	go func() {
		time.Sleep(10 * time.Second) // Give system time to settle
		d.performSync()
	}()

	for {
		select {
		case <-d.ctx.Done():
			d.logger.Info().Msg("Sync loop stopping due to context cancellation")
			return nil

		case <-ticker.C:
			if d.isRunning {
				d.performSync()
			}
		}
	}
}

// performSync executes a sync operation with retry logic
func (d *Daemon) performSync() {
	startTime := time.Now()
	d.logger.Debug().Msg("Starting scheduled sync")

	// Check if sync is enabled
	if !d.config.Sync.Enabled {
		d.logger.Debug().Msg("Sync disabled, skipping")
		return
	}

	// Check if we have valid authentication
	if !d.authManager.IsSessionActive() {
		d.logger.Debug().Msg("No active session, skipping sync")
		return
	}

	// Unlock storage if needed
	sessionKey, err := d.authManager.LoadSessionKey()
	if err != nil {
		d.logger.WithError(err).Debug().Msg("Failed to get session key, skipping sync")
		return
	}

	if err := d.storage.UnlockWithKey(sessionKey); err != nil {
		d.logger.WithError(err).Debug().Msg("Failed to unlock storage, skipping sync")
		return
	}

	// Perform sync with retries
	var lastErr error
	for attempt := 0; attempt < d.config.Daemon.MaxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff for retries
			backoffDuration := time.Duration(attempt*attempt) * d.config.Daemon.RetryInterval
			d.logger.WithFields(map[string]interface{}{
				"attempt": attempt + 1,
				"backoff": backoffDuration,
			}).Debug().Msg("Retrying sync after backoff")

			select {
			case <-time.After(backoffDuration):
			case <-d.ctx.Done():
				return
			}
		}

		// Attempt sync
		if err := d.syncService.SyncNow(); err != nil {
			lastErr = err
			d.logger.WithError(err).WithFields(map[string]interface{}{
				"attempt":     attempt + 1,
				"max_retries": d.config.Daemon.MaxRetries,
			}).Warn().Msg("Sync attempt failed")

			// Check if we should continue retrying
			if d.isRetryableError(err) && attempt < d.config.Daemon.MaxRetries-1 {
				continue
			}

			// Max retries reached or non-retryable error
			break
		}

		// Success
		d.syncCount++
		d.lastSyncTime = time.Now()
		duration := time.Since(startTime)

		d.logger.WithFields(map[string]interface{}{
			"duration":   duration,
			"sync_count": d.syncCount,
		}).Info().Msg("Sync completed successfully")

		// COMMENTED: Check and rebuild fuzzy search index - Moved to TUI responsibility
		//
		// WHY REMOVED: This was causing race conditions between daemon and TUI.
		// Now the TUI will detect when new data has been synced (by checking storage
		// timestamps) and rebuild its own fuzzy index as needed. This gives TUI
		// exclusive control over search indexing and eliminates concurrent access issues.
		//
		// d.logger.Debug().Msg("Checking fuzzy search index staleness after sync")
		// if err := d.searchService.CheckAndRebuildStaleIndex(); err != nil {
		//     d.logger.WithError(err).Warn().Msg("Failed to check/rebuild stale fuzzy index after sync")
		// }

		return
	}

	// All retries failed
	d.errorCount++
	d.logger.WithError(lastErr).WithFields(map[string]interface{}{
		"error_count": d.errorCount,
	}).Error().Msg("Sync failed after all retries")
}

// isRetryableError determines if an error is worth retrying
func (d *Daemon) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := err.Error()

	// Network-related errors are generally retryable
	retryablePatterns := []string{
		"connection refused",
		"connection reset",
		"timeout",
		"temporary failure",
		"network is unreachable",
		"no route to host",
		"connection timed out",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	// Authentication errors are generally not retryable
	nonRetryablePatterns := []string{
		"unauthorized",
		"forbidden",
		"invalid credentials",
		"authentication failed",
	}

	for _, pattern := range nonRetryablePatterns {
		if contains(errStr, pattern) {
			return false
		}
	}

	// Default to retryable for unknown errors
	return true
}

// setupSignalHandling sets up signal handlers for graceful shutdown
func (d *Daemon) setupSignalHandling() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for {
			select {
			case sig := <-sigChan:
				d.logger.WithField("signal", sig.String()).Info().Msg("Received signal")

				switch sig {
				case syscall.SIGHUP:
					// Reload configuration
					d.reloadConfig()
				case syscall.SIGINT, syscall.SIGTERM:
					// Graceful shutdown
					d.logger.Info().Msg("Initiating graceful shutdown")
					d.Stop()
					os.Exit(0)
				}
			case <-d.ctx.Done():
				return
			}
		}
	}()
}

// reloadConfig reloads the daemon configuration
func (d *Daemon) reloadConfig() {
	d.logger.Info().Msg("Reloading daemon configuration")

	// Load new configuration
	newConfig, err := config.Load("")
	if err != nil {
		d.logger.WithError(err).Error().Msg("Failed to reload configuration")
		return
	}

	// Update configuration
	oldInterval := d.config.Daemon.SyncInterval
	d.config = newConfig

	if d.config.Daemon.SyncInterval != oldInterval {
		d.logger.WithFields(map[string]interface{}{
			"old_interval": oldInterval,
			"new_interval": d.config.Daemon.SyncInterval,
		}).Info().Msg("Sync interval updated")
	}

	d.logger.Info().Msg("Configuration reloaded successfully")
}

// GetStatus returns the current daemon status
func (d *Daemon) GetStatus() *DaemonStatus {
	pidStatus, _ := d.pidManager.GetStatus()

	return &DaemonStatus{
		Running:       d.isRunning,
		PID:           pidStatus.PID,
		Uptime:        pidStatus.Uptime,
		LastSync:      d.lastSyncTime,
		SyncCount:     d.syncCount,
		ErrorCount:    d.errorCount,
		SyncInterval:  d.config.Daemon.SyncInterval,
		AutoStart:     d.config.Daemon.AutoStart,
		SystemService: d.config.Daemon.SystemService,
	}
}

// DaemonStatus represents the current status of the daemon
type DaemonStatus struct {
	Running       bool          `json:"running"`
	PID           int           `json:"pid,omitempty"`
	Uptime        time.Duration `json:"uptime,omitempty"`
	LastSync      time.Time     `json:"last_sync,omitempty"`
	SyncCount     int64         `json:"sync_count"`
	ErrorCount    int64         `json:"error_count"`
	SyncInterval  time.Duration `json:"sync_interval"`
	AutoStart     bool          `json:"auto_start"`
	SystemService bool          `json:"system_service"`
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				indexOf(s, substr) >= 0))
}

// indexOf returns the index of substr in s, or -1 if not found
func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
