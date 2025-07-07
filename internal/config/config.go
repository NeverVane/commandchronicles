package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BurntSushi/toml"
)

// Hardcoded sync server URL for SaaS model
// const DefaultSyncServerURL = "https://sync.commandchronicles.dev"
const DefaultSyncServerURL = "https://api.commandchronicles.dev"

// Config represents the complete configuration for CommandChronicles CLI
type Config struct {
	// Database configuration
	Database DatabaseConfig `toml:"database"`

	// Cache configuration
	Cache CacheConfig `toml:"cache"`

	// Security configuration
	Security SecurityConfig `toml:"security"`

	// TUI configuration
	TUI TUIConfig `toml:"tui"`

	// Shell integration configuration
	Shell ShellConfig `toml:"shell"`

	// Import/Export configuration
	ImportExport ImportExportConfig `toml:"import_export"`

	// Sync configuration
	Sync SyncConfig `toml:"sync"`

	// Daemon configuration
	Daemon DaemonConfig `toml:"daemon"`

	// Sentry configuration
	Sentry SentryConfig `toml:"sentry"`

	// Output configuration
	Output OutputConfig `toml:"output"`

	// Deletion configuration
	Deletion DeletionConfig `toml:"deletion"`

	// Tags configuration
	Tags TagsConfig `toml:"tags"`

	// Directory paths (computed, not stored in TOML)
	DataDir   string `toml:"-"`
	ConfigDir string `toml:"-"`
}

// DatabaseConfig contains database-related settings
type DatabaseConfig struct {
	// Path to the SQLite database file
	Path string `toml:"path"`

	// Connection pool settings
	MaxOpenConns int `toml:"max_open_conns"`
	MaxIdleConns int `toml:"max_idle_conns"`

	// WAL mode settings
	WALMode bool `toml:"wal_mode"`

	// Synchronous mode (NORMAL, FULL)
	SyncMode string `toml:"sync_mode"`
}

// CacheConfig contains memory cache settings
type CacheConfig struct {
	// Number of recent commands always kept in RAM
	HotCacheSize int `toml:"hot_cache_size"`

	// Batch size for loading additional commands during search
	SearchBatchSize int `toml:"search_batch_size"`

	// Maximum memory usage in MB during search operations
	MaxMemoryMB int `toml:"max_memory_mb"`

	// Interval between cache refreshes in seconds
	RefreshInterval int `toml:"refresh_interval"`

	// Enable cache compression
	Compression bool `toml:"compression"`

	// Percentage of max memory to trigger eviction (0.0 to 1.0)
	EvictionThreshold float64 `toml:"eviction_threshold"`

	// Maximum age for cache entries in hours
	MaxCacheAgeHours int `toml:"max_cache_age_hours"`

	// Percentage of entries to remove during eviction (0.0 to 1.0)
	EvictionPercentage float64 `toml:"eviction_percentage"`
}

// SecurityConfig contains security-related settings
type SecurityConfig struct {
	// Session key file path
	SessionKeyPath string `toml:"session_key_path"`

	// Session timeout in seconds (default: 3 months)
	SessionTimeout int `toml:"session_timeout"`

	// Argon2id parameters
	Argon2Time    uint32 `toml:"argon2_time"`
	Argon2Memory  uint32 `toml:"argon2_memory"`
	Argon2Threads uint8  `toml:"argon2_threads"`

	// Auto-lock on inactivity (seconds, 0 = disabled)
	AutoLockTimeout int `toml:"auto_lock_timeout"`

	// Secure memory clearing
	SecureMemoryClear bool `toml:"secure_memory_clear"`
}

// TUIConfig contains TUI interface settings
type TUIConfig struct {
	// Launch performance target in milliseconds
	LaunchTimeoutMS int `toml:"launch_timeout_ms"`

	// Enable syntax highlighting
	SyntaxHighlighting bool `toml:"syntax_highlighting"`

	// Color scheme (dark, light, auto)
	ColorScheme string `toml:"color_scheme"`

	// Enable animations
	Animations bool `toml:"animations"`

	// Results per page
	ResultsPerPage int `toml:"results_per_page"`

	// Fuzzy search threshold (0.0 to 1.0)
	FuzzyThreshold float64 `toml:"fuzzy_threshold"`
}

// ShellConfig contains shell integration settings
type ShellConfig struct {
	// Enable shell integration
	Enabled bool `toml:"enabled"`

	// Supported shells
	SupportedShells []string `toml:"supported_shells"`

	// Hook installation paths
	BashHookPath string `toml:"bash_hook_path"`
	ZshHookPath  string `toml:"zsh_hook_path"`

	// Command capture overhead limit in milliseconds
	CaptureTimeoutMS int `toml:"capture_timeout_ms"`

	// Enable graceful degradation
	GracefulDegradation bool `toml:"graceful_degradation"`

	// Auto-installation settings
	AutoInstall bool `toml:"auto_install"`

	// Backup configuration
	BackupDir       string `toml:"backup_dir"`
	BackupRetention int    `toml:"backup_retention_days"`
}

// ImportExportConfig contains import/export settings
type ImportExportConfig struct {
	// Default import format (auto, bash, zsh, fish)
	DefaultFormat string `toml:"default_format"`

	// Enable deduplication during import
	Deduplicate bool `toml:"deduplicate"`

	// Batch size for large imports
	BatchSize int `toml:"batch_size"`

	// Supported formats
	SupportedFormats []string `toml:"supported_formats"`
}

// SyncConfig contains synchronization settings
type SyncConfig struct {
	// Enable synchronization
	Enabled bool `toml:"enabled"`

	// Sync server URL
	ServerURL string `toml:"server_url"`

	// User email for authentication
	Email string `toml:"email"`

	// Sync interval in seconds
	SyncInterval int `toml:"sync_interval"`

	// Advanced options
	MaxRetries int `toml:"max_retries"`
	Timeout    int `toml:"timeout_seconds"`
	BatchSize  int `toml:"batch_size"`

	// Auto-sync on startup
	AutoSync bool `toml:"auto_sync"`

	// Enable conflict resolution
	ConflictResolution bool `toml:"conflict_resolution"`

	// Perfect Sync options
	PerfectSync             bool `toml:"perfect_sync"`
	IntegrityVerification   bool `toml:"integrity_verification"`
	HashCompression         bool `toml:"hash_compression"`
	MaxHashesPerRequest     int  `toml:"max_hashes_per_request"`
	IntegrityCheckFrequency int  `toml:"integrity_check_frequency"`
	HashCollectionTimeout   int  `toml:"hash_collection_timeout"`
}

// DaemonConfig contains daemon-related settings
type DaemonConfig struct {
	// Sync interval in seconds
	SyncInterval time.Duration `toml:"sync_interval"`

	// Retry interval on failure
	RetryInterval time.Duration `toml:"retry_interval"`

	// Maximum retries before giving up
	MaxRetries int `toml:"max_retries"`

	// Log level for daemon
	LogLevel string `toml:"log_level"`

	// PID file path
	PIDFile string `toml:"pid_file"`

	// Log file path
	LogFile string `toml:"log_file"`

	// Daemonize process
	Daemonize bool `toml:"daemonize"`

	// Auto-start daemon when commands are run
	AutoStart bool `toml:"auto_start"`

	// System service is installed
	SystemService bool `toml:"system_service"`
}

// SentryConfig contains Sentry error monitoring settings
type SentryConfig struct {
	// Enable Sentry error monitoring
	Enabled bool `toml:"enabled"`

	// Sentry DSN for error reporting
	DSN string `toml:"dsn"`

	// Environment name (development, staging, production)
	Environment string `toml:"environment"`

	// Sample rate for error reporting (0.0 to 1.0)
	SampleRate float64 `toml:"sample_rate"`

	// Release version for error grouping
	Release string `toml:"release"`

	// Debug mode for Sentry SDK
	Debug bool `toml:"debug"`
}

// OutputConfig contains CLI output formatting settings
type OutputConfig struct {
	// Enable colored output
	ColorsEnabled bool `toml:"colors_enabled"`

	// Color scheme: "modern", "conservative", "custom"
	ColorScheme string `toml:"color_scheme"`

	// Automatically disable colors when not in a TTY
	AutoDetectTTY bool `toml:"auto_detect_tty"`

	// Verbosity level: "minimal", "normal", "verbose"
	Verbosity string `toml:"verbosity"`

	// Custom color definitions (used when color_scheme = "custom")
	Colors ColorConfig `toml:"colors"`
}

// ColorConfig contains color definitions for different output types
type ColorConfig struct {
	Success string `toml:"success"` // Bright Green
	Error   string `toml:"error"`   // Bright Red
	Warning string `toml:"warning"` // Orange
	Info    string `toml:"info"`    // Bright Blue
	Tip     string `toml:"tip"`     // Bright Cyan
	Auth    string `toml:"auth"`    // Bright Blue
	Setup   string `toml:"setup"`   // Bright Magenta
	Sync    string `toml:"sync"`    // Bright Blue
	Stats   string `toml:"stats"`   // Bright Cyan
	Done    string `toml:"done"`    // Bright Green
}

// DeletionConfig contains deletion operation settings
type DeletionConfig struct {
	// Reset sync timestamp after full wipe operations
	ResetSyncOnWipe bool `toml:"reset_sync_on_wipe"`

	// Require explicit confirmation for wipe operations
	RequireConfirmation bool `toml:"require_confirmation"`

	// Export backup before deletion by default
	AutoExportBeforeWipe bool `toml:"auto_export_before_wipe"`
}

// TagsConfig contains tag-related settings
type TagsConfig struct {
	// Enable tag functionality
	Enabled bool `toml:"enabled"`

	// Show tags in TUI command display
	ShowInTUI bool `toml:"show_in_tui"`

	// Maximum number of tags to display in compact view
	MaxDisplayTags int `toml:"max_display_tags"`

	// Enable auto-tagging based on command patterns
	AutoTagging bool `toml:"auto_tagging"`

	// Auto-tagging rules (command prefix -> tag name)
	AutoTagRules map[string]string `toml:"auto_tag_rules"`

	// Visual indicators for tagged commands
	ShowIndicators bool `toml:"show_indicators"`

	// Separator for tag display (default: ", ")
	DisplaySeparator string `toml:"display_separator"`

	// Tag color preferences (tag name -> hex color code)
	TagColors map[string]string `toml:"tag_colors"`

	// Last updated timestamps for tag colors (tag name -> unix timestamp)
	TagColorsUpdated map[string]int64 `toml:"tag_colors_updated"`

	// Default color for new tags (hex color code)
	DefaultColor string `toml:"default_color"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	homeDir, _ := os.UserHomeDir()
	configDir := filepath.Join(homeDir, ".config", "commandchronicles")
	dataDir := filepath.Join(homeDir, ".local", "share", "commandchronicles")

	return &Config{
		Database: DatabaseConfig{
			Path:         filepath.Join(dataDir, "history.db"),
			MaxOpenConns: 50,
			MaxIdleConns: 10,
			WALMode:      true,
			SyncMode:     "NORMAL",
		},
		Cache: CacheConfig{
			HotCacheSize:       2000,
			SearchBatchSize:    5000,
			MaxMemoryMB:        100,
			RefreshInterval:    300, // 5 minutes
			Compression:        true,
			EvictionThreshold:  0.8,  // 80% memory usage triggers eviction
			MaxCacheAgeHours:   24,   // 24 hours max age
			EvictionPercentage: 0.25, // Remove 25% of entries during eviction
		},
		Security: SecurityConfig{
			SessionKeyPath:    filepath.Join(dataDir, "session"),
			SessionTimeout:    7776000, // 3 months in seconds
			Argon2Time:        3,
			Argon2Memory:      65536, // 64MB in KB
			Argon2Threads:     4,
			AutoLockTimeout:   0, // Disabled by default
			SecureMemoryClear: true,
		},
		TUI: TUIConfig{
			LaunchTimeoutMS:    50,
			SyntaxHighlighting: true,
			ColorScheme:        "auto",
			Animations:         true,
			ResultsPerPage:     20,
			FuzzyThreshold:     0.6,
		},
		Shell: ShellConfig{
			Enabled:             true,
			SupportedShells:     []string{"bash", "zsh"},
			BashHookPath:        filepath.Join(configDir, "hooks", "bash_hook.sh"),
			ZshHookPath:         filepath.Join(configDir, "hooks", "zsh_hook.sh"),
			CaptureTimeoutMS:    10,
			GracefulDegradation: true,
			AutoInstall:         false, // Require explicit opt-in for automatic installation
			BackupDir:           "",    // Empty means use same directory as config file
			BackupRetention:     30,    // Keep backups for 30 days
		},
		ImportExport: ImportExportConfig{
			DefaultFormat:    "auto",
			Deduplicate:      true,
			BatchSize:        1000,
			SupportedFormats: []string{"bash", "zsh", "fish", "json"},
		},
		Sync: SyncConfig{
			Enabled:                 false, // Disabled by default
			ServerURL:               "",
			Email:                   "",
			SyncInterval:            300, // 5 minutes
			MaxRetries:              3,
			Timeout:                 30, // 30 seconds
			BatchSize:               100,
			AutoSync:                false,
			ConflictResolution:      true,
			PerfectSync:             true,
			IntegrityVerification:   true,
			HashCompression:         true,
			MaxHashesPerRequest:     10000,
			IntegrityCheckFrequency: 86400, // 24 hours in seconds
			HashCollectionTimeout:   30,    // 30 seconds
		},
		Daemon: DaemonConfig{
			SyncInterval:  5 * time.Minute,
			RetryInterval: 30 * time.Second,
			MaxRetries:    3,
			LogLevel:      "info",
			PIDFile:       filepath.Join(dataDir, "daemon.pid"),
			LogFile:       filepath.Join(dataDir, "daemon.log"),
			Daemonize:     false,
			AutoStart:     false,
			SystemService: false,
		},
		Sentry: SentryConfig{
			Enabled:     true,
			DSN:         "https://471573a890f3bd6259c31a76e5afbbba@sentry.italy.h501.io/31",
			Environment: "development",
			SampleRate:  1.0,
			Debug:       false,
			Release:     "",
		},
		Output: OutputConfig{
			ColorsEnabled: true,
			ColorScheme:   "modern",
			AutoDetectTTY: true,
			Verbosity:     "minimal",
			Colors: ColorConfig{
				Success: "#00FF00", // Bright Green
				Error:   "#FF0000", // Bright Red
				Warning: "#FF8800", // Orange
				Info:    "#0088FF", // Bright Blue
				Tip:     "#00FFFF", // Bright Cyan
				Auth:    "#0088FF", // Bright Blue
				Setup:   "#FF00FF", // Bright Magenta
				Sync:    "#0088FF", // Bright Blue
				Stats:   "#00FFFF", // Bright Cyan
				Done:    "#00FF00", // Bright Green
			},
		},
		Deletion: DeletionConfig{
			ResetSyncOnWipe:      true,  // Default to resetting sync after wipe
			RequireConfirmation:  true,  // Always require confirmation
			AutoExportBeforeWipe: false, // Don't auto-export by default
		},
		Tags: TagsConfig{
			Enabled:        true,
			ShowInTUI:      true,
			MaxDisplayTags: 3,
			AutoTagging:    true,
			AutoTagRules: map[string]string{
				"docker":    "docker",
				"git":       "git",
				"kubectl":   "k8s",
				"npm":       "nodejs",
				"yarn":      "nodejs",
				"pip":       "python",
				"python":    "python",
				"go":        "golang",
				"cargo":     "rust",
				"make":      "build",
				"cmake":     "build",
				"ssh":       "network",
				"curl":      "network",
				"wget":      "network",
				"systemctl": "system",
				"sudo":      "system",
			},
			ShowIndicators:   true,
			DisplaySeparator: ", ",
			TagColors:        make(map[string]string),
			TagColorsUpdated: make(map[string]int64),
			DefaultColor:     "#00FFFF", // cyan
		},
		DataDir:   dataDir,
		ConfigDir: configDir,
	}
}

// Load loads configuration from the specified file path
func Load(configPath string) (*Config, error) {
	config := DefaultConfig()

	// If no config path specified, try default location
	if configPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return config, nil // Return defaults if can't determine home dir
		}
		configPath = filepath.Join(homeDir, ".config", "commandchronicles", "config.toml")
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Config file doesn't exist, return defaults
		config.ApplyDefaults()
		return config, nil
	}

	// Load and parse the TOML file
	if _, err := toml.DecodeFile(configPath, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", configPath, err)
	}

	// Apply defaults to fill in any missing values
	config.ApplyDefaults()

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Ensure directories exist
	if err := config.EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return config, nil
}

// GetSyncServerURL returns the hardcoded sync server URL
func (cfg *Config) GetSyncServerURL() string {
	return DefaultSyncServerURL
}

// Save saves the configuration to the specified file path
func (c *Config) Save(configPath string) error {
	// Ensure the config directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create or open the config file
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %w", err)
	}
	defer file.Close()

	// Encode the configuration as TOML
	encoder := toml.NewEncoder(file)
	if err := encoder.Encode(c); err != nil {
		return fmt.Errorf("failed to encode config as TOML: %w", err)
	}

	return nil
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	// Validate cache settings
	if c.Cache.HotCacheSize <= 0 {
		return fmt.Errorf("cache.hot_cache_size must be positive")
	}
	if c.Cache.SearchBatchSize <= 0 {
		return fmt.Errorf("cache.search_batch_size must be positive")
	}
	if c.Cache.MaxMemoryMB <= 0 {
		return fmt.Errorf("cache.max_memory_mb must be positive")
	}
	if c.Cache.RefreshInterval < 0 {
		return fmt.Errorf("cache.refresh_interval must be non-negative")
	}
	if c.Cache.EvictionThreshold <= 0 || c.Cache.EvictionThreshold > 1 {
		return fmt.Errorf("cache.eviction_threshold must be between 0.0 and 1.0")
	}
	if c.Cache.MaxCacheAgeHours <= 0 {
		return fmt.Errorf("cache.max_cache_age_hours must be positive")
	}
	if c.Cache.EvictionPercentage <= 0 || c.Cache.EvictionPercentage > 1 {
		return fmt.Errorf("cache.eviction_percentage must be between 0.0 and 1.0")
	}

	// Validate security settings
	if c.Security.SessionTimeout < 0 {
		return fmt.Errorf("security.session_timeout must be non-negative")
	}
	if c.Security.Argon2Time == 0 {
		return fmt.Errorf("security.argon2_time must be positive")
	}
	if c.Security.Argon2Memory == 0 {
		return fmt.Errorf("security.argon2_memory must be positive")
	}
	if c.Security.Argon2Threads == 0 {
		return fmt.Errorf("security.argon2_threads must be positive")
	}

	// Validate TUI settings
	if c.TUI.LaunchTimeoutMS <= 0 {
		return fmt.Errorf("tui.launch_timeout_ms must be positive")
	}
	if c.TUI.FuzzyThreshold < 0 || c.TUI.FuzzyThreshold > 1 {
		return fmt.Errorf("tui.fuzzy_threshold must be between 0.0 and 1.0")
	}
	if c.TUI.ResultsPerPage <= 0 {
		return fmt.Errorf("tui.results_per_page must be positive")
	}

	// Validate color scheme
	validColorSchemes := map[string]bool{"dark": true, "light": true, "auto": true}
	if !validColorSchemes[c.TUI.ColorScheme] {
		return fmt.Errorf("tui.color_scheme must be one of: dark, light, auto")
	}

	// Validate shell settings
	if c.Shell.CaptureTimeoutMS < 0 {
		return fmt.Errorf("shell.capture_timeout_ms must be non-negative")
	}

	// Validate import/export settings
	if c.ImportExport.BatchSize <= 0 {
		return fmt.Errorf("import_export.batch_size must be positive")
	}

	// Validate sync settings
	if c.Sync.Enabled {
		if c.Sync.ServerURL == "" {
			return fmt.Errorf("sync.server_url is required when sync is enabled")
		}
		if c.Sync.Email == "" {
			return fmt.Errorf("sync.email is required when sync is enabled")
		}
	}
	if c.Sync.SyncInterval < 0 {
		return fmt.Errorf("sync.sync_interval must be non-negative")
	}
	if c.Sync.MaxRetries < 0 {
		return fmt.Errorf("sync.max_retries must be non-negative")
	}
	if c.Sync.Timeout <= 0 {
		return fmt.Errorf("sync.timeout must be positive")
	}
	if c.Sync.BatchSize <= 0 {
		return fmt.Errorf("sync.batch_size must be positive")
	}
	if c.Sync.MaxHashesPerRequest <= 0 {
		return fmt.Errorf("sync.max_hashes_per_request must be positive")
	}
	if c.Sync.IntegrityCheckFrequency < 0 {
		return fmt.Errorf("sync.integrity_check_frequency must be non-negative")
	}
	if c.Sync.HashCollectionTimeout <= 0 {
		return fmt.Errorf("sync.hash_collection_timeout must be positive")
	}

	return nil
}

// EnsureDirectories creates necessary directories for the configuration
func (c *Config) EnsureDirectories() error {
	dirs := []string{
		filepath.Dir(c.Database.Path),
		filepath.Dir(c.Security.SessionKeyPath),
		filepath.Dir(c.Shell.BashHookPath),
		filepath.Dir(c.Shell.ZshHookPath),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetRefreshDuration returns the cache refresh interval as a time.Duration
func (c *Config) GetRefreshDuration() time.Duration {
	return time.Duration(c.Cache.RefreshInterval) * time.Second
}

// GetSessionTimeoutDuration returns the session timeout as a time.Duration
func (c *Config) GetSessionTimeoutDuration() time.Duration {
	return time.Duration(c.Security.SessionTimeout) * time.Second
}

// GetAutoLockDuration returns the auto-lock timeout as a time.Duration
func (c *Config) GetAutoLockDuration() time.Duration {
	if c.Security.AutoLockTimeout == 0 {
		return 0 // Disabled
	}
	return time.Duration(c.Security.AutoLockTimeout) * time.Second
}

// GetLaunchTimeout returns the TUI launch timeout as a time.Duration
func (c *Config) GetLaunchTimeout() time.Duration {
	return time.Duration(c.TUI.LaunchTimeoutMS) * time.Millisecond
}

// GetCaptureTimeout returns the shell capture timeout as a time.Duration
func (c *Config) GetCaptureTimeout() time.Duration {
	return time.Duration(c.Shell.CaptureTimeoutMS) * time.Millisecond
}

// GetMaxCacheAge returns the maximum cache age as a time.Duration
func (c *Config) GetMaxCacheAge() time.Duration {
	return time.Duration(c.Cache.MaxCacheAgeHours) * time.Hour
}

// GetSyncInterval returns the sync interval as a time.Duration
func (c *Config) GetSyncInterval() time.Duration {
	return time.Duration(c.Sync.SyncInterval) * time.Second
}

// GetSyncTimeout returns the sync timeout as a time.Duration
func (c *Config) GetSyncTimeout() time.Duration {
	return time.Duration(c.Sync.Timeout) * time.Second
}

// ApplyDefaults applies default values for all configuration sections
// This ensures that TOML decoding doesn't override defaults with zero values
func (c *Config) ApplyDefaults() {
	// Cache defaults
	if c.Cache.HotCacheSize <= 0 {
		c.Cache.HotCacheSize = 1000
	}
	if c.Cache.SearchBatchSize <= 0 {
		c.Cache.SearchBatchSize = 5000
	}
	if c.Cache.MaxMemoryMB <= 0 {
		c.Cache.MaxMemoryMB = 100
	}
	if c.Cache.RefreshInterval <= 0 {
		c.Cache.RefreshInterval = 300 // 5 minutes
	}
	if c.Cache.EvictionThreshold <= 0 {
		c.Cache.EvictionThreshold = 0.8 // 80%
	}
	if c.Cache.MaxCacheAgeHours <= 0 {
		c.Cache.MaxCacheAgeHours = 24 // 24 hours
	}
	if c.Cache.EvictionPercentage <= 0 {
		c.Cache.EvictionPercentage = 0.25 // 25%
	}

	// Database defaults
	if c.Database.MaxOpenConns <= 0 {
		c.Database.MaxOpenConns = 50
	}
	if c.Database.MaxIdleConns <= 0 {
		c.Database.MaxIdleConns = 10
	}
	if c.Database.SyncMode == "" {
		c.Database.SyncMode = "NORMAL"
	}

	// Security defaults
	if c.Security.Argon2Time <= 0 {
		c.Security.Argon2Time = 3
	}
	if c.Security.Argon2Memory <= 0 {
		c.Security.Argon2Memory = 65536 // 64MB in KB
	}
	if c.Security.Argon2Threads <= 0 {
		c.Security.Argon2Threads = 4
	}
	if c.Security.SessionTimeout <= 0 {
		c.Security.SessionTimeout = 7776000 // 3 months
	}

	// TUI defaults
	if c.TUI.LaunchTimeoutMS <= 0 {
		c.TUI.LaunchTimeoutMS = 50
	}
	if c.TUI.ColorScheme == "" {
		c.TUI.ColorScheme = "auto"
	}
	if c.TUI.ResultsPerPage <= 0 {
		c.TUI.ResultsPerPage = 20
	}
	if c.TUI.FuzzyThreshold <= 0 {
		c.TUI.FuzzyThreshold = 0.6
	}

	// Import/Export defaults
	if c.ImportExport.BatchSize <= 0 {
		c.ImportExport.BatchSize = 1000
	}
	if c.ImportExport.DefaultFormat == "" {
		c.ImportExport.DefaultFormat = "auto"
	}
	if len(c.ImportExport.SupportedFormats) == 0 {
		c.ImportExport.SupportedFormats = []string{"bash", "zsh", "fish", "auto"}
	}

	// Shell defaults
	if len(c.Shell.SupportedShells) == 0 {
		c.Shell.SupportedShells = []string{"bash", "zsh"}
	}

	// Daemon defaults
	if c.Daemon.SyncInterval <= 0 {
		c.Daemon.SyncInterval = 300 // 5 minutes
	}
	if c.Daemon.RetryInterval <= 0 {
		c.Daemon.RetryInterval = 60 // 1 minute
	}
	if c.Daemon.MaxRetries <= 0 {
		c.Daemon.MaxRetries = 3
	}

	// Sync defaults
	if c.Sync.ServerURL == "" {
		c.Sync.ServerURL = DefaultSyncServerURL
	}
	if c.Sync.SyncInterval == 0 {
		c.Sync.SyncInterval = 300 // 5 minutes
	}
	if c.Sync.MaxRetries == 0 {
		c.Sync.MaxRetries = 3
	}
	if c.Sync.Timeout == 0 {
		c.Sync.Timeout = 30 // 30 seconds
	}
	if c.Sync.BatchSize == 0 {
		c.Sync.BatchSize = 100
	}
	if c.Sync.MaxHashesPerRequest == 0 {
		c.Sync.MaxHashesPerRequest = 10000
	}
	if c.Sync.IntegrityCheckFrequency == 0 {
		c.Sync.IntegrityCheckFrequency = 86400 // 24 hours
	}
	if c.Sync.HashCollectionTimeout == 0 {
		c.Sync.HashCollectionTimeout = 30 // 30 seconds
	}
}

// GetIntegrityCheckFrequencyDuration returns the integrity check frequency as a time.Duration
func (c *Config) GetIntegrityCheckFrequencyDuration() time.Duration {
	return time.Duration(c.Sync.IntegrityCheckFrequency) * time.Second
}

// GetHashCollectionTimeoutDuration returns the hash collection timeout as a time.Duration
func (c *Config) GetHashCollectionTimeoutDuration() time.Duration {
	return time.Duration(c.Sync.HashCollectionTimeout) * time.Second
}

// IsPerfectSyncEnabled returns true if Perfect Sync is enabled and properly configured
func (c *Config) IsPerfectSyncEnabled() bool {
	return c.Sync.Enabled && c.Sync.PerfectSync
}

// ShouldUseIntegrityVerification returns true if integrity verification should be used
func (c *Config) ShouldUseIntegrityVerification() bool {
	return c.Sync.Enabled && c.Sync.IntegrityVerification
}
