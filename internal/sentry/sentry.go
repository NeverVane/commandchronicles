package sentry

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/getsentry/sentry-go"
)

// Client wraps the Sentry client with CommandChronicles-specific functionality
type Client struct {
	hub         *sentry.Hub
	config      *Config
	logger      *logger.Logger
	initialized bool
	version     string
	commit      string
	buildDate   string
	author      string
}

// Config contains Sentry-specific configuration
type Config struct {
	Enabled     bool    `toml:"enabled"`
	DSN         string  `toml:"dsn"`
	Environment string  `toml:"environment"`
	SampleRate  float64 `toml:"sample_rate"`
	Debug       bool    `toml:"debug"`
	Release     string  `toml:"release"`
}

// DefaultConfig returns default Sentry configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled:     true,
		DSN:         "", // Set via environment variable or config
		Environment: "development",
		SampleRate:  1.0,
		Debug:       false,
		Release:     "",
	}
}

// NewClient creates a new Sentry client with safe configuration
func NewClient(cfg *config.Config, version, commit, buildDate, author string) (*Client, error) {
	sentryConfig := DefaultConfig()
	if cfg != nil && cfg.Sentry.Enabled {
		sentryConfig.Enabled = cfg.Sentry.Enabled
		sentryConfig.DSN = cfg.Sentry.DSN
		sentryConfig.Environment = cfg.Sentry.Environment
		sentryConfig.SampleRate = cfg.Sentry.SampleRate
		sentryConfig.Debug = cfg.Sentry.Debug
		sentryConfig.Release = cfg.Sentry.Release
	}

	client := &Client{
		config:    sentryConfig,
		logger:    logger.GetLogger().WithComponent("sentry"),
		version:   version,
		commit:    commit,
		buildDate: buildDate,
		author:    author,
	}

	if err := client.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize Sentry client: %w", err)
	}

	return client, nil
}

// initialize sets up the Sentry SDK with safe configuration
func (c *Client) initialize() error {
	if !c.config.Enabled {
		c.logger.Info().Msg("Sentry monitoring disabled")
		return nil
	}

	if c.config.DSN == "" {
		c.logger.Warn().Msg("Sentry DSN not configured, monitoring disabled")
		return nil
	}

	// Build release string
	release := c.version
	if c.commit != "" {
		release = fmt.Sprintf("%s-%s", c.version, c.commit)
	}
	if c.config.Release != "" {
		release = c.config.Release
	}

	// Initialize Sentry with safe configuration
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              c.config.DSN,
		Environment:      c.config.Environment,
		Release:          release,
		SampleRate:       c.config.SampleRate,
		Debug:            c.config.Debug,
		AttachStacktrace: true,
		BeforeSend: func(event *sentry.Event, hint *sentry.EventHint) *sentry.Event {
			// Sanitize event before sending
			return c.sanitizeEvent(event)
		},
		BeforeBreadcrumb: func(breadcrumb *sentry.Breadcrumb, hint *sentry.BreadcrumbHint) *sentry.Breadcrumb {
			// Sanitize breadcrumbs
			return c.sanitizeBreadcrumb(breadcrumb)
		},
	})

	if err != nil {
		return fmt.Errorf("failed to initialize Sentry SDK: %w", err)
	}

	// Create isolated hub for this client
	c.hub = sentry.CurrentHub().Clone()

	// Configure default tags and context
	c.configureContext()

	c.initialized = true
	c.logger.Info().
		Str("environment", c.config.Environment).
		Str("release", release).
		Float64("sample_rate", c.config.SampleRate).
		Msg("Sentry monitoring initialized")

	return nil
}

// configureContext sets up safe default context for all Sentry events
func (c *Client) configureContext() {
	if !c.initialized {
		return
	}

	// Set safe tags
	c.hub.ConfigureScope(func(scope *sentry.Scope) {
		// Application info
		scope.SetTag("app.name", "commandchronicles-cli")
		scope.SetTag("app.version", c.version)
		scope.SetTag("app.commit", c.commit)
		scope.SetTag("app.build_date", c.buildDate)

		// System info
		scope.SetTag("os", runtime.GOOS)
		scope.SetTag("arch", runtime.GOARCH)
		scope.SetTag("go_version", runtime.Version())
		scope.SetTag("num_cpu", fmt.Sprintf("%d", runtime.NumCPU()))

		// Safe context
		scope.SetContext("runtime", map[string]interface{}{
			"go_version":    runtime.Version(),
			"go_os":         runtime.GOOS,
			"go_arch":       runtime.GOARCH,
			"num_cpu":       runtime.NumCPU(),
			"num_goroutine": runtime.NumGoroutine(),
		})

		scope.SetContext("application", map[string]interface{}{
			"name":       "commandchronicles-cli",
			"version":    c.version,
			"commit":     c.commit,
			"build_date": c.buildDate,
			"author":     c.author,
		})
	})
}

// CaptureError captures an error with safe context
func (c *Client) CaptureError(err error, component, operation string, tags map[string]string) {
	if !c.initialized || err == nil {
		return
	}

	c.hub.WithScope(func(scope *sentry.Scope) {
		// Set component and operation context
		scope.SetTag("component", component)
		scope.SetTag("operation", operation)

		// Add safe custom tags
		for key, value := range tags {
			scope.SetTag(key, c.sanitizeValue(value))
		}

		// Set operation context
		scope.SetContext("operation", map[string]interface{}{
			"component": component,
			"operation": operation,
			"timestamp": time.Now().UTC(),
		})

		c.hub.CaptureException(err)
	})

	c.logger.Debug().
		Str("component", component).
		Str("operation", operation).
		Err(err).
		Msg("Error captured by Sentry")
}

// CaptureMessage captures a message with safe context
func (c *Client) CaptureMessage(message, level, component, operation string, tags map[string]string) {
	if !c.initialized {
		return
	}

	sentryLevel := sentry.LevelInfo
	switch level {
	case "debug":
		sentryLevel = sentry.LevelDebug
	case "info":
		sentryLevel = sentry.LevelInfo
	case "warn", "warning":
		sentryLevel = sentry.LevelWarning
	case "error":
		sentryLevel = sentry.LevelError
	case "fatal":
		sentryLevel = sentry.LevelFatal
	}

	c.hub.WithScope(func(scope *sentry.Scope) {
		scope.SetTag("component", component)
		scope.SetTag("operation", operation)
		scope.SetLevel(sentryLevel)

		// Add safe custom tags
		for key, value := range tags {
			scope.SetTag(key, c.sanitizeValue(value))
		}

		scope.SetContext("operation", map[string]interface{}{
			"component": component,
			"operation": operation,
			"timestamp": time.Now().UTC(),
		})

		c.hub.CaptureMessage(c.sanitizeValue(message))
	})
}

// AddBreadcrumb adds a safe breadcrumb for operation tracking
func (c *Client) AddBreadcrumb(category, message, level string, data map[string]interface{}) {
	if !c.initialized {
		return
	}

	sentryLevel := sentry.LevelInfo
	switch level {
	case "debug":
		sentryLevel = sentry.LevelDebug
	case "info":
		sentryLevel = sentry.LevelInfo
	case "warn", "warning":
		sentryLevel = sentry.LevelWarning
	case "error":
		sentryLevel = sentry.LevelError
	}

	// Sanitize data
	safeData := make(map[string]interface{})
	for key, value := range data {
		if strValue, ok := value.(string); ok {
			safeData[key] = c.sanitizeValue(strValue)
		} else {
			safeData[key] = value
		}
	}

	c.hub.AddBreadcrumb(&sentry.Breadcrumb{
		Category:  category,
		Message:   c.sanitizeValue(message),
		Level:     sentryLevel,
		Data:      safeData,
		Timestamp: time.Now(),
	}, nil)
}

// Flush flushes pending events
func (c *Client) Flush(timeout time.Duration) bool {
	if !c.initialized {
		return true
	}
	return sentry.Flush(timeout)
}

// Close closes the Sentry client
func (c *Client) Close() {
	if c.initialized {
		c.Flush(2 * time.Second)
		c.initialized = false
		c.logger.Info().Msg("Sentry client closed")
	}
}

// WithContext returns a new client with additional context
func (c *Client) WithContext(ctx context.Context) *Client {
	if !c.initialized {
		return c
	}

	newClient := *c
	newClient.hub = sentry.GetHubFromContext(ctx)
	if newClient.hub == nil {
		newClient.hub = c.hub
	}
	return &newClient
}

// IsEnabled returns whether Sentry monitoring is enabled
func (c *Client) IsEnabled() bool {
	return c.initialized
}
