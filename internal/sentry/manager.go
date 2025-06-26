package sentry

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
	"github.com/rs/zerolog"
)

// Manager provides global access to Sentry functionality
type Manager struct {
	client      *Client
	factory     *LoggerFactory
	config      *config.Config
	logger      *logger.Logger
	initialized bool
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

var (
	globalManager *Manager
	managerOnce   sync.Once
)

// Initialize initializes the global Sentry manager
func Initialize(cfg *config.Config, version, commit, buildDate, author string) error {
	var initErr error

	managerOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		globalManager = &Manager{
			config: cfg,
			logger: logger.GetLogger().WithComponent("sentry-manager"),
			ctx:    ctx,
			cancel: cancel,
		}

		if err := globalManager.initialize(version, commit, buildDate, author); err != nil {
			initErr = fmt.Errorf("failed to initialize Sentry manager: %w", err)
			return
		}
	})

	return initErr
}

// GetManager returns the global Sentry manager instance
func GetManager() *Manager {
	if globalManager == nil {
		// Return a safe no-op manager if not initialized
		return &Manager{
			initialized: false,
			logger:      logger.GetLogger().WithComponent("sentry-manager-noop"),
		}
	}
	return globalManager
}

// initialize sets up the Sentry client and factory
func (m *Manager) initialize(version, commit, buildDate, author string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return nil
	}

	// Create Sentry client
	client, err := NewClient(m.config, version, commit, buildDate, author)
	if err != nil {
		return fmt.Errorf("failed to create Sentry client: %w", err)
	}

	m.client = client
	m.factory = NewLoggerFactory(client)
	m.initialized = true

	m.logger.Info().
		Bool("enabled", m.client.IsEnabled()).
		Str("version", version).
		Str("commit", commit).
		Msg("Sentry manager initialized")

	return nil
}

// IsEnabled returns whether Sentry monitoring is enabled
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.initialized && m.client != nil && m.client.IsEnabled()
}

// CaptureError captures an error with safe context
func (m *Manager) CaptureError(err error, component, operation string, tags ...map[string]string) {
	if !m.IsEnabled() || err == nil {
		return
	}

	// Merge tags
	mergedTags := make(map[string]string)
	for _, tagMap := range tags {
		for k, v := range tagMap {
			mergedTags[k] = v
		}
	}

	m.client.CaptureError(err, component, operation, mergedTags)
}

// CaptureMessage captures a message with safe context
func (m *Manager) CaptureMessage(message, level, component, operation string, tags ...map[string]string) {
	if !m.IsEnabled() {
		return
	}

	// Merge tags
	mergedTags := make(map[string]string)
	for _, tagMap := range tags {
		for k, v := range tagMap {
			mergedTags[k] = v
		}
	}

	m.client.CaptureMessage(message, level, component, operation, mergedTags)
}

// AddBreadcrumb adds a breadcrumb for operation tracking
func (m *Manager) AddBreadcrumb(category, message, level string, data map[string]interface{}) {
	if !m.IsEnabled() {
		return
	}

	m.client.AddBreadcrumb(category, message, level, data)
}

// WithComponent creates a component-specific error reporter
func (m *Manager) WithComponent(component string) *ComponentReporter {
	return &ComponentReporter{
		manager:   m,
		component: component,
	}
}

// CreateLogger creates a new logger with Sentry integration
func (m *Manager) CreateLogger(baseLogger zerolog.Logger, component string) *SentryLoggerAdapter {
	if !m.IsEnabled() {
		// Return a logger without Sentry integration
		return &SentryLoggerAdapter{
			logger: baseLogger.With().Str("component", component).Logger(),
			client: nil,
			hook:   nil,
		}
	}

	return m.factory.CreateLogger(baseLogger, component)
}

// CreateComponentLogger creates a component and operation specific logger
func (m *Manager) CreateComponentLogger(baseLogger zerolog.Logger, component, operation string) *SentryLoggerAdapter {
	if !m.IsEnabled() {
		// Return a logger without Sentry integration
		return &SentryLoggerAdapter{
			logger: baseLogger.With().
				Str("component", component).
				Str("operation", operation).
				Logger(),
			client: nil,
			hook:   nil,
		}
	}

	return m.factory.CreateComponentLogger(baseLogger, component, operation)
}

// Flush flushes pending Sentry events
func (m *Manager) Flush(timeout time.Duration) bool {
	if !m.IsEnabled() {
		return true
	}

	return m.client.Flush(timeout)
}

// Close closes the Sentry manager and client
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.initialized {
		return
	}

	if m.client != nil {
		m.client.Close()
	}

	if m.cancel != nil {
		m.cancel()
	}

	m.initialized = false
	m.logger.Info().Msg("Sentry manager closed")
}

// ComponentReporter provides component-specific error reporting
type ComponentReporter struct {
	manager   *Manager
	component string
}

// CaptureError captures an error for this component
func (cr *ComponentReporter) CaptureError(err error, operation string, tags ...map[string]string) {
	cr.manager.CaptureError(err, cr.component, operation, tags...)
}

// CaptureMessage captures a message for this component
func (cr *ComponentReporter) CaptureMessage(message, level, operation string, tags ...map[string]string) {
	cr.manager.CaptureMessage(message, level, cr.component, operation, tags...)
}

// AddBreadcrumb adds a breadcrumb for this component
func (cr *ComponentReporter) AddBreadcrumb(message, level string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["component"] = cr.component

	cr.manager.AddBreadcrumb(cr.component, message, level, data)
}

// WithOperation creates an operation-specific reporter
func (cr *ComponentReporter) WithOperation(operation string) *OperationReporter {
	return &OperationReporter{
		manager:   cr.manager,
		component: cr.component,
		operation: operation,
	}
}

// OperationReporter provides component and operation specific error reporting
type OperationReporter struct {
	manager   *Manager
	component string
	operation string
}

// CaptureError captures an error for this component and operation
func (or *OperationReporter) CaptureError(err error, tags ...map[string]string) {
	or.manager.CaptureError(err, or.component, or.operation, tags...)
}

// CaptureMessage captures a message for this component and operation
func (or *OperationReporter) CaptureMessage(message, level string, tags ...map[string]string) {
	or.manager.CaptureMessage(message, level, or.component, or.operation, tags...)
}

// AddBreadcrumb adds a breadcrumb for this component and operation
func (or *OperationReporter) AddBreadcrumb(message, level string, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["component"] = or.component
	data["operation"] = or.operation

	or.manager.AddBreadcrumb(or.component, message, level, data)
}

// Start marks the beginning of an operation
func (or *OperationReporter) Start() {
	or.AddBreadcrumb(fmt.Sprintf("Operation %s started", or.operation), "info", map[string]interface{}{
		"action": "start",
	})
}

// Success marks the successful completion of an operation
func (or *OperationReporter) Success(data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["action"] = "success"

	or.AddBreadcrumb(fmt.Sprintf("Operation %s completed successfully", or.operation), "info", data)
}

// Failure marks the failure of an operation
func (or *OperationReporter) Failure(err error, data map[string]interface{}) {
	if data == nil {
		data = make(map[string]interface{})
	}
	data["action"] = "failure"

	or.AddBreadcrumb(fmt.Sprintf("Operation %s failed", or.operation), "error", data)

	if err != nil {
		or.CaptureError(err)
	}
}

// Convenience functions for global access
func CaptureError(err error, component, operation string, tags ...map[string]string) {
	GetManager().CaptureError(err, component, operation, tags...)
}

func CaptureMessage(message, level, component, operation string, tags ...map[string]string) {
	GetManager().CaptureMessage(message, level, component, operation, tags...)
}

func AddBreadcrumb(category, message, level string, data map[string]interface{}) {
	GetManager().AddBreadcrumb(category, message, level, data)
}

func WithComponent(component string) *ComponentReporter {
	return GetManager().WithComponent(component)
}

func IsEnabled() bool {
	return GetManager().IsEnabled()
}

func Flush(timeout time.Duration) bool {
	return GetManager().Flush(timeout)
}

func Close() {
	GetManager().Close()
}
