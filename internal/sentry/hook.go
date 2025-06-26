package sentry

import (
	"fmt"
	"time"

	"github.com/rs/zerolog"
)

// ZerologHook implements zerolog.Hook to integrate Sentry with zerolog
type ZerologHook struct {
	client        *Client
	minLevel      zerolog.Level
	enabledLevels map[zerolog.Level]bool
}

// NewZerologHook creates a new zerolog hook for Sentry integration
func NewZerologHook(client *Client, minLevel zerolog.Level) *ZerologHook {
	enabledLevels := map[zerolog.Level]bool{
		zerolog.ErrorLevel: true,
		zerolog.FatalLevel: true,
		zerolog.PanicLevel: true,
	}

	// Include warn level if minLevel is warn or lower
	if minLevel <= zerolog.WarnLevel {
		enabledLevels[zerolog.WarnLevel] = true
	}

	return &ZerologHook{
		client:        client,
		minLevel:      minLevel,
		enabledLevels: enabledLevels,
	}
}

// Run is called by zerolog for each log event
func (h *ZerologHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	// Only process events at or above the configured minimum level
	if level < h.minLevel {
		return
	}

	// Only process enabled levels
	if !h.enabledLevels[level] {
		return
	}

	// Don't process if Sentry client is not initialized
	if !h.client.IsEnabled() {
		return
	}

	// Extract safe context from the log event
	ctx := h.extractSafeContext(e)

	// Get component and operation from context
	component := h.getStringFromContext(ctx, "component", "unknown")
	operation := h.getStringFromContext(ctx, "operation", "unknown")

	// Create safe tags
	tags := h.createSafeTags(ctx, level)

	// Handle different log levels
	switch level {
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		// Check if there's an error in the context
		if err := h.getErrorFromContext(ctx); err != nil {
			h.client.CaptureError(err, component, operation, tags)
		} else {
			// Capture as message if no error object
			h.client.CaptureMessage(msg, level.String(), component, operation, tags)
		}

	case zerolog.WarnLevel:
		// Capture warnings as messages
		h.client.CaptureMessage(msg, level.String(), component, operation, tags)

	default:
		// For other levels, just add breadcrumb
		h.client.AddBreadcrumb(component, msg, level.String(), map[string]interface{}{
			"operation": operation,
			"level":     level.String(),
		})
	}
}

// extractSafeContext extracts safe context information from a zerolog event
func (h *ZerologHook) extractSafeContext(e *zerolog.Event) map[string]interface{} {
	ctx := make(map[string]interface{})

	// This is a bit of a hack since zerolog doesn't expose internal context
	// We'll rely on the structured nature of our logging to extract safe fields
	return ctx
}

// getStringFromContext safely gets a string value from context
func (h *ZerologHook) getStringFromContext(ctx map[string]interface{}, key, defaultValue string) string {
	if value, exists := ctx[key]; exists {
		if strValue, ok := value.(string); ok {
			return h.client.sanitizeValue(strValue)
		}
	}
	return defaultValue
}

// getErrorFromContext attempts to extract an error from the context
func (h *ZerologHook) getErrorFromContext(ctx map[string]interface{}) error {
	if value, exists := ctx["error"]; exists {
		if err, ok := value.(error); ok {
			return err
		}
	}
	return nil
}

// createSafeTags creates safe tags for Sentry from log context
func (h *ZerologHook) createSafeTags(ctx map[string]interface{}, level zerolog.Level) map[string]string {
	tags := make(map[string]string)

	// Add log level
	tags["log_level"] = level.String()

	// Add timestamp
	tags["log_timestamp"] = time.Now().UTC().Format(time.RFC3339)

	// Extract safe context fields
	safeFields := []string{
		"component", "operation", "module", "function",
		"status", "result", "type", "kind", "category",
		"version", "build", "env", "stage",
	}

	for _, field := range safeFields {
		if value := h.getStringFromContext(ctx, field, ""); value != "" {
			tags[field] = value
		}
	}

	return tags
}

// SentryLoggerAdapter wraps a zerolog.Logger with Sentry integration
type SentryLoggerAdapter struct {
	logger zerolog.Logger
	client *Client
	hook   *ZerologHook
}

// NewSentryLoggerAdapter creates a new logger adapter with Sentry integration
func NewSentryLoggerAdapter(logger zerolog.Logger, client *Client) *SentryLoggerAdapter {
	hook := NewZerologHook(client, zerolog.WarnLevel)

	// Add the hook to the logger
	loggerWithHook := logger.Hook(hook)

	return &SentryLoggerAdapter{
		logger: loggerWithHook,
		client: client,
		hook:   hook,
	}
}

// WithComponent adds component context to the logger
func (s *SentryLoggerAdapter) WithComponent(component string) *SentryLoggerAdapter {
	// Add breadcrumb for component initialization
	s.client.AddBreadcrumb("component", fmt.Sprintf("Component %s initialized", component), "info", map[string]interface{}{
		"component": component,
		"action":    "initialize",
	})

	return &SentryLoggerAdapter{
		logger: s.logger.With().Str("component", component).Logger(),
		client: s.client,
		hook:   s.hook,
	}
}

// WithOperation adds operation context to the logger
func (s *SentryLoggerAdapter) WithOperation(operation string) *SentryLoggerAdapter {
	// Add breadcrumb for operation start
	s.client.AddBreadcrumb("operation", fmt.Sprintf("Operation %s started", operation), "info", map[string]interface{}{
		"operation": operation,
		"action":    "start",
	})

	return &SentryLoggerAdapter{
		logger: s.logger.With().Str("operation", operation).Logger(),
		client: s.client,
		hook:   s.hook,
	}
}

// CaptureError directly captures an error with context
func (s *SentryLoggerAdapter) CaptureError(err error, component, operation string) {
	if err == nil {
		return
	}

	tags := map[string]string{
		"direct_capture": "true",
	}

	s.client.CaptureError(err, component, operation, tags)

	// Also log it normally
	s.logger.Error().
		Err(err).
		Str("component", component).
		Str("operation", operation).
		Msg("Error captured directly")
}

// CaptureMessage directly captures a message with context
func (s *SentryLoggerAdapter) CaptureMessage(message, level, component, operation string) {
	tags := map[string]string{
		"direct_capture": "true",
	}

	s.client.CaptureMessage(message, level, component, operation, tags)
}

// AddBreadcrumb adds a breadcrumb to Sentry
func (s *SentryLoggerAdapter) AddBreadcrumb(category, message, level string, data map[string]interface{}) {
	s.client.AddBreadcrumb(category, message, level, data)
}

// GetZerologLogger returns the underlying zerolog logger
func (s *SentryLoggerAdapter) GetZerologLogger() zerolog.Logger {
	return s.logger
}

// Close closes the Sentry client
func (s *SentryLoggerAdapter) Close() {
	s.client.Close()
}

// Flush flushes pending Sentry events
func (s *SentryLoggerAdapter) Flush(timeout time.Duration) bool {
	return s.client.Flush(timeout)
}

// LoggerFactory creates loggers with Sentry integration
type LoggerFactory struct {
	client *Client
}

// NewLoggerFactory creates a new logger factory
func NewLoggerFactory(client *Client) *LoggerFactory {
	return &LoggerFactory{
		client: client,
	}
}

// CreateLogger creates a new logger with Sentry integration
func (f *LoggerFactory) CreateLogger(baseLogger zerolog.Logger, component string) *SentryLoggerAdapter {
	adapter := NewSentryLoggerAdapter(baseLogger, f.client)
	if component != "" {
		adapter = adapter.WithComponent(component)
	}
	return adapter
}

// CreateComponentLogger creates a component-specific logger
func (f *LoggerFactory) CreateComponentLogger(baseLogger zerolog.Logger, component, operation string) *SentryLoggerAdapter {
	adapter := NewSentryLoggerAdapter(baseLogger, f.client)
	if component != "" {
		adapter = adapter.WithComponent(component)
	}
	if operation != "" {
		adapter = adapter.WithOperation(operation)
	}
	return adapter
}
