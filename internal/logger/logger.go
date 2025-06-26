package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

// Logger wraps zerolog.Logger with additional functionality
type Logger struct {
	zerolog.Logger
	level  zerolog.Level
	output io.Writer
}

// Config represents logger configuration
type Config struct {
	// Log level (debug, info, warn, error)
	Level string `toml:"level"`
	
	// Output destination (stdout, stderr, or file path)
	Output string `toml:"output"`
	
	// Enable colored output (auto-detected for terminals)
	Color bool `toml:"color"`
	
	// Enable timestamp in logs
	Timestamp bool `toml:"timestamp"`
	
	// Enable caller information (file:line)
	Caller bool `toml:"caller"`
	
	// Log file rotation settings (only for file output)
	MaxSize    int  `toml:"max_size_mb"`    // Max size in MB before rotation
	MaxBackups int  `toml:"max_backups"`    // Max number of backup files
	MaxAge     int  `toml:"max_age_days"`   // Max age in days before deletion
	Compress   bool `toml:"compress"`       // Compress rotated files
}

// DefaultConfig returns default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:      "error",
		Output:     "stderr",
		Color:      true,
		Timestamp:  true,
		Caller:     false,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	}
}

var globalLogger *Logger

// Init initializes the global logger with the provided configuration
func Init(config *Config) error {
	if config == nil {
		config = DefaultConfig()
	}

	// Set error stack marshaling
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	// Parse log level
	level, err := zerolog.ParseLevel(config.Level)
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", config.Level, err)
	}

	// Configure output
	var output io.Writer
	switch config.Output {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// Assume it's a file path
		if err := os.MkdirAll(filepath.Dir(config.Output), 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		output = file
	}

	// Configure console writer for terminal output
	if (config.Output == "stdout" || config.Output == "stderr") && config.Color {
		consoleWriter := zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: time.RFC3339,
			NoColor:    !config.Color,
		}
		output = consoleWriter
	}

	// Create logger
	logger := zerolog.New(output).Level(level)
	
	if config.Timestamp {
		logger = logger.With().Timestamp().Logger()
	}
	
	if config.Caller {
		logger = logger.With().Caller().Logger()
	}

	globalLogger = &Logger{
		Logger: logger,
		level:  level,
		output: output,
	}

	// Set global logger
	log.Logger = globalLogger.Logger

	return nil
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		// Initialize with defaults if not already done
		_ = Init(DefaultConfig())
	}
	return globalLogger
}

// WithField adds a field to the logger context
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{
		Logger: l.Logger.With().Interface(key, value).Logger(),
		level:  l.level,
		output: l.output,
	}
}

// WithFields adds multiple fields to the logger context
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	ctx := l.Logger.With()
	for key, value := range fields {
		ctx = ctx.Interface(key, value)
	}
	return &Logger{
		Logger: ctx.Logger(),
		level:  l.level,
		output: l.output,
	}
}

// WithError adds an error field to the logger context
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.Logger.With().Err(err).Logger(),
		level:  l.level,
		output: l.output,
	}
}

// WithComponent adds a component field for structured logging
func (l *Logger) WithComponent(component string) *Logger {
	return l.WithField("component", component)
}

// WithOperation adds an operation field for structured logging
func (l *Logger) WithOperation(operation string) *Logger {
	return l.WithField("operation", operation)
}

// WithUserID adds a user ID field (for audit logging)
func (l *Logger) WithUserID(userID string) *Logger {
	return l.WithField("user_id", userID)
}

// WithSessionID adds a session ID field
func (l *Logger) WithSessionID(sessionID string) *Logger {
	return l.WithField("session_id", sessionID)
}

// Security creates a logger with security context
func (l *Logger) Security() *Logger {
	return l.WithComponent("security")
}

// Database creates a logger with database context
func (l *Logger) Database() *Logger {
	return l.WithComponent("database")
}

// Storage creates a logger with storage context
func (l *Logger) Storage() *Logger {
	return l.WithComponent("storage")
}

// Search creates a logger with search context
func (l *Logger) Search() *Logger {
	return l.WithComponent("search")
}

// TUI creates a logger with TUI context
func (l *Logger) TUI() *Logger {
	return l.WithComponent("tui")
}

// Shell creates a logger with shell integration context
func (l *Logger) Shell() *Logger {
	return l.WithComponent("shell")
}

// Config creates a logger with configuration context
func (l *Logger) Config() *Logger {
	return l.WithComponent("config")
}

// Audit logs an audit event with structured information
func (l *Logger) Audit(event string, fields map[string]interface{}) {
	evt := l.Info().Str("audit_event", event)
	for key, value := range fields {
		evt = evt.Interface(key, value)
	}
	evt.Msg("audit log")
}

// Performance logs performance metrics
func (l *Logger) Performance(operation string, duration time.Duration, fields map[string]interface{}) {
	evt := l.Info().
		Str("perf_operation", operation).
		Dur("duration", duration)
	
	for key, value := range fields {
		evt = evt.Interface(key, value)
	}
	evt.Msg("performance metric")
}

// Security convenience methods
func (l *Logger) SecurityInfo(msg string) {
	l.Security().Info().Msg(msg)
}

func (l *Logger) SecurityWarn(msg string) {
	l.Security().Warn().Msg(msg)
}

func (l *Logger) SecurityError(err error, msg string) {
	l.Security().WithError(err).Error().Msg(msg)
}

// Database convenience methods
func (l *Logger) DatabaseInfo(msg string) {
	l.Database().Info().Msg(msg)
}

func (l *Logger) DatabaseError(err error, msg string) {
	l.Database().WithError(err).Error().Msg(msg)
}

// Global convenience functions
func Debug() *zerolog.Event {
	return GetLogger().Debug()
}

func Info() *zerolog.Event {
	return GetLogger().Info()
}

func Warn() *zerolog.Event {
	return GetLogger().Warn()
}

func Error() *zerolog.Event {
	return GetLogger().Error()
}

func Fatal() *zerolog.Event {
	return GetLogger().Fatal()
}

func WithField(key string, value interface{}) *Logger {
	return GetLogger().WithField(key, value)
}

func WithFields(fields map[string]interface{}) *Logger {
	return GetLogger().WithFields(fields)
}

func WithError(err error) *Logger {
	return GetLogger().WithError(err)
}

func WithComponent(component string) *Logger {
	return GetLogger().WithComponent(component)
}

func Audit(event string, fields map[string]interface{}) {
	GetLogger().Audit(event, fields)
}

func Performance(operation string, duration time.Duration, fields map[string]interface{}) {
	GetLogger().Performance(operation, duration, fields)
}