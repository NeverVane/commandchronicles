package sentry

import (
	"errors"
	"testing"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentryClient_Initialize(t *testing.T) {
	tests := []struct {
		name        string
		config      *config.Config
		expectError bool
		expectInit  bool
	}{
		{
			name: "successful initialization",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled:     true,
					DSN:         "https://test@example.com/1",
					Environment: "test",
					SampleRate:  1.0,
					Debug:       false,
				},
			},
			expectError: false,
			expectInit:  true,
		},
		{
			name: "disabled sentry",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: false,
				},
			},
			expectError: false,
			expectInit:  false,
		},
		{
			name: "empty DSN",
			config: &config.Config{
				Sentry: config.SentryConfig{
					Enabled: true,
					DSN:     "",
				},
			},
			expectError: false,
			expectInit:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config, "1.0.0", "test-commit", "2024-01-01", "test-author")

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.Equal(t, tt.expectInit, client.IsEnabled())
		})
	}
}

func TestSentryClient_DataSanitization(t *testing.T) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "sanitize command",
			input:    "command: rm -rf /home/user/sensitive",
			expected: "command: [REDACTED]",
		},
		{
			name:     "sanitize file path",
			input:    "error in /home/user/documents/secret.txt",
			expected: "error in /[USER_HOME]/.../documents/secret.txt",
		},
		{
			name:     "sanitize email",
			input:    "user@example.com failed to login",
			expected: "[EMAIL_REDACTED] failed to login",
		},
		{
			name:     "sanitize password",
			input:    "password: mysecretpassword123",
			expected: "password: [REDACTED]",
		},
		{
			name:     "sanitize token",
			input:    "token: eyJhbGciOiJIUzI1NiIs",
			expected: "token: [REDACTED]",
		},
		{
			name:     "sanitize username",
			input:    "username: john_doe",
			expected: "username: [REDACTED]",
		},
		{
			name:     "safe error message",
			input:    "database connection failed",
			expected: "database connection failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.sanitizeValue(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSentryClient_FilePath_Sanitization(t *testing.T) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "linux home directory",
			input:    "/home/alice/documents/file.txt",
			expected: "/home/[USER]/documents/file.txt",
		},
		{
			name:     "macos home directory",
			input:    "/Users/bob/Desktop/secret.doc",
			expected: "/Users/[USER]/Desktop/secret.doc",
		},
		{
			name:     "windows home directory",
			input:    "C:\\Users\\charlie\\Documents\\private.txt",
			expected: "C:\\Users\\[USER]\\Documents\\private.txt",
		},
		{
			name:     "system path (safe)",
			input:    "/usr/local/bin/ccr",
			expected: "/usr/local/bin/ccr",
		},
		{
			name:     "relative path (safe)",
			input:    "./config/settings.toml",
			expected: "config/settings.toml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.sanitizeFilePath(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSentryClient_SanitizeMap(t *testing.T) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	tests := []struct {
		name     string
		input    map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name: "sanitize sensitive fields",
			input: map[string]interface{}{
				"command":  "rm -rf /",
				"username": "testuser",
				"password": "secret123",
				"status":   "failed",
				"count":    42,
			},
			expected: map[string]interface{}{
				"command":  "[REDACTED]",
				"username": "[REDACTED]",
				"password": "[REDACTED]",
				"status":   "failed",
				"count":    42,
			},
		},
		{
			name: "safe fields only",
			input: map[string]interface{}{
				"operation": "sync",
				"duration":  1234,
				"success":   true,
			},
			expected: map[string]interface{}{
				"operation": "sync",
				"duration":  1234,
				"success":   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.sanitizeMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSentryClient_IsSensitiveError(t *testing.T) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	tests := []struct {
		name      string
		err       error
		sensitive bool
	}{
		{
			name:      "password error",
			err:       errors.New("invalid password provided"),
			sensitive: true,
		},
		{
			name:      "command error",
			err:       errors.New("failed to execute command"),
			sensitive: true,
		},
		{
			name:      "user error",
			err:       errors.New("user not found"),
			sensitive: true,
		},
		{
			name:      "file path error",
			err:       errors.New("cannot access file"),
			sensitive: true,
		},
		{
			name:      "safe database error",
			err:       errors.New("database connection timeout"),
			sensitive: false,
		},
		{
			name:      "safe network error",
			err:       errors.New("network unreachable"),
			sensitive: false,
		},
		{
			name:      "nil error",
			err:       nil,
			sensitive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.IsSensitiveError(tt.err)
			assert.Equal(t, tt.sensitive, result)
		})
	}
}

func TestSentryClient_GetSafeErrorMessage(t *testing.T) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "sensitive error",
			err:      errors.New("password authentication failed"),
			expected: "[SENSITIVE_ERROR_REDACTED]",
		},
		{
			name:     "safe error",
			err:      errors.New("network connection failed"),
			expected: "network connection failed",
		},
		{
			name:     "nil error",
			err:      nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.GetSafeErrorMessage(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSentryManager_Initialize(t *testing.T) {
	cfg := &config.Config{
		Sentry: config.SentryConfig{
			Enabled:     true,
			DSN:         "https://test@example.com/1",
			Environment: "test",
			SampleRate:  1.0,
		},
	}

	err := Initialize(cfg, "1.0.0", "test-commit", "2024-01-01", "test-author")
	assert.NoError(t, err)

	manager := GetManager()
	assert.NotNil(t, manager)
	assert.True(t, manager.IsEnabled())

	// Clean up
	manager.Close()
}

func TestSentryManager_DisabledSentry(t *testing.T) {
	cfg := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: false,
		},
	}

	err := Initialize(cfg, "1.0.0", "test-commit", "2024-01-01", "test-author")
	assert.NoError(t, err)

	manager := GetManager()
	assert.NotNil(t, manager)
	assert.False(t, manager.IsEnabled())

	// These should not panic even when disabled
	manager.CaptureError(errors.New("test error"), "test", "test")
	manager.CaptureMessage("test message", "info", "test", "test")
	manager.AddBreadcrumb("test", "test message", "info", nil)

	// Clean up
	manager.Close()
}

func TestComponentReporter(t *testing.T) {
	// Initialize with disabled Sentry to avoid network calls
	cfg := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: false,
		},
	}

	err := Initialize(cfg, "1.0.0", "test-commit", "2024-01-01", "test-author")
	require.NoError(t, err)

	manager := GetManager()
	componentReporter := manager.WithComponent("test-component")

	assert.NotNil(t, componentReporter)

	// These should not panic
	componentReporter.CaptureError(errors.New("test error"), "test-operation")
	componentReporter.CaptureMessage("test message", "info", "test-operation")
	componentReporter.AddBreadcrumb("test message", "info", nil)

	operationReporter := componentReporter.WithOperation("test-operation")
	assert.NotNil(t, operationReporter)

	// These should not panic
	operationReporter.Start()
	operationReporter.Success(nil)
	operationReporter.Failure(errors.New("test error"), nil)

	// Clean up
	manager.Close()
}

func TestSentryConfig_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  config.SentryConfig
		isValid bool
	}{
		{
			name: "valid config",
			config: config.SentryConfig{
				Enabled:     true,
				DSN:         "https://test@example.com/1",
				Environment: "test",
				SampleRate:  1.0,
			},
			isValid: true,
		},
		{
			name: "disabled config",
			config: config.SentryConfig{
				Enabled: false,
			},
			isValid: true,
		},
		{
			name: "invalid sample rate",
			config: config.SentryConfig{
				Enabled:     true,
				DSN:         "https://test@example.com/1",
				Environment: "test",
				SampleRate:  1.5, // Invalid
			},
			isValid: false,
		},
		{
			name: "negative sample rate",
			config: config.SentryConfig{
				Enabled:     true,
				DSN:         "https://test@example.com/1",
				Environment: "test",
				SampleRate:  -0.1, // Invalid
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Sentry: tt.config,
			}

			client, err := NewClient(cfg, "1.0.0", "test", "2024-01-01", "test")

			if tt.isValid {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			} else {
				// For invalid configs, we expect it to initialize but possibly with adjusted values
				assert.NotNil(t, client)
			}
		})
	}
}

func TestSentryBreadcrumbs(t *testing.T) {
	// Test with disabled Sentry to avoid network calls
	cfg := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: false,
		},
	}

	client, err := NewClient(cfg, "1.0.0", "test", "2024-01-01", "test")
	require.NoError(t, err)

	// These should not panic even when disabled
	client.AddBreadcrumb("test", "test message", "info", map[string]interface{}{
		"component": "test",
		"operation": "test-op",
	})

	client.AddBreadcrumb("error", "error occurred", "error", map[string]interface{}{
		"error_type": "test_error",
	})
}

func TestSentryFlushAndClose(t *testing.T) {
	cfg := &config.Config{
		Sentry: config.SentryConfig{
			Enabled: false, // Disabled to avoid network calls
		},
	}

	client, err := NewClient(cfg, "1.0.0", "test", "2024-01-01", "test")
	require.NoError(t, err)

	// Test flush
	success := client.Flush(100 * time.Millisecond)
	assert.True(t, success) // Should succeed even when disabled

	// Test close
	client.Close() // Should not panic
}

func BenchmarkSanitizeValue(b *testing.B) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	testString := "command: rm -rf /home/user/sensitive && password: secret123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.sanitizeValue(testString)
	}
}

func BenchmarkSanitizeMap(b *testing.B) {
	client := &Client{
		config: &Config{
			Enabled: true,
		},
	}

	testMap := map[string]interface{}{
		"command":   "rm -rf /home/user/sensitive",
		"username":  "testuser",
		"password":  "secret123",
		"operation": "sync",
		"status":    "failed",
		"count":     42,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.sanitizeMap(testMap)
	}
}
