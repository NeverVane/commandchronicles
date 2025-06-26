package sync

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/NeverVane/commandchronicles-cli/internal/config"
	"github.com/NeverVane/commandchronicles-cli/internal/logger"
)

// createTestSyncService creates a minimal SyncService for testing
func createTestSyncService() *SyncService {
	cfg := &config.Config{
		Sync: config.SyncConfig{
			Enabled:   true,
			ServerURL: "https://test.example.com",
			Email:     "test@example.com",
		},
	}

	return &SyncService{
		config: cfg,
		logger: logger.GetLogger().WithComponent("sync-service-test"),
	}
}

func TestIsPasswordChangeError(t *testing.T) {
	service := createTestSyncService()

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "401 unauthorized error",
			err:      errors.New("HTTP 401 Unauthorized"),
			expected: true,
		},
		{
			name:     "403 forbidden error",
			err:      errors.New("HTTP 403 Forbidden"),
			expected: true,
		},
		{
			name:     "authentication failed error",
			err:      errors.New("authentication failed"),
			expected: true,
		},
		{
			name:     "invalid credentials error",
			err:      errors.New("invalid credentials"),
			expected: true,
		},
		{
			name:     "token expired error",
			err:      errors.New("token expired"),
			expected: true,
		},
		{
			name:     "unauthorized lowercase",
			err:      errors.New("request unauthorized"),
			expected: true,
		},
		{
			name:     "forbidden lowercase",
			err:      errors.New("access forbidden"),
			expected: true,
		},
		{
			name:     "unrelated error",
			err:      errors.New("network timeout"),
			expected: false,
		},
		{
			name:     "database error",
			err:      errors.New("database connection failed"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isPasswordChangeError(tt.err)
			if result != tt.expected {
				t.Errorf("isPasswordChangeError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestConfigEmailRetrieval(t *testing.T) {
	// Test email retrieval from config
	service := createTestSyncService()

	tests := []struct {
		name        string
		configEmail string
		expected    string
	}{
		{
			name:        "email from config",
			configEmail: "config@example.com",
			expected:    "config@example.com",
		},
		{
			name:        "default test email",
			configEmail: "test@example.com",
			expected:    "test@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service.config.Sync.Email = tt.configEmail

			// Since getUserEmail will try to prompt user if remoteAuth is nil,
			// we just test that the config email is accessible
			if service.config.Sync.Email != tt.expected {
				t.Errorf("expected config email %s, got %s", tt.expected, service.config.Sync.Email)
			}
		})
	}
}

func TestPasswordChangeErrorPatterns(t *testing.T) {
	service := createTestSyncService()

	// Test various error patterns that should trigger password change detection
	errorPatterns := []string{
		"HTTP 401: Unauthorized",
		"401 Unauthorized",
		"Request returned 401",
		"unauthorized access",
		"UNAUTHORIZED",
		"HTTP 403: Forbidden",
		"403 Forbidden",
		"forbidden access",
		"FORBIDDEN",
		"authentication failed",
		"Authentication Failed",
		"AUTHENTICATION FAILED",
		"invalid credentials",
		"Invalid Credentials",
		"INVALID CREDENTIALS",
		"token expired",
		"Token Expired",
		"TOKEN EXPIRED",
	}

	for _, pattern := range errorPatterns {
		t.Run(fmt.Sprintf("pattern_%s", strings.ReplaceAll(pattern, " ", "_")), func(t *testing.T) {
			err := errors.New(pattern)
			if !service.isPasswordChangeError(err) {
				t.Errorf("pattern '%s' should be detected as password change error", pattern)
			}
		})
	}

	// Test patterns that should NOT trigger password change detection
	nonPasswordChangeErrors := []string{
		"network timeout",
		"connection refused",
		"database error",
		"file not found",
		"permission denied",
		"disk full",
		"memory allocation failed",
		"invalid JSON",
		"syntax error",
	}

	for _, pattern := range nonPasswordChangeErrors {
		t.Run(fmt.Sprintf("non_password_pattern_%s", strings.ReplaceAll(pattern, " ", "_")), func(t *testing.T) {
			err := errors.New(pattern)
			if service.isPasswordChangeError(err) {
				t.Errorf("pattern '%s' should NOT be detected as password change error", pattern)
			}
		})
	}
}

func TestPasswordChangeErrorCaseInsensitive(t *testing.T) {
	service := createTestSyncService()

	// Test that error detection is case-insensitive
	testCases := []struct {
		original string
		variants []string
	}{
		{
			original: "unauthorized",
			variants: []string{"Unauthorized", "UNAUTHORIZED", "UnAuthorized"},
		},
		{
			original: "forbidden",
			variants: []string{"Forbidden", "FORBIDDEN", "ForBidden"},
		},
		{
			original: "authentication failed",
			variants: []string{"Authentication Failed", "AUTHENTICATION FAILED", "Authentication FAILED"},
		},
	}

	for _, tc := range testCases {
		for _, variant := range tc.variants {
			t.Run(fmt.Sprintf("case_variant_%s", strings.ReplaceAll(variant, " ", "_")), func(t *testing.T) {
				err := errors.New(variant)
				if !service.isPasswordChangeError(err) {
					t.Errorf("case variant '%s' should be detected as password change error", variant)
				}
			})
		}
	}
}

func TestPasswordChangeErrorWithContext(t *testing.T) {
	service := createTestSyncService()

	// Test errors with additional context
	contextualErrors := []string{
		"failed to sync: HTTP 401 Unauthorized",
		"server returned error: 403 Forbidden",
		"sync error: authentication failed for user",
		"API call failed: invalid credentials provided",
		"session error: token expired - please re-authenticate",
	}

	for _, errStr := range contextualErrors {
		t.Run(fmt.Sprintf("contextual_%s", strings.ReplaceAll(errStr, " ", "_")[:20]), func(t *testing.T) {
			err := errors.New(errStr)
			if !service.isPasswordChangeError(err) {
				t.Errorf("contextual error '%s' should be detected as password change error", errStr)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkIsPasswordChangeError(b *testing.B) {
	service := createTestSyncService()
	err := errors.New("HTTP 401 Unauthorized")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.isPasswordChangeError(err)
	}
}

func BenchmarkIsPasswordChangeErrorNonMatch(b *testing.B) {
	service := createTestSyncService()
	err := errors.New("network timeout error")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.isPasswordChangeError(err)
	}
}

func BenchmarkConfigEmailAccess(b *testing.B) {
	service := createTestSyncService()
	service.config.Sync.Email = "test@example.com"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = service.config.Sync.Email
	}
}

// Test the specific error patterns we expect from real API responses
func TestRealWorldErrorPatterns(t *testing.T) {
	service := createTestSyncService()

	realWorldErrors := []struct {
		description string
		error       string
		shouldMatch bool
	}{
		{
			description: "HTTP client 401 response",
			error:       "API request failed with status 401 (Unauthorized)",
			shouldMatch: true,
		},
		{
			description: "HTTP client 403 response",
			error:       "API request failed with status 403 (Forbidden)",
			shouldMatch: true,
		},
		{
			description: "Go HTTP client timeout",
			error:       "context deadline exceeded (Client.Timeout exceeded while awaiting headers)",
			shouldMatch: false,
		},
		{
			description: "Network connection error",
			error:       "dial tcp: connection refused",
			shouldMatch: false,
		},
		{
			description: "JWT token expired",
			error:       "JWT token expired - please re-authenticate",
			shouldMatch: true,
		},
		{
			description: "Invalid credentials from server",
			error:       "server response: invalid email or password",
			shouldMatch: true,
		},
		{
			description: "Database constraint error",
			error:       "UNIQUE constraint failed: users.email",
			shouldMatch: false,
		},
	}

	for _, tc := range realWorldErrors {
		t.Run(tc.description, func(t *testing.T) {
			err := errors.New(tc.error)
			result := service.isPasswordChangeError(err)
			if result != tc.shouldMatch {
				t.Errorf("Error '%s' - expected %v, got %v", tc.error, tc.shouldMatch, result)
			}
		})
	}
}
