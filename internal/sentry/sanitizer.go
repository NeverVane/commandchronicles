package sentry

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getsentry/sentry-go"
)

// SensitivePatterns contains regex patterns for detecting sensitive information
var SensitivePatterns = struct {
	Command  *regexp.Regexp
	FilePath *regexp.Regexp
	Username *regexp.Regexp
	Email    *regexp.Regexp
	Token    *regexp.Regexp
	Key      *regexp.Regexp
	Password *regexp.Regexp
	HomeDir  *regexp.Regexp
	SQLQuery *regexp.Regexp
}{
	Command:  regexp.MustCompile(`(?i)(command|cmd|exec|run)[:=]\s*['""]?([^'""]+)['""]?`),
	FilePath: regexp.MustCompile(`(?i)(/home/[^/\s]+|/Users/[^/\s]+|C:\\Users\\[^\\]+|[A-Za-z]:\\Users\\[^\\]+)`),
	Username: regexp.MustCompile(`(?i)(user|username|login)[:=]\s*['""]?([^'""]+)['""]?`),
	Email:    regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`),
	Token:    regexp.MustCompile(`(?i)(token|jwt|bearer|auth)[:=]\s*['""]?([a-zA-Z0-9._-]+)['""]?`),
	Key:      regexp.MustCompile(`(?i)(key|secret|password|pass)[:=]\s*['""]?([^'""]+)['""]?`),
	Password: regexp.MustCompile(`(?i)(password|passwd|pwd)[:=]\s*['""]?([^'""]+)['""]?`),
	HomeDir:  regexp.MustCompile(`(?i)(home|user).*?[/\\]([^/\\]+)[/\\]`),
	SQLQuery: regexp.MustCompile(`(?i)(select|insert|update|delete|create|drop|alter).*?from.*?`),
}

// SensitiveFields contains field names that should be sanitized
var SensitiveFields = []string{
	"command", "cmd", "exec", "run", "query", "sql",
	"user", "username", "login", "email", "mail",
	"password", "passwd", "pwd", "pass", "secret",
	"token", "jwt", "bearer", "auth", "key",
	"path", "file", "filename", "filepath", "dir", "directory",
	"data", "payload", "body", "content", "message",
	"session", "session_id", "session_key",
	"encrypted", "encrypted_data", "cipher",
}

// sanitizeValue sanitizes a string value by removing or redacting sensitive information
func (c *Client) sanitizeValue(value string) string {
	if value == "" {
		return value
	}

	// Remove command content
	if SensitivePatterns.Command.MatchString(value) {
		value = SensitivePatterns.Command.ReplaceAllString(value, "${1}: [REDACTED]")
	}

	// Sanitize file paths
	if SensitivePatterns.FilePath.MatchString(value) {
		value = SensitivePatterns.FilePath.ReplaceAllString(value, "/[USER_HOME]/...")
	}

	// Remove usernames
	if SensitivePatterns.Username.MatchString(value) {
		value = SensitivePatterns.Username.ReplaceAllString(value, "${1}: [REDACTED]")
	}

	// Remove email addresses
	if SensitivePatterns.Email.MatchString(value) {
		value = SensitivePatterns.Email.ReplaceAllString(value, "[EMAIL_REDACTED]")
	}

	// Remove tokens
	if SensitivePatterns.Token.MatchString(value) {
		value = SensitivePatterns.Token.ReplaceAllString(value, "${1}: [REDACTED]")
	}

	// Remove keys and passwords
	if SensitivePatterns.Key.MatchString(value) {
		value = SensitivePatterns.Key.ReplaceAllString(value, "${1}: [REDACTED]")
	}

	if SensitivePatterns.Password.MatchString(value) {
		value = SensitivePatterns.Password.ReplaceAllString(value, "${1}: [REDACTED]")
	}

	// Sanitize SQL queries
	if SensitivePatterns.SQLQuery.MatchString(value) {
		value = "[SQL_QUERY_REDACTED]"
	}

	return value
}

// sanitizeFilePath sanitizes file paths to remove personal information
func (c *Client) sanitizeFilePath(path string) string {
	if path == "" {
		return path
	}

	// Clean the path
	cleanPath := filepath.Clean(path)

	// Replace home directories
	if strings.Contains(cleanPath, "/home/") {
		parts := strings.Split(cleanPath, "/")
		for i := range parts {
			if i > 0 && parts[i-1] == "home" {
				parts[i] = "[USER]"
				break
			}
		}
		cleanPath = strings.Join(parts, "/")
	}

	if strings.Contains(cleanPath, "/Users/") {
		parts := strings.Split(cleanPath, "/")
		for i := range parts {
			if i > 0 && parts[i-1] == "Users" {
				parts[i] = "[USER]"
				break
			}
		}
		cleanPath = strings.Join(parts, "/")
	}

	// Replace Windows user directories
	if strings.Contains(cleanPath, "\\Users\\") {
		parts := strings.Split(cleanPath, "\\")
		for i := range parts {
			if i > 0 && parts[i-1] == "Users" {
				parts[i] = "[USER]"
				break
			}
		}
		cleanPath = strings.Join(parts, "\\")
	}

	return cleanPath
}

// sanitizeMap sanitizes a map of string values
func (c *Client) sanitizeMap(data map[string]interface{}) map[string]interface{} {
	if data == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	for key, value := range data {
		sanitizedKey := strings.ToLower(key)

		// Check if this is a sensitive field
		isSensitive := false
		for _, sensitiveField := range SensitiveFields {
			if strings.Contains(sanitizedKey, sensitiveField) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			sanitized[key] = "[REDACTED]"
		} else if strValue, ok := value.(string); ok {
			sanitized[key] = c.sanitizeValue(strValue)
		} else {
			sanitized[key] = value
		}
	}

	return sanitized
}

// sanitizeEvent sanitizes a Sentry event before sending
func (c *Client) sanitizeEvent(event *sentry.Event) *sentry.Event {
	if event == nil {
		return event
	}

	// Sanitize message
	if event.Message != "" {
		event.Message = c.sanitizeValue(event.Message)
	}

	// Sanitize exception messages
	for i, exception := range event.Exception {
		if exception.Value != "" {
			event.Exception[i].Value = c.sanitizeValue(exception.Value)
		}
	}

	// Sanitize tags
	for key, value := range event.Tags {
		sanitizedKey := strings.ToLower(key)
		isSensitive := false
		for _, sensitiveField := range SensitiveFields {
			if strings.Contains(sanitizedKey, sensitiveField) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			event.Tags[key] = "[REDACTED]"
		} else {
			event.Tags[key] = c.sanitizeValue(value)
		}
	}

	// Sanitize contexts
	for contextKey, contextValue := range event.Contexts {
		// Handle sentry.Context type properly
		if contextValue != nil {
			// Convert sentry.Context to map for sanitization
			contextMap := make(map[string]interface{})
			// Copy safe fields only - avoid reflection for security
			event.Contexts[contextKey] = contextMap
		}
	}

	// Sanitize extra data
	if event.Extra != nil {
		event.Extra = c.sanitizeMap(event.Extra)
	}

	// Sanitize user data (remove completely to be safe)
	if event.User.ID != "" || event.User.Username != "" || event.User.Email != "" {
		event.User = sentry.User{
			ID:       "[REDACTED]",
			Username: "[REDACTED]",
			Email:    "[REDACTED]",
		}
	}

	// Sanitize request data
	if event.Request != nil {
		if event.Request.URL != "" {
			event.Request.URL = c.sanitizeValue(event.Request.URL)
		}
		if event.Request.QueryString != "" {
			event.Request.QueryString = "[REDACTED]"
		}
		if event.Request.Data != "" {
			event.Request.Data = c.sanitizeValue(event.Request.Data)
		}
		if event.Request.Headers != nil {
			for key := range event.Request.Headers {
				if strings.ToLower(key) == "authorization" ||
					strings.ToLower(key) == "cookie" ||
					strings.ToLower(key) == "x-api-key" {
					event.Request.Headers[key] = "[REDACTED]"
				}
			}
		}
	}

	return event
}

// sanitizeBreadcrumb sanitizes a Sentry breadcrumb before adding
func (c *Client) sanitizeBreadcrumb(breadcrumb *sentry.Breadcrumb) *sentry.Breadcrumb {
	if breadcrumb == nil {
		return breadcrumb
	}

	// Sanitize message
	if breadcrumb.Message != "" {
		breadcrumb.Message = c.sanitizeValue(breadcrumb.Message)
	}

	// Sanitize data
	if breadcrumb.Data != nil {
		breadcrumb.Data = c.sanitizeMap(breadcrumb.Data)
	}

	// Sanitize category if it contains sensitive information
	if breadcrumb.Category != "" {
		breadcrumb.Category = c.sanitizeValue(breadcrumb.Category)
	}

	return breadcrumb
}

// IsSensitiveError checks if an error message contains sensitive information
func (c *Client) IsSensitiveError(err error) bool {
	if err == nil {
		return false
	}

	errorMsg := strings.ToLower(err.Error())

	// Check for sensitive patterns in error message
	sensitiveKeywords := []string{
		"password", "passwd", "pwd", "pass",
		"token", "jwt", "bearer", "auth",
		"key", "secret", "credential",
		"session", "cookie",
		"command", "cmd", "exec",
		"user", "username", "login",
		"path", "file", "directory",
	}

	for _, keyword := range sensitiveKeywords {
		if strings.Contains(errorMsg, keyword) {
			return true
		}
	}

	return false
}

// GetSafeErrorMessage returns a safe version of an error message
func (c *Client) GetSafeErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	if c.IsSensitiveError(err) {
		// Return a generic error message for sensitive errors
		return "[SENSITIVE_ERROR_REDACTED]"
	}

	return c.sanitizeValue(err.Error())
}

// GetSafeComponentContext returns safe context information for a component
func (c *Client) GetSafeComponentContext(component, operation string) map[string]interface{} {
	return map[string]interface{}{
		"component":        component,
		"operation":        operation,
		"timestamp":        "[TIMESTAMP]", // Will be set by Sentry
		"safe_mode":        true,
		"privacy_filtered": true,
	}
}
