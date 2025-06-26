package sync

import (
	"fmt"
	"time"
)

// SyncError represents a comprehensive sync error with context and recovery information
type SyncError struct {
	Type        string            `json:"type"`
	Message     string            `json:"message"`
	Code        string            `json:"code"`
	Recoverable bool              `json:"recoverable"`
	RetryAfter  time.Time         `json:"retry_after,omitempty"`
	Context     map[string]string `json:"context,omitempty"`
	Cause       error             `json:"-"`
}

// Error implements the error interface
func (e *SyncError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// Unwrap returns the underlying error for error unwrapping
func (e *SyncError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns true if the error can be retried
func (e *SyncError) IsRetryable() bool {
	return e.Recoverable && (e.RetryAfter.IsZero() || time.Now().After(e.RetryAfter))
}

// Sync error types
const (
	ErrTypeNetwork           = "network"
	ErrTypeIntegrityFailure  = "integrity_failure"
	ErrTypeAuthFailure       = "auth_failure"
	ErrTypeQuotaExceeded     = "quota_exceeded"
	ErrTypeCorruption        = "corruption"
	ErrTypeHashMismatch      = "hash_mismatch"
	ErrTypeInvalidChecksum   = "invalid_checksum"
	ErrTypeTimeout           = "timeout"
	ErrTypeStorageUnavailable = "storage_unavailable"
	ErrTypeInvalidResponse   = "invalid_response"
	ErrTypeConflictResolution = "conflict_resolution"
	ErrTypeResourceExhausted = "resource_exhausted"
)

// Sync error codes
const (
	CodeNetworkTimeout      = "NET_TIMEOUT"
	CodeNetworkUnreachable  = "NET_UNREACHABLE"
	CodeAuthTokenExpired    = "AUTH_TOKEN_EXPIRED"
	CodeAuthInvalidCreds    = "AUTH_INVALID_CREDS"
	CodeQuotaRecordsLimit   = "QUOTA_RECORDS_LIMIT"
	CodeQuotaStorageLimit   = "QUOTA_STORAGE_LIMIT"
	CodeIntegrityHashFail   = "INTEGRITY_HASH_FAIL"
	CodeIntegrityCorrupted  = "INTEGRITY_CORRUPTED"
	CodeStorageLocked       = "STORAGE_LOCKED"
	CodeStorageCorrupted    = "STORAGE_CORRUPTED"
	CodeServerError         = "SERVER_ERROR"
	CodeInvalidPayload      = "INVALID_PAYLOAD"
)

// NewSyncError creates a new sync error with the given parameters
func NewSyncError(errType, message, code string, recoverable bool, cause error) *SyncError {
	return &SyncError{
		Type:        errType,
		Message:     message,
		Code:        code,
		Recoverable: recoverable,
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// NewNetworkError creates a network-related sync error
func NewNetworkError(message string, cause error) *SyncError {
	return &SyncError{
		Type:        ErrTypeNetwork,
		Message:     message,
		Code:        CodeNetworkTimeout,
		Recoverable: true,
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// NewAuthError creates an authentication-related sync error
func NewAuthError(message string, cause error) *SyncError {
	return &SyncError{
		Type:        ErrTypeAuthFailure,
		Message:     message,
		Code:        CodeAuthTokenExpired,
		Recoverable: true,
		RetryAfter:  time.Now().Add(5 * time.Minute), // Wait 5 minutes before retry
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// NewIntegrityError creates an integrity-related sync error
func NewIntegrityError(message string, cause error) *SyncError {
	return &SyncError{
		Type:        ErrTypeIntegrityFailure,
		Message:     message,
		Code:        CodeIntegrityHashFail,
		Recoverable: false, // Integrity failures usually require manual intervention
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// NewQuotaError creates a quota-related sync error
func NewQuotaError(message string, cause error) *SyncError {
	return &SyncError{
		Type:        ErrTypeQuotaExceeded,
		Message:     message,
		Code:        CodeQuotaRecordsLimit,
		Recoverable: false, // Quota errors require user action
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// NewCorruptionError creates a corruption-related sync error
func NewCorruptionError(message string, cause error) *SyncError {
	return &SyncError{
		Type:        ErrTypeCorruption,
		Message:     message,
		Code:        CodeStorageCorrupted,
		Recoverable: false, // Corruption requires manual recovery
		Context:     make(map[string]string),
		Cause:       cause,
	}
}

// AddContext adds contextual information to the error
func (e *SyncError) AddContext(key, value string) *SyncError {
	if e.Context == nil {
		e.Context = make(map[string]string)
	}
	e.Context[key] = value
	return e
}

// WithRetryAfter sets the retry time for the error
func (e *SyncError) WithRetryAfter(retryAfter time.Time) *SyncError {
	e.RetryAfter = retryAfter
	return e
}

// ErrorClassifier helps classify and handle different types of errors
type ErrorClassifier struct{}

// NewErrorClassifier creates a new error classifier
func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{}
}

// ClassifyError analyzes an error and returns an appropriate SyncError
func (ec *ErrorClassifier) ClassifyError(err error) *SyncError {
	if err == nil {
		return nil
	}

	// Check if it's already a SyncError
	if syncErr, ok := err.(*SyncError); ok {
		return syncErr
	}

	// Classify based on error message patterns
	errMsg := err.Error()
	
	// Network-related errors
	if containsAny(errMsg, []string{"timeout", "connection refused", "no such host", "network unreachable"}) {
		return NewNetworkError("Network connectivity issue", err)
	}
	
	// Authentication errors
	if containsAny(errMsg, []string{"unauthorized", "authentication", "token expired", "invalid credentials"}) {
		return NewAuthError("Authentication failure", err)
	}
	
	// Storage errors
	if containsAny(errMsg, []string{"storage locked", "session expired", "encryption failed"}) {
		return NewSyncError(ErrTypeStorageUnavailable, "Storage unavailable", CodeStorageLocked, true, err)
	}
	
	// Integrity errors
	if containsAny(errMsg, []string{"hash mismatch", "checksum invalid", "integrity", "corrupted"}) {
		return NewIntegrityError("Data integrity issue", err)
	}
	
	// Default to network error with retry capability
	return NewNetworkError("Unknown sync error", err)
}

// RetryStrategy defines how to handle retries for different error types
type RetryStrategy struct {
	MaxRetries        int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
	RetryableErrors   map[string]bool
}

// DefaultRetryStrategy returns a sensible default retry strategy
func DefaultRetryStrategy() *RetryStrategy {
	return &RetryStrategy{
		MaxRetries:        3,
		InitialDelay:      1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
		RetryableErrors: map[string]bool{
			ErrTypeNetwork:           true,
			ErrTypeTimeout:           true,
			ErrTypeResourceExhausted: true,
			ErrTypeAuthFailure:       true,
		},
	}
}

// ShouldRetry determines if an error should be retried
func (rs *RetryStrategy) ShouldRetry(err *SyncError, attempt int) bool {
	if attempt >= rs.MaxRetries {
		return false
	}
	
	if !err.Recoverable {
		return false
	}
	
	if !err.IsRetryable() {
		return false
	}
	
	return rs.RetryableErrors[err.Type]
}

// GetDelay calculates the delay before the next retry attempt
func (rs *RetryStrategy) GetDelay(attempt int) time.Duration {
	delay := time.Duration(float64(rs.InitialDelay) * pow(rs.BackoffMultiplier, float64(attempt)))
	if delay > rs.MaxDelay {
		delay = rs.MaxDelay
	}
	return delay
}

// RecoveryAction represents an action to take when recovering from sync errors
type RecoveryAction struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
	Automatic   bool   `json:"automatic"`
}

// Recovery action types
const (
	RecoveryTypeRetry           = "retry"
	RecoveryTypeReauthenticate  = "reauthenticate"
	RecoveryTypeRebuildCache    = "rebuild_cache"
	RecoveryTypeValidateStorage = "validate_storage"
	RecoveryTypeFullResync      = "full_resync"
	RecoveryTypeManualIntervention = "manual_intervention"
)

// RecoveryManager provides recovery suggestions for different error types
type RecoveryManager struct {
	classifier *ErrorClassifier
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager() *RecoveryManager {
	return &RecoveryManager{
		classifier: NewErrorClassifier(),
	}
}

// GetRecoveryActions returns suggested recovery actions for an error
func (rm *RecoveryManager) GetRecoveryActions(err error) []RecoveryAction {
	syncErr := rm.classifier.ClassifyError(err)
	if syncErr == nil {
		return nil
	}
	
	switch syncErr.Type {
	case ErrTypeNetwork:
		return []RecoveryAction{
			{Type: RecoveryTypeRetry, Description: "Retry the operation", Automatic: true},
		}
	case ErrTypeAuthFailure:
		return []RecoveryAction{
			{Type: RecoveryTypeReauthenticate, Description: "Re-authenticate with the sync server", Command: "ccr sync enable", Automatic: false},
		}
	case ErrTypeIntegrityFailure:
		return []RecoveryAction{
			{Type: RecoveryTypeValidateStorage, Description: "Validate local storage integrity", Command: "ccr sync integrity", Automatic: false},
			{Type: RecoveryTypeFullResync, Description: "Perform full resync", Command: "ccr sync now", Automatic: false},
		}
	case ErrTypeCorruption:
		return []RecoveryAction{
			{Type: RecoveryTypeManualIntervention, Description: "Manual data recovery required", Automatic: false},
		}
	case ErrTypeQuotaExceeded:
		return []RecoveryAction{
			{Type: RecoveryTypeManualIntervention, Description: "Upgrade storage quota or clean up old records", Automatic: false},
		}
	default:
		return []RecoveryAction{
			{Type: RecoveryTypeRetry, Description: "Retry the operation", Automatic: true},
		}
	}
}

// Helper functions

func containsAny(str string, patterns []string) bool {
	for _, pattern := range patterns {
		if len(str) >= len(pattern) {
			for i := 0; i <= len(str)-len(pattern); i++ {
				if str[i:i+len(pattern)] == pattern {
					return true
				}
			}
		}
	}
	return false
}

func pow(base, exp float64) float64 {
	if exp == 0 {
		return 1
	}
	result := base
	for i := 1; i < int(exp); i++ {
		result *= base
	}
	return result
}