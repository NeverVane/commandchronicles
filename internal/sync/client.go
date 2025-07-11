package sync

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/NeverVane/commandchronicles/internal/config"
	"github.com/NeverVane/commandchronicles/internal/logger"
)

type SyncClient struct {
	config     *config.Config
	logger     *logger.Logger
	httpClient *http.Client
	remoteAuth *RemoteAuthenticator
}

// Auth endpoint types
type RegisterRequest struct {
	Email           string             `json:"email"`
	Password        string             `json:"password"`
	ConfirmPassword string             `json:"confirm_password"`
	Device          DeviceRegistration `json:"device"`
}

type RegisterResponse struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	AccessToken string `json:"access_token"`
	ExpiresAt   int64  `json:"expires_at"`
	DeviceID    string `json:"device_id"`
}

type LoginRequest struct {
	Email    string             `json:"email"`
	Password string             `json:"password"`
	Device   DeviceRegistration `json:"device"`
}

type LoginResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type LogoutRequest struct {
	DeviceID string `json:"device_id"`
}

type DeviceRegistration struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Hostname   string `json:"hostname"`
	Platform   string `json:"platform"`
	UserAgent  string `json:"user_agent"`
}

// Health endpoint types
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
	Database  string `json:"database"`
	Uptime    string `json:"uptime"`
}

type DetailedHealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
	Uptime    string `json:"uptime"`
	Database  struct {
		Status            string `json:"status"`
		MaxOpenConns      int    `json:"max_open_conns"`
		OpenConns         int    `json:"open_conns"`
		InUse             int    `json:"in_use"`
		Idle              int    `json:"idle"`
		WaitCount         int64  `json:"wait_count"`
		WaitDuration      string `json:"wait_duration"`
		MaxIdleClosed     int64  `json:"max_idle_closed"`
		MaxIdleTimeClosed int64  `json:"max_idle_time_closed"`
		MaxLifetimeClosed int64  `json:"max_lifetime_closed"`
	} `json:"database"`
	System struct {
		StartTime     string  `json:"start_time"`
		UptimeSeconds float64 `json:"uptime_seconds"`
	} `json:"system"`
}

// Sync endpoint types
type SyncUploadRequest struct {
	DeviceID string       `json:"device_id"`
	Records  []SyncRecord `json:"records"`
	Metadata SyncMetadata `json:"metadata"`
}

type SyncRecord struct {
	RecordHash       string   `json:"record_hash"`
	EncryptedPayload []byte   `json:"encrypted_payload"`
	TimestampMs      int64    `json:"timestamp_ms"`
	Hostname         string   `json:"hostname"`
	SessionID        string   `json:"session_id"`
	TargetDevices    []string `json:"target_devices,omitempty"` // Routing metadata
}

type SyncMetadata struct {
	ClientVersion    string `json:"client_version"`
	LastSyncTime     int64  `json:"last_sync_time"`
	TotalRecordCount int    `json:"total_record_count"`
}

type SyncUploadResponse struct {
	Success        bool   `json:"success"`
	ProcessedCount int    `json:"processed_count"`
	DuplicateCount int    `json:"duplicate_count"`
	ErrorCount     int    `json:"error_count"`
	Conflicts      int    `json:"conflicts,omitempty"`
	SyncSessionID  string `json:"sync_session_id"`
}

type ConflictInfo struct {
	LocalHash  string `json:"local_hash"`
	RemoteHash string `json:"remote_hash"`
	Resolution string `json:"resolution"`
	Timestamp  int64  `json:"timestamp"`
}

type SyncDownloadResponse struct {
	Records       []SyncRecord `json:"records"`
	HasMore       bool         `json:"has_more"`
	NextTimestamp int64        `json:"next_timestamp,omitempty"`
	TotalCount    int          `json:"total_count"`
	SyncSessionID string       `json:"sync_session_id"`
}

type SyncStatusResponse struct {
	LastSyncTime   int64 `json:"last_sync_time"`
	TotalRecords   int   `json:"total_records"`
	PendingUploads int   `json:"pending_uploads"`
	RecentSessions []struct {
		ID                string `json:"id"`
		StartedAt         string `json:"started_at"`
		CompletedAt       string `json:"completed_at"`
		RecordsUploaded   int    `json:"records_uploaded"`
		RecordsDownloaded int    `json:"records_downloaded"`
		ConflictsResolved int    `json:"conflicts_resolved"`
		Status            string `json:"status"`
	} `json:"recent_sessions"`
	DeviceCount int   `json:"device_count"`
	StorageUsed int64 `json:"storage_used"`
}

type CleanupRequest struct {
	RetentionDays int `json:"retention_days"`
}

type CleanupResponse struct {
	Success      bool   `json:"success"`
	DeletedCount int    `json:"deleted_count"`
	Message      string `json:"message"`
}

// User management types
type UserProfile struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	CreatedAt   string `json:"created_at"`
	LastLogin   string `json:"last_login"`
	DeviceCount int    `json:"device_count"`
	RecordCount int    `json:"record_count"`
	StorageUsed int64  `json:"storage_used"`
	IsActive    bool   `json:"is_active"`
}

type UpdateProfileRequest struct {
	Email string `json:"email,omitempty"`
}

type UserDevice struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform"`
	LastSeen    string `json:"last_seen"`
	CreatedAt   string `json:"created_at"`
	RecordCount int    `json:"record_count"`
	IsActive    bool   `json:"is_active"`
}

type DeleteDeviceResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	RecordsDeleted int    `json:"records_deleted"`
}

type DeleteAccountRequest struct {
	Confirmation string `json:"confirmation"`
}

type DeleteAccountResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	DeletedAt string `json:"deleted_at"`
}

type DevicesResponse struct {
	Devices []ServerDevice `json:"devices"`
}

type ServerDevice struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	LastSeen string `json:"last_seen"`
	IsActive bool   `json:"is_active"`
}

// ServerPasswordChangeRequest represents the request to change password on server
type ServerPasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// ServerPasswordChangeResponse represents the response from server password change
type ServerPasswordChangeResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// Generic response types
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type ServerErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Code    string                 `json:"code"`
	Details map[string]interface{} `json:"details,omitempty"`
}

func NewSyncClient(cfg *config.Config, remoteAuth *RemoteAuthenticator) *SyncClient {
	return &SyncClient{
		config:     cfg,
		logger:     logger.GetLogger().WithComponent("sync-client"),
		remoteAuth: remoteAuth,
		httpClient: &http.Client{
			Timeout: cfg.GetSyncTimeout(),
		},
	}
}

// Helper method to build API URL
func (sc *SyncClient) apiURL(endpoint string) string {
	return sc.config.GetSyncServerURL() + "/api/v1" + endpoint
}

// Helper method to create authenticated request
func (sc *SyncClient) newAuthenticatedRequest(method, url string, body []byte) (*http.Request, error) {
	token, err := sc.remoteAuth.GetValidToken()
	if err != nil {
		return nil, fmt.Errorf("authentication required: %w", err)
	}

	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewBuffer(body)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	return req, nil
}

// Helper method to handle API responses
func (sc *SyncClient) handleResponse(resp *http.Response, result interface{}) error {
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Read the raw response body first
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("API request failed with status %d (failed to read response body: %v)", resp.StatusCode, readErr)
		}

		// Try to parse as structured error response
		var errResp ServerErrorResponse
		if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
			// If JSON parsing fails, show raw response
			return fmt.Errorf("API request failed with status %d - raw response: %s", resp.StatusCode, string(bodyBytes))
		}

		// Return structured error
		return fmt.Errorf("API error: %s - %s", errResp.Error, errResp.Message)
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}

	return nil
}

// Auth endpoints
func (sc *SyncClient) Register(email, password, confirmPassword string, device DeviceRegistration) (*RegisterResponse, error) {
	req := RegisterRequest{
		Email:           email,
		Password:        password,
		ConfirmPassword: confirmPassword,
		Device:          device,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal register request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", sc.apiURL("/auth/register"), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("register request failed: %w", err)
	}

	var result RegisterResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) Login(email, password string, device DeviceRegistration) (*LoginResponse, error) {
	req := LoginRequest{
		Email:    email,
		Password: password,
		Device:   device,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", sc.apiURL("/auth/login"), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}

	var result LoginResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) RefreshToken(refreshToken string) (*LoginResponse, error) {
	req := RefreshRequest{RefreshToken: refreshToken}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal refresh request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", sc.apiURL("/auth/refresh"), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}

	var result LoginResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) Logout(deviceID string) error {
	req := LogoutRequest{DeviceID: deviceID}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal logout request: %w", err)
	}

	httpReq, err := sc.newAuthenticatedRequest("POST", sc.apiURL("/auth/logout"), reqBody)
	if err != nil {
		return err
	}

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("logout request failed: %w", err)
	}

	var result SuccessResponse
	return sc.handleResponse(resp, &result)
}

// Health endpoints
func (sc *SyncClient) Health() (*HealthResponse, error) {
	resp, err := sc.httpClient.Get(sc.apiURL("/health"))
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}

	var result HealthResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) DetailedHealth() (*DetailedHealthResponse, error) {
	resp, err := sc.httpClient.Get(sc.apiURL("/health/detailed"))
	if err != nil {
		return nil, fmt.Errorf("detailed health check failed: %w", err)
	}

	var result DetailedHealthResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

// Sync endpoints
func (sc *SyncClient) UploadRecords(records []SyncRecord, deviceID string, metadata SyncMetadata) (*SyncUploadResponse, error) {
	syncReq := SyncUploadRequest{
		Records:  records,
		DeviceID: deviceID,
		Metadata: metadata,
	}

	reqBody, err := json.Marshal(syncReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sync request: %w", err)
	}

	req, err := sc.newAuthenticatedRequest("POST", sc.apiURL("/sync/upload"), reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload request failed: %w", err)
	}

	var result SyncUploadResponse
	err = sc.handleResponse(resp, &result)
	if err != nil {
		return nil, err
	}

	sc.logger.Info().
		Int("uploaded", len(records)).
		Int("processed", result.ProcessedCount).
		Int("conflicts", result.Conflicts).
		Str("session_id", result.SyncSessionID).
		Msg("Upload completed")

	return &result, nil
}

func (sc *SyncClient) DownloadRecords(deviceID string, since int64, limit int, includeDeleted bool) (*SyncDownloadResponse, error) {
	url := fmt.Sprintf("%s/sync/download?device_id=%s", sc.apiURL(""), deviceID)
	url += fmt.Sprintf("&since=%d", since)
	if limit > 0 {
		url += fmt.Sprintf("&limit=%d", limit)
	}
	if includeDeleted {
		url += "&include_deleted=true"
	}

	req, err := sc.newAuthenticatedRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download request failed: %w", err)
	}

	var result SyncDownloadResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) GetSyncStatus(deviceID string) (*SyncStatusResponse, error) {
	url := fmt.Sprintf("%s/sync/status?device_id=%s", sc.apiURL(""), deviceID)

	req, err := sc.newAuthenticatedRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sync status request failed: %w", err)
	}

	var result SyncStatusResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

// VerifyIntegrity performs Perfect Sync integrity verification with the server
func (sc *SyncClient) VerifyIntegrity(request *PerfectSyncRequest) (*PerfectSyncResponse, error) {
	// Log request details, especially for empty hash lists
	isEmptyRequest := len(request.LocalState.AllHashes) == 0
	sc.logger.Debug().
		Str("device_id", request.DeviceID).
		Int("record_count", request.LocalState.RecordCount).
		Int("hash_count", len(request.LocalState.AllHashes)).
		Bool("empty_request", isEmptyRequest).
		Str("sync_type", request.RequestMetadata.SyncType).
		Msg("Sending integrity verification request")

	if isEmptyRequest {
		sc.logger.Info().Msg("Sending empty integrity verification request - client has no local records")
	}

	start := time.Now()

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal integrity request: %w", err)
	}

	sc.logger.Debug().
		Int("request_size_bytes", len(reqBody)).
		Msg("Integrity request prepared")

	url := fmt.Sprintf("%s/sync/verify-integrity", sc.apiURL(""))
	httpReq, err := sc.newAuthenticatedRequest("POST", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create integrity request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("integrity verification request failed: %w", err)
	}

	// Enhanced response validation
	if resp == nil {
		return nil, fmt.Errorf("received nil response from server")
	}

	sc.logger.Debug().
		Int("status_code", resp.StatusCode).
		Int64("content_length", resp.ContentLength).
		Msg("Received integrity verification response")

	// Check for empty response body
	if resp.ContentLength == 0 {
		sc.logger.Warn().Msg("Server returned empty response for integrity verification")
		// Return a default response for empty server response
		return &PerfectSyncResponse{
			SyncSessionID:   request.SyncSessionID,
			IntegrityStatus: "perfect",
			ServerState: ServerState{
				TotalRecordsForUser: 0,
				HashChecksum:        "",
				LatestTimestamp:     0,
			},
			SyncActions: SyncActions{
				MissingRecords:   []MissingRecord{},
				OrphanedHashes:   []string{},
				ConflictedHashes: []string{},
			},
			Statistics: SyncStatistics{
				RecordsToDownload: 0,
				RecordsToRemove:   0,
				PerfectMatches:    0,
				IntegrityScore:    1.0,
			},
		}, nil
	}

	var result PerfectSyncResponse
	if err := sc.handleResponse(resp, &result); err != nil {
		sc.logger.Error().
			Err(err).
			Int("status_code", resp.StatusCode).
			Int64("content_length", resp.ContentLength).
			Bool("empty_request", isEmptyRequest).
			Msg("Failed to handle integrity verification response")

		// Handle specific EOF errors with graceful fallback
		if err.Error() == "EOF" || strings.Contains(err.Error(), "EOF") {
			sc.logger.Warn().Msg("Server closed connection unexpectedly (EOF), providing fallback response")

			// Return a safe fallback response for EOF errors
			return &PerfectSyncResponse{
				SyncSessionID:   request.SyncSessionID,
				IntegrityStatus: "needs_sync",
				ServerState: ServerState{
					TotalRecordsForUser: 0,
					HashChecksum:        "",
					LatestTimestamp:     0,
				},
				SyncActions: SyncActions{
					MissingRecords:   []MissingRecord{},
					OrphanedHashes:   request.LocalState.AllHashes, // Assume all local records are orphaned
					ConflictedHashes: []string{},
				},
				Statistics: SyncStatistics{
					RecordsToDownload: 0,
					RecordsToRemove:   len(request.LocalState.AllHashes),
					PerfectMatches:    0,
					IntegrityScore:    0.0,
				},
			}, nil
		}

		// Handle JSON parsing errors with more context
		if strings.Contains(err.Error(), "cannot unmarshal") || strings.Contains(err.Error(), "invalid character") {
			sc.logger.Error().Msg("Server returned malformed JSON response")
			return nil, fmt.Errorf("server returned invalid JSON response for integrity verification: %w", err)
		}

		// Provide more context for empty request failures
		if isEmptyRequest {
			return nil, fmt.Errorf("failed to handle integrity response for empty request (client has no records): %w", err)
		}
		return nil, fmt.Errorf("failed to handle integrity response: %w", err)
	}

	duration := time.Since(start)
	sc.logger.Info().
		Dur("duration", duration).
		Str("integrity_status", result.IntegrityStatus).
		Int("records_to_download", result.Statistics.RecordsToDownload).
		Int("records_to_remove", result.Statistics.RecordsToRemove).
		Float64("integrity_score", result.Statistics.IntegrityScore).
		Bool("empty_request", isEmptyRequest).
		Msg("Integrity verification completed")

	return &result, nil
}

func (sc *SyncClient) CleanupOldRecords(retentionDays int) (*CleanupResponse, error) {
	req := CleanupRequest{RetentionDays: retentionDays}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal cleanup request: %w", err)
	}

	httpReq, err := sc.newAuthenticatedRequest("POST", sc.apiURL("/sync/cleanup"), reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("cleanup request failed: %w", err)
	}

	var result CleanupResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

// User management endpoints
func (sc *SyncClient) GetUserProfile() (*UserProfile, error) {
	req, err := sc.newAuthenticatedRequest("GET", sc.apiURL("/user/profile"), nil)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get profile request failed: %w", err)
	}

	var result UserProfile
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) UpdateUserProfile(email string) (*UserProfile, error) {
	req := UpdateProfileRequest{Email: email}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal update profile request: %w", err)
	}

	httpReq, err := sc.newAuthenticatedRequest("PUT", sc.apiURL("/user/profile"), reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("update profile request failed: %w", err)
	}

	var result UserProfile
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) GetUserDevices() (*DevicesResponse, error) {
	req, err := sc.newAuthenticatedRequest("GET", sc.apiURL("/user/devices"), nil)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get devices request failed: %w", err)
	}

	var result DevicesResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) DeleteDevice(deviceID string) (*DeleteDeviceResponse, error) {
	url := fmt.Sprintf("%s/user/devices/%s", sc.apiURL(""), deviceID)

	req, err := sc.newAuthenticatedRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("delete device request failed: %w", err)
	}

	var result DeleteDeviceResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

func (sc *SyncClient) DeleteAccount() (*DeleteAccountResponse, error) {
	req := DeleteAccountRequest{Confirmation: "DELETE_ACCOUNT"}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal delete account request: %w", err)
	}

	httpReq, err := sc.newAuthenticatedRequest("DELETE", sc.apiURL("/user/account"), reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("delete account request failed: %w", err)
	}

	var result DeleteAccountResponse
	err = sc.handleResponse(resp, &result)
	return &result, err
}

// BatchUpdateRecords uploads a batch of re-encrypted records during password change
func (sc *SyncClient) BatchUpdateRecords(request *BatchUpdateRequest) error {
	reqBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal batch update request: %w", err)
	}

	url := fmt.Sprintf("%s/sync/batch-update", sc.apiURL(""))
	httpReq, err := sc.newAuthenticatedRequest("PUT", url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create batch update request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("batch update request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return sc.handleBatchUpdateError(resp)
	}

	sc.logger.Debug().
		Int("batch_number", request.BatchMetadata.BatchNumber).
		Bool("is_last_batch", request.BatchMetadata.IsLastBatch).
		Int("record_count", len(request.Records)).
		Msg("Batch update completed successfully")

	return nil
}

// GetPasswordChangeLockStatus checks the status of password change lock
func (sc *SyncClient) GetPasswordChangeLockStatus() (*PasswordChangeLockStatus, error) {
	url := fmt.Sprintf("%s/user/password/lock-status", sc.apiURL(""))

	httpReq, err := sc.newAuthenticatedRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create lock status request: %w", err)
	}

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("lock status request failed: %w", err)
	}
	defer resp.Body.Close()

	var lockStatus PasswordChangeLockStatus
	if err := sc.handleResponse(resp, &lockStatus); err != nil {
		return nil, fmt.Errorf("failed to parse lock status response: %w", err)
	}

	return &lockStatus, nil
}

// ChangeServerPassword changes password on server and acquires password change lock
func (sc *SyncClient) ChangeServerPassword(currentPasswordHex, newPasswordHex string) (*ServerPasswordChangeResponse, error) {
	request := &ServerPasswordChangeRequest{
		CurrentPassword: currentPasswordHex,
		NewPassword:     newPasswordHex,
		ConfirmPassword: newPasswordHex,
	}

	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal password change request: %w", err)
	}

	url := fmt.Sprintf("%s/user/password", sc.apiURL(""))
	httpReq, err := sc.newAuthenticatedRequest("PUT", url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create password change request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := sc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("password change request failed: %w", err)
	}
	defer resp.Body.Close()

	var result ServerPasswordChangeResponse
	if err := sc.handleResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("password change failed: %w", err)
	}

	sc.logger.Info().
		Bool("success", result.Success).
		Str("message", result.Message).
		Msg("Server password change completed")

	return &result, nil
}

// handleBatchUpdateError handles specific error cases for batch updates
func (sc *SyncClient) handleBatchUpdateError(resp *http.Response) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("batch update failed with status %d (failed to read response: %v)", resp.StatusCode, err)
	}

	// Try to parse as structured error response
	var errorResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
		Code    string `json:"code"`
	}

	if err := json.Unmarshal(bodyBytes, &errorResp); err == nil && errorResp.Error != "" {
		switch resp.StatusCode {
		case http.StatusConflict:
			if strings.Contains(errorResp.Code, "PASSWORD_CHANGE_IN_PROGRESS") {
				return fmt.Errorf("password change already in progress by another device: %s", errorResp.Message)
			}
		case http.StatusGone:
			if strings.Contains(errorResp.Code, "LOCK_EXPIRED") {
				return fmt.Errorf("password change lock has expired: %s", errorResp.Message)
			}
		case http.StatusForbidden:
			if strings.Contains(errorResp.Code, "WRONG_DEVICE") {
				return fmt.Errorf("password change lock belongs to different device: %s", errorResp.Message)
			}
		case http.StatusPreconditionFailed:
			if strings.Contains(errorResp.Code, "NO_PASSWORD_CHANGE_LOCK") {
				return fmt.Errorf("no active password change lock found: %s", errorResp.Message)
			}
		}
		return fmt.Errorf("batch update failed: %s (%s)", errorResp.Message, errorResp.Error)
	}

	// Fallback to raw response
	return fmt.Errorf("batch update failed with status %d: %s", resp.StatusCode, string(bodyBytes))
}

// GetDevices fetches the list of devices for the current user
func (sc *SyncClient) GetDevices() ([]ServerDevice, error) {
	req, err := sc.newAuthenticatedRequest("GET", sc.apiURL("/devices"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	var devicesResp DevicesResponse
	if err := sc.handleResponse(resp, &devicesResp); err != nil {
		return nil, err
	}

	return devicesResp.Devices, nil
}
